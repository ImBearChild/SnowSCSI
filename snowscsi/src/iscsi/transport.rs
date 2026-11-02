//! BSD TCP transport (`transport_bsd.c`) — `std` feature only.
//!
//! [`TcpConn`] wraps `std::net::TcpStream` as an embedded-io byte stream
//! (thus a
//! [`Conn`]). A read timeout is applied at
//! construction so a stalled peer cannot hang the server forever — this
//! covers the login phase, the command loop, and Data-Out (DoS fix).
//! Read/write loops are exact (`read_exact` / `write_all`
//! in [`read_exact`] /
//! [`write_all`], RFC 3720 §3.1 byte stream).
//!
//! [`serve`] is the convenience entry: a serial accept
//! loop (MaxConnections = 1) that serves one connection at a time with a
//! fresh [`IscsiSession`], retrying accept failures with a backoff instead of C's
//! infinite busy retry. Each connection is driven by [`serve_conn`], the
//! protocol-agnostic shell loop over [`Action`]/[`Event`] (the session owns all
//! framing and drives the core [`Target`] itself).

use std::io;
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::core::storage::Storage;
use crate::core::{RunOutcome, RuntimeSet, ServeExit, Target};
use crate::iscsi::conn::{read_exact, write_all, Conn};
use crate::iscsi::pdu::BHS_SIZE;
use crate::iscsi::target::{Action, Event, IscsiSession, TargetError};

#[cfg(feature = "async-io")]
use crate::core::async_wake::{self, AsyncWake};
#[cfg(feature = "async-io")]
use crate::iscsi::conn::{read_exact_async, AsyncConn};

/// Default read timeout guarding login / command loop / Data-Out.
pub const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Backoff between accept() failures (C busy-looped).
pub const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// A `TcpStream` wrapped as an embedded-io byte stream.
pub struct TcpConn {
    stream: TcpStream,
}

impl TcpConn {
    /// Wrap `stream`, applying `read_timeout` (`None` = no timeout).
    ///
    /// Nagle's algorithm is disabled: an iSCSI exchange is request/response
    /// (the target writes a PDU only after the initiator asked for it), so
    /// coalescing small writes buys nothing and costs a delayed-ACK stall
    /// (~40 ms) whenever a PDU's tail trails earlier segments. A chunked
    /// `READ` that spans several Data-In PDUs hits that path on every command.
    pub fn new(stream: TcpStream, read_timeout: Option<Duration>) -> io::Result<Self> {
        stream.set_nodelay(true)?;
        stream.set_read_timeout(read_timeout)?;
        Ok(Self { stream })
    }

    /// Consume and return the underlying `TcpStream`.
    pub fn into_inner(self) -> TcpStream {
        self.stream
    }
}

impl embedded_io::ErrorType for TcpConn {
    type Error = io::Error;
}

impl embedded_io::Read for TcpConn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match std::io::Read::read(&mut self.stream, buf) {
            Ok(n) => Ok(n),
            Err(e) => {
                crate::debug!("tcp read error: {}", e);
                Err(e)
            }
        }
    }
}

impl embedded_io::Write for TcpConn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        std::io::Write::write(&mut self.stream, buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        std::io::Write::flush(&mut self.stream)
    }
}

/// Drive one iSCSI connection until the session closes it or the core needs
/// the application.
///
/// The shell is protocol-agnostic: it stores received bytes at the offset the
/// session asked for, writes complete PDUs, and hands the completion back as
/// an [`Event`]. The session owns all framing and drives the core [`Target`]
/// (with `storage` executing the device's storage operations).
///
/// The loop owns **no device lifetime**: [`ServeExit::Outcome`] is returned at
/// a point where no I/O is in flight, and [`ServeExit::WireGone`] settles the
/// live command first. The same target may serve the next connection.
///
/// `scratch` is the resident long-operation bank: an **empty** `scratch`
/// selects the shared bank (`work` serves both paths), and the loop drives the
/// long operation one `Tick` step per turn instead of reading the wire while
/// its token is in flight. An overlap session (`session.overlap()`) keeps both
/// banks inside `work`: input is never deferred for a long token, and the
/// boundary `Tick` before consuming a received PDU advances the long operation
/// on the bank the command does not hold.
pub fn serve_conn<C: Conn, S: RuntimeSet>(
    conn: &mut C,
    work: &mut [u8],
    scratch: &mut [u8],
    session: &mut IscsiSession,
    target: &mut Target<S>,
    storage: &mut dyn Storage,
) -> Result<ServeExit, TargetError> {
    let result = serve_conn_loop(conn, work, scratch, session, target, storage);
    // A lost connection (or a caller bug) leaves the wire unusable:
    // `connection_lost` makes the session's host seam fail closed, and
    // `link_lost` settles the live command so the next connection finds a
    // clean target. A handback return deliberately does not come here.
    if matches!(&result, Ok(ServeExit::WireGone)) || result.is_err() {
        session.connection_lost();
        target.link_lost(storage, session);
    }
    result
}

/// Return to the application if the core has something for it.
fn boundary_exit<S: RuntimeSet>(target: &mut Target<S>) -> Option<ServeExit> {
    match target.tick() {
        RunOutcome::ServiceReady => None,
        RunOutcome::ResourcesReady { lun } if !target.take_ready(lun) => None,
        outcome => Some(ServeExit::Outcome(outcome)),
    }
}

fn serve_conn_loop<C: Conn, S: RuntimeSet>(
    conn: &mut C,
    work: &mut [u8],
    scratch: &mut [u8],
    session: &mut IscsiSession,
    target: &mut Target<S>,
    storage: &mut dyn Storage,
) -> Result<ServeExit, TargetError> {
    if session.overlap() {
        let total = work.len();
        if !total.is_multiple_of(2)
            || total / 2 < crate::MIN_DATA_LEN + BHS_SIZE
            || !(total / 2 - BHS_SIZE).is_multiple_of(4)
        {
            return Err(TargetError::WorkBufTooSmall);
        }
    } else {
        if work.len() < crate::MIN_DATA_LEN + BHS_SIZE {
            return Err(TargetError::WorkBufTooSmall);
        }
        if !(work.len() - BHS_SIZE).is_multiple_of(4) {
            return Err(TargetError::WorkBufTooSmall);
        }
    }
    if scratch.len() < crate::MIN_DATA_LEN && !scratch.is_empty() {
        return Err(TargetError::WorkBufTooSmall);
    }
    let shared = scratch.is_empty() && !session.overlap();
    let mut ev = Event::Tick;
    loop {
        // Shared bank: while the resident long operation holds an adapter
        // token, `work` is its data bank. Drive it one step per turn and never
        // read the wire until it settles, so a staged PDU is never clobbered.
        if shared && target.long_io_in_flight() {
            match session.poll(Event::Tick, work, scratch, target, storage) {
                // Nothing is staged in `work`; the framing action is re-emitted
                // once the token settles.
                Action::HostRecv { .. } => continue,
                // No wire transfer is pending while the command waits on
                // storage; keep the loop turning so the token can settle.
                Action::StoragePending => continue,
                // A response is staged in `work`, which the long token owns:
                // dropping it (or sending it) would lose or corrupt output.
                Action::HostSend { .. } => return Err(TargetError::Internal),
                Action::Closed => return Ok(ServeExit::WireGone),
                Action::Error(e) => return Err(e),
            }
        }
        // Overlap: a long token never defers input (it owns the other bank),
        // but it still advances only on a boundary `Tick`. A receive
        // completion is such a boundary, so drive one step before consuming
        // the bytes; a mid-command receive re-emits its own action.
        if !shared && session.overlap() && matches!(ev, Event::HostRecv { .. }) {
            match session.poll(Event::Tick, work, scratch, target, storage) {
                Action::HostRecv { .. } | Action::StoragePending => {}
                Action::Closed => return Ok(ServeExit::WireGone),
                Action::Error(e) => return Err(e),
                Action::HostSend { .. } => return Err(TargetError::Internal),
            }
        }
        let action = session.poll(ev, work, scratch, target, storage);
        // The carried event has been consumed: this is the only point where
        // the loop may return to the application. A pending wire write (a PDU)
        // goes out first; the next entry re-emits it from session state.
        let wire_pending = matches!(action, Action::HostSend { .. });
        if !wire_pending {
            if let Some(exit) = boundary_exit(target) {
                return Ok(exit);
            }
        }
        match action {
            Action::HostRecv { .. } if shared && target.long_io_in_flight() => {
                // The step above started the resident long operation; its token
                // now owns `work`. The receive is re-emitted on the next entry,
                // so drop it and drive the long operation first.
                ev = Event::Tick;
                continue;
            }
            Action::HostSend { .. } if shared && target.long_io_in_flight() => {
                // The response lives in `work`, which the long token is using;
                // this state must not be reached.
                return Err(TargetError::Internal);
            }
            Action::HostRecv { offset, len } => {
                if offset.checked_add(len).is_none_or(|end| end > work.len()) {
                    return Err(TargetError::Internal);
                }
                // Exact read of the framing length the session asked for, at
                // the offset it chose. EOF or an I/O failure ends the
                // connection (settled by the wrapper).
                if read_exact(conn, &mut work[offset..offset + len]).is_err() {
                    return Ok(ServeExit::WireGone);
                }
                ev = Event::HostRecv { len };
            }
            Action::HostSend { bytes, .. } => {
                if write_all(conn, bytes).is_err() {
                    return Ok(ServeExit::WireGone);
                }
                ev = Event::HostSent;
            }
            Action::StoragePending => {
                // No wire I/O: retry the command once on the next turn with a
                // no-op tick. The blocking adapter is ready on that poll.
                ev = Event::Tick;
            }
            Action::Closed => {
                return Ok(ServeExit::WireGone);
            }
            Action::Error(e) => {
                return Err(e);
            }
        }
    }
}

/// Drive one iSCSI connection until the session closes it or the core needs
/// the application, over an asynchronous byte stream (feature `async-io`).
///
/// The awaited mirror of [`serve_conn`]: the same `Action`/`Event` protocol,
/// the same bank checks and the same connection-loss settlement, but reads and
/// writes are awaited and a [`Action::StoragePending`] step awaits the
/// [`AsyncWake`] adapter instead of spinning. Runtime binding is the caller's
/// concern; this crate only serves one connection and owns no listener.
#[cfg(feature = "async-io")]
pub async fn serve_conn_async<C, S, W>(
    conn: &mut C,
    work: &mut [u8],
    scratch: &mut [u8],
    session: &mut IscsiSession,
    target: &mut Target<S>,
    storage: &mut W,
) -> Result<ServeExit, TargetError>
where
    C: AsyncConn,
    S: RuntimeSet,
    W: Storage + AsyncWake,
{
    let result = async {
        if session.overlap() {
            let total = work.len();
            if !total.is_multiple_of(2)
                || total / 2 < crate::MIN_DATA_LEN + BHS_SIZE
                || !(total / 2 - BHS_SIZE).is_multiple_of(4)
            {
                return Err(TargetError::WorkBufTooSmall);
            }
        } else {
            if work.len() < crate::MIN_DATA_LEN + BHS_SIZE {
                return Err(TargetError::WorkBufTooSmall);
            }
            if !(work.len() - BHS_SIZE).is_multiple_of(4) {
                return Err(TargetError::WorkBufTooSmall);
            }
        }
        if scratch.len() < crate::MIN_DATA_LEN && !scratch.is_empty() {
            return Err(TargetError::WorkBufTooSmall);
        }
        let shared = scratch.is_empty() && !session.overlap();
        let mut ev = Event::Tick;
        loop {
            // Shared bank: while the resident long operation holds an adapter
            // token, `work` is its data bank. Drive it one step per turn and
            // never read the wire until it settles, so a staged PDU is never
            // clobbered.
            if shared && target.long_io_in_flight() {
                match session.poll(Event::Tick, work, scratch, target, &mut *storage) {
                    // Nothing is staged in `work`; the framing action is
                    // re-emitted once the token settles.
                    Action::HostRecv { .. } => continue,
                    // No wire transfer is pending while the command waits on
                    // storage; await the adapter so the token can settle.
                    Action::StoragePending => {
                        async_wake::wait(&mut *storage).await;
                        continue;
                    }
                    // A response is staged in `work`, which the long token
                    // owns: dropping it (or sending it) would lose or corrupt
                    // output.
                    Action::HostSend { .. } => return Err(TargetError::Internal),
                    Action::Closed => return Ok(ServeExit::WireGone),
                    Action::Error(e) => return Err(e),
                }
            }
            // Overlap: a long token never defers input (it owns the other
            // bank), but it still advances only on a boundary `Tick`. A
            // receive completion is such a boundary, so drive one step before
            // consuming the bytes; a mid-command receive re-emits its action.
            if !shared && session.overlap() && matches!(ev, Event::HostRecv { .. }) {
                match session.poll(Event::Tick, work, scratch, target, &mut *storage) {
                    Action::HostRecv { .. } | Action::StoragePending => {}
                    Action::Closed => return Ok(ServeExit::WireGone),
                    Action::Error(e) => return Err(e),
                    Action::HostSend { .. } => return Err(TargetError::Internal),
                }
            }
            let action = session.poll(ev, work, scratch, target, &mut *storage);
            // The carried event has been consumed: this is the only point
            // where the loop may return to the application. A pending PDU goes
            // out first (see the sync loop).
            let wire_pending = matches!(action, Action::HostSend { .. });
            if !wire_pending {
                if let Some(exit) = boundary_exit(target) {
                    return Ok(exit);
                }
            }
            match action {
                Action::HostRecv { .. } if shared && target.long_io_in_flight() => {
                    // The step above started the resident long operation; its
                    // token now owns `work`. The receive is re-emitted on the
                    // next entry, so drop it and drive the long operation first.
                    ev = Event::Tick;
                    continue;
                }
                Action::HostSend { .. } if shared && target.long_io_in_flight() => {
                    // The response lives in `work`, which the long token is
                    // using; this state must not be reached.
                    return Err(TargetError::Internal);
                }
                Action::HostRecv { offset, len } => {
                    if offset.checked_add(len).is_none_or(|end| end > work.len()) {
                        return Err(TargetError::Internal);
                    }
                    // Exact read of the framing length the session asked for,
                    // at the offset it chose. EOF or an I/O failure ends the
                    // connection (settled below).
                    if read_exact_async(conn, &mut work[offset..offset + len])
                        .await
                        .is_err()
                    {
                        return Ok(ServeExit::WireGone);
                    }
                    ev = Event::HostRecv { len };
                }
                Action::HostSend { bytes, .. } => {
                    if conn.write_all(bytes).await.is_err() {
                        return Ok(ServeExit::WireGone);
                    }
                    ev = Event::HostSent;
                }
                Action::StoragePending => {
                    // No wire I/O: await the storage adapter, then feed a
                    // no-op tick so the core re-polls the settled operation.
                    async_wake::wait(&mut *storage).await;
                    ev = Event::Tick;
                }
                Action::Closed => {
                    return Ok(ServeExit::WireGone);
                }
                Action::Error(e) => {
                    return Err(e);
                }
            }
        }
    }
    .await;

    // A lost connection (or a caller bug) leaves the wire unusable:
    // `connection_lost` makes the session's host seam fail closed, and
    // `link_lost` settles the live command so the next connection finds a
    // clean target. A handback return deliberately does not come here.
    if matches!(&result, Ok(ServeExit::WireGone)) || result.is_err() {
        session.connection_lost();
        target.link_lost(&mut *storage, session);
    }
    result
}

/// Serial accept loop: serve one connection at a time,
/// with accept-failure backoff retry.
///
/// Each accepted connection gets a fresh [`IscsiSession`] **and a fresh core
/// [`Target`] over the same slots**: a new session starts from a clean
/// protocol state (login restarts the sequence numbers) and a target that
/// ended with the previous transport never leaks its terminal state into the
/// next connection. Returns when `stop` is set, or on a caller bug (work buffer
/// too small).
///
/// `table` is the runtime slot table (the target rebinds its owner per
/// connection) and `storage` is shared across connections.
///
/// Note: `std::net::TcpListener::bind` uses the OS default listen backlog
/// (SOMAXCONN), not the C `listen(fd, 1)`; the serial loop still queues a
/// second connection in the backlog until the current one ends.
///
/// `overlap` creates each connection's [`IscsiSession`] with
/// [`IscsiSession::with_overlap`]; `work` is then the total of two equal banks
/// and must satisfy the per-bank floor.
#[allow(clippy::too_many_arguments)]
pub fn serve<P>(
    listener: TcpListener,
    stop: &AtomicBool,
    work: &mut [u8],
    scratch: &mut [u8],
    table: &mut [&mut dyn crate::core::Lu<Pair = P>],
    storage: &mut dyn Storage,
    read_timeout: Option<Duration>,
    overlap: bool,
) -> Result<(), TargetError> {
    if overlap {
        let total = work.len();
        if !total.is_multiple_of(2)
            || total / 2 < crate::MIN_DATA_LEN + BHS_SIZE
            || !(total / 2 - BHS_SIZE).is_multiple_of(4)
        {
            return Err(TargetError::WorkBufTooSmall);
        }
    } else {
        if work.len() < crate::MIN_DATA_LEN + BHS_SIZE {
            return Err(TargetError::WorkBufTooSmall);
        }
        if !(work.len() - BHS_SIZE).is_multiple_of(4) {
            return Err(TargetError::WorkBufTooSmall);
        }
    }
    if scratch.len() < crate::MIN_DATA_LEN && !scratch.is_empty() {
        return Err(TargetError::WorkBufTooSmall);
    }
    loop {
        if stop.load(Ordering::Relaxed) {
            return Ok(());
        }
        let (stream, peer) = match listener.accept() {
            Ok(x) => x,
            Err(e) => {
                if stop.load(Ordering::Relaxed) {
                    return Ok(());
                }
                crate::warn!("accept failed: {} retrying", e);
                std::thread::sleep(ACCEPT_BACKOFF);
                continue;
            }
        };
        crate::info!("accepted connection from {}", peer);
        let mut conn = match TcpConn::new(stream, read_timeout) {
            Ok(c) => c,
            Err(e) => {
                crate::warn!("failed to set up connection: {}", e);
                continue;
            }
        };
        let mut session = if overlap {
            IscsiSession::new().with_overlap()
        } else {
            IscsiSession::new()
        };
        let mut target = Target::new(&mut *table);
        let exit = serve_conn(&mut conn, work, scratch, &mut session, &mut target, storage)?;
        crate::info!("connection from {} ended ({:?})", peer, exit);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{BlockAttrs, BlockDevice};
    use crate::core::storage::{BlockingStorage, IoBuf, IoReq, StorageReceipt, SyncStorage};
    use crate::core::{Lu, LuImpl, NoMedium, Pair, Spc};
    use crate::iscsi::conn::{read_exact, write_all};
    use crate::iscsi::pdu::{flag, op, stage};
    use crate::MIN_DATA_LEN;
    use std::io::{Read as _, Write as _};

    fn be32(v: u32) -> [u8; 4] {
        v.to_be_bytes()
    }

    /// Null-separated login request text (matches the mock initiator).
    const REQ_TEXT: &str = "InitiatorName=iqn.1994-05.com.redhat:test\0TargetName=iqn.1970-01.local.snowscsi:target\0IscsiSessionType=Normal\0HeaderDigest=None\0DataDigest=None\0InitialR2T=Yes\0ImmediateData=Yes\0MaxRecvDataSegmentLength=8192\0";

    /// One-PDU Login Request BHS: I=1, T=1, CSG=1, NSG=3.
    fn login_bhs(dsl: u32, itt: u32) -> [u8; 48] {
        let mut bhs = [0u8; 48];
        bhs[0] = op::LOGIN_REQ | 0x40;
        bhs[1] = flag::T_BIT | ((stage::OP_PARAM & 0x03) << flag::CSG_SHIFT) | stage::FULL_FEATURE;
        bhs[5] = (dsl >> 16) as u8;
        bhs[6] = (dsl >> 8) as u8;
        bhs[7] = dsl as u8;
        bhs[16..20].copy_from_slice(&be32(itt));
        bhs
    }

    /// Read one PDU (BHS + data segment + padding) from a raw client socket.
    fn read_pdu(client: &mut TcpStream) -> (Vec<u8>, Vec<u8>) {
        let mut bhs = [0u8; 48];
        client.read_exact(&mut bhs).unwrap();
        let dsl = (u32::from(bhs[5]) << 16) | (u32::from(bhs[6]) << 8) | u32::from(bhs[7]);
        let mut data = vec![0u8; dsl as usize];
        if dsl > 0 {
            client.read_exact(&mut data).unwrap();
        }
        let pad = (4 - ((48 + dsl as usize) & 3)) & 3;
        if pad > 0 {
            let mut junk = [0u8; 3];
            client.read_exact(&mut junk[..pad]).unwrap();
        }
        (bhs.to_vec(), data)
    }

    fn send_pdu(client: &mut TcpStream, bhs: &[u8; 48], data: &[u8]) {
        client.write_all(bhs).unwrap();
        client.write_all(data).unwrap();
        let pad = (4 - ((48 + data.len()) & 3)) & 3;
        client.write_all(&[0u8; 3][..pad]).unwrap();
    }

    /// Storage double: login/NOP/logout never issue storage IO.
    struct Sink;

    impl SyncStorage for Sink {
        fn exec(&mut self, _req: IoReq, buf: IoBuf<'_>) -> StorageReceipt {
            let len = match &buf {
                IoBuf::None => 0,
                IoBuf::Read(b) => b.len(),
                IoBuf::Write(b) => b.len(),
            };
            StorageReceipt::ok(len)
        }
    }

    #[test]
    fn tcp_conn_roundtrip() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut conn = TcpConn::new(stream, Some(Duration::from_secs(5))).unwrap();
            let mut buf = [0u8; 5];
            read_exact(&mut conn, &mut buf).unwrap();
            assert_eq!(&buf, b"hello");
            write_all(&mut conn, b"world").unwrap();
        });
        let mut client = TcpStream::connect(addr).unwrap();
        client.write_all(b"hello").unwrap();
        let mut buf = [0u8; 5];
        client.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"world");
        handle.join().unwrap();
    }

    #[test]
    fn tcp_conn_read_timeout_aborts_stalled_peer() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut conn = TcpConn::new(stream, Some(Duration::from_millis(200))).unwrap();
            let mut buf = [0u8; 48];
            assert!(read_exact(&mut conn, &mut buf).is_err());
        });
        let client = TcpStream::connect(addr).unwrap();
        handle.join().unwrap();
        drop(client);
    }

    #[test]
    fn serve_handles_login_nop_and_logout_over_tcp() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let stop = AtomicBool::new(false);
        let mut work = vec![0u8; MIN_DATA_LEN + BHS_SIZE];
        let mut scratch = vec![0u8; MIN_DATA_LEN];
        let mut slot = LuImpl::new(Spc::new(BlockDevice::new(BlockAttrs::new(32, 512))), 0u8);
        let mut table: [&mut dyn Lu<Pair = Pair<NoMedium, u8>>; 1] = [&mut slot];
        let mut storage = BlockingStorage::new(Sink);

        // The adapter is deliberately `!Send`: `serve` runs on this thread and
        // the initiator runs on the scoped thread.
        std::thread::scope(|scope| {
            let handle = scope.spawn(|| {
                let mut client = TcpStream::connect(addr).unwrap();

                // Login → Login Response.
                let text = REQ_TEXT.as_bytes();
                send_pdu(&mut client, &login_bhs(text.len() as u32, 1), text);
                let (bhs, _data) = read_pdu(&mut client);
                assert_eq!(bhs[0] & 0x3F, op::LOGIN_RESP);
                assert_ne!(bhs[1] & 0x80, 0); // T=1
                assert_eq!(&bhs[16..20], &be32(1)); // ITT echoed
                assert_eq!(&bhs[24..28], &be32(0)); // StatSN = 0
                assert_eq!(bhs[36], 0x00); // Status-Class = 0

                // NOP-Out → NOP-In (keepalive, TTT echoed back).
                let mut nop = [0u8; 48];
                nop[0] = op::NOP_OUT;
                nop[16..20].copy_from_slice(&be32(0xABCD));
                nop[20..24].copy_from_slice(&be32(0xFFFF_FFFF));
                client.write_all(&nop).unwrap();
                let (bhs, _) = read_pdu(&mut client);
                assert_eq!(bhs[0] & 0x3F, op::NOP_IN);
                assert_eq!(&bhs[16..20], &be32(0xABCD)); // ITT echoed
                assert_eq!(&bhs[20..24], &be32(0xFFFF_FFFF)); // TTT echoed

                // Logout → Logout Response → connection closes.
                let mut lo = [0u8; 48];
                lo[0] = op::LOGOUT_REQ;
                lo[16..20].copy_from_slice(&be32(0xCAFE));
                client.write_all(&lo).unwrap();
                let (bhs, _) = read_pdu(&mut client);
                assert_eq!(bhs[0] & 0x3F, op::LOGOUT_RESP);

                drop(client);
                // Wake the blocked accept() so serve() can observe `stop`.
                // If teardown won the race — serve() finished serve_conn,
                // saw `stop` at the top of its loop and exited without ever
                // parking in accept() — the listener is already dropped and
                // connecting fails with ConnectionRefused. That is fine: it
                // proves serve() observed stop on its own.
                stop.store(true, Ordering::SeqCst);
                if let Ok(poke) = TcpStream::connect(addr) {
                    drop(poke);
                }
            });

            serve(
                listener,
                &stop,
                &mut work,
                &mut scratch,
                &mut table,
                &mut storage,
                Some(Duration::from_secs(5)),
                false,
            )
            .unwrap();
            handle.join().unwrap();
        });
    }

    /// A connection whose peer is already gone: every read returns EOF.
    struct Eof;

    impl embedded_io::ErrorType for Eof {
        type Error = std::io::Error;
    }

    impl embedded_io::Read for Eof {
        fn read(&mut self, _buf: &mut [u8]) -> Result<usize, Self::Error> {
            Ok(0)
        }
    }

    impl embedded_io::Write for Eof {
        fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
            Ok(buf.len())
        }

        fn flush(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    /// `MIN_DATA_LEN` + BHS is accepted, one byte less is rejected before any
    /// wire read.
    #[test]
    fn serve_conn_checks_the_bank_floor_before_reading() {
        let mut slot = LuImpl::new(Spc::new(BlockDevice::new(BlockAttrs::new(16, 512))), 0u8);
        let mut table: [&mut dyn Lu<Pair = Pair<NoMedium, u8>>; 1] = [&mut slot];
        let mut storage = BlockingStorage::new(Sink);
        let mut session = IscsiSession::new();
        let mut target = Target::new(&mut table[..]);
        let mut scratch = vec![0u8; MIN_DATA_LEN];

        let mut short = vec![0u8; MIN_DATA_LEN + BHS_SIZE - 1];
        let mut conn = Eof;
        assert_eq!(
            serve_conn(
                &mut conn,
                &mut short,
                &mut scratch,
                &mut session,
                &mut target,
                &mut storage
            ),
            Err(TargetError::WorkBufTooSmall)
        );

        let mut work = vec![0u8; MIN_DATA_LEN + BHS_SIZE];
        let mut conn = Eof;
        assert_eq!(
            serve_conn(
                &mut conn,
                &mut work,
                &mut scratch,
                &mut session,
                &mut target,
                &mut storage
            ),
            Ok(ServeExit::WireGone),
            "the floor bank is accepted; the peer EOF closes the connection"
        );
    }

    /// The accept-loop entry applies the same floor before accepting.
    #[test]
    fn serve_checks_the_bank_floor_before_accepting() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let stop = AtomicBool::new(false);
        let mut work = vec![0u8; MIN_DATA_LEN + BHS_SIZE - 1];
        let mut scratch = vec![0u8; MIN_DATA_LEN];
        let mut slot = LuImpl::new(Spc::new(BlockDevice::new(BlockAttrs::new(16, 512))), 0u8);
        let mut table: [&mut dyn Lu<Pair = Pair<NoMedium, u8>>; 1] = [&mut slot];
        let mut storage = BlockingStorage::new(Sink);
        assert_eq!(
            serve(
                listener,
                &stop,
                &mut work,
                &mut scratch,
                &mut table,
                &mut storage,
                None,
                false,
            ),
            Err(TargetError::WorkBufTooSmall)
        );
    }
}
