//! BSD TCP transport (`transport_bsd.c`) — `std` feature only.
//!
//! [`TcpConn`] wraps `std::net::TcpStream` as an embedded-io byte stream
//! (thus a
//! [`Conn`](crate::iscsi::conn::Conn)). A read timeout is applied at
//! construction so a stalled peer cannot hang the server forever — this
//! covers the login phase, the command loop, and Data-Out (DoS fix).
//! Read/write loops are exact (`read_exact` / `write_all`
//! in [`read_exact`](crate::iscsi::conn::read_exact) /
//! [`write_all`](crate::iscsi::conn::write_all), RFC 3720 §3.1 byte stream).
//!
//! [`serve`] is the convenience entry: a serial accept
//! loop (MaxConnections = 1) that serves one connection at a time with a
//! fresh [`IscsiSession`], retrying accept failures with a backoff instead of C's
//! infinite busy retry.

use std::io;
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::iscsi::target::{serve_conn, IscsiSession, TargetError};
use crate::scsi::Luns;

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
    pub fn new(stream: TcpStream, read_timeout: Option<Duration>) -> io::Result<Self> {
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

/// Serial accept loop: serve one connection at a time,
/// with accept-failure backoff retry.
///
/// Each accepted connection gets a fresh [`IscsiSession`] (login restarts the
/// sequence numbers). Returns when `stop` is set, or on a caller bug
/// (work buffer too small).
///
/// `luns` bundles the LUN devices and their aligned storage planes (see
/// [`crate::scsi::Luns`]); it is shared across every connection and handed to
/// [`serve_conn`], which executes device-yielded `Store` ops against the
/// planes.
///
/// Note: `std::net::TcpListener::bind` uses the OS default listen backlog
/// (SOMAXCONN), not the C `listen(fd, 1)`; the serial loop still queues a
/// second connection in the backlog until the current one ends.
pub fn serve(
    listener: TcpListener,
    stop: &AtomicBool,
    work: &mut [u8],
    luns: &mut Luns<'_>,
    read_timeout: Option<Duration>,
) -> Result<(), TargetError> {
    if work.len() < crate::MIN_DATA_LEN + crate::iscsi::pdu::BHS_SIZE {
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
        let mut session = IscsiSession::new();
        match serve_conn(&mut conn, work, &mut session, luns) {
            Ok(()) => crate::info!("connection from {} ended", peer),
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::seekable_storage::RamBackend;
    use crate::common::store::StorePlane;
    use crate::iscsi::conn::{read_exact, write_all};
    use crate::iscsi::pdu::{flag, op, stage};
    use crate::scsi::block::BlockDevice;
    use crate::scsi::device::ScsiDevice;
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
        let mut work = vec![0u8; MIN_DATA_LEN + crate::iscsi::pdu::BHS_SIZE];
        let mut ram = vec![0u8; 16 * 1024 * 1024];
        let mut dev = BlockDevice::disk(&mut RamBackend::new(&mut ram), 512).unwrap();
        let mut devs: [&mut dyn ScsiDevice; 1] = [&mut dev];
        // Login/NOP/Logout never yield a `Store`; the aligned plane slot is
        // the self-backed placeholder (`None`).
        let mut planes: [Option<StorePlane>; 1] = [None];
        let mut luns = Luns::new(&mut devs, &mut planes);

        // `Luns` (hence `StorePlane`) is intentionally `!Send`, so `serve`
        // runs on this thread and the initiator runs on the scoped thread.
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
                &mut luns,
                Some(Duration::from_secs(5)),
            )
            .unwrap();
            handle.join().unwrap();
        });
    }
}
