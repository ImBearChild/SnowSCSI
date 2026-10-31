//! Storage and host execution seams.
//!
//! Both seams are **metadata token + re-borrow on every poll**:
//! `begin_exec`/`begin_recv`/`begin_send` only see metadata, and the buffer is
//! re-borrowed by `poll_exec`/`poll_host`. This module therefore never stores a
//! `&mut [u8]`, never allocates and never uses `unsafe`; a token carries no
//! lifetime.
//!
//! Contract violations are **receipt errors**, not a separate return channel:
//! an unknown token, a token that already reached `Ready`, a full slot pool and
//! a `dir`/`len` vs `IoBuf`/`HostBuf` mismatch all produce
//! `Fault::Contract` inside [`StorageReceipt`]/[`HostReceipt`]. The runner
//! settles on that receipt, never maps it to SCSI sense, and may only reuse a
//! buffer/token after the receipt is `Ready` or `cancel` returned.
//!
//! `BlockingStorage`/`BlockingHost` are the synchronous-platform adapters: four
//! fixed slots each, no allocation, no thread or executor binding. Production
//! code provides the real adapter; this module deliberately ships **no**
//! `NullHost`, sink or model storage stand-in.
//!
//! # Path ambiguity with the `core` crate
//!
//! This module lives inside `crate::core`, so the language crate is always
//! spelled `::core::…` here.

use ::core::task::{Context, Poll};

use crate::common::seekable_storage::{FlatData, StorageError, WritableFlatData};

use super::async_wake::AsyncWake;
use super::device::{DataPlan, Direction, TargetId};
use super::errors::{Delivery, Effect, Fault};

/// Fixed token/slot count of the blocking adapters.
const SLOTS: usize = 4;

// ===========================================================================
// Storage vocabulary
// ===========================================================================

/// Bounded storage operation family.
///
/// `resource` is interpreted **only inside the current Lu's pair/backing set**
/// and are not global resource ids: a command on LUN *n* can never
/// address LUN *m*'s resource.
#[derive(Debug)]
pub enum StorageOp<'a> {
    /// Device → backing read into `buf`.
    Read {
        /// Resource id, local to the current Lu.
        resource: u16,
        /// Byte offset inside the resource.
        offset: u64,
        /// Destination buffer.
        buf: &'a mut [u8],
    },
    /// Backing write from `buf`.
    Write {
        /// Resource id, local to the current Lu.
        resource: u16,
        /// Byte offset inside the resource.
        offset: u64,
        /// Source buffer.
        buf: &'a [u8],
    },
    /// Flush/synchronize a resource; no data buffer.
    Sync {
        /// Resource id, local to the current Lu.
        resource: u16,
    },
}

/// Read-only speculative prefetch.
///
/// Deliberately a separate type from [`StorageOp`] so a write or sync can
/// never be disguised as a prefetch. Prefetch shares
/// [`Storage::begin_exec`]/[`Storage::poll_exec`] with ordinary reads.
#[derive(Debug)]
pub enum PrefetchOp<'a> {
    /// Speculative read into `buf`.
    Read {
        /// Resource id, local to the current Lu.
        resource: u16,
        /// Byte offset inside the resource.
        offset: u64,
        /// Destination buffer.
        buf: &'a mut [u8],
    },
}

/// Required write of an already-received chunk.
///
/// Deliberately a separate type from [`StorageOp`] so a read or sync can never
/// be submitted as a wire-step companion. The write shares
/// [`Storage::begin_exec`]/[`Storage::poll_exec`] with ordinary writes.
#[derive(Debug)]
pub enum WriteOp<'a> {
    /// Write a chunk the host already delivered.
    Write {
        /// Resource id, local to the current Lu.
        resource: u16,
        /// Byte offset inside the resource.
        offset: u64,
        /// Source buffer.
        buf: &'a [u8],
    },
}

/// Metadata-only storage request.
///
/// [`IoToken`] is unrelated to buffer lifetime: `dir` and `len` are what
/// `begin_exec` sees, and `poll_exec` must be handed a matching [`IoBuf`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IoReq {
    /// Resource id, local to the current Lu.
    pub resource: u16,
    /// Byte offset inside the resource.
    pub offset: u64,
    /// Number of bytes to transfer; `0` for [`Direction::None`].
    pub len: u32,
    /// Transfer direction; fixes which [`IoBuf`] variant is legal.
    pub dir: Direction,
}

/// Buffer supplied on each [`Storage::poll_exec`].
///
/// The correspondence with [`IoReq::dir`] is exhaustive:
///
/// - `Direction::None` ⇔ `IoBuf::None` and `len == 0` (sync/no-data ops must
///   **not** pass a zero-length `Read`/`Write`);
/// - `Direction::ToHost` ⇔ `IoBuf::Read(buf)` and `len == buf.len()`;
/// - `Direction::FromHost` ⇔ `IoBuf::Write(buf)` and `len == buf.len()`.
///
/// Any other combination is `Fault::Contract` in the returned
/// [`StorageReceipt`].
#[derive(Debug)]
pub enum IoBuf<'a> {
    /// No data phase (`dir == Direction::None`, `len == 0`).
    None,
    /// Device reads from the backing into this buffer (`dir == ToHost`).
    Read(&'a mut [u8]),
    /// Device writes this buffer to the backing (`dir == FromHost`).
    Write(&'a [u8]),
}

/// Opaque storage adapter token.
///
/// Fields are private, it is `Copy` and it carries no lifetime, so a token can
/// never pin a buffer across a `Pending` poll. A token is valid for exactly one
/// operation: it is not reused for another request, and it stops being
/// accepted after `Ready` or `cancel`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IoToken {
    index: u8,
    tag: u32,
}

impl IoToken {
    /// Token that no adapter accepts; returned when the slot pool is full.
    const INVALID: IoToken = IoToken {
        index: u8::MAX,
        tag: 0,
    };

    /// The invalid token (`BlockingStorage` returns it on pool exhaustion).
    pub(crate) const fn invalid() -> Self {
        Self::INVALID
    }

    /// Build an adapter-owned token.
    ///
    /// Tokens are opaque to the runner: it only passes them back to the same
    /// adapter. An adapter that implements [`Storage`] itself mints its own
    /// `(index, tag)` pair and must ensure a tag is not reused while the
    /// token is live.
    #[must_use]
    pub const fn new(index: u8, tag: u32) -> Self {
        Self { index, tag }
    }

    /// Whether this token names a slot at all.
    ///
    /// The runner checks this to distinguish "pool exhausted" from a usable
    /// token before it starts polling.
    pub(crate) const fn is_valid(self) -> bool {
        self.index != u8::MAX
    }
}

/// Whether `buf` is the legal buffer for `req`.
pub(crate) const fn buf_matches(req: IoReq, buf: &IoBuf<'_>) -> bool {
    match (req.dir, buf) {
        (Direction::None, IoBuf::None) => req.len == 0,
        (Direction::ToHost, IoBuf::Read(b)) => req.len as usize == b.len(),
        (Direction::FromHost, IoBuf::Write(b)) => req.len as usize == b.len(),
        _ => false,
    }
}

/// Contract-violation receipt (`Poll::Ready` with `error = Some(Contract)`).
pub(crate) const fn contract_receipt() -> StorageReceipt {
    StorageReceipt::failed(Fault::Contract, 0, Effect::Known)
}

/// Poll-first storage seam.
///
/// The runner owns the buffers and the ordering: `begin_exec` takes metadata
/// only, `poll_exec` re-borrows the buffer on every call, and `cancel` settles
/// the token (idempotent; the token is dead afterwards). A buffer must not be
/// reused between a `Pending` poll and the matching `Ready`/`cancel`.
pub trait Storage {
    /// Select the LUN whose backing the next operations address.
    ///
    /// One adapter may serve several LUNs (a CLI target with independent
    /// backends); the runner calls this once per entry before addressing
    /// `lun`. Single-LUN adapters keep the default no-op.
    fn select_lun(&mut self, lun: usize) {
        let _ = lun;
    }

    /// Start one operation from metadata alone.
    ///
    /// Returns a token that the adapter rejects on every poll when no slot is
    /// free (`IoToken::invalid()`), never a panic and never an allocation.
    fn begin_exec(&mut self, req: IoReq) -> IoToken;

    /// Poll the operation named by `token`.
    ///
    /// `Pending` means the buffer stays borrowed by the caller until the next
    /// poll or `cancel`. `Ready` carries the adapter facts; an unknown token, an
    /// already-`Ready` token or a `buf` that does not match `req` yields
    /// `Fault::Contract`.
    fn poll_exec(&mut self, token: IoToken, buf: IoBuf<'_>) -> Poll<StorageReceipt>;

    /// Stop waiting on `token`; idempotent, and the token is dead afterwards.
    fn cancel(&mut self, token: IoToken);
}

/// Synchronous storage convenience.
///
/// [`BlockingStorage`] lifts it into [`Storage`]. Sync/no-data operations use
/// [`IoBuf::None`] here as well.
pub trait SyncStorage {
    /// Execute one operation to completion.
    fn exec(&mut self, req: IoReq, buf: IoBuf<'_>) -> StorageReceipt;
}

/// Fixed four-slot synchronous storage adapter.
///
/// No allocation, no thread or executor binding, and the inner adapter only
/// ever sees requests through [`SyncStorage::exec`]. Pool exhaustion, unknown
/// tokens, repeated `Ready` and `dir`/`len` mismatches are reported as
/// `StorageReceipt { error: Some(Fault::Contract), .. }` — never as a panic and
/// never as a bare [`Fault`].
pub struct BlockingStorage<S: SyncStorage> {
    inner: S,
    slots: [Option<(IoReq, u32)>; SLOTS],
    next_tag: u32,
}

impl<S: SyncStorage> BlockingStorage<S> {
    /// Wrap a synchronous adapter with the four-slot token pool.
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            slots: [None; SLOTS],
            next_tag: 1,
        }
    }

    /// Borrow the wrapped adapter.
    pub fn inner(&self) -> &S {
        &self.inner
    }

    /// Mutably borrow the wrapped adapter (test/probe inspection).
    pub fn inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    /// Mint a token for `req`, or [`IoToken::invalid`] when all slots are busy.
    fn begin(&mut self, req: IoReq) -> IoToken {
        for (index, slot) in self.slots.iter_mut().enumerate() {
            if slot.is_none() {
                let tag = self.next_tag;
                self.next_tag = self.next_tag.wrapping_add(1).max(1);
                *slot = Some((req, tag));
                return IoToken {
                    index: index as u8,
                    tag,
                };
            }
        }
        IoToken::invalid()
    }

    /// Read the live request for `token`, if the token still names a slot.
    fn live_req(&self, token: IoToken) -> Option<IoReq> {
        if !token.is_valid() {
            return None;
        }
        match self.slots.get(token.index as usize) {
            Some(Some((req, tag))) if *tag == token.tag => Some(*req),
            _ => None,
        }
    }

    /// Clear the slot named by `token`, but only if it still holds that exact
    /// operation (a stale token never cancels a newer one).
    fn release(&mut self, token: IoToken) {
        if !token.is_valid() {
            return;
        }
        if let Some(slot) = self.slots.get_mut(token.index as usize) {
            if matches!(slot, Some((_, tag)) if *tag == token.tag) {
                *slot = None;
            }
        }
    }
}

impl<S: SyncStorage> Storage for BlockingStorage<S> {
    fn begin_exec(&mut self, req: IoReq) -> IoToken {
        self.begin(req)
    }

    fn poll_exec(&mut self, token: IoToken, buf: IoBuf<'_>) -> Poll<StorageReceipt> {
        let req = match self.live_req(token) {
            Some(req) => req,
            None => return Poll::Ready(contract_receipt()),
        };
        // Clear before exec: the token is spent even if the buffer is wrong or
        // the inner adapter reports an error.
        self.release(token);
        if !buf_matches(req, &buf) {
            return Poll::Ready(contract_receipt());
        }
        Poll::Ready(self.inner.exec(req, buf))
    }

    fn cancel(&mut self, token: IoToken) {
        self.release(token);
    }
}

/// A blocking adapter is always ready: its `poll_exec` never returns
/// [`Poll::Pending`], so an asynchronous shell waiting on it completes at once.
impl<S: SyncStorage> AsyncWake for BlockingStorage<S> {
    fn poll_wake(&mut self, _cx: &mut Context<'_>) -> Poll<()> {
        Poll::Ready(())
    }
}

// ===========================================================================
// Byte-plane adapters
// ===========================================================================

/// Read-only byte-plane adapter: lifts [`FlatData`] into [`SyncStorage`].
///
/// A write request is a legal request this plane refuses, so it reports
/// [`Fault::NotWritable`] rather than [`Fault::Contract`]; the receipt still
/// carries the direction-implied effect. A sync has nothing to flush and
/// succeeds with zero confirmed bytes.
pub struct ReadOnlyPlane<T: FlatData> {
    plane: T,
}

impl<T: FlatData> ReadOnlyPlane<T> {
    /// Wrap a read-only plane.
    pub const fn new(plane: T) -> Self {
        Self { plane }
    }

    /// Borrow the wrapped plane.
    pub fn plane(&self) -> &T {
        &self.plane
    }

    /// Mutably borrow the wrapped plane.
    pub fn plane_mut(&mut self) -> &mut T {
        &mut self.plane
    }
}

impl<T: FlatData> SyncStorage for ReadOnlyPlane<T> {
    fn exec(&mut self, req: IoReq, buf: IoBuf<'_>) -> StorageReceipt {
        let dir = req.dir;
        match (dir, buf) {
            (Direction::ToHost, IoBuf::Read(b)) if b.len() == req.len as usize => {
                match self.plane.read_at(req.offset, b) {
                    Ok(()) => StorageReceipt::ok(req.len as usize),
                    Err(e) => StorageReceipt::failed_for(dir, e),
                }
            }
            (Direction::FromHost, IoBuf::Write(b)) if b.len() == req.len as usize => {
                StorageReceipt::failed_for(dir, StorageError::NotWritable)
            }
            (Direction::None, IoBuf::None) if req.len == 0 => StorageReceipt::ok(0),
            _ => contract_receipt(),
        }
    }
}

/// Read/write byte-plane adapter: lifts [`WritableFlatData`] into
/// [`SyncStorage`].
///
/// The plumbing of [`FlatData::read_at`] / [`WritableFlatData::write_at`] /
/// [`WritableFlatData::sync`] is mechanical; [`BlockingStorage::from_plane`]
/// wraps this for adapters that only need a byte plane and no custom request
/// shaping.
pub struct WritablePlane<T: WritableFlatData> {
    plane: T,
}

impl<T: WritableFlatData> WritablePlane<T> {
    /// Wrap a writable plane.
    pub const fn new(plane: T) -> Self {
        Self { plane }
    }

    /// Borrow the wrapped plane.
    pub fn plane(&self) -> &T {
        &self.plane
    }

    /// Mutably borrow the wrapped plane.
    pub fn plane_mut(&mut self) -> &mut T {
        &mut self.plane
    }
}

impl<T: WritableFlatData> SyncStorage for WritablePlane<T> {
    fn exec(&mut self, req: IoReq, buf: IoBuf<'_>) -> StorageReceipt {
        let dir = req.dir;
        let result = match (dir, buf) {
            (Direction::ToHost, IoBuf::Read(b)) if b.len() == req.len as usize => {
                self.plane.read_at(req.offset, b).map(|()| b.len())
            }
            (Direction::FromHost, IoBuf::Write(b)) if b.len() == req.len as usize => {
                self.plane.write_at(req.offset, b).map(|()| b.len())
            }
            (Direction::None, IoBuf::None) if req.len == 0 => self.plane.sync().map(|()| 0),
            _ => return contract_receipt(),
        };
        match result {
            Ok(confirmed) => StorageReceipt::ok(confirmed),
            Err(e) => StorageReceipt::failed_for(dir, e),
        }
    }
}

impl<T: WritableFlatData> BlockingStorage<WritablePlane<T>> {
    /// Serve a writable byte plane directly from a blocking adapter.
    ///
    /// ```no_run
    /// # use snowscsi::common::seekable_storage::RamBackend;
    /// # use snowscsi::core::storage::BlockingStorage;
    /// let mut ram = [0u8; 4096];
    /// let storage = BlockingStorage::from_plane(RamBackend::new(&mut ram));
    /// ```
    pub fn from_plane(plane: T) -> Self {
        Self::new(WritablePlane::new(plane))
    }

    /// Borrow the wrapped plane.
    pub fn plane(&self) -> &T {
        self.inner().plane()
    }

    /// Mutably borrow the wrapped plane.
    pub fn plane_mut(&mut self) -> &mut T {
        self.inner_mut().plane_mut()
    }
}

impl<T: FlatData> BlockingStorage<ReadOnlyPlane<T>> {
    /// Serve a read-only byte plane directly from a blocking adapter.
    ///
    /// Writes are refused with [`Fault::NotWritable`], never with a contract
    /// violation, so a read-only LUN still answers WRITE with DATA PROTECT.
    pub fn from_read_plane(plane: T) -> Self {
        Self::new(ReadOnlyPlane::new(plane))
    }

    /// Borrow the wrapped plane.
    pub fn plane(&self) -> &T {
        self.inner().plane()
    }

    /// Mutably borrow the wrapped plane.
    pub fn plane_mut(&mut self) -> &mut T {
        self.inner_mut().plane_mut()
    }
}

// ===========================================================================
// Host vocabulary
// ===========================================================================

/// Metadata-only host request.
///
/// [`HostToken`] is unrelated to buffer lifetime; the buffer is re-borrowed on
/// every [`HostTransport::poll_host`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostReq {
    /// Number of bytes to transfer; `0` means a zero-length data phase.
    pub len: u32,
    /// Wire direction of the host data phase.
    pub dir: Direction,
}

/// Which of the caller's two data banks a host phase buffer lives in.
///
/// The runner derives it from the buffer's address; a buffer outside both
/// banks is a contract violation and never reaches the host adapter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BankSide {
    /// The primary `work` bank.
    Work,
    /// The alternate bank (`alt`).
    Alt,
}

/// Buffer supplied on each [`HostTransport::poll_host`].
///
/// `Recv` pairs with `Direction::FromHost` and `Send` with `Direction::ToHost`;
/// the length must equal [`HostReq::len`]. There is no "no-data" variant: a
/// host data phase with `Direction::None` is a contract violation. `bank` names
/// the caller bank the slice belongs to and is informational for single-bank
/// transports.
#[derive(Debug)]
pub enum HostBuf<'a> {
    /// Host → device data lands here.
    Recv {
        /// Destination window inside the named bank.
        buf: &'a mut [u8],
        /// Bank the window belongs to.
        bank: BankSide,
    },
    /// Device → host data is taken from here.
    Send {
        /// Source window inside the named bank.
        bytes: &'a [u8],
        /// Bank the window belongs to.
        bank: BankSide,
    },
}

/// Opaque host-side token.
///
/// Same opacity rules as [`IoToken`]: private fields, `Copy`, no lifetime, one
/// operation per token, dead after `Ready` or `cancel`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostToken {
    index: u8,
    tag: u32,
}

impl HostToken {
    /// Token that no transport accepts; returned when the slot pool is full.
    const INVALID: HostToken = HostToken {
        index: u8::MAX,
        tag: 0,
    };

    /// The invalid token (`BlockingHost` returns it on pool exhaustion).
    pub(crate) const fn invalid() -> Self {
        Self::INVALID
    }

    /// Build an adapter-owned host token (same rules as [`IoToken::new`]).
    #[must_use]
    pub const fn new(index: u8, tag: u32) -> Self {
        Self { index, tag }
    }

    /// Whether this token names a slot at all.
    pub(crate) const fn is_valid(self) -> bool {
        self.index != u8::MAX
    }
}

/// Whether `buf` is the legal buffer for `req`.
const fn host_buf_matches(req: HostReq, buf: &HostBuf<'_>) -> bool {
    match (req.dir, buf) {
        (Direction::FromHost, HostBuf::Recv { buf: b, .. }) => req.len as usize == b.len(),
        (Direction::ToHost, HostBuf::Send { bytes: b, .. }) => req.len as usize == b.len(),
        _ => false,
    }
}

/// Contract-violation host receipt.
const fn host_contract_receipt() -> HostReceipt {
    HostReceipt::new(0, Some(Fault::Contract), TargetId::UNBOUND)
}

/// Transport-facing data seam.
///
/// The runner owns command/storage ordering; the transport owns wire framing,
/// burst limits, R2T/Data-Out, BOT data phases and partial delivery. Polls only
/// ever return a [`HostReceipt`]: a `Fault::Contract` is a receipt error, not a
/// second return channel.
pub trait HostTransport {
    /// Publish the single data plan for this command.
    ///
    /// # Errors
    ///
    /// Returning `Err` rejects the plan (phase/limit mismatch); the runner
    /// settles the command with `Delivery::Failed` and sends no data.
    fn publish(&mut self, plan: DataPlan) -> Result<(), Fault>;

    /// Start receiving host data (`Direction::FromHost`).
    fn begin_recv(&mut self, req: HostReq) -> HostToken;

    /// Start sending device data (`Direction::ToHost`).
    fn begin_send(&mut self, req: HostReq) -> HostToken;

    /// Poll the pending data phase named by `token`.
    ///
    /// `Pending` keeps the buffer borrowed by the caller. Unknown, repeated or
    /// direction/length-mismatched tokens yield `HostReceipt.error =
    /// Some(Fault::Contract)`; once a receipt is terminal the runner stops
    /// advancing and settles.
    fn poll_host(&mut self, token: HostToken, buf: HostBuf<'_>) -> Poll<HostReceipt>;

    /// Stop waiting on `token`; idempotent, and the token is dead afterwards.
    fn cancel(&mut self, token: HostToken);

    /// How far the current completion has been delivered to the host.
    fn delivery(&self) -> Delivery;
}

/// Synchronous transport convenience.
///
/// [`BlockingHost`] lifts it into [`HostTransport`]; synchronous platforms only
/// implement this plus [`SyncStorage`].
pub trait SyncHost {
    /// Publish the single data plan for this command.
    ///
    /// # Errors
    ///
    /// Returning `Err` rejects the plan; the runner settles with
    /// `Delivery::Failed` and sends no data.
    fn publish(&mut self, plan: DataPlan) -> Result<(), Fault>;

    /// Receive host data (`Direction::FromHost`) into `buf`.
    fn receive(&mut self, req: HostReq, buf: HostBuf<'_>) -> HostReceipt;

    /// Send device data (`Direction::ToHost`) from `buf`.
    fn send(&mut self, req: HostReq, buf: HostBuf<'_>) -> HostReceipt;

    /// How far the current completion has been delivered to the host.
    fn delivery(&self) -> Delivery;
}

/// Fixed four-slot synchronous host adapter.
///
/// Symmetric to [`BlockingStorage`]: `begin_recv`/`begin_send` complete
/// immediately and `poll_host` is always `Ready`. Pool exhaustion, unknown
/// tokens, repeated `Ready` and direction/length mismatches produce
/// `HostReceipt.error = Some(Fault::Contract)`; the accepted count is clamped
/// to [`HostReq::len`] and the receipt owner is stamped [`TargetId::UNBOUND`]
/// (the runner re-stamps it).
pub struct BlockingHost<H: SyncHost> {
    inner: H,
    slots: [Option<(HostReq, u32)>; SLOTS],
    next_tag: u32,
}

impl<H: SyncHost> BlockingHost<H> {
    /// Wrap a synchronous transport with the four-slot token pool.
    pub fn new(inner: H) -> Self {
        Self {
            inner,
            slots: [None; SLOTS],
            next_tag: 1,
        }
    }

    /// Borrow the wrapped transport.
    pub fn inner(&self) -> &H {
        &self.inner
    }

    /// Mutably borrow the wrapped transport (test/probe inspection).
    pub fn inner_mut(&mut self) -> &mut H {
        &mut self.inner
    }

    /// Mint a token for `req`, or [`HostToken::invalid`] when all slots are busy.
    fn begin(&mut self, req: HostReq) -> HostToken {
        for (index, slot) in self.slots.iter_mut().enumerate() {
            if slot.is_none() {
                let tag = self.next_tag;
                self.next_tag = self.next_tag.wrapping_add(1).max(1);
                *slot = Some((req, tag));
                return HostToken {
                    index: index as u8,
                    tag,
                };
            }
        }
        HostToken::invalid()
    }

    /// Read the live request for `token`, if the token still names a slot.
    fn live_req(&self, token: HostToken) -> Option<HostReq> {
        if !token.is_valid() {
            return None;
        }
        match self.slots.get(token.index as usize) {
            Some(Some((req, tag))) if *tag == token.tag => Some(*req),
            _ => None,
        }
    }

    /// Clear the slot named by `token`, but only if it still holds that exact
    /// data phase (a stale token never cancels a newer one).
    fn release(&mut self, token: HostToken) {
        if !token.is_valid() {
            return;
        }
        if let Some(slot) = self.slots.get_mut(token.index as usize) {
            if matches!(slot, Some((_, tag)) if *tag == token.tag) {
                *slot = None;
            }
        }
    }
}

impl<H: SyncHost> HostTransport for BlockingHost<H> {
    fn publish(&mut self, plan: DataPlan) -> Result<(), Fault> {
        self.inner.publish(plan)
    }

    fn begin_recv(&mut self, req: HostReq) -> HostToken {
        self.begin(req)
    }

    fn begin_send(&mut self, req: HostReq) -> HostToken {
        self.begin(req)
    }

    fn poll_host(&mut self, token: HostToken, buf: HostBuf<'_>) -> Poll<HostReceipt> {
        let req = match self.live_req(token) {
            Some(req) => req,
            None => return Poll::Ready(host_contract_receipt()),
        };
        // Clear before the call: the token is spent even when the buffer or the
        // inner transport misbehaves.
        self.release(token);
        if !host_buf_matches(req, &buf) {
            return Poll::Ready(host_contract_receipt());
        }
        let receipt = match buf {
            HostBuf::Recv { buf: b, bank } => {
                self.inner.receive(req, HostBuf::Recv { buf: b, bank })
            }
            HostBuf::Send { bytes: b, bank } => {
                self.inner.send(req, HostBuf::Send { bytes: b, bank })
            }
        };
        Poll::Ready(HostReceipt::new(
            receipt.accepted().min(req.len as usize),
            receipt.error(),
            TargetId::UNBOUND,
        ))
    }

    fn cancel(&mut self, token: HostToken) {
        self.release(token);
    }

    fn delivery(&self) -> Delivery {
        self.inner.delivery()
    }
}

// ===========================================================================
// Receipts
// ===========================================================================

/// Application-side execution facts returned by a storage adapter.
///
/// [`StorageReceipt::confirmed`] is the confirmed prefix, not a success flag: a
/// short/failed operation keeps the bytes it really confirmed, and
/// [`Effect::UnknownRemainder`] marks a cancelled pending write/sync whose
/// remainder is unknown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StorageReceipt {
    /// Confirmed byte prefix.
    pub confirmed: usize,
    /// Adapter fault, if any.
    pub error: Option<Fault>,
    /// How much of the requested effect is actually known.
    pub effect: Effect,
}

impl StorageReceipt {
    /// Complete success with `confirmed` bytes.
    pub const fn ok(confirmed: usize) -> Self {
        Self {
            confirmed,
            error: None,
            effect: Effect::Known,
        }
    }

    /// Failure with a confirmed prefix and an effect qualifier.
    pub const fn failed(error: Fault, confirmed: usize, effect: Effect) -> Self {
        Self {
            confirmed,
            error: Some(error),
            effect,
        }
    }

    /// Failure reported by a byte-plane backend, with the effect implied by
    /// `dir`.
    ///
    /// A read is known to have left nothing behind; a failed write may have
    /// reached the medium partially, so its remainder is reported as unknown.
    /// A failed sync is reported as known: the error receipt was observed,
    /// which is not the same as a settlement that was never observed.
    pub fn failed_for(dir: Direction, error: StorageError) -> Self {
        Self::failed(
            Fault::from(error),
            0,
            match dir {
                Direction::FromHost => Effect::UnknownRemainder,
                _ => Effect::Known,
            },
        )
    }
}

/// Map the byte-plane error vocabulary onto the core fault vocabulary.
///
/// The two vocabularies are otherwise disjoint, so every adapter over a
/// [`FlatData`]/[`WritableFlatData`] plane needs the same four-arm mapping;
/// it lives here once, next to [`StorageReceipt::failed_for`].
impl From<StorageError> for Fault {
    fn from(e: StorageError) -> Self {
        match e {
            StorageError::OutOfBounds => Self::OutOfBounds,
            StorageError::NotWritable => Self::NotWritable,
            StorageError::Io(_) => Self::Io,
            StorageError::Unsupported => Self::Unsupported,
        }
    }
}

/// Opaque storage-IO receipt.
///
/// Fields are private: only the runner constructs one and stamps its owner, so
/// a device can report facts but cannot forge an [`IoReceipt`]. Identity is the
/// owner only; using it across targets must be rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IoReceipt {
    confirmed: usize,
    error: Option<Fault>,
    effect: Effect,
    owner: TargetId,
}

impl IoReceipt {
    /// Crate-private constructor; only the runner mints a receipt.
    #[allow(dead_code)] // constructed by the runner card
    pub(crate) const fn new(
        confirmed: usize,
        error: Option<Fault>,
        effect: Effect,
        owner: TargetId,
    ) -> Self {
        Self {
            confirmed,
            error,
            effect,
            owner,
        }
    }

    /// Stamp an adapter receipt with the owning runner's identity.
    #[allow(dead_code)] // constructed by the runner card
    pub(crate) fn from_storage(receipt: StorageReceipt, owner: TargetId) -> Self {
        Self::new(receipt.confirmed, receipt.error, receipt.effect, owner)
    }

    /// Test/crate-internal constructor (never part of the application API).
    #[allow(dead_code)] // used by seam tests and the runner card
    pub(crate) const fn test(confirmed: usize, error: Option<Fault>, effect: Effect) -> Self {
        Self::new(confirmed, error, effect, TargetId::UNBOUND)
    }

    /// Confirmed byte prefix reported by the adapter.
    pub const fn confirmed(&self) -> usize {
        self.confirmed
    }

    /// Adapter fault, if any.
    pub const fn error(&self) -> Option<Fault> {
        self.error
    }

    /// How much of the requested effect is known.
    pub const fn effect(&self) -> Effect {
        self.effect
    }

    /// Owning target identity.
    pub const fn owner(&self) -> TargetId {
        self.owner
    }
}

/// Opaque host-delivery receipt.
///
/// Fields are private; only the runner constructs one and stamps its owner.
/// [`HostReceipt::accepted`] is the actual accepted/sent prefix, which may be
/// shorter than the request (a short data phase is not a fabricated success).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostReceipt {
    accepted: usize,
    error: Option<Fault>,
    owner: TargetId,
}

impl HostReceipt {
    /// Crate-private constructor; only the runner/blocking adapter mints one.
    pub(crate) const fn new(accepted: usize, error: Option<Fault>, owner: TargetId) -> Self {
        Self {
            accepted,
            error,
            owner,
        }
    }

    /// Build a receipt from adapter facts for a `SyncHost` implementation.
    ///
    /// The owner is left [`TargetId::UNBOUND`]; the runner re-stamps the real
    /// owner, so an adapter cannot forge ownership.
    #[must_use]
    pub const fn from_adapter(accepted: usize, error: Option<Fault>) -> Self {
        Self::new(accepted, error, TargetId::UNBOUND)
    }

    /// Test/crate-internal constructor (never part of the application API).
    #[allow(dead_code)] // used by seam tests and the runner card
    pub(crate) const fn test(accepted: usize, error: Option<Fault>) -> Self {
        Self::new(accepted, error, TargetId::UNBOUND)
    }

    /// Accepted/sent byte prefix.
    pub const fn accepted(&self) -> usize {
        self.accepted
    }

    /// Transport fault, if any.
    pub const fn error(&self) -> Option<Fault> {
        self.error
    }

    /// Owning target identity.
    pub const fn owner(&self) -> TargetId {
        self.owner
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    const RES: u16 = 3;
    const OFF: u64 = 4096;

    /// Buffer-variant tag recorded by the test adapters.
    const KIND_NONE: u8 = 0;
    const KIND_READ: u8 = 1;
    const KIND_WRITE: u8 = 2;

    fn read_req(len: u32) -> IoReq {
        IoReq {
            resource: RES,
            offset: OFF,
            len,
            dir: Direction::ToHost,
        }
    }

    fn write_req(len: u32) -> IoReq {
        IoReq {
            resource: RES,
            offset: OFF,
            len,
            dir: Direction::FromHost,
        }
    }

    fn sync_req() -> IoReq {
        IoReq {
            resource: RES,
            offset: 0,
            len: 0,
            dir: Direction::None,
        }
    }

    fn token(index: u8, tag: u32) -> IoToken {
        IoToken { index, tag }
    }

    fn host_token(index: u8, tag: u32) -> HostToken {
        HostToken { index, tag }
    }

    /// Unwrap a `Ready` storage poll (the blocking adapters never return
    /// `Pending`).
    fn ready(poll: Poll<StorageReceipt>) -> StorageReceipt {
        match poll {
            Poll::Ready(receipt) => receipt,
            Poll::Pending => panic!("BlockingStorage must return Ready"),
        }
    }

    /// Unwrap a `Ready` host poll.
    fn host_ready(poll: Poll<HostReceipt>) -> HostReceipt {
        match poll {
            Poll::Ready(receipt) => receipt,
            Poll::Pending => panic!("BlockingHost must return Ready"),
        }
    }

    fn is_storage_contract(receipt: StorageReceipt) -> bool {
        receipt == StorageReceipt::failed(Fault::Contract, 0, Effect::Known)
    }

    fn is_host_contract(receipt: HostReceipt) -> bool {
        receipt.error() == Some(Fault::Contract)
            && receipt.accepted() == 0
            && receipt.owner() == TargetId::UNBOUND
    }

    /// Observed request/buffer pair (proves only metadata reaches `begin_*`).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct Call {
        resource: u16,
        offset: u64,
        len: u32,
        dir: Direction,
        kind: u8,
        buf_len: usize,
    }

    struct Recorder {
        calls: [Option<Call>; 8],
        count: usize,
        receipt: Option<StorageReceipt>,
    }

    impl Recorder {
        fn new() -> Self {
            Self {
                calls: [None; 8],
                count: 0,
                receipt: None,
            }
        }

        fn count(&self) -> usize {
            self.count
        }

        fn last(&self) -> Call {
            self.calls[self.count - 1].expect("recorded call")
        }
    }

    impl SyncStorage for Recorder {
        fn exec(&mut self, req: IoReq, buf: IoBuf<'_>) -> StorageReceipt {
            let (kind, buf_len) = match &buf {
                IoBuf::None => (KIND_NONE, 0),
                IoBuf::Read(b) => (KIND_READ, b.len()),
                IoBuf::Write(b) => (KIND_WRITE, b.len()),
            };
            if self.count < self.calls.len() {
                self.calls[self.count] = Some(Call {
                    resource: req.resource,
                    offset: req.offset,
                    len: req.len,
                    dir: req.dir,
                    kind,
                    buf_len,
                });
                self.count += 1;
            }
            match self.receipt {
                Some(receipt) => receipt,
                None => StorageReceipt::ok(buf_len),
            }
        }
    }

    fn storage() -> BlockingStorage<Recorder> {
        BlockingStorage::new(Recorder::new())
    }

    #[test]
    fn four_slots_then_fifth_begin_is_invalid() {
        let mut store = storage();
        let mut tokens = [IoToken::invalid(); SLOTS];
        for (slot, token) in tokens.iter_mut().enumerate() {
            *token = store.begin_exec(sync_req());
            assert!(token.is_valid(), "slot {slot} must be usable");
        }
        let fifth = store.begin_exec(sync_req());
        assert!(!fifth.is_valid(), "fifth begin must exhaust the pool");
        assert!(is_storage_contract(ready(
            store.poll_exec(fifth, IoBuf::None)
        )));
        // The four live tokens still complete normally.
        for token in tokens {
            assert_eq!(
                ready(store.poll_exec(token, IoBuf::None)),
                StorageReceipt::ok(0)
            );
        }
        assert_eq!(store.inner().count(), 4);
    }

    #[test]
    fn unknown_token_is_contract() {
        let mut store = storage();
        // Stale tag on an existing index, out-of-range index, and the invalid
        // token are all unknown.
        assert!(is_storage_contract(ready(
            store.poll_exec(token(0, 7), IoBuf::None)
        )));
        assert!(is_storage_contract(ready(
            store.poll_exec(token(9, 1), IoBuf::None)
        )));
        assert!(is_storage_contract(ready(
            store.poll_exec(IoToken::invalid(), IoBuf::None)
        )));
        store.cancel(IoToken::invalid());
        store.cancel(token(9, 1));
        assert_eq!(
            store.inner().count(),
            0,
            "contract tokens never reach inner"
        );
    }

    #[test]
    fn repeated_ready_is_contract() {
        let mut store = storage();
        let first = store.begin_exec(sync_req());
        assert_eq!(
            ready(store.poll_exec(first, IoBuf::None)),
            StorageReceipt::ok(0)
        );
        assert!(is_storage_contract(ready(
            store.poll_exec(first, IoBuf::None)
        )));
        assert_eq!(store.inner().count(), 1, "spent token must not re-execute");
    }

    #[test]
    fn cancel_is_idempotent_and_frees_the_slot() {
        let mut store = storage();
        let a = store.begin_exec(sync_req());
        let b = store.begin_exec(sync_req());
        store.cancel(a);
        store.cancel(a);
        assert!(is_storage_contract(ready(store.poll_exec(a, IoBuf::None))));

        // The freed slot is reusable, and the new token is a different
        // operation: the cancelled token stays dead.
        let c = store.begin_exec(sync_req());
        assert!(c.is_valid());
        assert_ne!(c, a);
        assert!(is_storage_contract(ready(store.poll_exec(a, IoBuf::None))));
        assert_eq!(
            ready(store.poll_exec(b, IoBuf::None)),
            StorageReceipt::ok(0)
        );
        assert_eq!(
            ready(store.poll_exec(c, IoBuf::None)),
            StorageReceipt::ok(0)
        );
        assert_eq!(store.inner().count(), 2);
    }

    #[test]
    fn cancel_with_stale_token_does_not_clear_another_operation() {
        let mut store = storage();
        let a = store.begin_exec(sync_req());
        let b = store.begin_exec(sync_req());
        // Same slot index as `b`, but `a`'s tag: a stale token, not `b`.
        store.cancel(token(b.index, a.tag));
        assert_eq!(
            ready(store.poll_exec(b, IoBuf::None)),
            StorageReceipt::ok(0)
        );
        store.cancel(a);
        assert!(is_storage_contract(ready(store.poll_exec(a, IoBuf::None))));
    }

    #[test]
    fn sync_uses_io_buf_none() {
        let mut store = storage();
        let op = store.begin_exec(sync_req());
        assert_eq!(
            ready(store.poll_exec(op, IoBuf::None)),
            StorageReceipt::ok(0)
        );
        assert_eq!(
            store.inner().last(),
            Call {
                resource: RES,
                offset: 0,
                len: 0,
                dir: Direction::None,
                kind: KIND_NONE,
                buf_len: 0,
            }
        );

        // A zero-length Read must not stand in for a no-data operation.
        let op = store.begin_exec(sync_req());
        assert!(is_storage_contract(ready(
            store.poll_exec(op, IoBuf::Read(&mut []))
        )));
        let op = store.begin_exec(sync_req());
        assert!(is_storage_contract(ready(
            store.poll_exec(op, IoBuf::Write(&[]))
        )));
        assert_eq!(store.inner().count(), 1);
    }

    #[test]
    fn to_host_requires_matching_read_buf() {
        let mut store = storage();
        let mut buf = [0xa5u8; 8];

        let op = store.begin_exec(read_req(8));
        assert!(is_storage_contract(ready(
            store.poll_exec(op, IoBuf::Write(&[0u8; 8]))
        )));
        let op = store.begin_exec(read_req(8));
        assert!(is_storage_contract(ready(
            store.poll_exec(op, IoBuf::Read(&mut buf[..4]))
        )));
        let op = store.begin_exec(read_req(8));
        assert!(is_storage_contract(ready(store.poll_exec(op, IoBuf::None))));

        let op = store.begin_exec(read_req(4));
        assert_eq!(
            ready(store.poll_exec(op, IoBuf::Read(&mut buf[..4]))),
            StorageReceipt::ok(4)
        );
        assert_eq!(
            store.inner().last(),
            Call {
                resource: RES,
                offset: OFF,
                len: 4,
                dir: Direction::ToHost,
                kind: KIND_READ,
                buf_len: 4,
            }
        );
    }

    #[test]
    fn from_host_requires_matching_write_buf() {
        let mut store = storage();
        let mut recv = [0u8; 8];

        let op = store.begin_exec(write_req(8));
        assert!(is_storage_contract(ready(
            store.poll_exec(op, IoBuf::Read(&mut recv))
        )));
        let op = store.begin_exec(write_req(8));
        assert!(is_storage_contract(ready(
            store.poll_exec(op, IoBuf::Write(&recv[..4]))
        )));
        let op = store.begin_exec(write_req(8));
        assert!(is_storage_contract(ready(store.poll_exec(op, IoBuf::None))));

        let op = store.begin_exec(write_req(8));
        assert_eq!(
            ready(store.poll_exec(op, IoBuf::Write(&recv))),
            StorageReceipt::ok(8)
        );
        assert_eq!(store.inner().last().kind, KIND_WRITE);
    }

    #[test]
    fn mismatch_clears_the_slot_for_reuse() {
        let mut store = storage();
        let mut ops = [IoToken::invalid(); SLOTS];
        for op in &mut ops {
            *op = store.begin_exec(read_req(4));
        }
        let buf = [0u8; 4];
        for op in ops {
            // Wrong direction: receipt is Contract and the slot is consumed.
            assert!(is_storage_contract(ready(
                store.poll_exec(op, IoBuf::Write(&buf))
            )));
        }
        let mut again = [IoToken::invalid(); SLOTS];
        for op in &mut again {
            *op = store.begin_exec(sync_req());
            assert!(op.is_valid(), "mismatch must have freed every slot");
        }
        for op in again {
            assert_eq!(
                ready(store.poll_exec(op, IoBuf::None)),
                StorageReceipt::ok(0)
            );
        }
    }

    #[test]
    fn begin_exec_receives_metadata_only() {
        let mut store = storage();
        let op = store.begin_exec(read_req(16));
        assert_eq!(store.inner().count(), 0, "begin_exec must not call inner");
        let mut buf = [0u8; 16];
        assert_eq!(
            ready(store.poll_exec(op, IoBuf::Read(&mut buf))),
            StorageReceipt::ok(16)
        );
        assert_eq!(
            store.inner().last(),
            Call {
                resource: RES,
                offset: OFF,
                len: 16,
                dir: Direction::ToHost,
                kind: KIND_READ,
                buf_len: 16,
            }
        );
    }

    #[test]
    fn inner_receipt_facts_pass_through() {
        let mut store = storage();
        store.inner_mut().receipt = Some(StorageReceipt::failed(
            Fault::Io,
            8,
            Effect::UnknownRemainder,
        ));
        let op = store.begin_exec(write_req(16));
        let buf = [0u8; 16];
        assert_eq!(
            ready(store.poll_exec(op, IoBuf::Write(&buf))),
            StorageReceipt::failed(Fault::Io, 8, Effect::UnknownRemainder)
        );
    }

    #[test]
    fn storage_op_families_are_debug_and_distinct() {
        let mut buf = [0u8; 4];
        let read = StorageOp::Read {
            resource: 1,
            offset: 2,
            buf: &mut buf,
        };
        assert!(format!("{read:?}").contains("Read"));
        let write = StorageOp::Write {
            resource: 1,
            offset: 2,
            buf: &[],
        };
        assert!(format!("{write:?}").contains("Write"));
        let sync = StorageOp::Sync { resource: 1 };
        assert!(format!("{sync:?}").contains("Sync"));
        let prefetch = PrefetchOp::Read {
            resource: 1,
            offset: 2,
            buf: &mut buf,
        };
        assert!(format!("{prefetch:?}").contains("Read"));
    }

    // -----------------------------------------------------------------
    // Host seam
    // -----------------------------------------------------------------

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct HostCall {
        len: u32,
        dir: Direction,
        kind: u8,
        buf_len: usize,
    }

    struct HostRecorder {
        recv_calls: usize,
        send_calls: usize,
        last: Option<HostCall>,
        accepts: usize,
        error: Option<Fault>,
        delivery: Delivery,
        published: usize,
        publish_error: Option<Fault>,
    }

    impl HostRecorder {
        fn new() -> Self {
            Self {
                recv_calls: 0,
                send_calls: 0,
                last: None,
                accepts: 0,
                error: None,
                delivery: Delivery::Complete,
                published: 0,
                publish_error: None,
            }
        }
    }

    impl SyncHost for HostRecorder {
        fn publish(&mut self, _plan: DataPlan) -> Result<(), Fault> {
            match self.publish_error {
                Some(fault) => Err(fault),
                None => {
                    self.published += 1;
                    Ok(())
                }
            }
        }

        fn receive(&mut self, req: HostReq, buf: HostBuf<'_>) -> HostReceipt {
            match buf {
                HostBuf::Recv { buf: b, .. } => {
                    self.recv_calls += 1;
                    self.last = Some(HostCall {
                        len: req.len,
                        dir: req.dir,
                        kind: KIND_READ,
                        buf_len: b.len(),
                    });
                    for byte in b.iter_mut() {
                        *byte = 0x5a;
                    }
                }
                HostBuf::Send { bytes: b, .. } => {
                    self.send_calls += 1;
                    self.last = Some(HostCall {
                        len: req.len,
                        dir: req.dir,
                        kind: KIND_WRITE,
                        buf_len: b.len(),
                    });
                }
            }
            HostReceipt::new(self.accepts, self.error, TargetId::new(9))
        }

        fn send(&mut self, req: HostReq, buf: HostBuf<'_>) -> HostReceipt {
            self.receive(req, buf)
        }

        fn delivery(&self) -> Delivery {
            self.delivery
        }
    }

    fn host() -> BlockingHost<HostRecorder> {
        BlockingHost::new(HostRecorder::new())
    }

    fn recv_req(len: u32) -> HostReq {
        HostReq {
            len,
            dir: Direction::FromHost,
        }
    }

    fn send_req(len: u32) -> HostReq {
        HostReq {
            len,
            dir: Direction::ToHost,
        }
    }

    #[test]
    fn host_four_slots_then_fifth_begin_is_invalid() {
        let mut host = host();
        let mut tokens = [HostToken::invalid(); SLOTS];
        for (slot, token) in tokens.iter_mut().enumerate() {
            *token = host.begin_recv(recv_req(4));
            assert!(token.is_valid(), "slot {slot} must be usable");
        }
        let fifth = host.begin_send(send_req(4));
        assert!(!fifth.is_valid(), "fifth begin must exhaust the pool");
        assert!(is_host_contract(host_ready(host.poll_host(
            fifth,
            HostBuf::Send {
                bytes: &[0u8; 4],
                bank: BankSide::Work
            }
        ))));
        for token in tokens {
            let mut buf = [0u8; 4];
            let receipt = host_ready(host.poll_host(
                token,
                HostBuf::Recv {
                    buf: &mut buf,
                    bank: BankSide::Work,
                },
            ));
            assert_eq!(receipt.error(), None);
            assert_eq!(buf, [0x5a; 4], "inner must see the caller's buffer");
        }
        assert_eq!(host.inner().recv_calls, 4);
    }

    #[test]
    fn host_unknown_and_repeated_tokens_are_contract() {
        let mut host = host();
        assert!(is_host_contract(host_ready(host.poll_host(
            host_token(0, 7),
            HostBuf::Recv {
                buf: &mut [0u8; 4],
                bank: BankSide::Work
            }
        ))));
        assert!(is_host_contract(host_ready(host.poll_host(
            host_token(9, 1),
            HostBuf::Recv {
                buf: &mut [0u8; 4],
                bank: BankSide::Work
            }
        ))));
        assert!(is_host_contract(host_ready(host.poll_host(
            HostToken::invalid(),
            HostBuf::Recv {
                buf: &mut [0u8; 4],
                bank: BankSide::Work
            }
        ))));
        assert_eq!(host.inner().recv_calls + host.inner().send_calls, 0);

        let token = host.begin_recv(recv_req(2));
        let mut buf = [0u8; 2];
        assert_eq!(
            host_ready(host.poll_host(
                token,
                HostBuf::Recv {
                    buf: &mut buf,
                    bank: BankSide::Work
                }
            ))
            .error(),
            None
        );
        assert!(is_host_contract(host_ready(host.poll_host(
            token,
            HostBuf::Recv {
                buf: &mut buf,
                bank: BankSide::Work
            }
        ))));
        assert_eq!(host.inner().recv_calls, 1);
    }

    #[test]
    fn host_direction_and_length_contract() {
        let mut host = host();

        // Recv token polled with Send data.
        let token = host.begin_recv(recv_req(4));
        assert!(is_host_contract(host_ready(host.poll_host(
            token,
            HostBuf::Send {
                bytes: &[0u8; 4],
                bank: BankSide::Work
            }
        ))));
        // Send token polled with Recv data.
        let token = host.begin_send(send_req(4));
        assert!(is_host_contract(host_ready(host.poll_host(
            token,
            HostBuf::Recv {
                buf: &mut [0u8; 4],
                bank: BankSide::Work
            }
        ))));
        // Length mismatch in both directions.
        let token = host.begin_recv(recv_req(4));
        assert!(is_host_contract(host_ready(host.poll_host(
            token,
            HostBuf::Recv {
                buf: &mut [0u8; 8],
                bank: BankSide::Work
            }
        ))));
        let token = host.begin_send(send_req(4));
        assert!(is_host_contract(host_ready(host.poll_host(
            token,
            HostBuf::Send {
                bytes: &[0u8; 3],
                bank: BankSide::Work
            }
        ))));
        // A no-data host phase has no legal HostBuf variant.
        let token = host.begin_send(HostReq {
            len: 0,
            dir: Direction::None,
        });
        assert!(is_host_contract(host_ready(host.poll_host(
            token,
            HostBuf::Send {
                bytes: &[],
                bank: BankSide::Work
            }
        ))));
        assert_eq!(host.inner().recv_calls + host.inner().send_calls, 0);

        // Matching pairs reach the right SyncHost method.
        let token = host.begin_recv(recv_req(4));
        let mut buf = [0u8; 4];
        let receipt = host_ready(host.poll_host(
            token,
            HostBuf::Recv {
                buf: &mut buf,
                bank: BankSide::Work,
            },
        ));
        assert_eq!(receipt.error(), None);
        assert_eq!(host.inner().recv_calls, 1);
        assert_eq!(host.inner().send_calls, 0);
        assert_eq!(
            host.inner().last,
            Some(HostCall {
                len: 4,
                dir: Direction::FromHost,
                kind: KIND_READ,
                buf_len: 4,
            })
        );

        let token = host.begin_send(send_req(4));
        let receipt = host_ready(host.poll_host(
            token,
            HostBuf::Send {
                bytes: &[0u8; 4],
                bank: BankSide::Work,
            },
        ));
        assert_eq!(receipt.error(), None);
        assert_eq!(host.inner().send_calls, 1);
        assert_eq!(
            host.inner().last,
            Some(HostCall {
                len: 4,
                dir: Direction::ToHost,
                kind: KIND_WRITE,
                buf_len: 4,
            })
        );
    }

    #[test]
    fn host_accepted_is_clamped_to_request_len() {
        let mut host = host();
        host.inner_mut().accepts = 99;
        let token = host.begin_recv(recv_req(4));
        let mut buf = [0u8; 4];
        let receipt = host_ready(host.poll_host(
            token,
            HostBuf::Recv {
                buf: &mut buf,
                bank: BankSide::Work,
            },
        ));
        assert_eq!(receipt.accepted(), 4);
        assert_eq!(receipt.error(), None);
        // The runner re-stamps the owner, so the adapter's own stamp is dropped.
        assert_eq!(receipt.owner(), TargetId::UNBOUND);

        host.inner_mut().accepts = 2;
        let token = host.begin_send(send_req(4));
        let receipt = host_ready(host.poll_host(
            token,
            HostBuf::Send {
                bytes: &[0u8; 4],
                bank: BankSide::Work,
            },
        ));
        assert_eq!(receipt.accepted(), 2, "short data phase stays short");
    }

    #[test]
    fn host_cancel_is_idempotent_and_frees_the_slot() {
        let mut host = host();
        let a = host.begin_recv(recv_req(4));
        let b = host.begin_recv(recv_req(4));
        host.cancel(a);
        host.cancel(a);
        let mut buf = [0u8; 4];
        assert!(is_host_contract(host_ready(host.poll_host(
            a,
            HostBuf::Recv {
                buf: &mut buf,
                bank: BankSide::Work
            }
        ))));

        let c = host.begin_recv(recv_req(4));
        assert!(c.is_valid());
        assert_ne!(c, a);
        assert!(is_host_contract(host_ready(host.poll_host(
            a,
            HostBuf::Recv {
                buf: &mut buf,
                bank: BankSide::Work
            }
        ))));
        assert_eq!(
            host_ready(host.poll_host(
                b,
                HostBuf::Recv {
                    buf: &mut buf,
                    bank: BankSide::Work
                }
            ))
            .error(),
            None
        );
        assert_eq!(
            host_ready(host.poll_host(
                c,
                HostBuf::Recv {
                    buf: &mut buf,
                    bank: BankSide::Work
                }
            ))
            .error(),
            None
        );
        assert_eq!(host.inner().recv_calls, 2);

        // A stale token never cancels a newer phase in the same slot.
        let d = host.begin_recv(recv_req(4));
        host.cancel(host_token(d.index, a.tag));
        assert_eq!(
            host_ready(host.poll_host(
                d,
                HostBuf::Recv {
                    buf: &mut buf,
                    bank: BankSide::Work
                }
            ))
            .error(),
            None
        );
    }

    #[test]
    fn host_delegates_publish_and_delivery() {
        let mut host = host();
        let plan = DataPlan {
            direction: Direction::ToHost,
            bytes: 512,
        };
        assert_eq!(host.publish(plan), Ok(()));
        assert_eq!(host.inner().published, 1);
        host.inner_mut().publish_error = Some(Fault::Contract);
        assert_eq!(host.publish(plan), Err(Fault::Contract));

        assert_eq!(host.delivery(), Delivery::Complete);
        host.inner_mut().delivery = Delivery::Failed;
        assert_eq!(host.delivery(), Delivery::Failed);
    }

    #[test]
    fn receipts_are_values_with_accessors() {
        let storage_receipt = StorageReceipt::ok(7);
        assert_eq!(storage_receipt.confirmed, 7);
        assert_eq!(storage_receipt.error, None);
        assert_eq!(storage_receipt.effect, Effect::Known);

        let io = IoReceipt::test(7, None, Effect::Known);
        assert_eq!(io.confirmed(), 7);
        assert_eq!(io.error(), None);
        assert_eq!(io.effect(), Effect::Known);
        assert_eq!(io.owner(), TargetId::UNBOUND);
        assert_eq!(
            IoReceipt::from_storage(storage_receipt, TargetId::UNBOUND),
            io
        );
        assert_eq!(
            IoReceipt::new(
                0,
                Some(Fault::Cancelled),
                Effect::UnknownRemainder,
                TargetId::UNBOUND
            )
            .effect(),
            Effect::UnknownRemainder
        );

        let host_receipt = HostReceipt::test(3, Some(Fault::Io));
        assert_eq!(host_receipt.accepted(), 3);
        assert_eq!(host_receipt.error(), Some(Fault::Io));
        assert_eq!(host_receipt.owner(), TargetId::UNBOUND);
    }

    #[test]
    fn writable_plane_round_trips_and_syncs() {
        use crate::common::seekable_storage::RamBackend;

        let mut ram = [0u8; 32];
        let mut storage = BlockingStorage::from_plane(RamBackend::new(&mut ram));

        let write = storage.begin_exec(IoReq {
            resource: RES,
            offset: 0,
            len: 4,
            dir: Direction::FromHost,
        });
        let data = [7u8, 8, 9, 10];
        let receipt = ready(storage.poll_exec(write, IoBuf::Write(&data)));
        assert_eq!(receipt.error, None);
        assert_eq!(receipt.confirmed, 4);

        let read = storage.begin_exec(IoReq {
            resource: RES,
            offset: 0,
            len: 4,
            dir: Direction::ToHost,
        });
        let mut out = [0u8; 4];
        let receipt = ready(storage.poll_exec(read, IoBuf::Read(&mut out)));
        assert_eq!(receipt.error, None);
        assert_eq!(out, data);

        let sync = storage.begin_exec(sync_req());
        let receipt = ready(storage.poll_exec(sync, IoBuf::None));
        assert_eq!(receipt.error, None);
        assert_eq!(receipt.confirmed, 0);

        assert_eq!(storage.plane().capacity(), 32);
    }

    #[test]
    fn read_only_plane_refuses_writes_without_a_contract_fault() {
        use crate::common::seekable_storage::RamBackend;

        let mut ram = [1u8; 16];
        let mut storage = BlockingStorage::from_read_plane(RamBackend::new(&mut ram));

        let read = storage.begin_exec(IoReq {
            resource: RES,
            offset: 0,
            len: 4,
            dir: Direction::ToHost,
        });
        let mut out = [0u8; 4];
        let receipt = ready(storage.poll_exec(read, IoBuf::Read(&mut out)));
        assert_eq!(receipt.error, None);
        assert_eq!(out, [1u8; 4]);

        let write = storage.begin_exec(IoReq {
            resource: RES,
            offset: 0,
            len: 4,
            dir: Direction::FromHost,
        });
        let data = [2u8; 4];
        let receipt = ready(storage.poll_exec(write, IoBuf::Write(&data)));
        assert_eq!(receipt.error, Some(Fault::NotWritable));
        assert_eq!(receipt.effect, Effect::UnknownRemainder);
        assert_eq!(receipt.confirmed, 0);

        let sync = storage.begin_exec(sync_req());
        let receipt = ready(storage.poll_exec(sync, IoBuf::None));
        assert_eq!(receipt.error, None);
    }

    #[test]
    fn plane_bounds_errors_keep_the_vector_direction_effect() {
        use crate::common::seekable_storage::RamBackend;

        let mut ram = [0u8; 8];
        let mut storage = BlockingStorage::from_plane(RamBackend::new(&mut ram));

        let read = storage.begin_exec(IoReq {
            resource: RES,
            offset: 4,
            len: 8,
            dir: Direction::ToHost,
        });
        let mut out = [0u8; 8];
        let receipt = ready(storage.poll_exec(read, IoBuf::Read(&mut out)));
        assert_eq!(receipt.error, Some(Fault::OutOfBounds));
        assert_eq!(receipt.effect, Effect::Known);

        let write = storage.begin_exec(IoReq {
            resource: RES,
            offset: 4,
            len: 8,
            dir: Direction::FromHost,
        });
        let data = [0u8; 8];
        let receipt = ready(storage.poll_exec(write, IoBuf::Write(&data)));
        assert_eq!(receipt.error, Some(Fault::OutOfBounds));
        assert_eq!(receipt.effect, Effect::UnknownRemainder);
    }
}
