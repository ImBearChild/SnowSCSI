//! Application glue between the CLI's device specifications and the core
//! `Target` seams.
//!
//! The CLI serves a heterogeneous LUN set (block disks and MMC drives) through
//! one core target, so it needs three adapters that the library deliberately
//! leaves to the application:
//!
//! - [`CliMedium`] — one MMC medium enum (flat CD / DVD-RAM) so the drive type
//!   stays a single `MmcDrive<CliMedium>`;
//! - [`CliLu`] — one runtime `Lu` enum over the block and MMC slot types, with
//!   a single [`CliPair`] (the core `Pair` type of this application);
//! - [`CliStorage`] — a [`Storage`] adapter over the per-LUN [`OwnedPlane`]s,
//!   routed by the runner's `select_lun` hook.
//!
//! The glue owns no protocol state: every method forwards to the wrapped core
//! type.

use core::task::Poll;

use snowscsi::block::BlockDevice;
use snowscsi::cdrom::media::LiveData;
#[cfg(feature = "bundle")]
use snowscsi::common::flat_bundle::FlatBundle;
use snowscsi::common::seekable_storage::{FlatData, StorageError, WritableFlatData};
use snowscsi::common::store::{StoreOp, StorePlane};
use snowscsi::core::storage::{IoBuf, IoReq, IoToken, Storage, StorageReceipt};
use snowscsi::core::{
    Admission, BoundaryPermit, Change, ChangeResult, CommandContext, CommandPermit, Completion,
    Delivery, Effect, Fault, Feedback, InterruptReason, KnownEffects, LongInfo, Lu, LuImpl, LuInfo,
    OwnerBindPermit, Pair, PollStep, Sense, Spc, TargetId, UaClass,
};
#[cfg(feature = "dvdram")]
use snowscsi::mmc::DvdRamMedium;
use snowscsi::mmc::{DiscInfo, FlatCdMedium, MmcAttrs, MmcDrive, MmcMedium, MmcOp, Session, Track};
use snowscsi::scsi::backend::FileBackend;
use snowscsi::scsi::fs_backend::StdFsBackend;

#[cfg(feature = "tokio")]
pub mod tokio_conn;
pub mod worker;

/// Application backing handle: the CLI only needs an identity per LUN.
pub type CliBacking = u32;

/// One CLI-owned store plane.
///
/// Every variant owns its bytes — there is no borrow — so a plane can be moved
/// into a worker thread or an asynchronous backend task. The synchronous path
/// still builds a temporary [`StorePlane`] borrow per operation.
// The CLI builds one plane per LUN; the size difference is dominated by the
// live scanner's file table, not a hot-path concern (same rationale as
// `CliLu` below).
#[allow(clippy::large_enum_variant)]
pub enum OwnedPlane {
    /// Read-only file or block device.
    BlockRo(FileBackend),
    /// Writable file or block device.
    BlockRw(FileBackend),
    /// In-memory plane (`--block ram=`, `--dvdram=ram`).
    Ram {
        /// Backing bytes.
        bytes: Vec<u8>,
        /// Whether the LUN may write (the media policy is separate).
        writable: bool,
    },
    /// Directory-chunked filesystem plane (read-only or writable, as opened).
    #[cfg(feature = "bundle")]
    Bundle(FlatBundle<StdFsBackend>),
    /// Live ISO9660 directory scan (read-only).
    Live(LiveData<StdFsBackend>),
}

impl OwnedPlane {
    /// Whether this plane should be addressed as a writable plane.
    fn is_writable(&self) -> bool {
        match self {
            Self::BlockRw(_) => true,
            Self::Ram { writable, .. } => *writable,
            #[cfg(feature = "bundle")]
            Self::Bundle(bundle) => !bundle.is_read_only(),
            Self::BlockRo(_) | Self::Live(_) => false,
        }
    }

    /// Build the erased borrow the synchronous store path executes on.
    fn as_store_plane(&mut self) -> StorePlane<'_> {
        if self.is_writable() {
            StorePlane::BlockRw(self)
        } else {
            StorePlane::BlockRo(self)
        }
    }
}

/// Bounds-checked in-memory read.
pub(crate) fn ram_read(bytes: &[u8], off: u64, buf: &mut [u8]) -> Result<(), StorageError> {
    let start = usize::try_from(off).map_err(|_| StorageError::OutOfBounds)?;
    let end = start
        .checked_add(buf.len())
        .filter(|end| *end <= bytes.len())
        .ok_or(StorageError::OutOfBounds)?;
    buf.copy_from_slice(&bytes[start..end]);
    Ok(())
}

impl FlatData for OwnedPlane {
    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> Result<(), StorageError> {
        match self {
            Self::BlockRo(backend) | Self::BlockRw(backend) => backend.read_at(off, buf),
            Self::Ram { bytes, .. } => ram_read(bytes, off, buf),
            #[cfg(feature = "bundle")]
            Self::Bundle(bundle) => bundle.read_at(off, buf),
            Self::Live(live) => live.read_at(off, buf),
        }
    }

    fn capacity(&self) -> u64 {
        match self {
            Self::BlockRo(backend) | Self::BlockRw(backend) => backend.capacity(),
            Self::Ram { bytes, .. } => bytes.len() as u64,
            #[cfg(feature = "bundle")]
            Self::Bundle(bundle) => bundle.capacity(),
            Self::Live(live) => live.capacity(),
        }
    }
}

impl WritableFlatData for OwnedPlane {
    fn write_at(&mut self, off: u64, buf: &[u8]) -> Result<(), StorageError> {
        match self {
            Self::BlockRw(backend) => backend.write_at(off, buf),
            Self::Ram {
                bytes,
                writable: true,
            } => ram_write(bytes, off, buf),
            #[cfg(feature = "bundle")]
            Self::Bundle(bundle) => bundle.write_at(off, buf),
            _ => Err(StorageError::NotWritable),
        }
    }

    fn sync(&mut self) -> Result<(), StorageError> {
        match self {
            Self::BlockRw(backend) => backend.sync(),
            #[cfg(feature = "bundle")]
            Self::Bundle(bundle) => bundle.sync(),
            // A read-only plane, or memory that already is the store.
            Self::BlockRo(_) | Self::Live(_) | Self::Ram { .. } => Ok(()),
        }
    }

    fn fill_at(&mut self, off: u64, len: u64, byte: u8) -> Result<(), StorageError> {
        match self {
            Self::BlockRw(backend) => backend.fill_at(off, len, byte),
            Self::Ram {
                bytes,
                writable: true,
            } => {
                let start = usize::try_from(off).map_err(|_| StorageError::OutOfBounds)?;
                let end = usize::try_from(len)
                    .ok()
                    .and_then(|len| start.checked_add(len))
                    .filter(|end| *end <= bytes.len())
                    .ok_or(StorageError::OutOfBounds)?;
                bytes[start..end].fill(byte);
                Ok(())
            }
            #[cfg(feature = "bundle")]
            Self::Bundle(bundle) => bundle.fill_at(off, len, byte),
            _ => Err(StorageError::NotWritable),
        }
    }
}

/// Bounds-checked in-memory write.
pub(crate) fn ram_write(bytes: &mut [u8], off: u64, buf: &[u8]) -> Result<(), StorageError> {
    let start = usize::try_from(off).map_err(|_| StorageError::OutOfBounds)?;
    let end = start
        .checked_add(buf.len())
        .filter(|end| *end <= bytes.len())
        .ok_or(StorageError::OutOfBounds)?;
    bytes[start..end].copy_from_slice(buf);
    Ok(())
}

/// The media member of a CLI pair: a block slot has no medium, an MMC slot
/// carries one of the supported media.
pub enum CliPairMedium {
    /// Block slot (`NoMedium`).
    Block(snowscsi::core::NoMedium),
    /// MMC slot.
    Mmc(CliMedium),
}

/// The one pair type of the CLI target.
pub type CliPair = Pair<CliPairMedium, CliBacking>;

/// MMC medium enum: a flat read-only CD or a blank DVD-RAM.
pub enum CliMedium {
    /// Read-only CD data medium.
    Flat(FlatCdMedium),
    /// Rewritable DVD-RAM medium.
    #[cfg(feature = "dvdram")]
    DvdRam(DvdRamMedium),
}

impl MmcMedium for CliMedium {
    type State = ();

    fn attrs(&self) -> MmcAttrs {
        match self {
            Self::Flat(m) => m.attrs(),
            #[cfg(feature = "dvdram")]
            Self::DvdRam(m) => m.attrs(),
        }
    }

    fn state(&self) -> &Self::State {
        &()
    }

    fn begin(&mut self, op: MmcOp) -> Result<(), Completion> {
        match self {
            Self::Flat(m) => m.begin(op),
            #[cfg(feature = "dvdram")]
            Self::DvdRam(m) => m.begin(op),
        }
    }

    fn poll<'a>(&mut self, fb: Feedback, data: &'a mut [u8]) -> PollStep<'a> {
        match self {
            Self::Flat(m) => m.poll(fb, data),
            #[cfg(feature = "dvdram")]
            Self::DvdRam(m) => m.poll(fb, data),
        }
    }

    fn poll_with_alt<'a>(
        &mut self,
        fb: Feedback,
        data: &'a mut [u8],
        alt: &'a mut [u8],
    ) -> PollStep<'a> {
        match self {
            Self::Flat(m) => m.poll_with_alt(fb, data, alt),
            #[cfg(feature = "dvdram")]
            Self::DvdRam(m) => m.poll_with_alt(fb, data, alt),
        }
    }

    fn active(&self) -> bool {
        match self {
            Self::Flat(m) => m.active(),
            #[cfg(feature = "dvdram")]
            Self::DvdRam(m) => m.active(),
        }
    }

    fn interrupt(&mut self, reason: InterruptReason, known: KnownEffects) {
        match self {
            Self::Flat(m) => m.interrupt(reason, known),
            #[cfg(feature = "dvdram")]
            Self::DvdRam(m) => m.interrupt(reason, known),
        }
    }

    fn commit(&mut self) -> Result<(), Completion> {
        match self {
            Self::Flat(m) => m.commit(),
            #[cfg(feature = "dvdram")]
            Self::DvdRam(m) => m.commit(),
        }
    }

    fn track(&self, number: u16) -> Option<Track> {
        match self {
            Self::Flat(m) => m.track(number),
            #[cfg(feature = "dvdram")]
            Self::DvdRam(m) => m.track(number),
        }
    }

    fn session(&self, number: u16) -> Option<Session> {
        match self {
            Self::Flat(m) => m.session(number),
            #[cfg(feature = "dvdram")]
            Self::DvdRam(m) => m.session(number),
        }
    }

    fn disc_info(&self) -> DiscInfo {
        match self {
            Self::Flat(m) => m.disc_info(),
            #[cfg(feature = "dvdram")]
            Self::DvdRam(m) => m.disc_info(),
        }
    }
}

/// Block slot type: the public six-command SPC wrapper over a block profile.
pub type CliBlockLu = LuImpl<Spc<BlockDevice>, CliBacking>;
/// MMC slot type: the public six-command SPC wrapper over an MMC drive.
pub type CliMmcLu = LuImpl<Spc<MmcDrive<CliMedium>>, CliBacking>;

/// One runtime LUN over the two slot kinds, sharing [`CliPair`].
// The two slot kinds are deliberately unboxed: the CLI builds one per LUN and
// the size difference is a few hundred bytes, not a hot-path concern.
#[allow(clippy::large_enum_variant)]
pub enum CliLu {
    /// Block disk (PDT 0x00) or optical block profile.
    Block(CliBlockLu),
    /// MMC drive (PDT 0x05).
    Mmc(CliMmcLu),
}

fn block_pair(pair: Pair<snowscsi::core::NoMedium, CliBacking>) -> CliPair {
    Pair {
        medium: CliPairMedium::Block(pair.medium),
        backing: pair.backing,
    }
}

fn from_block_pair(pair: CliPair) -> Result<Pair<snowscsi::core::NoMedium, CliBacking>, CliPair> {
    match pair.medium {
        CliPairMedium::Block(medium) => Ok(Pair {
            medium,
            backing: pair.backing,
        }),
        CliPairMedium::Mmc(_) => Err(pair),
    }
}

fn mmc_pair(pair: Pair<CliMedium, CliBacking>) -> CliPair {
    Pair {
        medium: CliPairMedium::Mmc(pair.medium),
        backing: pair.backing,
    }
}

fn from_mmc_pair(pair: CliPair) -> Result<Pair<CliMedium, CliBacking>, CliPair> {
    match pair.medium {
        CliPairMedium::Mmc(medium) => Ok(Pair {
            medium,
            backing: pair.backing,
        }),
        CliPairMedium::Block(_) => Err(pair),
    }
}

fn convert_change<P, Q>(change: Change<P>, f: impl Fn(P) -> Q) -> Change<Q> {
    match change {
        Change::Install(p) => Change::Install(f(p)),
        Change::Replace(p) => Change::Replace(f(p)),
        Change::Remove => Change::Remove,
    }
}

fn convert_result<P, Q>(result: ChangeResult<P>, f: impl Fn(P) -> Q) -> ChangeResult<Q> {
    ChangeResult {
        pair: result.pair.map(f),
        local: result.local,
        delivery: result.delivery,
        effects: result.effects,
    }
}

impl Lu for CliLu {
    type Pair = CliPair;

    fn admit(&self, cdb: &[u8]) -> Admission {
        match self {
            Self::Block(lu) => lu.admit(cdb),
            Self::Mmc(lu) => lu.admit(cdb),
        }
    }

    fn prepare(
        &mut self,
        permit: &CommandPermit,
        ctx: CommandContext,
        cdb: &[u8],
    ) -> Result<(), Completion> {
        match self {
            Self::Block(lu) => lu.prepare(permit, ctx, cdb),
            Self::Mmc(lu) => lu.prepare(permit, ctx, cdb),
        }
    }

    fn active(&self) -> bool {
        match self {
            Self::Block(lu) => lu.active(),
            Self::Mmc(lu) => lu.active(),
        }
    }

    fn resume(&mut self, permit: &CommandPermit) -> Result<(), Completion> {
        match self {
            Self::Block(lu) => lu.resume(permit),
            Self::Mmc(lu) => lu.resume(permit),
        }
    }

    fn poll<'a>(
        &mut self,
        permit: &CommandPermit,
        feedback: Feedback,
        data: &'a mut [u8],
    ) -> PollStep<'a> {
        match self {
            Self::Block(lu) => lu.poll(permit, feedback, data),
            Self::Mmc(lu) => lu.poll(permit, feedback, data),
        }
    }

    fn poll_with_alt<'a>(
        &mut self,
        permit: &CommandPermit,
        feedback: Feedback,
        data: &'a mut [u8],
        alt: &'a mut [u8],
    ) -> PollStep<'a> {
        match self {
            Self::Block(lu) => lu.poll_with_alt(permit, feedback, data, alt),
            Self::Mmc(lu) => lu.poll_with_alt(permit, feedback, data, alt),
        }
    }

    fn poll_long<'a>(
        &mut self,
        permit: &CommandPermit,
        feedback: Feedback,
        data: &'a mut [u8],
    ) -> PollStep<'a> {
        match self {
            Self::Block(lu) => lu.poll_long(permit, feedback, data),
            Self::Mmc(lu) => lu.poll_long(permit, feedback, data),
        }
    }

    fn long_info(&self) -> LongInfo {
        match self {
            Self::Block(lu) => lu.long_info(),
            Self::Mmc(lu) => lu.long_info(),
        }
    }

    fn snapshot(&self) -> LuInfo {
        match self {
            Self::Block(lu) => lu.snapshot(),
            Self::Mmc(lu) => lu.snapshot(),
        }
    }

    fn interrupt(
        &mut self,
        permit: &CommandPermit,
        reason: InterruptReason,
        known: KnownEffects,
    ) -> Result<(), Fault> {
        match self {
            Self::Block(lu) => lu.interrupt(permit, reason, known),
            Self::Mmc(lu) => lu.interrupt(permit, reason, known),
        }
    }

    fn finish_delivery(&mut self, permit: &CommandPermit, delivery: Delivery) {
        match self {
            Self::Block(lu) => lu.finish_delivery(permit, delivery),
            Self::Mmc(lu) => lu.finish_delivery(permit, delivery),
        }
    }

    fn autosense_delivered(&mut self, permit: &CommandPermit, sense: Sense) {
        match self {
            Self::Block(lu) => lu.autosense_delivered(permit, sense),
            Self::Mmc(lu) => lu.autosense_delivered(permit, sense),
        }
    }

    fn raise_ua(&mut self, permit: &CommandPermit, class: UaClass) {
        match self {
            Self::Block(lu) => lu.raise_ua(permit, class),
            Self::Mmc(lu) => lu.raise_ua(permit, class),
        }
    }

    fn owner(&self) -> TargetId {
        match self {
            Self::Block(lu) => lu.owner(),
            Self::Mmc(lu) => lu.owner(),
        }
    }

    fn bind_owner(&mut self, permit: &OwnerBindPermit, owner: TargetId) {
        match self {
            Self::Block(lu) => lu.bind_owner(permit, owner),
            Self::Mmc(lu) => lu.bind_owner(permit, owner),
        }
    }

    fn take_rt(&mut self, permit: &BoundaryPermit) -> Option<ChangeResult<CliPair>> {
        match self {
            Self::Block(lu) => lu.take_rt(permit).map(|r| convert_result(r, block_pair)),
            Self::Mmc(lu) => lu.take_rt(permit).map(|r| convert_result(r, mmc_pair)),
        }
    }

    fn has_result(&self) -> bool {
        match self {
            Self::Block(lu) => lu.has_result(),
            Self::Mmc(lu) => lu.has_result(),
        }
    }

    fn force_remove_rt(&mut self, permit: &BoundaryPermit) -> Result<(), Fault> {
        match self {
            Self::Block(lu) => lu.force_remove_rt(permit),
            Self::Mmc(lu) => lu.force_remove_rt(permit),
        }
    }

    fn install_rt(
        &mut self,
        permit: &BoundaryPermit,
        pair: CliPair,
    ) -> Result<(), (CliPair, Fault)> {
        match self {
            Self::Block(lu) => match from_block_pair(pair) {
                Ok(pair) => lu
                    .install_rt(permit, pair)
                    .map_err(|(p, f)| (block_pair(p), f)),
                Err(pair) => Err((pair, Fault::Contract)),
            },
            Self::Mmc(lu) => match from_mmc_pair(pair) {
                Ok(pair) => lu
                    .install_rt(permit, pair)
                    .map_err(|(p, f)| (mmc_pair(p), f)),
                Err(pair) => Err((pair, Fault::Contract)),
            },
        }
    }

    fn propose_rt(
        &mut self,
        permit: &BoundaryPermit,
        change: Change<CliPair>,
    ) -> Result<(), (Change<CliPair>, Fault)> {
        match self {
            Self::Block(lu) => {
                let inner = change_cross(change, from_block_pair);
                match inner {
                    Ok(change) => lu
                        .propose_rt(permit, change)
                        .map_err(|(c, f)| (convert_change(c, block_pair), f)),
                    Err(change) => Err((change, Fault::Contract)),
                }
            }
            Self::Mmc(lu) => {
                let inner = change_cross(change, from_mmc_pair);
                match inner {
                    Ok(change) => lu
                        .propose_rt(permit, change)
                        .map_err(|(c, f)| (convert_change(c, mmc_pair), f)),
                    Err(change) => Err((change, Fault::Contract)),
                }
            }
        }
    }

    fn advance_rt(&mut self, permit: &BoundaryPermit) -> Result<(), Fault> {
        match self {
            Self::Block(lu) => lu.advance_rt(permit),
            Self::Mmc(lu) => lu.advance_rt(permit),
        }
    }

    fn eject_rt(&mut self, permit: &BoundaryPermit) -> Result<(), Fault> {
        match self {
            Self::Block(lu) => lu.eject_rt(permit),
            Self::Mmc(lu) => lu.eject_rt(permit),
        }
    }

    fn take_eject_request(&mut self) -> bool {
        match self {
            Self::Block(_) => false,
            Self::Mmc(lu) => lu.take_eject_request(),
        }
    }
}

/// Convert a `Change<CliPair>` into the slot-specific pair, keeping the
/// original on a type mismatch (the caller returns it unchanged).
fn change_cross<P>(
    change: Change<CliPair>,
    f: impl Fn(CliPair) -> Result<P, CliPair>,
) -> Result<Change<P>, Change<CliPair>> {
    match change {
        Change::Install(pair) => match f(pair) {
            Ok(p) => Ok(Change::Install(p)),
            Err(pair) => Err(Change::Install(pair)),
        },
        Change::Replace(pair) => match f(pair) {
            Ok(p) => Ok(Change::Replace(p)),
            Err(pair) => Err(Change::Replace(pair)),
        },
        Change::Remove => Ok(Change::Remove),
    }
}

/// Fixed-slot synchronous storage over the per-LUN [`OwnedPlane`]s.
///
/// A plane executes synchronously, so `begin_exec` only records the request
/// and `poll_exec` builds the temporary [`StorePlane`] borrow, runs it and
/// answers `Ready` immediately. The runner selects the addressed LUN
/// (`Storage::select_lun`) before each entry, which keeps one adapter usable
/// for the whole heterogeneous slot set.
pub struct CliStorage {
    planes: Vec<Option<OwnedPlane>>,
    lun: usize,
    pending: Option<(IoReq, u32)>,
    tag: u32,
}

impl CliStorage {
    /// Build the adapter over one plane slot per LUN.
    pub fn new(planes: Vec<Option<OwnedPlane>>) -> Self {
        Self {
            planes,
            lun: 0,
            pending: None,
            tag: 1,
        }
    }

    /// Flush every plane; errors are returned for the caller to report.
    pub fn sync(
        &mut self,
    ) -> Result<(), (usize, snowscsi::common::seekable_storage::StorageError)> {
        for (i, plane) in self.planes.iter_mut().enumerate() {
            if let Some(plane) = plane {
                plane.as_store_plane().sync().map_err(|e| (i, e))?;
            }
        }
        Ok(())
    }

    fn contract() -> StorageReceipt {
        StorageReceipt::failed(Fault::Contract, 0, Effect::Known)
    }
}

impl Storage for CliStorage {
    fn select_lun(&mut self, lun: usize) {
        self.lun = lun;
    }

    fn begin_exec(&mut self, req: IoReq) -> IoToken {
        if self.pending.is_some() || self.lun >= self.planes.len() {
            return IoToken::new(u8::MAX, 0);
        }
        let tag = self.tag;
        self.tag = self.tag.wrapping_add(1).max(1);
        self.pending = Some((req, tag));
        IoToken::new(0, tag)
    }

    fn poll_exec(&mut self, token: IoToken, buf: IoBuf<'_>) -> Poll<StorageReceipt> {
        let (req, tag) = match self.pending {
            Some((req, tag)) if token == IoToken::new(0, tag) => (req, tag),
            _ => return Poll::Ready(Self::contract()),
        };
        let _ = tag;
        self.pending = None;
        let ok = match (req.dir, &buf) {
            (snowscsi::core::Direction::None, IoBuf::None) => req.len == 0,
            (snowscsi::core::Direction::ToHost, IoBuf::Read(b)) => req.len as usize == b.len(),
            (snowscsi::core::Direction::FromHost, IoBuf::Write(b)) => req.len as usize == b.len(),
            _ => false,
        };
        if !ok {
            return Poll::Ready(Self::contract());
        }
        let Some(plane) = self.planes.get_mut(self.lun).and_then(|p| p.as_mut()) else {
            return Poll::Ready(Self::contract());
        };
        let mut plane = plane.as_store_plane();
        let (op, confirmed) = match buf {
            IoBuf::None => (StoreOp::Sync, 0),
            IoBuf::Read(b) => {
                let len = b.len();
                (
                    StoreOp::Read {
                        off: req.offset,
                        buf: b,
                    },
                    len,
                )
            }
            IoBuf::Write(b) => {
                let len = b.len();
                (
                    StoreOp::Write {
                        off: req.offset,
                        buf: b,
                    },
                    len,
                )
            }
        };
        match plane.do_op(op) {
            Ok(()) => Poll::Ready(StorageReceipt::ok(confirmed)),
            Err(e) => Poll::Ready(StorageReceipt::failed_for(req.dir, e)),
        }
    }

    fn cancel(&mut self, token: IoToken) {
        if let Some((_, tag)) = self.pending {
            if token == IoToken::new(0, tag) {
                self.pending = None;
            }
        }
    }
}

/// Inline storage never pends, so an async shell waiting on it completes on
/// the first poll (the same contract as the library's synchronous adapter).
#[cfg(feature = "tokio")]
impl snowscsi::core::async_wake::AsyncWake for CliStorage {
    fn poll_wake(&mut self, _cx: &mut core::task::Context<'_>) -> Poll<()> {
        Poll::Ready(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_send<T: Send>() {}

    #[test]
    fn owned_plane_is_send() {
        assert_send::<OwnedPlane>();
    }
}
