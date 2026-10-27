//! `MmcMedium` seam (`02-api-profiles.md` §6.1/§6.7).
//!
//! The medium owns semantics and state; the drive owns CDB decoding,
//! validation and response encoding. A medium is a `Device::Medium` member,
//! not a `Storage`: it produces [`StorageOp`](crate::core::storage::StorageOp)
//! through [`PollStep`] and the runner executes it against the backing.
//!
//! `commit` is a local metadata hook only (no storage IO); durable host data is
//! committed by `MmcOp::Commit` (SYNCHRONIZE CACHE).

use super::attrs::{DiscInfo, MmcAttrs, Session, Track};
use super::op::MmcOp;
use crate::core::{Completion, Feedback, InterruptReason, KnownEffects, PollStep};

/// An MMC media implementation (flat CD, live plane, bundle wrapper, …).
pub trait MmcMedium {
    /// Public state projection returned by [`Self::state`].
    type State;

    /// Static attributes of the current medium.
    fn attrs(&self) -> MmcAttrs;

    /// Current state projection.
    fn state(&self) -> &Self::State;

    /// Admit `op`, or reject it with a fixed completion before any IO.
    ///
    /// `Err(Completion::Good)` is reserved for a no-op success; any other
    /// `Err` is a CHECK/Busy completion.
    fn begin(&mut self, op: MmcOp) -> Result<(), Completion>;

    /// One step of the admitted operation. The slice is the caller's bank and
    /// is re-borrowed on every poll.
    fn poll<'a>(&mut self, fb: Feedback, data: &'a mut [u8]) -> PollStep<'a>;

    /// Whether an admitted operation is still unfinished.
    fn active(&self) -> bool;

    /// Settle an abnormal end; must preserve confirmed effects.
    fn interrupt(&mut self, reason: InterruptReason, known: KnownEffects);

    /// Local medium-metadata commit. No storage IO; not a durability promise.
    fn commit(&mut self) -> Result<(), Completion> {
        Ok(())
    }

    /// Read-only track description for TOC/TRACK INFORMATION encoding.
    fn track(&self, number: u16) -> Option<Track>;

    /// Read-only session description for TOC format 1.
    fn session(&self, number: u16) -> Option<Session>;

    /// Disc-information summary for READ DISC INFORMATION.
    fn disc_info(&self) -> DiscInfo;
}
