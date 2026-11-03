//! `MmcMedium` seam.
//!
//! The medium owns semantics and state; the drive owns CDB decoding,
//! validation and response encoding. A medium is a `Device::Medium` member,
//! not a `Storage`: it produces [`StorageOp`](crate::core::storage::StorageOp)
//! through [`PollStep`] and the runner executes it against the backing.
//!
//! `commit` is a local metadata hook only (no storage IO); durable host data is
//! committed by `MmcOp::Commit` (SYNCHRONIZE CACHE).

use super::attrs::{
    AtipInfo, DiscInfo, MmcAttrs, Session, Track, TrackInfo, TrackInfoRequest, TrackStatus,
};
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

    /// One step with an optional second caller bank.
    ///
    /// Default: ignore `alt` and behave exactly like [`Self::poll`]. A medium
    /// that pre-reads the next chunk overrides this and lands the `Prefetch`
    /// in `alt`.
    fn poll_with_alt<'a>(
        &mut self,
        fb: Feedback,
        data: &'a mut [u8],
        alt: &'a mut [u8],
    ) -> PollStep<'a> {
        let _ = alt;
        self.poll(fb, data)
    }

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

    /// Track description for READ TRACK INFORMATION.
    ///
    /// The default projects [`Self::track`], [`Self::session`] and
    /// [`Self::attrs`] as a closed, fully recorded medium: every selected
    /// track is [`TrackStatus::Complete`], its recorded and allocated length
    /// are its block count, the next writable address is one past its end and
    /// nothing remains free. A recordable medium overrides this to expose
    /// partial, reserved and invisible tracks.
    ///
    /// `Number(0)` and `Number(0xFF)` select no track here; those encodings
    /// only have meaning on recordable media.
    fn track_info(&self, request: TrackInfoRequest) -> Option<TrackInfo> {
        match request {
            TrackInfoRequest::Number(0 | 0xFF) => None,
            TrackInfoRequest::Number(number) => self.track(number).map(recorded_track_info),
            TrackInfoRequest::Lba(lba) => {
                let attrs = self.attrs();
                (1..=attrs.tracks)
                    .filter_map(|number| self.track(number))
                    .find(|track| {
                        lba >= track.start_lba && lba < track.start_lba.saturating_add(track.blocks)
                    })
                    .map(recorded_track_info)
            }
            TrackInfoRequest::Session(number) => {
                let session = self.session(number)?;
                self.track(session.first_track).map(recorded_track_info)
            }
        }
    }

    /// Disc-information summary for READ DISC INFORMATION.
    fn disc_info(&self) -> DiscInfo;

    /// ATIP descriptor data for READ TOC format 4 (MMC-6 Table 488).
    ///
    /// Only a CD-R/RW has a pre-groove to describe; a stamped CD or a
    /// non-CD medium returns `None`, and the drive answers the format 4
    /// request with `ILLEGAL REQUEST / INVALID FIELD IN CDB` (`24/00`).
    /// Default: no ATIP.
    fn atip(&self) -> Option<AtipInfo> {
        None
    }

    /// Whether [`MmcOp::Blank`] has medium semantics (an erasable disc).
    ///
    /// The drive uses this to route BLANK to the medium before the generic
    /// whole-medium zero-fill path. The default is `false`: only a rewritable
    /// medium with a real blank state (a CD-RW bundle) opts in. The medium
    /// still owns the per-call validation (write-once, recovery latch, unsupported
    /// blanking type).
    fn blank_supported(&self) -> bool {
        false
    }

    /// The host entered or left the Write Parameters Test Write mode.
    ///
    /// A medium that can simulate writes must consume the host's data without
    /// recording it. Default: ignore the mode; a write is a real write.
    fn set_test_write(&mut self, on: bool) {
        let _ = on;
    }

    /// The host selected whether the next session closure keeps the disc open
    /// for another session (Write Parameters page 0x05 Multi-session = `11b`).
    ///
    /// A sequential recordable medium uses this to choose between closing the
    /// session and finalizing the disc. `00b` and the finalize-compatible CD
    /// `01b` both arrive as `false`. Default: ignore the mode; a session
    /// closure finalizes.
    fn set_multi_session(&mut self, open: bool) {
        let _ = open;
    }
}

/// Project a closed, fully recorded track into the track-information view.
fn recorded_track_info(track: Track) -> TrackInfo {
    TrackInfo {
        number: track.number,
        session: track.session,
        start_lba: signed_lba(track.start_lba),
        length: track.blocks,
        allocated: track.blocks,
        nwa: track.start_lba.saturating_add(track.blocks),
        free_blocks: 0,
        status: TrackStatus::Complete,
        kind: track.kind,
        packet: false,
    }
}

/// Clamp a non-negative LBA into the signed track-information field.
const fn signed_lba(lba: u64) -> i64 {
    if lba > i64::MAX as u64 {
        i64::MAX
    } else {
        lba as i64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mmc::attrs::TrackKind;
    use crate::mmc::flat::FlatCdMedium;

    #[test]
    fn default_track_info_describes_the_recorded_track() {
        let medium = FlatCdMedium::read_only(16);
        let info = medium
            .track_info(TrackInfoRequest::Number(1))
            .expect("track 1");
        assert_eq!(info.number, 1);
        assert_eq!(info.session, 1);
        assert_eq!(info.start_lba, 0);
        assert_eq!(info.length, 16);
        assert_eq!(info.allocated, 16);
        assert_eq!(info.nwa, 16);
        assert_eq!(info.free_blocks, 0);
        assert_eq!(info.status, TrackStatus::Complete);
        assert_eq!(info.kind, TrackKind::Data);
        assert!(!info.packet);
    }

    #[test]
    fn default_track_info_selects_by_lba() {
        let medium = FlatCdMedium::read_only(16);
        assert_eq!(
            medium
                .track_info(TrackInfoRequest::Lba(15))
                .map(|i| i.number),
            Some(1)
        );
        assert_eq!(medium.track_info(TrackInfoRequest::Lba(16)), None);
        assert_eq!(
            medium
                .track_info(TrackInfoRequest::Lba(0))
                .map(|i| i.number),
            Some(1)
        );
    }

    #[test]
    fn default_track_info_selects_the_first_track_of_a_session() {
        let medium = FlatCdMedium::read_only(16);
        assert_eq!(
            medium
                .track_info(TrackInfoRequest::Session(1))
                .map(|i| i.number),
            Some(1)
        );
        assert_eq!(medium.track_info(TrackInfoRequest::Session(2)), None);
    }

    #[test]
    fn default_track_info_has_no_zero_or_lead_out_track() {
        let medium = FlatCdMedium::read_only(16);
        assert_eq!(medium.track_info(TrackInfoRequest::Number(0)), None);
        assert_eq!(medium.track_info(TrackInfoRequest::Number(0xFF)), None);
    }
}
