//! Persistent TOC slot layout for the recordable CD medium (CD-R/CD-RW).
//!
//! A slot is a fixed-size INI document: a 256-byte header, the body with the
//! disc/track/session layout, and `;` comment padding up to the configured slot
//! size. Two slots alternate. A save writes the body and padding first and the
//! header last, so the last valid slot is only replaced after the whole new
//! slot has been written; until then its old header still fails the new body's
//! length/checksum check.
//!
//! This module is pure: it formats and parses bytes and never performs I/O.
//!
//! # Two-step read
//!
//! The body length is not known before the header is parsed. An application
//! reads the first [`TOC_HEADER_LEN`] bytes of each slot, calls
//! [`TocHeader::parse`] to learn `slot_size`, then reads that many bytes and
//! calls `parse` through `CdrBundleMedium::open`. When the application knows
//! which physical slot it
//! read, `CdrBundleMedium::open_at` also rejects a document whose stored `slot`
//! differs from that position (a copied or restored slot).
//!
//! Track fields are serialized so the body satisfies `length <= written`:
//! `length` is the user-written prefix and `written` is the recorded extent
//! (including close padding), with `nwa = data_start_lba + written`.
//!
//! # Equal sequence numbers
//!
//! [`TocHeader::newer_than`] defines the selection policy: the higher `seq`
//! wins, and an equal `seq` pair selects the higher slot index. `parse`
//! validates the stored `slot` field; it never infers the slot from `seq`.

use core::fmt::Write as _;

use heapless::{String, Vec};

use super::{
    CdrDiscState, DiscKind, SessionEntry, TrackEntry, MAX_SESSIONS, MAX_TRACKS, MEDIUM_LEADIN,
};
use crate::mmc::attrs::{TrackKind, TrackStatus};

/// Length of the fixed slot header.
pub const TOC_HEADER_LEN: usize = 256;
/// Smallest slot that can hold a header and at least one track/session.
pub const TOC_SLOT_MIN: u32 = 4096;
/// Largest accepted slot size.
pub const TOC_SLOT_MAX: u32 = 64 * 1024;
/// Default slot size for a blank medium.
pub const TOC_SLOT_DEFAULT: u32 = TOC_SLOT_MAX;
/// Storage resource of TOC slot 0.
pub const TOC_RESOURCE_0: u16 = 1;
/// Storage resource of TOC slot 1.
pub const TOC_RESOURCE_1: u16 = 2;
/// First storage resource used for track payloads (`16 + track`).
pub const TRACK_RESOURCE_BASE: u16 = 16;

const TOC_MAGIC: &str = "snow_cdr_bnd";
const TOC_VERSION: u32 = 1;
const BODY_LINE_MAX: usize = 96;
/// Conservative per-track body budget used to bound `max_tracks`.
const TRACK_BODY_MAX: usize = 320;
/// Conservative per-session body budget.
const SESSION_BODY_MAX: usize = 192;
/// Conservative budget for the four global body properties.
const GLOBAL_BODY_MAX: usize = 160;

/// Storage resource of TOC slot `slot` (`0` or `1`).
#[must_use]
pub const fn toc_resource(slot: u8) -> u16 {
    if slot == 0 {
        TOC_RESOURCE_0
    } else {
        TOC_RESOURCE_1
    }
}

/// File name of TOC slot `slot` (`0` or `1`).
#[must_use]
pub const fn toc_file(slot: u8) -> &'static str {
    if slot == 0 {
        "toc.0"
    } else {
        "toc.1"
    }
}

/// Storage resource of `track` (`16 + track`).
#[must_use]
pub const fn track_resource(track: u16) -> u16 {
    TRACK_RESOURCE_BASE.wrapping_add(track)
}

/// File name of `track` (`track_<n>.bin`).
#[must_use]
pub fn track_file(track: u16) -> String<16> {
    let mut out = String::new();
    // `track_65535.bin` is 15 bytes, so the buffer cannot overflow.
    let _ = write!(out, "track_{track}.bin");
    out
}

/// How a valid TOC that was written by an interrupted command is recovered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recovery {
    /// Drop the unclosed tail and any session it leaves empty.
    Delete,
    /// Keep the written prefix, close the records and protect the disc.
    ReadOnly,
}

/// A TOC slot that cannot be opened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TocError {
    /// The header `magic` value is missing or wrong.
    BadMagic,
    /// The header `version` value is missing or unsupported.
    BadVersion,
    /// The header is malformed (missing field, duplicate, unknown key).
    BadHeader,
    /// The body is malformed or inconsistent with its sections.
    Invalid,
    /// The declared slot size or `max_tracks` exceeds the supported bound.
    TooLarge,
    /// The requested slot size is below [`TOC_SLOT_MIN`].
    BadSlotSize,
    /// The medium is read-only (a recovery latch) and refuses a snapshot.
    WriteProtected,
}

impl core::fmt::Display for TocError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadMagic => write!(f, "invalid TOC magic"),
            Self::BadVersion => write!(f, "unsupported TOC version"),
            Self::BadHeader => write!(f, "malformed TOC header"),
            Self::Invalid => write!(f, "invalid TOC body"),
            Self::TooLarge => write!(f, "TOC slot is too large"),
            Self::BadSlotSize => write!(f, "TOC slot is too small"),
            Self::WriteProtected => write!(f, "medium is write-protected"),
        }
    }
}

impl core::error::Error for TocError {}

/// Parsed 256-byte slot header.
///
/// The header binds the body through `body_len` and `checksum`; `slot` is the
/// physical slot index and is never inferred from `seq`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TocHeader {
    /// Sequence number of the save that produced this slot.
    pub seq: u32,
    /// Total slot size in bytes.
    pub slot_size: u32,
    /// Largest number of tracks the slot can hold.
    pub max_tracks: u16,
    /// Physical slot index (`0` or `1`).
    pub slot: u8,
    /// Length of the body in bytes.
    pub body_len: u32,
    /// Checksum of the body bytes.
    pub checksum: u32,
}

impl TocHeader {
    /// Parse the first 256 bytes of a slot.
    ///
    /// This is the first step of the documented two-step read. Only the
    /// header is parsed; `parse` later validates the body length and checksum
    /// against the full slot.
    pub fn parse(bytes: &[u8]) -> Result<Self, TocError> {
        if bytes.len() < TOC_HEADER_LEN {
            return Err(TocError::BadHeader);
        }
        let text =
            core::str::from_utf8(&bytes[..TOC_HEADER_LEN]).map_err(|_| TocError::BadHeader)?;
        let mut magic = None;
        let mut version = None;
        let mut slot = None;
        let mut slot_size = None;
        let mut max_tracks = None;
        let mut body_len = None;
        let mut checksum = None;
        let mut seq = None;
        for item in ini_core::Parser::new(text).auto_trim(true) {
            match item {
                ini_core::Item::SectionEnd | ini_core::Item::Comment(_) | ini_core::Item::Blank => {
                }
                ini_core::Item::Error(_) | ini_core::Item::Section(_) => {
                    return Err(TocError::BadHeader);
                }
                ini_core::Item::Property(_, None) => return Err(TocError::BadHeader),
                ini_core::Item::Property(key, Some(value)) => match key {
                    "magic" => set_once(&mut magic, value).ok_or(TocError::BadHeader)?,
                    "version" => {
                        let parsed = value.parse::<u32>().map_err(|_| TocError::BadHeader)?;
                        set_once(&mut version, parsed).ok_or(TocError::BadHeader)?;
                    }
                    "slot" => {
                        let parsed = value.parse::<u8>().map_err(|_| TocError::BadHeader)?;
                        set_once(&mut slot, parsed).ok_or(TocError::BadHeader)?;
                    }
                    "slot_size" => {
                        let parsed = value.parse::<u32>().map_err(|_| TocError::BadHeader)?;
                        set_once(&mut slot_size, parsed).ok_or(TocError::BadHeader)?;
                    }
                    "max_tracks" => {
                        let parsed = value.parse::<u16>().map_err(|_| TocError::BadHeader)?;
                        set_once(&mut max_tracks, parsed).ok_or(TocError::BadHeader)?;
                    }
                    "body_len" => {
                        let parsed = value.parse::<u32>().map_err(|_| TocError::BadHeader)?;
                        set_once(&mut body_len, parsed).ok_or(TocError::BadHeader)?;
                    }
                    "checksum" => {
                        let parsed = value.parse::<u32>().map_err(|_| TocError::BadHeader)?;
                        set_once(&mut checksum, parsed).ok_or(TocError::BadHeader)?;
                    }
                    "seq" => {
                        let parsed = value.parse::<u32>().map_err(|_| TocError::BadHeader)?;
                        set_once(&mut seq, parsed).ok_or(TocError::BadHeader)?;
                    }
                    _ => return Err(TocError::BadHeader),
                },
            }
        }
        if magic != Some(TOC_MAGIC) {
            return Err(TocError::BadMagic);
        }
        if version != Some(TOC_VERSION) {
            return Err(TocError::BadVersion);
        }
        let slot = slot.ok_or(TocError::BadHeader)?;
        let slot_size = slot_size.ok_or(TocError::BadHeader)?;
        let max_tracks = max_tracks.ok_or(TocError::BadHeader)?;
        let body_len = body_len.ok_or(TocError::BadHeader)?;
        let checksum = checksum.ok_or(TocError::BadHeader)?;
        let seq = seq.ok_or(TocError::BadHeader)?;
        if slot > 1 {
            return Err(TocError::Invalid);
        }
        if slot_size < TOC_SLOT_MIN {
            return Err(TocError::BadSlotSize);
        }
        if slot_size > TOC_SLOT_MAX {
            return Err(TocError::TooLarge);
        }
        if max_tracks == 0
            || max_tracks > MAX_TRACKS as u16
            || max_tracks > max_tracks_for_slot(slot_size)
        {
            return Err(TocError::TooLarge);
        }
        if body_len == 0 || body_len as usize > slot_size as usize - TOC_HEADER_LEN {
            return Err(TocError::Invalid);
        }
        if seq == 0 {
            return Err(TocError::Invalid);
        }
        Ok(Self {
            seq,
            slot_size,
            max_tracks,
            slot,
            body_len,
            checksum,
        })
    }

    /// Selection policy for two valid headers: higher `seq` wins, then the
    /// higher slot index.
    #[must_use]
    pub fn newer_than(&self, other: &Self) -> bool {
        self.seq > other.seq || (self.seq == other.seq && self.slot > other.slot)
    }
}

fn set_once<T: Copy>(slot: &mut Option<T>, value: T) -> Option<()> {
    if slot.is_some() {
        return None;
    }
    *slot = Some(value);
    Some(())
}

/// Parsed and validated TOC content.
pub(crate) struct ParsedToc {
    /// Header that produced this content.
    pub header: TocHeader,
    /// Recordable media kind.
    pub kind: DiscKind,
    /// Disc state.
    pub disc: CdrDiscState,
    /// Addressable logical blocks.
    pub capacity: u64,
    /// Start address of the disc lead-in.
    pub medium_leadin: i64,
    /// Track records in slot order.
    pub tracks: Vec<TrackEntry, MAX_TRACKS>,
    /// Session records in slot order.
    pub sessions: Vec<SessionEntry, MAX_SESSIONS>,
}

/// Largest track count that fits a slot of `slot_size` bytes.
#[must_use]
pub fn max_tracks_for_slot(slot_size: u32) -> u16 {
    let overhead = TOC_HEADER_LEN
        .saturating_add(GLOBAL_BODY_MAX)
        .saturating_add(MAX_SESSIONS.saturating_mul(SESSION_BODY_MAX))
        .saturating_add("end = 1\n".len());
    let size = slot_size as usize;
    if size <= overhead {
        return 0;
    }
    let count = (size - overhead) / TRACK_BODY_MAX;
    count.min(MAX_TRACKS) as u16
}

/// Render the fixed 256-byte slot header.
pub(crate) fn header_bytes(
    slot: u8,
    slot_size: u32,
    max_tracks: u16,
    body_len: u32,
    checksum: u32,
    seq: u32,
) -> [u8; TOC_HEADER_LEN] {
    let mut text = String::<192>::new();
    let _ = write!(
        text,
        "magic = {TOC_MAGIC}\nversion = {TOC_VERSION}\nslot = {slot}\nslot_size = {slot_size}\nmax_tracks = {max_tracks}\nbody_len = {body_len}\nchecksum = {checksum}\nseq = {seq}\n"
    );
    let mut out = [b';'; TOC_HEADER_LEN];
    let n = text.len().min(TOC_HEADER_LEN);
    out[..n].copy_from_slice(&text.as_bytes()[..n]);
    pad_lines(&mut out, n);
    out
}

/// Fill `out[at..]` with complete `;` comment lines, ending on a newline.
fn pad_lines(out: &mut [u8], mut at: usize) {
    while at < out.len() {
        let remaining = out.len() - at;
        let semis = remaining.saturating_sub(1).min(64);
        out[at..at + semis].fill(b';');
        at += semis;
        out[at] = b'\n';
        at += 1;
    }
}

/// One line sink for body rendering.
trait LineSink {
    fn line(&mut self, text: &str);
}

/// Body length counter.
struct Counter(usize);

impl LineSink for Counter {
    fn line(&mut self, text: &str) {
        self.0 += text.len() + 1;
    }
}

/// Body checksum sink.
struct Checksum(u32);

impl LineSink for Checksum {
    fn line(&mut self, text: &str) {
        for byte in text.as_bytes() {
            self.0 = crc_update(self.0, *byte);
        }
        self.0 = crc_update(self.0, b'\n');
    }
}

const fn crc_update(mut crc: u32, byte: u8) -> u32 {
    crc ^= byte as u32;
    let mut bit = 0;
    while bit < 8 {
        let mask = 0u32.wrapping_sub(crc & 1);
        crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        bit += 1;
    }
    crc
}

/// CRC-32 of an arbitrary byte slice.
pub(crate) fn checksum(bytes: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for byte in bytes {
        crc = crc_update(crc, *byte);
    }
    !crc
}

/// Body chunk renderer: skips `at` bytes, then fills the output.
struct Chunk<'a> {
    out: &'a mut [u8],
    skip: usize,
    written: usize,
}

impl LineSink for Chunk<'_> {
    fn line(&mut self, text: &str) {
        for byte in text.as_bytes() {
            self.byte(*byte);
        }
        self.byte(b'\n');
    }
}

impl Chunk<'_> {
    fn byte(&mut self, byte: u8) {
        if self.skip > 0 {
            self.skip -= 1;
        } else if self.written < self.out.len() {
            self.out[self.written] = byte;
            self.written += 1;
        }
    }
}

/// Number of bytes of the body (without the slot header or padding).
pub(crate) fn body_len(
    tracks: &[TrackEntry],
    sessions: &[SessionEntry],
    capacity: u64,
    leadin: i64,
    disc: CdrDiscState,
    kind: DiscKind,
) -> usize {
    let mut counter = Counter(0);
    write_body(tracks, sessions, capacity, leadin, disc, kind, &mut counter);
    counter.0
}

/// Checksum of the body bytes.
pub(crate) fn body_checksum(
    tracks: &[TrackEntry],
    sessions: &[SessionEntry],
    capacity: u64,
    leadin: i64,
    disc: CdrDiscState,
    kind: DiscKind,
) -> u32 {
    let mut sink = Checksum(0xFFFF_FFFF);
    write_body(tracks, sessions, capacity, leadin, disc, kind, &mut sink);
    !sink.0
}

/// Render `out.len()` body bytes starting at body offset `at`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn render_body(
    tracks: &[TrackEntry],
    sessions: &[SessionEntry],
    capacity: u64,
    leadin: i64,
    disc: CdrDiscState,
    kind: DiscKind,
    at: usize,
    out: &mut [u8],
) -> usize {
    let mut sink = Chunk {
        out,
        skip: at,
        written: 0,
    };
    write_body(tracks, sessions, capacity, leadin, disc, kind, &mut sink);
    sink.written
}

/// Render padding bytes `out.len()` starting at padding offset `at` (of `total`).
pub(crate) fn render_padding(total: usize, at: usize, out: &mut [u8]) -> usize {
    let mut written = 0;
    for (index, byte) in out.iter_mut().enumerate() {
        let pos = at + index;
        if pos >= total {
            break;
        }
        *byte = if pos + 1 == total || pos % 65 == 64 {
            b'\n'
        } else {
            b';'
        };
        written += 1;
    }
    written
}

fn write_body(
    tracks: &[TrackEntry],
    sessions: &[SessionEntry],
    capacity: u64,
    leadin: i64,
    disc: CdrDiscState,
    kind: DiscKind,
    sink: &mut impl LineSink,
) {
    let mut line = String::<BODY_LINE_MAX>::new();
    let _ = write!(line, "disc_type = {}", disc_kind_text(kind));
    sink.line(&line);
    line.clear();
    let _ = write!(line, "disc_state = {}", disc_text(disc));
    sink.line(&line);
    line.clear();
    let _ = write!(line, "capacity_sectors = {capacity}");
    sink.line(&line);
    line.clear();
    let _ = write!(line, "medium_leadin = {leadin}");
    sink.line(&line);

    for track in tracks {
        line.clear();
        let _ = write!(line, "[track.{}]", track.number);
        sink.line(&line);
        line.clear();
        let _ = write!(line, "status = {}", status_text(track.status));
        sink.line(&line);
        line.clear();
        let _ = write!(line, "session = {}", track.session);
        sink.line(&line);
        line.clear();
        let _ = write!(line, "start_lba = {}", track.start_lba);
        sink.line(&line);
        line.clear();
        let _ = write!(line, "data_start_lba = {}", track.data_start_lba);
        sink.line(&line);
        line.clear();
        let _ = write!(line, "allocated = {}", track.allocated);
        sink.line(&line);
        line.clear();
        // File `length` is the user-written prefix; file `written` is the
        // recorded extent (including close padding).
        let _ = write!(line, "length = {}", track.written);
        sink.line(&line);
        line.clear();
        let _ = write!(line, "written = {}", track.length);
        sink.line(&line);
        line.clear();
        let _ = write!(line, "nwa = {}", track.nwa);
        sink.line(&line);
        line.clear();
        let _ = write!(line, "kind = {}", kind_text(track.kind));
        sink.line(&line);
        line.clear();
        let _ = write!(line, "reserved = {}", u8::from(track.reserved));
        sink.line(&line);
    }

    for session in sessions {
        line.clear();
        let _ = write!(line, "[session.{}]", session.number);
        sink.line(&line);
        line.clear();
        let _ = write!(line, "first_track = {}", session.first_track);
        sink.line(&line);
        line.clear();
        let _ = write!(line, "last_track = {}", session.last_track);
        sink.line(&line);
        line.clear();
        let _ = write!(line, "start_lba = {}", session.start_lba);
        sink.line(&line);
        line.clear();
        let _ = write!(line, "lead_out_lba = {}", session.lead_out_lba);
        sink.line(&line);
        line.clear();
        let _ = write!(line, "closed = {}", u8::from(session.closed));
        sink.line(&line);
    }

    sink.line("end = 1");
}

const fn disc_text(disc: CdrDiscState) -> &'static str {
    match disc {
        CdrDiscState::Blank => "blank",
        CdrDiscState::Appendable => "appendable",
        CdrDiscState::Finalized => "finalized",
    }
}

const fn disc_kind_text(kind: DiscKind) -> &'static str {
    match kind {
        DiscKind::Cdr => "cdr",
        DiscKind::Cdrw => "cdrw",
    }
}

fn parse_disc_kind(value: &str) -> Option<DiscKind> {
    match value {
        "cdr" => Some(DiscKind::Cdr),
        "cdrw" => Some(DiscKind::Cdrw),
        _ => None,
    }
}

const fn status_text(status: TrackStatus) -> &'static str {
    match status {
        TrackStatus::Invisible => "invisible",
        TrackStatus::Reserved => "reserved",
        TrackStatus::Incomplete => "incomplete",
        TrackStatus::Complete => "complete",
    }
}

const fn kind_text(kind: TrackKind) -> &'static str {
    match kind {
        TrackKind::Data => "data",
        TrackKind::Audio => "audio",
    }
}

fn parse_disc(value: &str) -> Option<CdrDiscState> {
    match value {
        "blank" => Some(CdrDiscState::Blank),
        "appendable" => Some(CdrDiscState::Appendable),
        "finalized" => Some(CdrDiscState::Finalized),
        _ => None,
    }
}

fn parse_status(value: &str) -> Option<TrackStatus> {
    match value {
        "invisible" => Some(TrackStatus::Invisible),
        "reserved" => Some(TrackStatus::Reserved),
        "incomplete" => Some(TrackStatus::Incomplete),
        "complete" => Some(TrackStatus::Complete),
        _ => None,
    }
}

fn parse_kind(value: &str) -> Option<TrackKind> {
    match value {
        "data" => Some(TrackKind::Data),
        "audio" => Some(TrackKind::Audio),
        _ => None,
    }
}

const GLOBAL_ALL: u8 = 0x0F;
const TRACK_ALL: u16 = 0x03FF;
const SESSION_ALL: u8 = 0x1F;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Section {
    Track,
    Session,
}

/// Parse and strictly validate a full slot (header + body + padding).
///
/// `capacity_hint` is the caller's sector count; `0` accepts the stored value.
/// A non-zero hint that disagrees with the slot is rejected.
pub(crate) fn parse(slot: &[u8], capacity_hint: u64) -> Result<ParsedToc, TocError> {
    let header = TocHeader::parse(slot)?;
    if header.slot_size as usize != slot.len() {
        return Err(TocError::Invalid);
    }
    let body_end = TOC_HEADER_LEN
        .checked_add(header.body_len as usize)
        .ok_or(TocError::Invalid)?;
    if body_end > slot.len() {
        return Err(TocError::Invalid);
    }
    let body = &slot[TOC_HEADER_LEN..body_end];
    if body.last() != Some(&b'\n') || checksum(body) != header.checksum {
        return Err(TocError::Invalid);
    }
    let padding = &slot[body_end..];
    if padding.iter().any(|byte| *byte != b';' && *byte != b'\n') || slot.last() != Some(&b'\n') {
        return Err(TocError::Invalid);
    }
    let text = core::str::from_utf8(body).map_err(|_| TocError::Invalid)?;

    let mut globals = 0u8;
    let mut kind = None;
    let mut disc = None;
    let mut capacity = None;
    let mut leadin = None;
    let mut tracks: Vec<TrackEntry, MAX_TRACKS> = Vec::new();
    let mut track_seen: Vec<u16, MAX_TRACKS> = Vec::new();
    let mut sessions: Vec<SessionEntry, MAX_SESSIONS> = Vec::new();
    let mut session_seen: Vec<u8, MAX_SESSIONS> = Vec::new();
    let mut current: Option<Section> = None;
    let mut sessions_started = false;
    let mut ended = false;

    for item in ini_core::Parser::new(text).auto_trim(true) {
        match item {
            ini_core::Item::SectionEnd | ini_core::Item::Comment(_) | ini_core::Item::Blank => {}
            ini_core::Item::Error(_) => return Err(TocError::Invalid),
            ini_core::Item::Property(_, None) => return Err(TocError::Invalid),
            ini_core::Item::Property(key, Some(value)) => {
                if key == "end" {
                    if ended || value != "1" || globals != GLOBAL_ALL {
                        return Err(TocError::Invalid);
                    }
                    ended = true;
                    current = None;
                    continue;
                }
                if ended {
                    return Err(TocError::Invalid);
                }
                match current {
                    None => {
                        let bit = match key {
                            "disc_type" => {
                                kind = Some(parse_disc_kind(value).ok_or(TocError::Invalid)?);
                                0x01
                            }
                            "disc_state" => {
                                disc = Some(parse_disc(value).ok_or(TocError::Invalid)?);
                                0x02
                            }
                            "capacity_sectors" => {
                                capacity =
                                    Some(value.parse::<u64>().map_err(|_| TocError::Invalid)?);
                                0x04
                            }
                            "medium_leadin" => {
                                leadin = Some(value.parse::<i64>().map_err(|_| TocError::Invalid)?);
                                0x08
                            }
                            _ => return Err(TocError::Invalid),
                        };
                        if globals & bit != 0 {
                            return Err(TocError::Invalid);
                        }
                        globals |= bit;
                    }
                    Some(Section::Track) => {
                        let index = tracks.len().checked_sub(1).ok_or(TocError::Invalid)?;
                        let track = tracks.get_mut(index).ok_or(TocError::Invalid)?;
                        let bit = match key {
                            "status" => {
                                track.status = parse_status(value).ok_or(TocError::Invalid)?;
                                0x0001
                            }
                            "session" => {
                                track.session =
                                    value.parse::<u16>().map_err(|_| TocError::Invalid)?;
                                0x0002
                            }
                            "start_lba" => {
                                track.start_lba =
                                    value.parse::<u64>().map_err(|_| TocError::Invalid)?;
                                0x0004
                            }
                            "data_start_lba" => {
                                track.data_start_lba =
                                    value.parse::<u64>().map_err(|_| TocError::Invalid)?;
                                0x0008
                            }
                            "allocated" => {
                                track.allocated =
                                    value.parse::<u64>().map_err(|_| TocError::Invalid)?;
                                0x0010
                            }
                            // File `length` is the user-written prefix.
                            "length" => {
                                track.written =
                                    value.parse::<u64>().map_err(|_| TocError::Invalid)?;
                                0x0020
                            }
                            // File `written` is the recorded extent.
                            "written" => {
                                track.length =
                                    value.parse::<u64>().map_err(|_| TocError::Invalid)?;
                                0x0040
                            }
                            "nwa" => {
                                track.nwa = value.parse::<u64>().map_err(|_| TocError::Invalid)?;
                                0x0080
                            }
                            "kind" => {
                                track.kind = parse_kind(value).ok_or(TocError::Invalid)?;
                                0x0100
                            }
                            "reserved" => {
                                track.reserved = match value {
                                    "0" => false,
                                    "1" => true,
                                    _ => return Err(TocError::Invalid),
                                };
                                0x0200
                            }
                            _ => return Err(TocError::Invalid),
                        };
                        let seen = track_seen.get_mut(index).ok_or(TocError::Invalid)?;
                        if *seen & bit != 0 {
                            return Err(TocError::Invalid);
                        }
                        *seen |= bit;
                    }
                    Some(Section::Session) => {
                        let index = sessions.len().checked_sub(1).ok_or(TocError::Invalid)?;
                        let session = sessions.get_mut(index).ok_or(TocError::Invalid)?;
                        let bit = match key {
                            "first_track" => {
                                session.first_track =
                                    value.parse::<u16>().map_err(|_| TocError::Invalid)?;
                                0x01
                            }
                            "last_track" => {
                                session.last_track =
                                    value.parse::<u16>().map_err(|_| TocError::Invalid)?;
                                0x02
                            }
                            "start_lba" => {
                                session.start_lba =
                                    value.parse::<u64>().map_err(|_| TocError::Invalid)?;
                                0x04
                            }
                            "lead_out_lba" => {
                                session.lead_out_lba =
                                    value.parse::<u64>().map_err(|_| TocError::Invalid)?;
                                0x08
                            }
                            "closed" => {
                                session.closed = match value {
                                    "0" => false,
                                    "1" => true,
                                    _ => return Err(TocError::Invalid),
                                };
                                0x10
                            }
                            _ => return Err(TocError::Invalid),
                        };
                        let seen = session_seen.get_mut(index).ok_or(TocError::Invalid)?;
                        if *seen & bit != 0 {
                            return Err(TocError::Invalid);
                        }
                        *seen |= bit;
                    }
                }
            }
            ini_core::Item::Section(name) => {
                if ended || globals != GLOBAL_ALL {
                    return Err(TocError::Invalid);
                }
                if let Some(number) = name.strip_prefix("track.") {
                    let number = number.parse::<u16>().map_err(|_| TocError::Invalid)?;
                    if sessions_started
                        || number != tracks.len() as u16 + 1
                        || number > header.max_tracks
                    {
                        return Err(TocError::Invalid);
                    }
                    tracks
                        .push(TrackEntry {
                            number,
                            session: 0,
                            start_lba: 0,
                            data_start_lba: 0,
                            allocated: 0,
                            length: 0,
                            written: 0,
                            nwa: 0,
                            status: TrackStatus::Invisible,
                            kind: TrackKind::Data,
                            reserved: false,
                        })
                        .map_err(|_| TocError::Invalid)?;
                    track_seen.push(0).map_err(|_| TocError::Invalid)?;
                    current = Some(Section::Track);
                } else if let Some(number) = name.strip_prefix("session.") {
                    let number = number.parse::<u16>().map_err(|_| TocError::Invalid)?;
                    if number != sessions.len() as u16 + 1 || number > MAX_SESSIONS as u16 {
                        return Err(TocError::Invalid);
                    }
                    sessions
                        .push(SessionEntry {
                            number,
                            first_track: 0,
                            last_track: 0,
                            start_lba: 0,
                            lead_out_lba: 0,
                            closed: false,
                        })
                        .map_err(|_| TocError::Invalid)?;
                    session_seen.push(0).map_err(|_| TocError::Invalid)?;
                    sessions_started = true;
                    current = Some(Section::Session);
                } else {
                    return Err(TocError::Invalid);
                }
            }
        }
    }

    if !ended || globals != GLOBAL_ALL {
        return Err(TocError::Invalid);
    }
    let disc = disc.ok_or(TocError::Invalid)?;
    let kind = kind.ok_or(TocError::Invalid)?;
    let capacity = capacity.ok_or(TocError::Invalid)?;
    if capacity == 0 || (capacity_hint != 0 && capacity_hint != capacity) {
        return Err(TocError::Invalid);
    }
    let medium_leadin = leadin.unwrap_or(MEDIUM_LEADIN);

    if track_seen.iter().any(|seen| *seen != TRACK_ALL)
        || session_seen.iter().any(|seen| *seen != SESSION_ALL)
    {
        return Err(TocError::Invalid);
    }
    if disc == CdrDiscState::Blank && (!tracks.is_empty() || !sessions.is_empty()) {
        return Err(TocError::Invalid);
    }
    if !tracks.is_empty() && sessions.is_empty() {
        return Err(TocError::Invalid);
    }

    for track in &tracks {
        if track.session == 0
            || track.start_lba > track.data_start_lba
            || track.data_start_lba > capacity
            || track.written > track.length
            || track.length > capacity
            || track.data_start_lba.saturating_add(track.length) > capacity
            || track.nwa != track.data_start_lba.saturating_add(track.length)
            || (track.allocated > 0
                && track.nwa > track.data_start_lba.saturating_add(track.allocated))
        {
            return Err(TocError::Invalid);
        }
    }

    let mut previous_last = 0u16;
    for (index, session) in sessions.iter().enumerate() {
        let expected_first = previous_last + 1;
        if session.first_track != expected_first
            || session.last_track < session.first_track
            || session.lead_out_lba < session.start_lba
            || session.lead_out_lba > capacity
        {
            return Err(TocError::Invalid);
        }
        let mut first_track = None;
        let mut last_track = None;
        for number in session.first_track..=session.last_track {
            let track = tracks
                .iter()
                .find(|track| track.number == number)
                .ok_or(TocError::Invalid)?;
            if track.session != session.number {
                return Err(TocError::Invalid);
            }
            if first_track.is_none() {
                first_track = Some(track);
            }
            last_track = Some(track);
        }
        let first_track = first_track.ok_or(TocError::Invalid)?;
        let last_track = last_track.ok_or(TocError::Invalid)?;
        if first_track.start_lba != session.start_lba || last_track.nwa != session.lead_out_lba {
            return Err(TocError::Invalid);
        }
        previous_last = session.last_track;
        if index == sessions.len() - 1 && previous_last as usize != tracks.len() {
            return Err(TocError::Invalid);
        }
    }

    Ok(ParsedToc {
        header,
        kind,
        disc,
        capacity,
        medium_leadin,
        tracks,
        sessions,
    })
}
