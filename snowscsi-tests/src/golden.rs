//! Wire-level golden baseline recorder for the M0 milestone
//! (`__ASYNC_SEP_PLAN.md` §3 / §5.1).
//!
//! This module is the **contract** shared by the USB driver
//! ([`crate::golden_drive`]), the USB scenarios ([`crate::golden_usb`]) and
//! the iSCSI scenarios ([`crate::golden_iscsi`]). It provides:
//!
//! - scripted [`RecBotIo`] (bulk) / [`RecGadget`] (control) seams that record
//!   the host↔device byte stream as [`TraceEntry`] values;
//! - a scripted [`RecConn`] for the iSCSI byte stream;
//! - the textual fixture codec ([`render`]) and the bless/compare gate
//!   ([`bless_or_check`]);
//! - a non-degeneracy guard ([`assert_well_formed`]).
//!
//! Determinism: there is no wall clock, no real timeout and no randomness —
//! a probe is scripted as [`InStep::WouldBlock`] and every backend is a
//! pattern-filled `RamBackend`. The recorder ignores the `recv_out` timeout
//! argument entirely (the core never reads a clock).

use core::time::Duration;
use std::collections::VecDeque;
use std::path::PathBuf;

use snowscsi::usb::{BotIo, BotIoErr, CtrlReq, Gadget};

use crate::mock_bot::{MockAck, MockReply};

/// USB Bulk-Only command block wrapper magic (`b"USBC"` little endian).
pub const CBW_MAGIC: [u8; 4] = [0x55, 0x53, 0x42, 0x43];
/// USB Bulk-Only command status wrapper magic (`b"USBS"` little endian).
pub const CSW_MAGIC: [u8; 4] = [0x55, 0x53, 0x42, 0x53];

/// One recorded wire or seam event (both directions plus marker events).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TraceEntry {
    /// Host → device bytes on the bulk-OUT pipe (`>>`).
    H2D(Vec<u8>),
    /// Device → host bytes on the bulk-IN pipe (`<<`).
    D2H(Vec<u8>),
    /// A seam event marker (`--`): `stall_both` / `stall_in` / `disconnected`.
    Mark(&'static str),
}

/// The out-of-band control requests the driver may service (mirrors the three
/// [`CtrlReq`] variants — there is no `ClearFeatureHalt` on the wire seam).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CtrlStep {
    BotReset,
    GetMaxLun,
    LinkReset,
}

/// One step of a scenario's bulk script. `Ctrl` steps are split out into the
/// [`RecGadget`] queue by [`split`] and never appear on the bulk wire.
#[derive(Clone, Debug)]
pub enum InStep {
    /// Feed exactly `buf.len()` bytes (length mismatch is a test bug → panic).
    Bytes(Vec<u8>),
    /// The non-blocking receive found nothing (`WouldBlock`).
    WouldBlock,
    /// The link dropped (`Disconnected`).
    Disconnect,
    /// An out-of-band control request.
    Ctrl(CtrlStep),
}

/// Scripted bulk driver that records every byte it moves.
#[derive(Default)]
pub struct RecBotIo {
    steps: VecDeque<InStep>,
    /// Recorded wire/seam trace, in order.
    pub trace: Vec<TraceEntry>,
    /// Number of successful `stall_both` calls.
    pub stall_count: u32,
    /// Number of successful `stall_in` calls.
    pub stall_in_count: u32,
}

impl RecBotIo {
    /// Build from a bulk-only script (see [`split`] to separate `Ctrl` steps).
    pub fn new(steps: Vec<InStep>) -> Self {
        Self {
            steps: steps.into(),
            trace: Vec::new(),
            stall_count: 0,
            stall_in_count: 0,
        }
    }

    /// Whether the bulk script is exhausted.
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    /// Queue one more bulk step.
    pub fn feed(&mut self, step: InStep) {
        self.steps.push_back(step);
    }
}

impl BotIo for RecBotIo {
    fn try_recv_out(&mut self, buf: &mut [u8]) -> Result<usize, BotIoErr> {
        match self.steps.pop_front() {
            Some(InStep::Bytes(b)) => {
                assert_eq!(
                    b.len(),
                    buf.len(),
                    "RecBotIo: script Bytes length {} != requested {} (the script must be exact)",
                    b.len(),
                    buf.len()
                );
                buf.copy_from_slice(&b);
                self.trace.push(TraceEntry::H2D(b));
                Ok(buf.len())
            }
            Some(InStep::WouldBlock) => Err(BotIoErr::WouldBlock),
            Some(InStep::Disconnect) => {
                self.trace.push(TraceEntry::Mark("disconnected"));
                Err(BotIoErr::Disconnected)
            }
            Some(InStep::Ctrl(_)) => {
                panic!("RecBotIo: Ctrl step reached the bulk queue (use golden::split)")
            }
            // Exhausted script: the driver decides (probe → OutIdle; else panic).
            None => Err(BotIoErr::WouldBlock),
        }
    }

    fn recv_out(&mut self, buf: &mut [u8], _timeout: Option<Duration>) -> Result<usize, BotIoErr> {
        self.try_recv_out(buf)
    }

    fn send_in(&mut self, buf: &[u8]) -> Result<(), BotIoErr> {
        self.trace.push(TraceEntry::D2H(buf.to_vec()));
        Ok(())
    }

    fn stall_both(&mut self) -> Result<(), ()> {
        self.stall_count += 1;
        self.trace.push(TraceEntry::Mark("stall_both"));
        Ok(())
    }

    fn stall_in(&mut self) -> Result<(), ()> {
        self.stall_in_count += 1;
        self.trace.push(TraceEntry::Mark("stall_in"));
        Ok(())
    }

    /// Pure capability query (no trace side effect): the scripted driver
    /// always reports STALL support.
    fn can_stall_in(&self) -> bool {
        true
    }
}

/// Scripted control gadget: pops one [`CtrlStep`] at a time and hands back
/// recording ack/reply handles.
#[derive(Default)]
pub struct RecGadget {
    steps: VecDeque<CtrlStep>,
    /// One recording handle per `BotReset` served.
    pub acks: Vec<MockAck>,
    /// One recording handle per `GetMaxLun` served.
    pub replies: Vec<MockReply>,
}

impl RecGadget {
    /// Build from a control-only script.
    pub fn new(steps: Vec<CtrlStep>) -> Self {
        Self {
            steps: steps.into(),
            acks: Vec::new(),
            replies: Vec::new(),
        }
    }

    /// Whether the control script is exhausted.
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }
}

impl<'a> Gadget<'a> for RecGadget {
    type Ack = MockAck;
    type Reply = MockReply;

    fn try_next_ctrl(&'a mut self) -> Option<CtrlReq<MockAck, MockReply>> {
        match self.steps.pop_front()? {
            CtrlStep::BotReset => {
                let ack = MockAck::new();
                self.acks.push(ack.clone());
                Some(CtrlReq::BotReset { ack })
            }
            CtrlStep::GetMaxLun => {
                let reply = MockReply::new();
                self.replies.push(reply.clone());
                Some(CtrlReq::GetMaxLun { reply })
            }
            CtrlStep::LinkReset => Some(CtrlReq::LinkReset),
        }
    }
}

/// Split a mixed scenario script into the bulk driver and the control gadget.
/// Order within each channel is preserved.
pub fn split(script: Vec<InStep>) -> (RecBotIo, RecGadget) {
    let mut bulk = Vec::new();
    let mut ctrl = Vec::new();
    for step in script {
        match step {
            InStep::Ctrl(c) => ctrl.push(c),
            other => bulk.push(other),
        }
    }
    (RecBotIo::new(bulk), RecGadget::new(ctrl))
}

/// Scripted iSCSI byte-stream connection that records both directions.
///
/// Mirrors [`crate::mock_conn::MockConn`]'s `feed` API; `rx` is retained so
/// host→device bytes are traced as they are read (a driver-side truncation
/// shows up as a wire diff).
#[derive(Default)]
pub struct RecConn {
    rx: VecDeque<u8>,
    /// Device → host bytes written so far.
    pub tx: Vec<u8>,
    /// Recorded wire trace, in order.
    pub trace: Vec<TraceEntry>,
}

impl RecConn {
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue a BHS plus its data segment (no padding; use [`Self::feed_padded`]
    /// when RFC 3720 4-byte padding is wanted).
    pub fn feed(&mut self, bhs: &[u8; 48], data: &[u8]) {
        self.rx.extend(bhs);
        self.rx.extend(data);
    }

    /// Push raw inbound bytes (for AHS / odd framing).
    pub fn feed_bytes(&mut self, bytes: &[u8]) {
        self.rx.extend(bytes);
    }

    /// Queue a BHS plus data segment with RFC 3720 padding.
    pub fn feed_padded(&mut self, bhs: &[u8; 48], data: &[u8]) {
        let dsl = data.len();
        let total = 48 + dsl;
        let pad = (4 - (total & 3)) & 3;
        self.rx.extend(bhs);
        self.rx.extend(data);
        self.rx.resize(self.rx.len() + pad, 0);
    }

    /// Queue a LOGIN request BHS carrying `text`.
    pub fn feed_login_text(&mut self, text: &str) {
        let t = text.as_bytes();
        let dsl = t.len() as u32;
        let mut bhs = [0u8; 48];
        bhs[0] = 0x03;
        bhs[5] = (dsl >> 16) as u8;
        bhs[6] = (dsl >> 8) as u8;
        bhs[7] = dsl as u8;
        self.feed_padded(&bhs, t);
    }
}

impl embedded_io::ErrorType for RecConn {
    type Error = core::convert::Infallible;
}

impl embedded_io::Read for RecConn {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        let n = buf.len().min(self.rx.len());
        for (out, b) in buf.iter_mut().zip(self.rx.iter()).take(n) {
            *out = *b;
        }
        self.rx.drain(..n);
        if n > 0 {
            self.trace.push(TraceEntry::H2D(buf[..n].to_vec()));
        }
        Ok(n)
    }
}

impl embedded_io::Write for RecConn {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        self.tx.extend_from_slice(buf);
        self.trace.push(TraceEntry::D2H(buf.to_vec()));
        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

/// Render a fixture: a `# config:` header followed by one line per entry.
pub fn render(config: &str, entries: &[TraceEntry]) -> String {
    let mut s = String::with_capacity(64 + entries.len() * 40);
    s.push_str("# config: ");
    s.push_str(config);
    s.push('\n');
    for entry in entries {
        match entry {
            TraceEntry::H2D(b) => {
                s.push_str(">> ");
                push_hex(&mut s, b);
                s.push('\n');
            }
            TraceEntry::D2H(b) => {
                s.push_str("<< ");
                push_hex(&mut s, b);
                s.push('\n');
            }
            TraceEntry::Mark(m) => {
                s.push_str("-- ");
                s.push_str(m);
                s.push('\n');
            }
        }
    }
    s
}

fn push_hex(out: &mut String, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
}

fn parse_hex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    assert!(
        s.len().is_multiple_of(2),
        "fixture hex line has an odd number of digits: {s:?}"
    );
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("valid hex"))
        .collect()
}

/// Decode a rendered fixture back into its `(config, entries)` — the inverse of
/// [`render`] for a well-formed fixture (§3 "fixture 编解码").
///
/// Only the three [`TraceEntry`] kinds and the three known marker names are
/// accepted; anything else is a test bug and panics. This is the strict
/// counterpart to [`render`]: `parse(&render(c, e)) == (c, e)`.
pub fn parse(text: &str) -> (String, Vec<TraceEntry>) {
    let mut lines = text.lines();
    let header = lines.next().expect("fixture must start with a header line");
    let config = header
        .strip_prefix("# config: ")
        .unwrap_or_else(|| panic!("fixture header must be `# config: …`, got {header:?}"))
        .to_string();
    let mut entries = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        } else if let Some(hex) = line.strip_prefix(">> ") {
            entries.push(TraceEntry::H2D(parse_hex(hex)));
        } else if let Some(hex) = line.strip_prefix("<< ") {
            entries.push(TraceEntry::D2H(parse_hex(hex)));
        } else if let Some(mark) = line.strip_prefix("-- ") {
            let mark = match mark {
                "stall_both" => "stall_both",
                "stall_in" => "stall_in",
                "disconnected" => "disconnected",
                other => panic!("unknown fixture marker {other:?}"),
            };
            entries.push(TraceEntry::Mark(mark));
        } else {
            panic!("malformed fixture line {line:?}");
        }
    }
    (config, entries)
}

/// Absolute path of `<crate>/golden/<name>.trace`.
pub fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("golden")
        .join(format!("{name}.trace"))
}

fn bless_enabled() -> bool {
    let on = |k: &str| std::env::var(k).map(|v| v == "1").unwrap_or(false);
    // `SNOWSCSI_BLESS` is the name pinned by the plan; `SNOWDRIVE_BLESS` is
    // accepted as an alias for the pre-rename spelling.
    on("SNOWSCSI_BLESS") || on("SNOWDRIVE_BLESS")
}

/// Bless (re-record) or verify one fixture.
///
/// With `SNOWSCSI_BLESS=1` the fixture is written to `<crate>/golden/`.
/// Otherwise the recorded text is compared byte-for-byte with the on-disk
/// fixture; a mismatch prints the first differing offset with 16 bytes of
/// context on each side. Without the environment variable **nothing is ever
/// written**.
pub fn bless_or_check(name: &str, text: &str) {
    let path = fixture_path(name);
    if bless_enabled() {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).expect("create golden dir");
        }
        std::fs::write(&path, text).expect("write fixture");
        return;
    }
    let expected = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "golden fixture {} missing or unreadable: {e}\n\
             (run with SNOWSCSI_BLESS=1 to record it)",
            path.display()
        )
    });
    if expected != text {
        let e = expected.as_bytes();
        let a = text.as_bytes();
        let off = (0..e.len().min(a.len()))
            .find(|&i| e[i] != a[i])
            .unwrap_or(e.len().min(a.len()));
        let lo = off.saturating_sub(16);
        let hi_e = (off + 16).min(e.len());
        let hi_a = (off + 16).min(a.len());
        panic!(
            "golden fixture {} mismatch at byte {off}\n  expected: {}\n  actual:   {}",
            path.display(),
            hex_with_marker(&e[lo..hi_e], off - lo),
            hex_with_marker(&a[lo..hi_a], off - lo),
        );
    }
}

fn hex_with_marker(bytes: &[u8], marker: usize) -> String {
    let mut s = String::new();
    for (i, &b) in bytes.iter().enumerate() {
        if i == marker {
            s.push('[');
        }
        s.push_str(&format!("{b:02x}"));
        if i == marker {
            s.push(']');
        } else {
            s.push(' ');
        }
    }
    s
}

/// Non-degeneracy guard: a fixture must be structurally a real wire capture —
/// a `# config:` header, both directions present, a plausible number of lines,
/// and (for BOT) the CBW/CSW magics with the tag echoed back.
pub fn assert_well_formed(name: &str, text: &str) {
    let mut lines = text.lines().filter(|l| !l.trim().is_empty());
    let header = lines
        .next()
        .unwrap_or_else(|| panic!("{name}: empty fixture"));
    assert!(
        header.starts_with("# config:"),
        "{name}: first line must be a `# config:` header, got {header:?}"
    );
    let kind = header
        .split_whitespace()
        .find_map(|tok| tok.strip_prefix("kind="))
        .unwrap_or("");

    let mut h2d = 0usize;
    let mut d2h = 0usize;
    let mut cbw_tags: Vec<u32> = Vec::new();
    let mut csw_tags: Vec<u32> = Vec::new();
    let mut first_h2d: Option<Vec<u8>> = None;
    let mut total = 1usize;
    for line in lines {
        total += 1;
        if let Some(hex) = line.strip_prefix(">> ") {
            h2d += 1;
            let bytes = parse_hex(hex);
            if first_h2d.is_none() {
                first_h2d = Some(bytes.clone());
            }
            if bytes.len() >= 8 && bytes[..4] == CBW_MAGIC {
                cbw_tags.push(u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]));
            }
        } else if let Some(hex) = line.strip_prefix("<< ") {
            d2h += 1;
            let bytes = parse_hex(hex);
            if bytes.len() >= 8 && bytes[..4] == CSW_MAGIC {
                csw_tags.push(u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]));
            }
        } else {
            assert!(
                line.starts_with("-- "),
                "{name}: malformed fixture line {line:?}"
            );
        }
    }

    assert!(total >= 3, "{name}: fixture has too few lines ({total})");
    assert!(h2d >= 1, "{name}: no host→device bytes recorded");
    assert!(d2h >= 1, "{name}: no device→host bytes recorded");

    match kind {
        "bot" => {
            assert!(
                !cbw_tags.is_empty(),
                "{name}: no CBW (magic 55534243) on the bulk-OUT wire"
            );
            assert!(
                !csw_tags.is_empty(),
                "{name}: no CSW (magic 55534253) on the bulk-IN wire"
            );
            for tag in &csw_tags {
                assert!(
                    cbw_tags.contains(tag),
                    "{name}: CSW tag {tag} was never sent in a CBW"
                );
            }
        }
        "iscsi" => {
            if let Some(bytes) = &first_h2d {
                assert!(!bytes.is_empty(), "{name}: empty first H2D PDU");
                assert_eq!(
                    bytes[0] & 0x3F,
                    0x03,
                    "{name}: first H2D PDU is not a LOGIN_REQUEST"
                );
            }
        }
        other => panic!("{name}: unknown fixture kind {other:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use embedded_io::{Read, Write};
    use snowscsi::usb::{BotIo, BotIoErr};

    /// Deliberately-missing fixture name used to prove the read path never
    /// writes. Never created on disk.
    const PROBE: &str = "__golden_missing_probe_do_not_commit";

    #[test]
    fn render_roundtrips_entries() {
        let entries = vec![
            TraceEntry::H2D(vec![0x55, 0x53, 0x42, 0x43, 1, 0, 0, 0]),
            TraceEntry::D2H(vec![0x55, 0x53, 0x42, 0x53, 1, 0, 0, 0, 0, 0, 0, 0, 0]),
            TraceEntry::Mark("stall_both"),
        ];
        let text = render("kind=bot mps=512 policy=ShortNoStall luns=1", &entries);
        assert_eq!(
            text,
            "# config: kind=bot mps=512 policy=ShortNoStall luns=1\n\
             >> 5553424301000000\n\
             << 55534253010000000000000000\n\
             -- stall_both\n"
        );
    }

    #[test]
    fn split_preserves_channel_order() {
        let (io, gadget) = split(vec![
            InStep::Ctrl(CtrlStep::GetMaxLun),
            InStep::Bytes(vec![1, 2, 3]),
            InStep::WouldBlock,
            InStep::Ctrl(CtrlStep::BotReset),
        ]);
        assert!(!io.is_empty());
        assert!(!gadget.is_empty());
        // The bulk channel keeps only the two bulk steps.
        assert!(matches!(io.steps.front(), Some(InStep::Bytes(_))));
    }

    #[test]
    fn render_parse_roundtrips_all_entry_kinds() {
        let config = "kind=bot mps=64 policy=Short luns=2";
        let entries = vec![
            TraceEntry::H2D(vec![0x55, 0x53, 0x42, 0x43, 0xde, 0xad, 0xbe, 0xef]),
            TraceEntry::D2H(vec![0x55, 0x53, 0x42, 0x53, 1, 0, 0, 0]),
            TraceEntry::Mark("stall_both"),
            TraceEntry::H2D(Vec::new()),
            TraceEntry::D2H(Vec::new()),
            TraceEntry::Mark("stall_in"),
            TraceEntry::Mark("disconnected"),
        ];
        let text = render(config, &entries);
        let (parsed_config, parsed) = parse(&text);
        assert_eq!(parsed_config, config);
        assert_eq!(parsed, entries);
    }

    #[test]
    fn recbotio_records_bytes_marks_and_exhaustion() {
        let mut io = RecBotIo::new(vec![InStep::Bytes(vec![0xaa, 0xbb]), InStep::WouldBlock]);
        let mut buf = [0u8; 2];
        assert_eq!(io.try_recv_out(&mut buf), Ok(2));
        assert_eq!(buf, [0xaa, 0xbb]);
        assert_eq!(io.try_recv_out(&mut buf), Err(BotIoErr::WouldBlock));
        // Exhausted script → `WouldBlock` (the driver's probe → OutIdle).
        assert_eq!(io.try_recv_out(&mut buf), Err(BotIoErr::WouldBlock));
        io.send_in(&[0x01, 0x02]).unwrap();
        assert_eq!(io.stall_both(), Ok(()));
        assert_eq!(io.stall_in(), Ok(()));
        assert_eq!(io.stall_count, 1);
        assert_eq!(io.stall_in_count, 1);
        assert_eq!(
            io.trace,
            vec![
                TraceEntry::H2D(vec![0xaa, 0xbb]),
                TraceEntry::D2H(vec![0x01, 0x02]),
                TraceEntry::Mark("stall_both"),
                TraceEntry::Mark("stall_in"),
            ]
        );
    }

    #[test]
    fn recbotio_records_disconnect_mark() {
        let mut io = RecBotIo::new(vec![InStep::Disconnect]);
        let mut buf = [0u8; 4];
        assert_eq!(io.try_recv_out(&mut buf), Err(BotIoErr::Disconnected));
        assert_eq!(io.trace, vec![TraceEntry::Mark("disconnected")]);
    }

    #[test]
    #[should_panic(expected = "script Bytes length")]
    fn recbotio_panics_on_scripts_length_mismatch() {
        let mut io = RecBotIo::new(vec![InStep::Bytes(vec![1, 2, 3])]);
        let mut buf = [0u8; 2];
        let _ = io.try_recv_out(&mut buf);
    }

    #[test]
    fn recconn_traces_both_directions() {
        let mut conn = RecConn::new();
        // LOGIN_REQUEST BHS + 15-byte text + 1 pad byte = 64 bytes.
        conn.feed_login_text("InitiatorName=x");
        let mut buf = [0u8; 64];
        let n = conn.read(&mut buf).unwrap();
        assert_eq!(n, 64);
        assert_eq!(buf[0], 0x03);
        conn.write(&[0x24, 0x00, 0x00, 0x00]).unwrap();
        assert_eq!(conn.tx, vec![0x24, 0x00, 0x00, 0x00]);
        assert_eq!(
            conn.trace,
            vec![
                TraceEntry::H2D(buf.to_vec()),
                TraceEntry::D2H(vec![0x24, 0x00, 0x00, 0x00]),
            ]
        );
    }

    #[test]
    fn well_formed_accepts_bot_fixture() {
        let text = render(
            "kind=bot mps=512 policy=ShortNoStall luns=1",
            &[
                TraceEntry::H2D(vec![0x55, 0x53, 0x42, 0x43, 7, 0, 0, 0]),
                TraceEntry::D2H(vec![0x55, 0x53, 0x42, 0x53, 7, 0, 0, 0, 0, 0, 0, 0, 0]),
            ],
        );
        assert_well_formed("unit", &text);
    }

    #[test]
    #[should_panic(expected = "no CSW")]
    fn well_formed_rejects_missing_csw() {
        let text = render(
            "kind=bot mps=512 policy=ShortNoStall luns=1",
            &[
                TraceEntry::H2D(vec![0x55, 0x53, 0x42, 0x43, 7, 0, 0, 0]),
                TraceEntry::D2H(vec![0xAA, 0xBB]),
            ],
        );
        assert_well_formed("unit", &text);
    }

    #[test]
    fn well_formed_accepts_iscsi_fixture() {
        let mut login = vec![0u8; 48];
        login[0] = 0x03; // LOGIN_REQUEST opcode (first H2D PDU)
        let text = render(
            "kind=iscsi isid=4000000000000001",
            &[
                TraceEntry::H2D(login),
                TraceEntry::D2H(vec![0x23; 48]), // LOGIN_RESPONSE
            ],
        );
        assert_well_formed("unit-iscsi", &text);
    }

    #[test]
    fn bless_or_check_without_env_panics_and_writes_nothing() {
        if bless_enabled() {
            // Never author the probe fixture while blessing.
            return;
        }
        let text = render("kind=bot mps=64 policy=ShortNoStall luns=1", &[]);
        let err = std::panic::catch_unwind(|| bless_or_check(PROBE, &text))
            .expect_err("bless_or_check must panic on a missing fixture without SNOWSCSI_BLESS");
        let msg = err
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| err.downcast_ref::<&str>().copied())
            .unwrap_or("");
        assert!(msg.contains("missing"), "unexpected panic payload: {msg:?}");
        assert!(
            !fixture_path(PROBE).exists(),
            "bless_or_check must not write fixtures without SNOWSCSI_BLESS"
        );
    }
}
