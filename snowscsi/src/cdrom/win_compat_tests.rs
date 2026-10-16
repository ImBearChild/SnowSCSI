//! Windows-compatibility regression tests for the DvdRam CD-ROM profile.
//!
//! Captured-traffic background (usbredir → usb-storage on Windows 10):
//! during enumeration Windows fires a burst of SECURITY PROTOCOL IN (A2h)
//! probes that the drive correctly rejects with ILLEGAL REQUEST. With the
//! former "any pending sense preempts the next command" behaviour, that
//! stale sense then poisoned the following GET EVENT STATUS NOTIFICATION /
//! GET CONFIGURATION polls, Windows' media-state machine gave up and the
//! medium was treated as read-only (no format UI, `format X:` silent-exit).
//! Per SPC-4 only a UNIT ATTENTION may preempt a later command — see the
//! pending-sense gate in [`CdromDrive::do_cmd`].

use crate::cdrom::drive::CdromDrive;
#[cfg(feature = "dvdram")]
use crate::cdrom::dvdram::DvdRamMedia;
use crate::scsi::backend::{BlockBackend, RamBackend};
use crate::scsi::device::CommandOutcome;
use crate::scsi::spc::SpcDevice as _;

#[allow(dead_code)]
fn hex(b: &[u8]) -> String {
    b.iter()
        .map(|x| format!("{x:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// READ FORMAT CAPACITIES must advertise the Formattable Capacity Descriptor
/// with Format Type 00h and Type Dependent Parameter = block length 0800h
/// (MMC-6 Tables 468/469). Hosts echo this descriptor verbatim inside the
/// FORMAT UNIT parameter list (dvd+rw-format does exactly that), so a wrong
/// TDP here turns into an INVALID-FIELD failure over there.
#[test]
fn rfc_formattable_descriptor_tdp_is_block_length() {
    let mut img = vec![0u8; 2048 * 204800];
    let mut dev = CdromDrive::new();
    let mut bb = BlockBackend::Ram(RamBackend::new(&mut img));
    #[cfg(feature = "dvdram")]
    {
        let media = DvdRamMedia::open(&mut bb);
        dev.load_quiet(crate::cdrom::media::CdMedia::Rw(media));
    }
    #[cfg(not(feature = "dvdram"))]
    dev.load_quiet(crate::cdrom::media::CdMedia::ro(&mut bb));

    let mut w = [0u8; crate::MIN_DATA_LEN];
    let cdb = [0x23u8, 0, 0, 0, 0, 0, 0, 0, 0x14, 0]; // alloc=20
    let out = dev.do_cmd(&cdb, &mut w).unwrap();
    let n = match out {
        CommandOutcome::OutInline { len } => len,
        other => panic!("expected inline data, got {other:?}"),
    };
    assert_eq!(n, 20);
    assert_eq!(w[3], 16, "capacity list length = 2 descriptors");
    // Current/Maximum Capacity Descriptor: formatted media, 2048-byte blocks.
    assert_eq!(w[8], 0x02);
    assert_eq!(&w[9..12], &[0x00, 0x08, 0x00]);
    // Formattable Capacity Descriptor: Full Format (type 00h « 2), and the
    // Type Dependent Parameter MUST carry the block length.
    assert_eq!(w[16], 0x00, "format type 00h");
    assert_eq!(
        &w[17..20],
        &[0x00, 0x08, 0x00],
        "TDP must advertise block length 2048"
    );
}

/// Single-command sanity: the probes Windows sends must behave per spec.
#[test]
fn win_single_cmds_diag() {
    let mut img = vec![0u8; 2048 * 204800];
    let mut dev = CdromDrive::new();
    let mut bb = BlockBackend::Ram(RamBackend::new(&mut img));
    #[cfg(feature = "dvdram")]
    {
        let media = DvdRamMedia::open(&mut bb);
        dev.load_quiet(crate::cdrom::media::CdMedia::Rw(media));
    }
    #[cfg(not(feature = "dvdram"))]
    dev.load_quiet(crate::cdrom::media::CdMedia::ro(&mut bb));

    // consume initial UA
    let mut w = [0u8; crate::MIN_DATA_LEN];
    let _ = dev.do_cmd(&[0x00; 6], &mut w);
    let _ = dev.take_sense();

    let _cases: &[(&str, Vec<u8>)] = &[
        ("GESN class=00", vec![0x4A, 1, 0, 0, 0x00, 0, 0, 0, 0x08, 0]),
        ("GESN class=10", vec![0x4A, 1, 0, 0, 0x10, 0, 0, 0, 0x08, 0]),
        ("GETCFG alloc8", vec![0x46, 0, 0, 0, 0, 0, 0, 0, 0x08, 0]),
        ("MODESNSE p20", vec![0x5A, 0, 0x20, 0, 0, 0, 0, 0, 0x80, 0]),
        (
            "ATA PASSTHRU",
            vec![0x85, 8, 0x24, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0xA1, 0],
        ),
        (
            "SEC PROTO IN",
            vec![0xA2, 0, 0, 0, 0x80, 0, 0, 0, 0, 0, 0, 0],
        ),
    ];
    for (name, cdb, expect) in [
        (
            "GESN class=00",
            vec![0x4A, 1, 0, 0, 0x00, 0, 0, 0, 0x08, 0],
            "inline4", // NEA=1 → header only (MMC-6 Table 265)
        ),
        (
            "GESN class=10",
            vec![0x4A, 1, 0, 0, 0x10, 0, 0, 0, 0x08, 0],
            "inline8",
        ),
        (
            "GETCFG alloc8",
            vec![0x46, 0, 0, 0, 0, 0, 0, 0, 0x08, 0],
            "inline8",
        ),
        (
            "MODESENSE p20",
            vec![0x5A, 0, 0x20, 0, 0, 0, 0, 0, 0x80, 0],
            "cc24",
        ),
        (
            "ATA PASSTHRU",
            vec![0x85, 8, 0x24, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0xA1, 0],
            "cc20",
        ),
        (
            "SEC PROTO IN",
            vec![0xA2, 0, 0, 0, 0x80, 0, 0, 0, 0, 0, 0, 0],
            "cc20",
        ),
    ] {
        let mut w = [0u8; crate::MIN_DATA_LEN];
        let out = dev.do_cmd(&cdb, &mut w).unwrap();
        match (expect, &out) {
            ("inline4", CommandOutcome::OutInline { len }) => assert_eq!(*len, 4),
            ("inline8", CommandOutcome::OutInline { len }) => assert_eq!(*len, 8),
            ("cc20", CommandOutcome::CheckCondition) => {
                let s = dev.peek_sense().unwrap();
                assert_eq!(s.key, crate::scsi::scsi::SenseKey::IllegalRequest);
                assert_eq!(s.asc, crate::scsi::scsi::asc::INVALID_COMMAND);
            }
            ("cc24", CommandOutcome::CheckCondition) => {
                let s = dev.peek_sense().unwrap();
                assert_eq!(s.key, crate::scsi::scsi::SenseKey::IllegalRequest);
                assert_eq!(s.asc, crate::scsi::scsi::asc::INVALID_FIELD);
            }
            _ => panic!("{name}: unexpected outcome {out:?}"),
        }
        let _ = dev.take_sense();
    }
}

/// Regression: a rejected SECURITY PROTOCOL IN leaves NO lingering sense —
/// the next GET EVENT STATUS NOTIFICATION and GET CONFIGURATION must succeed.
#[test]
fn win_rejected_probe_does_not_poison_next_command() {
    let mut img = vec![0u8; 2048 * 204800];
    let mut dev = CdromDrive::new();
    let mut bb = BlockBackend::Ram(RamBackend::new(&mut img));
    #[cfg(feature = "dvdram")]
    {
        let media = DvdRamMedia::open(&mut bb);
        dev.load_quiet(crate::cdrom::media::CdMedia::Rw(media));
    }
    #[cfg(not(feature = "dvdram"))]
    dev.load_quiet(crate::cdrom::media::CdMedia::ro(&mut bb));

    let mut w = [0u8; crate::MIN_DATA_LEN];
    let _ = dev.do_cmd(&[0x00; 6], &mut w); // initial UA via TUR
    let _ = dev.take_sense();

    let spi = [0xA2u8, 0, 0, 0, 0x80, 0, 0, 0, 0, 0, 0, 0];
    for i in 0..6 {
        let out = dev.do_cmd(&spi, &mut w).unwrap();
        assert_eq!(out, CommandOutcome::CheckCondition, "A2 #{i} must reject");
        assert_eq!(
            dev.peek_sense().unwrap().asc,
            crate::scsi::scsi::asc::INVALID_COMMAND
        );
    }

    // The host fetches the reason via REQUEST SENSE — it must see the exact
    // ASC/ASCQ the rejection carried. (Regression: stale-sense cleanup used
    // to blind REQUEST SENSE into answering NO SENSE, breaking Windows'
    // eject retry loop which relies on reading MEDIUM REMOVAL PREVENTED.)
    {
        let rs = [0x03u8, 0, 0, 0, 0x12, 0];
        let out = dev.do_cmd(&rs, &mut w).unwrap();
        let CommandOutcome::OutInline { .. } = out else {
            panic!("REQUEST SENSE must serve data");
        };
        assert_eq!(w[2], 0x05);
        assert_eq!(w[12], crate::scsi::scsi::asc::INVALID_COMMAND);
    }

    let gesn = [0x4Au8, 1, 0, 0, 0x00, 0, 0, 0, 0x08, 0];
    let out = dev.do_cmd(&gesn, &mut w).unwrap();
    assert!(
        matches!(out, CommandOutcome::OutInline { .. }),
        "stale ILLEGAL REQUEST sense must not fail GESN"
    );

    let getcfg = [0x46u8, 0, 0, 0, 0, 0, 0, 0, 0x08, 0];
    let out = dev.do_cmd(&getcfg, &mut w).unwrap();
    assert!(
        matches!(out, CommandOutcome::OutInline { .. }),
        "stale sense must not fail GET CONFIGURATION"
    );
}

/// UNIT ATTENTION keeps its preemption semantics: reported exactly once on
/// the next non-bypass command, consumed on delivery.
///
/// MMC-6 §4.1.6.1: GET CONFIGURATION (0x46) and GESN (0x4A) are exempt from
/// UA preemption (same as INQUIRY / REQUEST SENSE). The UA remains pending
/// until a non-bypassed command delivers it.
#[test]
fn win_ua_still_reports_once() {
    use crate::scsi::scsi::{asc, Sense, SenseKey};

    let mut img = vec![0u8; 2048 * 204800];
    let mut dev = CdromDrive::new();
    let mut bb = BlockBackend::Ram(RamBackend::new(&mut img));
    #[cfg(feature = "dvdram")]
    {
        let media = DvdRamMedia::open(&mut bb);
        dev.load_quiet(crate::cdrom::media::CdMedia::Rw(media));
    }
    #[cfg(not(feature = "dvdram"))]
    dev.load_quiet(crate::cdrom::media::CdMedia::ro(&mut bb));

    let mut w = [0u8; crate::MIN_DATA_LEN];
    dev.set_sense(Sense::new(
        SenseKey::UnitAttention,
        asc::MEDIUM_MAY_HAVE_CHANGED,
        0,
    ));

    // GESN (0x4A) must bypass UA per MMC-6 §4.1.6.1 — UA stays pending.
    let gesn = [0x4Au8, 1, 0, 0, 0x10, 0, 0, 0, 0x08, 0];
    let out = dev.do_cmd(&gesn, &mut w).unwrap();
    assert!(
        matches!(out, CommandOutcome::OutInline { .. }),
        "GESN must not be preempted by UA"
    );
    assert!(
        dev.peek_sense().is_some(),
        "UA must remain pending after GESN (bypassed)"
    );

    // GET CONFIGURATION (0x46) must also bypass UA per MMC-6 §4.1.6.1.
    let getcfg = [0x46u8, 0, 0, 0, 0, 0, 0, 0, 0x08, 0];
    let out = dev.do_cmd(&getcfg, &mut w).unwrap();
    assert!(
        matches!(out, CommandOutcome::OutInline { .. }),
        "GET CONFIGURATION must not be preempted by UA"
    );
    assert!(
        dev.peek_sense().is_some(),
        "UA must remain pending after GET CONFIGURATION (bypassed)"
    );

    // A non-bypassed command (e.g. MODE SENSE(6)) delivers the UA exactly once.
    let mode_sense = [0x1Au8, 0, 0x3F, 0, 0x08, 0];
    assert_eq!(
        dev.do_cmd(&mode_sense, &mut w).unwrap(),
        CommandOutcome::CheckCondition
    );
    assert!(dev.peek_sense().is_none(), "UA delivered once");
}

// ── Scripted Windows enumeration sequence ───────────────────────────
//
// Ordered transactions distilled from a real usbredir capture (win10 /
// usbstor, see tools/usbms-pcap.py to extract more when a new host quirk
// shows up). Driven through the real `BotSession` so core-level UA
// handling and the device pending-sense gate are exercised together.
// Assertions are spec-level invariants, not byte parity with the capture.

#[cfg(feature = "usb")]
mod enumeration_sequence {
    use super::*;
    use crate::common::store::StorePlane;
    use crate::scsi::device::ScsiDevice;
    use crate::scsi::scsi::asc;
    use crate::usb::target::{Action, BotSession, Event};
    use crate::usb::CSW_LEN;

    /// One BOT transaction: build the CBW, run the state machine to
    /// completion, return (csw_status, response bytes).
    ///
    /// FORMAT/BLANK and SYNCHRONIZE CACHE no longer run inline in the command
    /// phase: the drive arms an agenda and the session drains it as
    /// [`Action::Store`] (`Fill`/`Sync`) ops before the terminal status. The
    /// loop below executes each op on the LUN's store plane and feeds the
    /// result back as [`Event::StoreDone`] — invisible on the wire, so the
    /// CSW status and response bytes are unchanged.
    #[allow(clippy::too_many_arguments)]
    fn tx(
        session: &mut BotSession,
        dev: &mut CdromDrive,
        planes: &mut [Option<StorePlane<'_>>],
        work: &mut [u8],
        dir_in: bool,
        declared: usize,
        cdb: &[u8],
        payload: &[u8],
    ) -> (u8, Vec<u8>) {
        let mut cbw = [0u8; 31];
        cbw[0..4].copy_from_slice(&0x4342_5355u32.to_le_bytes());
        cbw[8..12].copy_from_slice(&(declared as u32).to_le_bytes());
        if dir_in {
            cbw[12] = 0x80;
        }
        cbw[14] = cdb.len() as u8;
        cbw[15..15 + cdb.len()].copy_from_slice(cdb);

        let mut sent_payload = 0usize;
        let mut out: Vec<u8> = Vec::new();
        let mut csw_status = 0xFFu8;
        let mut csw_seen = false;
        let mut guard = 0usize;

        let mut devs: [&mut dyn ScsiDevice; 1] = [&mut *dev];
        work[..cbw.len()].copy_from_slice(&cbw);
        // First turn feeds the CBW; every later turn carries the completion of
        // the previous action. A whole-disc FORMAT agenda emits one `Fill` per
        // 64 KiB chunk, so the guard is sized for the largest test disc.
        let mut ev = Event::HostRecv { len: cbw.len() };
        loop {
            guard += 1;
            assert!(guard < 1_000_000, "tx stuck: cdb={cdb:02x?}");
            match session.poll(ev, work, &mut devs) {
                // CSW sent: the core is back in Command phase waiting for
                // the next CBW — transaction complete.
                Action::HostRecv {
                    len: 31,
                    probe: false,
                } if csw_seen => break,
                Action::HostRecv { len, probe } => {
                    // Overrun probe: try once with no data — "nothing more
                    // from the host" ends the drain and moves to the CSW.
                    if probe {
                        ev = Event::HostIdle;
                        continue;
                    }
                    // Data-Out payload (FORMAT UNIT parameter list etc.)
                    let take = len.min(payload.len().saturating_sub(sent_payload)).max(1);
                    let end = (sent_payload + take).min(payload.len());
                    let chunk = if sent_payload < payload.len() {
                        payload[sent_payload..end].to_vec()
                    } else {
                        vec![0u8; len]
                    };
                    sent_payload += chunk.len();
                    work[..chunk.len()].copy_from_slice(&chunk);
                    ev = Event::HostRecv { len: chunk.len() };
                }
                Action::HostSend { bytes, .. } => {
                    if bytes.len() == CSW_LEN {
                        csw_status = bytes[12];
                        csw_seen = true;
                    } else {
                        out.extend_from_slice(bytes);
                    }
                    ev = Event::HostSent;
                }
                Action::Store { lun, op, .. } => {
                    let result = planes[lun]
                        .as_mut()
                        .expect("cdrom LUN must have a store plane")
                        .do_op(op);
                    ev = Event::StoreDone { result };
                }
                Action::StallBoth => panic!("unexpected StallBoth"),
                Action::StallIn => panic!("unexpected StallIn in a non-Short session"),
                Action::Error(e) => panic!("BOT core error: {e:?}"),
            }
        }
        (csw_status, out)
    }

    #[test]
    fn windows_enumeration_and_format_flow() {
        use crate::cdrom::media::CdMedia;
        let mut img = vec![0u8; 2048 * 204800];
        let mut dev = CdromDrive::new();
        let mut bb = BlockBackend::Ram(RamBackend::new(&mut img));
        #[cfg(feature = "dvdram")]
        {
            let media = DvdRamMedia::open(&mut bb);
            dev.load_quiet(CdMedia::Rw(media));
        }
        #[cfg(not(feature = "dvdram"))]
        dev.load_quiet(CdMedia::ro(&mut bb));

        // Real store plane for the cdrom LUN: the FORMAT `Fill` and SYNC CACHE
        // `Sync` agenda ops are executed against it (previously inline).
        #[cfg(feature = "dvdram")]
        let mut planes: [Option<StorePlane<'_>>; 1] = [Some(StorePlane::BlockRw(&mut bb))];
        #[cfg(not(feature = "dvdram"))]
        let mut planes: [Option<StorePlane<'_>>; 1] = [Some(StorePlane::BlockRo(&mut bb))];

        let mut session = BotSession::new();
        let mut work = vec![0u8; crate::MIN_DATA_LEN];
        // Production arms a reset-UA on link events before the first command.
        {
            let mut no_devs: [&mut dyn ScsiDevice; 0] = [];
            let _ = session.poll(Event::Reset, &mut work, &mut no_devs);
        }

        macro_rules! run {
            ($dirin:expr, $decl:expr, $cdb:expr, $payload:expr) => {{
                let r = tx(
                    &mut session,
                    &mut dev,
                    &mut planes,
                    &mut work,
                    $dirin,
                    $decl,
                    &$cdb,
                    $payload,
                );
                assert_eq!(r.0, 0, "tx {:?} must pass", $cdb);
                r.1
            }};
        }

        // Attach burst: INQUIRY / VPD / GESN(class=00!) — the class-00 GESN is
        // what used to fail with the stale A2 sense.
        run!(true, 36, [0x12u8, 0, 0, 0, 0x24, 0], &[]);
        run!(true, 96, [0x12u8, 0, 0, 0, 0x60, 0], &[]);
        run!(true, 8, [0x4Au8, 1, 0, 0, 0x00, 0, 0, 0, 0x08, 0], &[]);

        // Hosts open with TEST UNIT READY: delivers the core's reset-UA once,
        // fetched via REQUEST SENSE (ASC 29h).
        {
            let tur = [0x00u8; 6];
            let (st, _) = tx(
                &mut session,
                &mut dev,
                &mut planes,
                &mut work,
                false,
                0,
                &tur,
                &[],
            );
            assert_eq!(st, 1, "reset-UA delivered on first TUR");
            let rs = [0x03u8, 0, 0, 0, 0x12, 0];
            let (st, sense) = tx(
                &mut session,
                &mut dev,
                &mut planes,
                &mut work,
                true,
                18,
                &rs,
                &[],
            );
            assert_eq!(st, 0);
            assert_eq!(sense[2], 0x06, "sense key UNIT ATTENTION");
            assert_eq!(sense[12], 0x29, "POWER ON, RESET OR BUS DEVICE RESET");
        }

        // The A2 probe storm must keep failing without poisoning anything.
        for _ in 0..3 {
            let (st, _) = tx(
                &mut session,
                &mut dev,
                &mut planes,
                &mut work,
                false,
                0,
                &[0xA2u8, 0, 0, 0, 0x80, 0, 0, 0, 0, 0, 0, 0],
                &[],
            );
            assert_eq!(st, 1);
            assert_eq!(dev.peek_sense().map(|s| s.asc), Some(asc::INVALID_COMMAND));
        }

        // GET CONFIGURATION right after the storm — regression for #109.
        let cfg = run!(true, 240, [0x46u8, 0, 0, 0, 0, 0, 0, 0, 0xF0, 0], &[]);
        // Data Length may exceed the allocation length — the drive reports the
        // full payload size (it is not truncated by the allocation limit, per
        // MMC-6 §6.5).  Just verify it is present and consistent.
        let data_len = u32::from_be_bytes(cfg[0..4].try_into().unwrap());
        assert!(
            data_len > 0 && data_len <= 0xFFFF,
            "DataLength out of range"
        );

        // Media query set.
        run!(true, 10, [0x25u8, 0, 0, 0, 0, 0, 0, 0, 0, 0], &[]);
        let disc = run!(true, 36, [0x51u8, 0, 0, 0, 0, 0, 0, 0, 0x24, 0], &[]);
        assert_eq!(
            disc[2] & 0x03,
            2,
            "disc status 10b Finalized (always formatted)"
        );
        assert_eq!(disc[2] & 0x0C, 0x0C, "state of last session 11b Complete");
        assert_ne!(disc[2] & 0x10, 0, "erasable");
        let cap = run!(true, 20, [0x23u8, 0, 0, 0, 0, 0, 0, 0, 0x14, 0], &[]);
        assert_eq!(&cap[17..20], &[0x00, 0x08, 0x00], "formattable TDP");

        // MODE SENSE(10) page 2A: write DVD-RAM capability bit set.
        let p2a = run!(
            true,
            0x48,
            [0x5Au8, 0x08, 0x2A, 0, 0, 0, 0, 0, 0x48, 0],
            &[]
        );
        assert_eq!(p2a[8], 0x2A);
        assert_ne!(p2a[11] & 0x20, 0, "write DVD-RAM bit");

        // dvd+rw-format style quick FORMAT UNIT (Immed), then UA once.
        let nb = 204800u32.to_be_bytes();
        let mut pl = Vec::new();
        pl.extend_from_slice(&[0x00, 0xA2, 0x00, 0x08]);
        pl.extend_from_slice(&nb);
        pl.extend_from_slice(&[0x00, 0x00, 0x08, 0x00]);
        let fu = [0x04u8, 0x19, 0, 0, 0, 0];
        let r = tx(
            &mut session,
            &mut dev,
            &mut planes,
            &mut work,
            false,
            12,
            &fu,
            &pl,
        );
        assert_eq!(r.0, 0, "FORMAT UNIT must pass");

        let tur = [0x00u8; 6];
        let (st, _) = tx(
            &mut session,
            &mut dev,
            &mut planes,
            &mut work,
            false,
            0,
            &tur,
            &[],
        );
        assert_eq!(st, 1, "UA delivered on next TUR");
        assert!(dev.peek_sense().is_none(), "UA consumed once");

        // Polling resumes cleanly; medium now empty.
        let gesn = run!(true, 8, [0x4Au8, 1, 0, 0, 0x10, 0, 0, 0, 0x08, 0], &[]);
        assert_eq!(
            &gesn[0..2],
            &[0x00, 0x06],
            "Event Descriptor Length = 2 + 4"
        );
        assert_eq!(gesn[2], 0x04); // NEA=0, Notification Class = Media
        assert_eq!(gesn[3], 0x10); // supported classes
        assert_eq!(gesn[4], 0x00); // Event Code 0 = NoChg
        assert_eq!(gesn[5], 0x02); // media present
        let disc = run!(true, 36, [0x51u8, 0, 0, 0, 0, 0, 0, 0, 0x24, 0], &[]);
        assert_eq!(disc[2] & 0x03, 2, "medium stays always-formatted (10b)");

        // Eject while PREVENT is held: the user intent overrides the lock —
        // tray opens, GOOD, and the medium parks (NOT READY 3Ah/02h after).
        run!(false, 0, [0x1Eu8, 0, 0, 0, 0x01, 0], &[]);
        let (st, _) = tx(
            &mut session,
            &mut dev,
            &mut planes,
            &mut work,
            false,
            0,
            &[0x1Bu8, 0, 0, 0, 0x02, 0],
            &[],
        );
        assert_eq!(st, 0, "user eject overrides PREVENT");
        assert!(!dev.is_media_present());
        {
            // First TUR delivers the eject's MEDIUM-MAY-HAVE-CHANGED UA…
            let tur = [0x00u8; 6];
            let (st, _) = tx(
                &mut session,
                &mut dev,
                &mut planes,
                &mut work,
                false,
                0,
                &tur,
                &[],
            );
            assert_eq!(st, 1);
            assert!(dev.peek_sense().is_none(), "UA consumed once");
            // …the next one reports the open tray.
            let (st, _) = tx(
                &mut session,
                &mut dev,
                &mut planes,
                &mut work,
                false,
                0,
                &tur,
                &[],
            );
            assert_eq!(st, 1);
            let s = dev.peek_sense().unwrap();
            assert_eq!((s.asc, s.ascq), (asc::MEDIUM_NOT_PRESENT, 0x02));
        }
    }
}
