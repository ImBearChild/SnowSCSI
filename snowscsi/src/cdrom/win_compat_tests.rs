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
