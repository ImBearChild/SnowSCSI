//! libiscsi whitebox integration tests.
//!
//! A real initiator (libiscsi) drives the in-process Rust iSCSI target over a
//! real TCP loopback connection. FFI uses opaque pointers plus a tiny C
//! accessor (`tests/c/iscsi_access.c`, compiled by `cc` in build.rs) so no
//! libiscsi struct layout is assumed on the Rust side.
//!
//! ABI notes:
//! - `iscsi_connect_sync` only establishes TCP; login needs
//!   `iscsi_full_connect_sync` (TCP + Login Request + UA-eating TUR).
//! - `iscsi_testunitready_sync` returns `struct scsi_task *`, not `int`.
//!
//! The WRITE(10) path is the regression test for the W-bit fix (`de7e8c1`):
//! libiscsi emits the Linux-kernel byte 1 layout (F|W|ATTR), and a target
//! that misreads the W bit (0x04) rejects these writes with CHECK CONDITION.

use std::ffi::{c_int, CStr, CString};
use std::net::TcpListener;
use std::thread;

use snowscsi::common::seekable_storage::RamBackend;
use snowscsi::common::store::StorePlane;
use snowscsi::iscsi::pdu::BHS_SIZE;
use snowscsi::iscsi::target::{IscsiSession, TargetError};
use snowscsi::iscsi::transport::{serve_conn, TcpConn, DEFAULT_READ_TIMEOUT};
use snowscsi::scsi::block::BlockDevice;
use snowscsi::scsi::device::ScsiDevice;
use snowscsi::scsi::Luns;
use snowscsi::MIN_DATA_LEN;

/// libiscsi constants (iscsi.h / scsi-lowlevel.h).
const ISCSI_SESSION_NORMAL: c_int = 2;
const ISCSI_HEADER_DIGEST_NONE_CRC32C: c_int = 1;
const SCSI_STATUS_GOOD: c_int = 0;
const SCSI_STATUS_CHECK_CONDITION: c_int = 2;
const SENSE_KEY_ILLEGAL_REQUEST: c_int = 5;

/// 16 MiB RAM disk = 32768 logical blocks of 512 B (last LBA 32767).
const RAM_SIZE: usize = 16 * 1024 * 1024;
const BLOCK_SIZE: u32 = 512;
const LAST_LBA: u32 = 32767;

/// Opaque libiscsi FFI surface. All handles are `*mut c_void`; struct access
/// goes through the C accessors, never through a hand-written layout.
mod ffi {
    use core::ffi::{c_char, c_int, c_void};

    pub type Iscsi = *mut c_void;
    pub type Task = *mut c_void;

    extern "C" {
        pub fn iscsi_create_context(initiator_name: *const c_char) -> Iscsi;
        pub fn iscsi_destroy_context(iscsi: Iscsi) -> c_int;
        pub fn iscsi_set_targetname(iscsi: Iscsi, targetname: *const c_char) -> c_int;
        pub fn iscsi_set_session_type(iscsi: Iscsi, session_type: c_int) -> c_int;
        pub fn iscsi_set_header_digest(iscsi: Iscsi, value: c_int) -> c_int;
        pub fn iscsi_full_connect_sync(iscsi: Iscsi, portal: *const c_char, lun: c_int) -> c_int;
        pub fn iscsi_disconnect(iscsi: Iscsi) -> c_int;
        pub fn iscsi_get_error(iscsi: Iscsi) -> *const c_char;
        pub fn iscsi_testunitready_sync(iscsi: Iscsi, lun: c_int) -> Task;
        pub fn iscsi_inquiry_sync(
            iscsi: Iscsi,
            lun: c_int,
            evpd: c_int,
            page_code: c_int,
            maxsize: c_int,
        ) -> Task;
        pub fn iscsi_readcapacity10_sync(iscsi: Iscsi, lun: c_int, lba: c_int, pmi: c_int) -> Task;
        pub fn iscsi_read10_sync(
            iscsi: Iscsi,
            lun: c_int,
            lba: u32,
            datalen: u32,
            blocksize: c_int,
            rdprotect: c_int,
            dpo: c_int,
            fua: c_int,
            fua_nv: c_int,
            group_number: c_int,
        ) -> Task;
        pub fn iscsi_write10_sync(
            iscsi: Iscsi,
            lun: c_int,
            lba: u32,
            data: *const u8,
            datalen: u32,
            blocksize: c_int,
            wrprotect: c_int,
            dpo: c_int,
            fua: c_int,
            fua_nv: c_int,
            group_number: c_int,
        ) -> Task;
        pub fn scsi_free_scsi_task(task: Task);
        pub fn snow_task_status(task: Task) -> c_int;
        pub fn snow_task_datain_size(task: Task) -> c_int;
        pub fn snow_task_datain_data(task: Task) -> *const u8;
        pub fn snow_task_sense_key(task: Task) -> c_int;
    }
}

/// Owned `iscsi_context`; disconnect + free on drop (panic-safe teardown).
struct IscsiCtx {
    raw: ffi::Iscsi,
}

impl IscsiCtx {
    fn new(initiator_name: &str) -> Self {
        let name = CString::new(initiator_name).unwrap();
        let raw = unsafe { ffi::iscsi_create_context(name.as_ptr()) };
        assert!(!raw.is_null(), "iscsi_create_context failed");
        Self { raw }
    }

    fn error(&self) -> String {
        let e = unsafe { ffi::iscsi_get_error(self.raw) };
        if e.is_null() {
            "unknown libiscsi error".to_string()
        } else {
            unsafe { CStr::from_ptr(e) }.to_string_lossy().into_owned()
        }
    }

    fn set_targetname(&self, target: &str) {
        let t = CString::new(target).unwrap();
        assert_eq!(
            unsafe { ffi::iscsi_set_targetname(self.raw, t.as_ptr()) },
            0,
            "set_targetname: {}",
            self.error()
        );
    }

    fn set_session_type(&self, session_type: c_int) {
        assert_eq!(
            unsafe { ffi::iscsi_set_session_type(self.raw, session_type) },
            0,
            "set_session_type: {}",
            self.error()
        );
    }

    fn set_header_digest(&self, value: c_int) {
        assert_eq!(
            unsafe { ffi::iscsi_set_header_digest(self.raw, value) },
            0,
            "set_header_digest: {}",
            self.error()
        );
    }

    /// Full connect: TCP + Login Request (+ the UA-eating TUR libiscsi issues
    /// right after login). `iscsi_connect_sync` alone is NOT enough — it only
    /// establishes TCP and leaves `is_loggedin == 0`, so every later SCSI
    /// command fails with "Trying to send command while not logged in".
    fn full_connect(&self, portal: &str) {
        let p = CString::new(portal).unwrap();
        assert_eq!(
            unsafe { ffi::iscsi_full_connect_sync(self.raw, p.as_ptr(), 0) },
            0,
            "full_connect: {}",
            self.error()
        );
    }

    fn disconnect(&self) {
        unsafe { ffi::iscsi_disconnect(self.raw) };
    }

    fn test_unit_ready(&self, lun: c_int) -> Task {
        let raw = unsafe { ffi::iscsi_testunitready_sync(self.raw, lun) };
        assert!(!raw.is_null(), "TUR transport: {}", self.error());
        Task { raw }
    }

    fn inquiry(&self, lun: c_int, evpd: c_int, page_code: c_int, maxsize: c_int) -> Task {
        let raw = unsafe { ffi::iscsi_inquiry_sync(self.raw, lun, evpd, page_code, maxsize) };
        assert!(!raw.is_null(), "INQUIRY transport: {}", self.error());
        Task { raw }
    }

    fn read_capacity10(&self, lun: c_int) -> Task {
        let raw = unsafe { ffi::iscsi_readcapacity10_sync(self.raw, lun, 0, 0) };
        assert!(!raw.is_null(), "READ CAPACITY transport: {}", self.error());
        Task { raw }
    }

    fn read10(&self, lun: c_int, lba: u32, datalen: u32, blocksize: c_int) -> Task {
        let raw = unsafe {
            ffi::iscsi_read10_sync(self.raw, lun, lba, datalen, blocksize, 0, 0, 0, 0, 0)
        };
        assert!(!raw.is_null(), "READ(10) transport: {}", self.error());
        Task { raw }
    }

    fn write10(&self, lun: c_int, lba: u32, data: &[u8], blocksize: c_int) -> Task {
        let raw = unsafe {
            ffi::iscsi_write10_sync(
                self.raw,
                lun,
                lba,
                data.as_ptr(),
                data.len() as u32,
                blocksize,
                0,
                0,
                0,
                0,
                0,
            )
        };
        assert!(!raw.is_null(), "WRITE(10) transport: {}", self.error());
        Task { raw }
    }
}

impl Drop for IscsiCtx {
    fn drop(&mut self) {
        unsafe { ffi::iscsi_destroy_context(self.raw) };
    }
}

/// Owned `scsi_task`; freed on drop.
struct Task {
    raw: ffi::Task,
}

impl Task {
    fn status(&self) -> c_int {
        unsafe { ffi::snow_task_status(self.raw) }
    }

    fn datain(&self) -> &[u8] {
        let size = unsafe { ffi::snow_task_datain_size(self.raw) };
        if size <= 0 {
            return &[];
        }
        let ptr = unsafe { ffi::snow_task_datain_data(self.raw) };
        assert!(!ptr.is_null(), "datain data pointer is null");
        unsafe { std::slice::from_raw_parts(ptr, size as usize) }
    }

    fn sense_key(&self) -> c_int {
        unsafe { ffi::snow_task_sense_key(self.raw) }
    }
}

impl Drop for Task {
    fn drop(&mut self) {
        unsafe { ffi::scsi_free_scsi_task(self.raw) };
    }
}

/// Start the in-process target on an ephemeral loopback port. Returns the
/// port and the server thread join handle.
fn start_target() -> (u16, thread::JoinHandle<Result<(), TargetError>>) {
    let (port, handle, _rams) = start_target_n_luns(1);
    (port, handle)
}

/// Like [`start_target`], but with `n` independent RAM-backed LUNs (LUN 0..n-1).
///
/// The RAMs must outlive the spawned thread, so they're `Arc<Mutex<…>>`-shared
/// with the closure. Each LUN has its own storage; libiscsi's per-LUN
/// discovery (and the explicit `iscsi_inquiry_sync(lun, …)` below) is the
/// regression test for the multi-LUN `REPORT LUNS` fix.
#[allow(clippy::type_complexity)]
fn start_target_n_luns(
    n: usize,
) -> (
    u16,
    thread::JoinHandle<Result<(), TargetError>>,
    Vec<std::sync::Arc<std::sync::Mutex<Vec<u8>>>>,
) {
    use std::sync::{Arc, Mutex};
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().unwrap().port();
    let rams: Vec<Arc<Mutex<Vec<u8>>>> = (0..n)
        .map(|_| Arc::new(Mutex::new(vec![0u8; RAM_SIZE])))
        .collect();
    let rams_for_thread = rams.to_vec();
    let handle = thread::spawn(move || {
        let (stream, _peer) = listener.accept().expect("target accept");
        let mut conn = TcpConn::new(stream, Some(DEFAULT_READ_TIMEOUT)).expect("tcp conn");
        let mut work = vec![0u8; MIN_DATA_LEN + BHS_SIZE];
        let mut session = IscsiSession::new();
        // Hold RAM guards in a Vec to extend their lifetime across `serve_conn`.
        let mut guards: Vec<std::sync::MutexGuard<'_, Vec<u8>>> = Vec::with_capacity(n);
        for r in &rams_for_thread {
            guards.push(r.lock().unwrap());
        }
        // Coerce each guard to a `&mut [u8]` slice view, build the device and
        // its aligned store plane.
        let mut backends: Vec<RamBackend<'_>> = guards
            .iter_mut()
            .map(|g| RamBackend::new(&mut g[..]))
            .collect();
        let mut devs: Vec<BlockDevice> = backends
            .iter_mut()
            .map(|b| BlockDevice::disk(b, BLOCK_SIZE).expect("device"))
            .collect();
        let mut dev_slices: Vec<&mut dyn ScsiDevice> =
            devs.iter_mut().map(|d| d as &mut dyn ScsiDevice).collect();
        let mut planes: Vec<Option<StorePlane<'_>>> = backends
            .iter_mut()
            .map(|b| Some(StorePlane::BlockRw(b)))
            .collect();
        let mut luns = Luns::new(&mut dev_slices, &mut planes);
        serve_conn(&mut conn, &mut work, &mut session, &mut luns)
    });
    (port, handle, rams)
}

/// Connect a libiscsi context to the in-process target and log in.
fn connect(port: u16) -> IscsiCtx {
    let iscsi = IscsiCtx::new("iqn.1994-05.com.redhat:snowscsi-test");
    iscsi.set_targetname("iqn.1970-01.local.snowscsi:target");
    iscsi.set_session_type(ISCSI_SESSION_NORMAL);
    iscsi.set_header_digest(ISCSI_HEADER_DIGEST_NONE_CRC32C);
    iscsi.full_connect(&format!("127.0.0.1:{port}"));
    iscsi
}

/// Drop the connection and assert the target loop exited cleanly.
fn teardown(iscsi: &IscsiCtx, server: thread::JoinHandle<Result<(), TargetError>>) {
    iscsi.disconnect();
    server
        .join()
        .expect("target thread panicked")
        .expect("target server error");
}

#[test]
fn test_unit_ready_inquiry_read_capacity() {
    let (port, server) = start_target();
    let iscsi = connect(port);

    assert_eq!(
        iscsi.test_unit_ready(0).status(),
        SCSI_STATUS_GOOD,
        "TUR: {}",
        iscsi.error()
    );

    let task = iscsi.inquiry(0, 0, 0, 256);
    assert_eq!(
        task.status(),
        SCSI_STATUS_GOOD,
        "INQUIRY: {}",
        iscsi.error()
    );
    let data = task.datain();
    assert!(data.len() >= 66, "INQUIRY data too short: {}", data.len());
    assert_eq!(data[0] & 0x1F, 0, "PDT must be 0 (direct-access)");
    assert_eq!(data[2], 0x06, "byte[2] must be SPC-4 (分歧2)");
    assert_eq!(&data[8..16], b"SnowSCSI", "vendor ID");
    assert_eq!(&data[16..32], b"Virtual Disk    ", "product ID");
    assert_eq!(&data[32..36], b"0100", "product revision");
    let desc = |i: usize| u16::from_be_bytes([data[58 + 2 * i], data[58 + 2 * i + 1]]);
    assert_eq!(desc(0), 0x00A0, "version descriptor SAM-5");
    assert_eq!(desc(1), 0x0960, "version descriptor iSCSI");
    assert_eq!(desc(2), 0x0460, "version descriptor SPC-4");
    assert_eq!(desc(3), 0x04C0, "version descriptor SBC-3");

    let task = iscsi.read_capacity10(0);
    assert_eq!(
        task.status(),
        SCSI_STATUS_GOOD,
        "READ CAPACITY: {}",
        iscsi.error()
    );
    let data = task.datain();
    assert_eq!(data.len(), 8, "RC10 returns 8 bytes");
    assert_eq!(
        u32::from_be_bytes([data[0], data[1], data[2], data[3]]),
        LAST_LBA
    );
    assert_eq!(
        u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
        BLOCK_SIZE
    );

    teardown(&iscsi, server);
}

/// WRITE(10)+READ(10) roundtrip over the wire, 100 iterations. libiscsi
/// sends the Linux-kernel byte 1 layout — this is the W-bit regression
/// (a target reading W as 0x04 rejects every one of these with
/// CHECK CONDITION).
#[test]
fn write_read_roundtrip_100() {
    let (port, server) = start_target();
    let iscsi = connect(port);

    for i in 0..100u32 {
        let mut buf = vec![0u8; 512];
        buf[..4].copy_from_slice(&i.to_be_bytes());
        buf[4..].fill(0xA5);
        let t = iscsi.write10(0, i, &buf, BLOCK_SIZE as c_int);
        assert_eq!(
            t.status(),
            SCSI_STATUS_GOOD,
            "WRITE lba={i}: {}",
            iscsi.error()
        );
        let t = iscsi.read10(0, i, 512, BLOCK_SIZE as c_int);
        assert_eq!(
            t.status(),
            SCSI_STATUS_GOOD,
            "READ lba={i}: {}",
            iscsi.error()
        );
        assert_eq!(t.datain(), &buf[..], "roundtrip mismatch at lba={i}");
    }

    teardown(&iscsi, server);
}

/// A write past the end of the device must surface a CHECK CONDITION with
/// ILLEGAL REQUEST sense on the wire.
#[test]
fn write_out_of_range_sense() {
    let (port, server) = start_target();
    let iscsi = connect(port);

    let buf = vec![0x5Au8; 512];
    let t = iscsi.write10(0, LAST_LBA + 1, &buf, BLOCK_SIZE as c_int);
    assert_eq!(
        t.status(),
        SCSI_STATUS_CHECK_CONDITION,
        "out-of-range write must be CHECK CONDITION: {}",
        iscsi.error()
    );
    assert_eq!(
        t.sense_key(),
        SENSE_KEY_ILLEGAL_REQUEST,
        "sense key must be ILLEGAL_REQUEST (5): {}",
        iscsi.error()
    );

    teardown(&iscsi, server);
}

/// CHECK CONDITION sense is owned and consumed exactly once (autosense):
/// after an out-of-range WRITE the next TUR must be GOOD, not a repeated
/// CHECK (verifies `take_sense()` clears the device).
#[test]
fn out_of_range_sense_is_consumed() {
    let (port, server) = start_target();
    let iscsi = connect(port);

    let buf = vec![0x5Au8; 512];
    let t = iscsi.write10(0, LAST_LBA + 1, &buf, BLOCK_SIZE as c_int);
    assert_eq!(
        t.status(),
        SCSI_STATUS_CHECK_CONDITION,
        "out-of-range write must be CHECK CONDITION: {}",
        iscsi.error()
    );
    assert_eq!(t.sense_key(), SENSE_KEY_ILLEGAL_REQUEST);

    // Next command must be GOOD - sense must have been consumed by autosense.
    let t2 = iscsi.test_unit_ready(0);
    assert_eq!(
        t2.status(),
        SCSI_STATUS_GOOD,
        "sense must be consumed after autosense, TUR should be GOOD: {}",
        iscsi.error()
    );

    teardown(&iscsi, server);
}

/// FlatBundle backend over the real iSCSI wire with mkfs-like scattered and
/// large (R2T) writes — reproduces the `WRITE(10)` Medium Error seen with the
/// kernel initiator without needing root.
#[test]
fn bundle_scattered_writes_over_iscsi() {
    use snowscsi::common::flat_bundle::FlatBundle;
    use snowscsi::scsi::fs_backend::StdFsBackend;

    let size: u64 = 32 << 20;
    let dir = std::env::temp_dir().join(format!(
        "snowscsi_wb_bundle_{}_{}",
        std::process::id(),
        line!()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let dir_for_thread = dir.to_string_lossy().into_owned();

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().unwrap().port();
    let handle = thread::spawn(move || {
        let (stream, _peer) = listener.accept().expect("target accept");
        let mut conn = TcpConn::new(stream, Some(DEFAULT_READ_TIMEOUT)).expect("tcp conn");
        let mut work = vec![0u8; MIN_DATA_LEN + BHS_SIZE];
        let mut session = IscsiSession::new();
        let mut bundle = FlatBundle::new(
            StdFsBackend::new(&dir_for_thread),
            1 << 20,
            size,
            BLOCK_SIZE,
        )
        .expect("bundle");
        let mut dev = BlockDevice::disk(&mut bundle, BLOCK_SIZE).expect("device");
        let mut devs: [&mut dyn ScsiDevice; 1] = [&mut dev];
        let mut planes: [Option<StorePlane<'_>>; 1] = [Some(StorePlane::BlockRw(&mut bundle))];
        let mut luns = Luns::new(&mut devs, &mut planes);
        serve_conn(&mut conn, &mut work, &mut session, &mut luns)
    });

    let iscsi = connect(port);

    // Every 4 KiB block, visited in a deterministic shuffled order (holes,
    // cross-chunk, LRU churn), written as a single immediate WRITE(10).
    let mut lbas: Vec<u32> = (0..(size / 4096) as u32).map(|i| i * 8).collect();
    lbas.sort_by_key(|l| l.wrapping_mul(2654435761) ^ 0x9E37_79B9);
    for &lba in &lbas {
        let buf = vec![(lba & 0xFF) as u8; 4096];
        let t = iscsi.write10(0, lba, &buf, BLOCK_SIZE as c_int);
        assert_eq!(
            t.status(),
            SCSI_STATUS_GOOD,
            "4 KiB WRITE lba={lba}: {}",
            iscsi.error()
        );
    }

    // Large multi-R2T writes (mkfs' 4 MiB runs).
    for &lba in &[0u32, 8192, 16384, 32768, 49152, 57344] {
        let buf = vec![0x5Au8; 4 * 1024 * 1024];
        let t = iscsi.write10(0, lba, &buf, BLOCK_SIZE as c_int);
        assert_eq!(
            t.status(),
            SCSI_STATUS_GOOD,
            "4 MiB WRITE lba={lba}: {}",
            iscsi.error()
        );
    }

    teardown(&iscsi, handle);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Multi-LUN: the target is configured with three independent LUNs.
/// libiscsi's `iscsi_full_connect_sync` issues a TEST UNIT READY at LUN 0
/// (and implicitly relies on REPORT LUNS to populate its internal map). The
/// fix for the "Linux client only discovers LUN 0" bug is in
/// `iscsi_target::handle_report_luns` — here we additionally probe LUN 1 and
/// LUN 2 directly to confirm the per-LUN routing works on the wire.
#[test]
fn multi_lun_routes_by_lun() {
    let (port, server, _rams) = start_target_n_luns(3);
    let iscsi = connect(port);

    for lun in 0..3 {
        let t = iscsi.test_unit_ready(lun);
        assert_eq!(
            t.status(),
            SCSI_STATUS_GOOD,
            "TUR LUN {lun}: {}",
            iscsi.error()
        );
        let t = iscsi.inquiry(lun, 0, 0, 96);
        assert_eq!(
            t.status(),
            SCSI_STATUS_GOOD,
            "INQUIRY LUN {lun}: {}",
            iscsi.error()
        );
        let data = t.datain();
        assert!(data.len() >= 8, "INQUIRY LUN {lun}: short data");
        assert_eq!(data[0] & 0x1F, 0, "LUN {lun} PDT must be 0");
    }

    // LUN 3 is out of range — the target must answer with a SCSI Check
    // Condition (LOGICAL UNIT NOT SUPPORTED), not GOOD, and keep the
    // session alive (no Reject / connection teardown).
    let t = iscsi.test_unit_ready(3);
    assert_ne!(
        t.status(),
        SCSI_STATUS_GOOD,
        "LUN 3 must not be reachable: {}",
        iscsi.error()
    );

    teardown(&iscsi, server);
}
