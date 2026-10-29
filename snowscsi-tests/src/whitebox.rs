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
//! - The asynchronous form of `iscsi_write10_sync` is `iscsi_write10_task`
//!   in the installed libiscsi (the `*_async` spelling exists only in older
//!   releases); it returns the `struct scsi_task *` immediately and reports
//!   the terminal status through a callback.
//!
//! The WRITE(10) path is the regression test for the W-bit fix (`de7e8c1`):
//! libiscsi emits the Linux-kernel byte 1 layout (F|W|ATTR), and a target
//! that misreads the W bit (0x04) rejects these writes with CHECK CONDITION.

use std::ffi::{c_int, c_void, CStr, CString};
use std::net::TcpListener;
use std::thread;

use snowscsi::common::seekable_storage::RamBackend;
use snowscsi::common::store::StorePlane;
use snowscsi::core::{Lu, Target};
use snowscsi::iscsi::pdu::BHS_SIZE;
use snowscsi::iscsi::target::{IscsiSession, TargetError};
use snowscsi::iscsi::transport::{serve_conn, TcpConn, DEFAULT_READ_TIMEOUT};
use snowscsi::MIN_DATA_LEN;

use crate::iscsi_harness::{PlaneSet, TestLu, TestPair};

/// libiscsi constants (iscsi.h / scsi-lowlevel.h).
const ISCSI_SESSION_NORMAL: c_int = 2;
const ISCSI_HEADER_DIGEST_NONE_CRC32C: c_int = 1;
const ISCSI_IMMEDIATE_DATA_NO: c_int = 0;
const ISCSI_INITIAL_R2T_YES: c_int = 1;
const SCSI_STATUS_GOOD: c_int = 0;
const SCSI_STATUS_CHECK_CONDITION: c_int = 2;
const SENSE_KEY_ILLEGAL_REQUEST: c_int = 5;
const SENSE_KEY_ABORTED_COMMAND: c_int = 0x0B;
/// `0B/45/00` as libiscsi stores it in `struct scsi_sense.ascq`.
const ASCQ_ABORTED_COMMAND: c_int = 0x4500;

/// `poll(2)` event bits for [`ffi::snow_iscsi_pump`].
const POLLIN: c_int = 0x001;
const POLLOUT: c_int = 0x004;

/// 16 MiB RAM disk = 32768 logical blocks of 512 B (last LBA 32767).
const RAM_SIZE: usize = 16 * 1024 * 1024;
const BLOCK_SIZE: u32 = 512;
const LAST_LBA: u32 = 32767;

/// Largest host transfer the reconnect/abort tests drive: 1 MiB (2048
/// blocks). `MaxBurstLength` is 256 KiB, so the target must solicit four R2T
/// bursts and the command is still in flight after the first one — that is
/// what makes the mid-transfer drop/abort deterministic. Each test sizes its
/// `work` bank to `write_len + BHS_SIZE`, so the transfer fits in one device
/// chunk.
const LARGE_XFER: usize = 1024 * 1024;

/// R2T-roundtrip transfer: 2 MiB = 4096 blocks. `MaxBurstLength` is 256 KiB,
/// and the target declares an 8192-byte receive segment, so this needs eight
/// R2T bursts, each carried by several Data-Out PDUs. Bank = `len + BHS_SIZE`.
const R2T_XFER: usize = 2 * 1024 * 1024;

/// Opaque libiscsi FFI surface. All handles are `*mut c_void`; struct access
/// goes through the C accessors, never through a hand-written layout.
mod ffi {
    use core::ffi::{c_char, c_int, c_void};

    pub type Iscsi = *mut c_void;
    pub type Task = *mut c_void;

    /// `iscsi_command_cb`: `(iscsi, status, struct scsi_task *, private_data)`.
    pub type CommandCb = Option<extern "C" fn(Iscsi, c_int, Task, *mut c_void)>;

    extern "C" {
        pub fn iscsi_create_context(initiator_name: *const c_char) -> Iscsi;
        pub fn iscsi_destroy_context(iscsi: Iscsi) -> c_int;
        pub fn iscsi_set_targetname(iscsi: Iscsi, targetname: *const c_char) -> c_int;
        pub fn iscsi_set_session_type(iscsi: Iscsi, session_type: c_int) -> c_int;
        pub fn iscsi_set_header_digest(iscsi: Iscsi, value: c_int) -> c_int;
        pub fn iscsi_set_immediate_data(iscsi: Iscsi, value: c_int) -> c_int;
        pub fn iscsi_set_initial_r2t(iscsi: Iscsi, value: c_int) -> c_int;
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
        pub fn iscsi_write10_task(
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
            cb: CommandCb,
            private_data: *mut c_void,
        ) -> Task;
        pub fn iscsi_task_mgmt_abort_task_sync(iscsi: Iscsi, task: Task) -> c_int;
        pub fn scsi_free_scsi_task(task: Task);
        pub fn snow_task_status(task: Task) -> c_int;
        pub fn snow_task_datain_size(task: Task) -> c_int;
        pub fn snow_task_datain_data(task: Task) -> *const u8;
        pub fn snow_task_sense_key(task: Task) -> c_int;
        pub fn snow_task_sense_ascq(task: Task) -> c_int;
        pub fn snow_task_itt(task: Task) -> u32;
        pub fn snow_iscsi_pump(iscsi: Iscsi, events: c_int, timeout_ms: c_int) -> c_int;
        pub fn snow_iscsi_drop(iscsi: Iscsi) -> c_int;
    }
}

/// Terminal result recorded by an asynchronous command callback.
///
/// libiscsi frees the `scsi_task` once the callback returns, so the fields the
/// test cares about are copied out here instead of keeping the task pointer.
#[derive(Default)]
struct AsyncCompletion {
    done: bool,
    status: c_int,
    sense_key: c_int,
    sense_ascq: c_int,
}

/// libiscsi command callback: snapshot the terminal status and sense.
extern "C" fn record_completion(
    _iscsi: ffi::Iscsi,
    status: c_int,
    task: ffi::Task,
    private_data: *mut c_void,
) {
    // SAFETY: `private_data` is the `AsyncCompletion` the test keeps alive for
    // the whole life of the command (including `iscsi_destroy_context`, which
    // cancels outstanding PDUs through this same callback).
    let completion = unsafe { &mut *(private_data as *mut AsyncCompletion) };
    completion.done = true;
    completion.status = status;
    if !task.is_null() {
        completion.sense_key = unsafe { ffi::snow_task_sense_key(task) };
        completion.sense_ascq = unsafe { ffi::snow_task_sense_ascq(task) };
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

    /// `ImmediateData` the initiator asks for during login (must be set before
    /// the connection is established).
    fn set_immediate_data(&self, value: c_int) {
        assert_eq!(
            unsafe { ffi::iscsi_set_immediate_data(self.raw, value) },
            0,
            "set_immediate_data: {}",
            self.error()
        );
    }

    /// `InitialR2T` the initiator asks for during login.
    fn set_initial_r2t(&self, value: c_int) {
        assert_eq!(
            unsafe { ffi::iscsi_set_initial_r2t(self.raw, value) },
            0,
            "set_initial_r2t: {}",
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

    /// Start a WRITE(10) without waiting for it to finish.
    ///
    /// libiscsi keeps ownership of the returned task and frees it after the
    /// callback runs, so the pointer is only valid for task management and must
    /// never be freed here. `data` must outlive the transfer: libiscsi sends
    /// Data-Out PDUs straight out of it.
    fn write10_async(
        &self,
        lun: c_int,
        lba: u32,
        data: &[u8],
        completion: &mut AsyncCompletion,
    ) -> ffi::Task {
        let raw = unsafe {
            ffi::iscsi_write10_task(
                self.raw,
                lun,
                lba,
                data.as_ptr(),
                data.len() as u32,
                BLOCK_SIZE as c_int,
                0,
                0,
                0,
                0,
                0,
                Some(record_completion),
                completion as *mut AsyncCompletion as *mut c_void,
            )
        };
        assert!(!raw.is_null(), "WRITE(10) async: {}", self.error());
        raw
    }

    /// Drive one `poll(2)` round of the libiscsi event loop.
    ///
    /// Returns 1 when events were serviced, 0 on timeout, -1 on error.
    fn pump(&self, events: c_int, timeout_ms: c_int) -> c_int {
        unsafe { ffi::snow_iscsi_pump(self.raw, events, timeout_ms) }
    }

    /// Pump until at least one event was serviced (bounded to ~20 s).
    fn pump_until_event(&self, events: c_int) {
        for _ in 0..100 {
            match self.pump(events, 200) {
                1 => return,
                0 => continue,
                rc => panic!("libiscsi pump failed ({rc}): {}", self.error()),
            }
        }
        panic!("no socket event within 20 s: {}", self.error());
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
        let mut scratch = vec![0u8; MIN_DATA_LEN];
        let mut session = IscsiSession::new();
        // Hold RAM guards in a Vec to extend their lifetime across `serve_conn`.
        let mut guards: Vec<std::sync::MutexGuard<'_, Vec<u8>>> = Vec::with_capacity(n);
        for r in &rams_for_thread {
            guards.push(r.lock().unwrap());
        }
        // Coerce each guard to a `&mut [u8]` slice view, build the slot and its
        // aligned store plane.
        let mut backends: Vec<RamBackend<'_>> = guards
            .iter_mut()
            .map(|g| RamBackend::new(&mut g[..]))
            .collect();
        let mut slots: Vec<TestLu> = (0..n)
            .map(|i| {
                TestLu::block(
                    (RAM_SIZE / BLOCK_SIZE as usize) as u64,
                    BLOCK_SIZE,
                    i as u32,
                )
            })
            .collect();
        let mut table: Vec<&mut dyn Lu<Pair = TestPair>> = slots
            .iter_mut()
            .map(|s| s as &mut dyn Lu<Pair = TestPair>)
            .collect();
        let mut target = Target::new(&mut table[..]);
        let mut storage = PlaneSet::new(
            backends
                .iter_mut()
                .map(|b| Some(StorePlane::BlockRw(b)))
                .collect(),
        );
        serve_conn(
            &mut conn,
            &mut work,
            &mut scratch,
            &mut session,
            &mut target,
            &mut storage,
        )
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

/// Log in with `ImmediateData=No` and `InitialR2T=Yes`.
///
/// The initiator then must not put any write data in the command PDU and the
/// target must solicit every byte with an R2T — the write stalls as soon as the
/// first burst is delivered, which is what the in-flight tests need.
fn connect_forced_r2t(port: u16) -> IscsiCtx {
    let iscsi = IscsiCtx::new("iqn.1994-05.com.redhat:snowscsi-test");
    iscsi.set_targetname("iqn.1970-01.local.snowscsi:target");
    iscsi.set_session_type(ISCSI_SESSION_NORMAL);
    iscsi.set_header_digest(ISCSI_HEADER_DIGEST_NONE_CRC32C);
    iscsi.set_immediate_data(ISCSI_IMMEDIATE_DATA_NO);
    iscsi.set_initial_r2t(ISCSI_INITIAL_R2T_YES);
    iscsi.full_connect(&format!("127.0.0.1:{port}"));
    iscsi
}

/// Serve `connections` connections one after another from **one** set of LUN
/// slots and one storage plane.
///
/// The slots and the RAM plane are created once, before the accept loop, so a
/// second connection reaches the very same `Lu` instances a dropped connection
/// left behind. Each connection still gets a fresh `IscsiSession` and a fresh
/// `Target`, like the production accept loop. `work_len` sizes the command bank
/// for the largest transfer the initiator will issue.
fn start_target_serving(
    connections: usize,
    work_len: usize,
) -> (u16, thread::JoinHandle<Result<(), TargetError>>) {
    assert!(work_len >= MIN_DATA_LEN + BHS_SIZE, "bank too small");
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().unwrap().port();
    let handle = thread::spawn(move || {
        // The plane and the slots live for every connection, so slot state (and
        // with it the regression under test) survives a reconnect.
        let mut ram = vec![0u8; RAM_SIZE];
        let mut backend = RamBackend::new(&mut ram[..]);
        let mut slots = [TestLu::block(
            (RAM_SIZE / BLOCK_SIZE as usize) as u64,
            BLOCK_SIZE,
            0,
        )];
        let mut table: Vec<&mut dyn Lu<Pair = TestPair>> = slots
            .iter_mut()
            .map(|s| s as &mut dyn Lu<Pair = TestPair>)
            .collect();
        let mut storage = PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut backend))]);
        for _ in 0..connections {
            let (stream, _peer) = listener.accept().expect("target accept");
            let mut conn = TcpConn::new(stream, Some(DEFAULT_READ_TIMEOUT)).expect("tcp conn");
            let mut work = vec![0u8; work_len];
            let mut scratch = vec![0u8; MIN_DATA_LEN];
            let mut session = IscsiSession::new();
            let mut target = Target::new(&mut table[..]);
            serve_conn(
                &mut conn,
                &mut work,
                &mut scratch,
                &mut session,
                &mut target,
                &mut storage,
            )?;
        }
        Ok(())
    });
    (port, handle)
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
    assert_eq!(data.len(), 36, "the standard INQUIRY page is 36 bytes");
    assert_eq!(data[0] & 0x1F, 0, "PDT must be 0 (direct-access)");
    assert_eq!(data[2], 5, "byte[2] must be SPC-3");
    assert_eq!(data[4], 31, "additional length");
    assert_eq!(&data[8..16], b"SNOW\0\0\0\0", "vendor ID");
    assert_eq!(&data[16..32], b"SCSI\0\0\0\0\0\0\0\0\0\0\0\0", "product ID");
    assert_eq!(&data[32..36], b"P1  ", "product revision");

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
        // A 4 MiB WRITE(10) with a 4 MiB command bank (no chunking needed).
        let mut work = vec![0u8; 4 * 1024 * 1024 + BHS_SIZE];
        let mut session = IscsiSession::new();
        let mut bundle = FlatBundle::new(
            StdFsBackend::new(&dir_for_thread),
            1 << 20,
            size,
            BLOCK_SIZE,
        )
        .expect("bundle");
        let mut slots = [TestLu::block(size / u64::from(BLOCK_SIZE), BLOCK_SIZE, 0)];
        let mut table: Vec<&mut dyn Lu<Pair = TestPair>> = slots
            .iter_mut()
            .map(|s| s as &mut dyn Lu<Pair = TestPair>)
            .collect();
        let mut target = Target::new(&mut table[..]);
        let mut scratch = vec![0u8; MIN_DATA_LEN];
        let mut storage = PlaneSet::new(vec![Some(StorePlane::BlockRw(&mut bundle))]);
        serve_conn(
            &mut conn,
            &mut work,
            &mut scratch,
            &mut session,
            &mut target,
            &mut storage,
        )
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

/// Reconnect after a connection is dropped with a command in flight.
///
/// The dropped connection leaves a WRITE(10) owned by the target slot. If that
/// command is not settled when the wire goes away, the slot stays active and
/// every command on the next connection is answered BUSY. Both connections
/// therefore have to reach the same `Lu` slots (see [`start_target_serving`]),
/// and the first command on the new connection must be GOOD.
#[test]
fn reconnect_after_in_flight_drop() {
    let (port, server) = start_target_serving(2, LARGE_XFER + BHS_SIZE);

    // A stalled write is the in-flight state, and the socket teardown is the
    // drop: libiscsi's blocking helpers always run their own event loop to
    // completion, so the only way to abandon a transfer mid-wire is to
    // shutdown(2) the context's fd (`snow_iscsi_drop`).
    let mut completion = Box::new(AsyncCompletion::default());
    let first = connect_forced_r2t(port);
    let payload = vec![0xA7u8; LARGE_XFER];
    let task = first.write10_async(0, 0, &payload, &mut completion);
    let itt = unsafe { ffi::snow_task_itt(task) };
    assert_ne!(itt, 0xFFFF_FFFF, "the write must own a real ITT");

    // POLLOUT flushes the command PDU; the following POLLIN reads the R2T the
    // target sends because `InitialR2T=Yes` withholds every data byte. The
    // write needs four 256 KiB bursts, so it is still incomplete (and cannot
    // complete: no further R2T can be answered) when the wire is cut.
    assert_eq!(
        first.pump(POLLOUT, 5_000),
        1,
        "the command PDU must be flushed: {}",
        first.error()
    );
    first.pump_until_event(POLLIN);
    assert!(
        !completion.done,
        "the write must still be in flight (R2T) before the connection is dropped"
    );

    assert_eq!(
        unsafe { ffi::snow_iscsi_drop(first.raw) },
        0,
        "shutdown of the connection: {}",
        first.error()
    );
    assert!(
        !completion.done,
        "the write must never complete on the dropped wire"
    );
    // Destroys the context; libiscsi cancels the local task and reports it as
    // CANCELLED through `record_completion` (hence `completion` outlives it).
    drop(first);

    // The regression: a new connection to the same slots must be fully usable.
    let second = connect(port);
    let t = second.test_unit_ready(0);
    assert_eq!(
        t.status(),
        SCSI_STATUS_GOOD,
        "the slot left by the dropped connection must not answer BUSY/CHECK \
         CONDITION: {}",
        second.error()
    );

    let t = second.read10(0, 0, 4096, BLOCK_SIZE as c_int);
    assert_eq!(
        t.status(),
        SCSI_STATUS_GOOD,
        "READ after the reconnect: {}",
        second.error()
    );
    assert_eq!(t.datain().len(), 4096, "the LUN geometry must be intact");

    let mut buf = vec![0u8; 4096];
    buf[..4].copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
    buf[4..].fill(0x5A);
    let t = second.write10(0, 16, &buf, BLOCK_SIZE as c_int);
    assert_eq!(
        t.status(),
        SCSI_STATUS_GOOD,
        "WRITE after the reconnect: {}",
        second.error()
    );
    let t = second.read10(0, 16, 4096, BLOCK_SIZE as c_int);
    assert_eq!(
        t.status(),
        SCSI_STATUS_GOOD,
        "READ back after the reconnect: {}",
        second.error()
    );
    assert_eq!(
        t.datain(),
        &buf[..],
        "data must round-trip on the new connection"
    );

    teardown(&second, server);
}

/// ABORT TASK of a write that is waiting for host data.
///
/// The target must answer the task-management request with COMPLETE (0x00),
/// settle the aborted command as CHECK CONDITION `0B/45/00`, and keep the
/// session usable for the next command.
#[test]
fn abort_task_settles_in_flight_write() {
    let (port, server) = start_target_serving(1, LARGE_XFER + BHS_SIZE);

    let mut completion = Box::new(AsyncCompletion::default());
    let iscsi = connect_forced_r2t(port);
    let payload = vec![0x5Cu8; LARGE_XFER];
    let task = iscsi.write10_async(0, 0, &payload, &mut completion);
    let itt = unsafe { ffi::snow_task_itt(task) };
    assert_ne!(itt, 0xFFFF_FFFF, "the write must own a real ITT");

    // Only the command PDU is flushed here. `ImmediateData=No` keeps the data
    // out of it and `InitialR2T=Yes` makes the target solicit every byte, so
    // the write cannot complete until the initiator answers an R2T — and the
    // R2T is deliberately left unread. The target therefore owns the command
    // (it has the WRITE, zero data bytes) when the abort arrives. The socket
    // delivers the command before the TMF, so the abort hits it in flight.
    assert_eq!(
        iscsi.pump(POLLOUT, 5_000),
        1,
        "the command PDU must be flushed: {}",
        iscsi.error()
    );
    assert!(
        !completion.done,
        "no data byte was sent, so the write cannot have completed"
    );

    // `iscsi_task_mgmt_abort_task_sync` maps the TMF response onto its return
    // code: 0 is COMPLETE (0x00); TASK DOES NOT EXIST (0x01) becomes -1 with an
    // explanatory `iscsi_get_error`.
    let abort = unsafe { ffi::iscsi_task_mgmt_abort_task_sync(iscsi.raw, task) };
    if abort == 0 {
        // COMPLETE (0x00): the target owned the task. Its status must reach
        // the initiator as CHECK CONDITION 0B/45/00.
        for _ in 0..100 {
            if completion.done {
                break;
            }
            match iscsi.pump(POLLIN, 200) {
                0 | 1 => continue,
                rc => panic!("libiscsi pump failed ({rc}): {}", iscsi.error()),
            }
        }
        assert!(
            completion.done,
            "the aborted command must settle on the wire: {}",
            iscsi.error()
        );
        assert_eq!(
            completion.status, SCSI_STATUS_CHECK_CONDITION,
            "an aborted command must end as CHECK CONDITION"
        );
        assert_eq!(
            completion.sense_key, SENSE_KEY_ABORTED_COMMAND,
            "sense key must be ABORTED COMMAND (0x0B)"
        );
        assert_eq!(
            completion.sense_ascq, ASCQ_ABORTED_COMMAND,
            "sense must be 0B/45/00 (ASC/ASCQ 45/00)"
        );
    } else {
        // Honest alternative: 0x01 means the target no longer had the task,
        // which may only happen when the command already completed.
        assert!(
            completion.done,
            "abort reported the task absent while it was still in flight: {}",
            iscsi.error()
        );
        assert_eq!(
            completion.status, SCSI_STATUS_GOOD,
            "an absent task must mean the write already completed"
        );
    }

    let t = iscsi.test_unit_ready(0);
    assert_eq!(
        t.status(),
        SCSI_STATUS_GOOD,
        "the session must survive ABORT TASK: {}",
        iscsi.error()
    );

    teardown(&iscsi, server);
}

/// WRITE(10)/READ(10) of a transfer that needs R2T and several Data-Out PDUs.
///
/// `ImmediateData=No` forbids data in the command PDU and `InitialR2T=Yes`
/// requires the target to solicit every byte, so the write can only complete
/// through the R2T/Data-Out state machine: 2 MiB at the 256 KiB `MaxBurstLength`
/// is eight solicited bursts, each split into PDUs no larger than the target's
/// declared receive segment. The read-back must be byte-exact.
#[test]
fn forced_r2t_write_read_roundtrip() {
    // A command bank large enough for the whole plan (no device chunking).
    let (port, server) = start_target_serving(1, R2T_XFER + BHS_SIZE);
    let iscsi = connect_forced_r2t(port);

    // LBA 64..4160 of the 32768-block disk: 4096 blocks of 512 B.
    const LBA: u32 = 64;
    let payload: Vec<u8> = (0..R2T_XFER).map(|i| ((i * 37) % 251) as u8).collect();

    let t = iscsi.write10(0, LBA, &payload, BLOCK_SIZE as c_int);
    assert_eq!(
        t.status(),
        SCSI_STATUS_GOOD,
        "WRITE through the forced R2T path: {}",
        iscsi.error()
    );

    let t = iscsi.read10(0, LBA, R2T_XFER as u32, BLOCK_SIZE as c_int);
    assert_eq!(
        t.status(),
        SCSI_STATUS_GOOD,
        "READ back through the R2T-negotiated session: {}",
        iscsi.error()
    );
    assert_eq!(
        t.datain().len(),
        R2T_XFER,
        "the read must return the whole transfer"
    );
    assert_eq!(
        t.datain(),
        &payload[..],
        "the R2T/Data-Out roundtrip must be byte-exact"
    );

    teardown(&iscsi, server);
}
