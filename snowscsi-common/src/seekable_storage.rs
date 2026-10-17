//! Random-access seekable storage seam (backend_ram.c).
//!
//! [`SeekableStorage`] models **random-access, cursor-addressed byte
//! storage** — the backing store behind a block device, not a block-addressed
//! (LBA) device itself. Sequential / append-only media (tape, CD-R burning)
//! need their own storage abstraction. Errors are no_std ([`StorageError`]).
//!
//! Supertraits: [`embedded_io::Read`] + [`embedded_io::Write`] +
//! [`embedded_io::Seek`] — random-access byte storage using standard
//! embedded-io cursor semantics.

use embedded_io::Error as _;
use embedded_io::ErrorKind as IoErrorKind;

/// Block-storage error (no_std, `core::error::Error`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum StorageError {
    /// `offset + len` exceeds the backend capacity.
    OutOfBounds,
    /// SeekableStorage opened read-only rejected a write.
    NotWritable,
    /// Underlying I/O failed (file backend).
    Io(IoErrorKind),
    /// The requested operation is not part of the addressed store plane's
    /// model (e.g. a filesystem `FileRead` against a block plane, or a block
    /// `Read` against a filesystem plane). Distinct from [`Self::NotWritable`],
    /// which is a *policy* rejection of a write the plane could otherwise model.
    Unsupported,
}

impl core::fmt::Display for StorageError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::OutOfBounds => write!(f, "backend access out of bounds"),
            Self::NotWritable => write!(f, "backend is read-only"),
            Self::Io(kind) => write!(f, "backend I/O error: {kind:?}"),
            Self::Unsupported => write!(f, "operation not supported by this store plane"),
        }
    }
}

impl core::error::Error for StorageError {}

impl From<super::fs_storage::FsError> for StorageError {
    fn from(e: super::fs_storage::FsError) -> Self {
        match e {
            super::fs_storage::FsError::NotFound | super::fs_storage::FsError::OutOfBounds => {
                Self::OutOfBounds
            }
            super::fs_storage::FsError::NotWritable => Self::NotWritable,
            super::fs_storage::FsError::Io(kind) => Self::Io(kind),
        }
    }
}

/// Stack chunk size for the default `fill_at` loops ([`SeekableStorage`] and
/// [`WritableFlatData`]). One sector (512 B): safe for every backend's
/// alignment (SD blocks, 512e sectors) and small enough for an MCU stack —
/// pushing `Fill` down to the seam is precisely so a whole-disc FORMAT never
/// needs a large buffer. Backends with a cheaper primitive override `fill_at`
/// (`RamBackend` uses `memset`; the std file backend uses a larger chunk to
/// amortize syscalls).
const FILL_CHUNK: usize = 512;

/// Random-access seekable storage backend.
///
/// Supertraits: [`embedded_io::Read`] + [`embedded_io::Write`] +
/// [`embedded_io::Seek`] — random-access byte storage using standard
/// embedded-io cursor semantics. Extension methods: [`Self::capacity`]
/// and [`Self::sync`] (SYNCHRONIZE CACHE needs persistence beyond `flush`).
///
/// Not suited to sequential/append-only media (tape, CD-R) — those need
/// separate storage abstractions. No `Send` supertrait — single-threaded
/// targets never cross threads; call sites that need `Send` add their own
/// bound.
pub trait SeekableStorage: embedded_io::Read + embedded_io::Write + embedded_io::Seek {
    /// Backing store size in bytes (64-bit).
    ///
    /// Needed by READ CAPACITY; embedded-io has no size query.
    fn capacity(&self) -> u64;

    /// Persist all pending writes to backing store (disk: flush + fsync).
    ///
    /// `Write::flush` only reaches the OS page cache; `sync()` calls
    /// through to the platform fsync. RAM backends are no-op.
    fn sync(&mut self) -> Result<(), Self::Error>;

    /// Fill `len` bytes at `off` with `byte` (random access).
    ///
    /// Default: loop `write_all` over a 512-byte stack chunk — no
    /// `alloc`. Backends with a cheaper primitive override: `RamBackend` uses
    /// `memset`; the std file backend uses a larger chunk to amortize syscalls.
    ///
    /// This is the raw cursor-level primitive: it does **not** bounds-check
    /// against [`Self::capacity`]. The [`WritableFlatData`] blanket checks
    /// (returning [`StorageError::OutOfBounds`]) before delegating, so
    /// implementations that touch fixed memory should still re-check
    /// defensively for direct callers.
    fn fill_at(&mut self, mut off: u64, mut len: u64, byte: u8) -> Result<(), Self::Error> {
        let chunk = [byte; FILL_CHUNK];
        while len > 0 {
            let n = core::cmp::min(len, FILL_CHUNK as u64) as usize;
            self.seek(embedded_io::SeekFrom::Start(off))?;
            self.write_all(&chunk[..n])?;
            off += n as u64;
            len -= n as u64;
        }
        Ok(())
    }
}

/// Read-only disc data plane: offset-addressed byte source (① in the
/// capability ladder).
///
/// This is the media-layer seam — deliberately NOT [`SeekableStorage`]:
/// the error type is fixed ([`StorageError`], no `Self::Error`
/// projection) so `&mut dyn FlatData` is object-safe without associated
/// type bindings, and addressing is explicit-offset rather than
/// cursor-based (the cursor becomes a private detail of each impl, not a
/// cross-layer contract).
///
/// Implement this directly for generated/streamed sources (live ISO9660,
/// compressed images). Random-access block backends get it for free via
/// the blanket impl below.
pub trait FlatData {
    /// Read `buf.len()` bytes starting at `off`.
    ///
    /// Implementations must bounds-check: `off + buf.len() > capacity()`
    /// is [`StorageError::OutOfBounds`] (do NOT rely on seek
    /// truncation / short reads).
    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> Result<(), StorageError>;

    /// Backing size in bytes (geometry derivation).
    fn capacity(&self) -> u64;
}

/// Writable disc data plane (② in the capability ladder): [`FlatData`]
/// plus offset-addressed write and flush.
///
/// Object-safe by construction (fixed error type) — this is what the
/// random-writable media slot erases to. Block backends get it via the
/// blanket impl; implement it directly only for exotic writable planes.
pub trait WritableFlatData: FlatData {
    /// Write `buf.len()` bytes at `off`. Same bounds contract as
    /// [`FlatData::read_at`].
    ///
    /// Convention: reject *policy* read-only states with
    /// [`StorageError::NotWritable`] — never a bare I/O error — so
    /// devices can surface DATA PROTECT instead of WRITE FAULT.
    fn write_at(&mut self, off: u64, buf: &[u8]) -> Result<(), StorageError>;

    /// Persist pending writes beyond page cache (`fsync` semantics).
    fn sync(&mut self) -> Result<(), StorageError>;

    /// Fill `len` bytes at `off` with `byte`.
    ///
    /// Default: bounds-check against [`FlatData::capacity`] (rejecting an
    /// `off + len` overflow and a past-capacity range with
    /// [`StorageError::OutOfBounds`]) then loop [`Self::write_at`] over a
    /// 512-byte stack chunk — no `alloc`. Backends reached through
    /// the [`SeekableStorage`] blanket override via [`SeekableStorage::fill_at`]
    /// (e.g. RAM `memset`); direct implementations may override too.
    fn fill_at(&mut self, mut off: u64, mut len: u64, byte: u8) -> Result<(), StorageError> {
        let end = off.checked_add(len).ok_or(StorageError::OutOfBounds)?;
        if end > self.capacity() {
            return Err(StorageError::OutOfBounds);
        }
        let chunk = [byte; FILL_CHUNK];
        while len > 0 {
            let n = core::cmp::min(len, FILL_CHUNK as u64) as usize;
            self.write_at(off, &chunk[..n])?;
            off += n as u64;
            len -= n as u64;
        }
        Ok(())
    }
}

// Blanket lift: every block backend speaks both disc planes for free.
// (Only ONE blanket per rung keyed on SeekableStorage — and NO bare
// `FlatData for &mut T` forwarding blanket anywhere: pairing it with
// these would hit E0119, since a downstream `SeekableStorage for &mut _`
// impl could make them overlap. Runtime erasure therefore goes through
// the dedicated newtype refs below.)
impl<B: SeekableStorage + ?Sized> FlatData for B {
    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> Result<(), StorageError> {
        let end = off
            .checked_add(buf.len() as u64)
            .ok_or(StorageError::OutOfBounds)?;
        if end > SeekableStorage::capacity(self) {
            return Err(StorageError::OutOfBounds);
        }
        self.seek(embedded_io::SeekFrom::Start(off))
            .map_err(|e| StorageError::Io(e.kind()))?;
        self.read_exact(buf).map_err(|e| match e {
            embedded_io::ReadExactError::UnexpectedEof => StorageError::OutOfBounds,
            embedded_io::ReadExactError::Other(e) => StorageError::Io(e.kind()),
        })
    }

    fn capacity(&self) -> u64 {
        SeekableStorage::capacity(self)
    }
}

impl<B: SeekableStorage + ?Sized> WritableFlatData for B {
    fn write_at(&mut self, off: u64, buf: &[u8]) -> Result<(), StorageError> {
        let end = off
            .checked_add(buf.len() as u64)
            .ok_or(StorageError::OutOfBounds)?;
        if end > SeekableStorage::capacity(self) {
            return Err(StorageError::OutOfBounds);
        }
        self.seek(embedded_io::SeekFrom::Start(off))
            .map_err(|e| StorageError::Io(e.kind()))?;
        self.write_all(buf).map_err(map_policy_err)
    }

    fn sync(&mut self) -> Result<(), StorageError> {
        SeekableStorage::sync(self).map_err(map_policy_err)
    }

    fn fill_at(&mut self, off: u64, len: u64, byte: u8) -> Result<(), StorageError> {
        // Bounds first, so a past-capacity fill is `OutOfBounds` and never an
        // implicit file growth; then delegate to the backend's fill.
        let end = off.checked_add(len).ok_or(StorageError::OutOfBounds)?;
        if end > SeekableStorage::capacity(self) {
            return Err(StorageError::OutOfBounds);
        }
        SeekableStorage::fill_at(self, off, len, byte).map_err(map_policy_err)
    }
}

/// Error mapping for the write path of the [`SeekableStorage`] blanket.
///
/// Convention: a backend that refuses writes as *policy*
/// reports `ErrorKind::PermissionDenied`, which lands here as
/// [`StorageError::NotWritable`] (→ SCSI DATA PROTECT). Any other
/// kind is a plain I/O failure. Third-party backends should follow the
/// same convention for their read-only states.
fn map_policy_err<E: embedded_io::Error>(err: E) -> StorageError {
    if err.kind() == IoErrorKind::PermissionDenied {
        StorageError::NotWritable
    } else {
        StorageError::Io(err.kind())
    }
}

/// Erased read-only plane: what the media slot actually stores.
///
/// A newtype (rather than bare `&mut dyn FlatData`) keeps coherence
/// clean against the [`SeekableStorage`] blanket above, and gives the slot
/// a concrete `FlatData` implementor without any reference-forwarding
/// blanket.
pub struct FlatRef<'a>(pub(crate) &'a mut dyn FlatData);

impl core::fmt::Debug for FlatRef<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The erased inner type is not nameable; summarize by geometry.
        f.debug_struct("FlatRef")
            .field("capacity", &self.0.capacity())
            .finish()
    }
}

impl<'a> FlatRef<'a> {
    /// Erase any read-only source into a slot-usable plane reference.
    pub fn new<D: FlatData>(data: &'a mut D) -> Self {
        Self(data)
    }
}

impl FlatData for FlatRef<'_> {
    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> Result<(), StorageError> {
        self.0.read_at(off, buf)
    }

    fn capacity(&self) -> u64 {
        self.0.capacity()
    }
}

/// Erased writable plane (media slot side).
pub struct RwRef<'a>(pub(crate) &'a mut dyn WritableFlatData);

impl core::fmt::Debug for RwRef<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The erased inner type is not nameable; summarize by geometry.
        f.debug_struct("RwRef")
            .field("capacity", &self.0.capacity())
            .finish()
    }
}

impl<'a> RwRef<'a> {
    /// Erase any writable backend into a slot-usable plane reference.
    pub fn new<D: WritableFlatData>(data: &'a mut D) -> Self {
        Self(data)
    }
}

impl FlatData for RwRef<'_> {
    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> Result<(), StorageError> {
        self.0.read_at(off, buf)
    }

    fn capacity(&self) -> u64 {
        self.0.capacity()
    }
}

impl WritableFlatData for RwRef<'_> {
    fn write_at(&mut self, off: u64, buf: &[u8]) -> Result<(), StorageError> {
        self.0.write_at(off, buf)
    }

    fn sync(&mut self) -> Result<(), StorageError> {
        self.0.sync()
    }

    fn fill_at(&mut self, off: u64, len: u64, byte: u8) -> Result<(), StorageError> {
        self.0.fill_at(off, len, byte)
    }
}

/// RAM backend. Wraps a caller-provided `&mut [u8]` and implements
/// `embedded_io::Read + Write + Seek` + [`SeekableStorage`].
///
/// `embedded_io` does not provide a combined `Read+Write+Seek` impl for
/// bare `&mut [u8]`, so this struct adds cursor state.
#[derive(Debug)]
pub struct RamBackend<'a> {
    data: &'a mut [u8],
    pos: u64,
}

impl<'a> RamBackend<'a> {
    pub fn new(data: &'a mut [u8]) -> Self {
        Self { data, pos: 0 }
    }
}

impl embedded_io::ErrorType for RamBackend<'_> {
    type Error = embedded_io::ErrorKind;
}

impl embedded_io::Read for RamBackend<'_> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        let start = self.pos as usize;
        let available = self.data.len().saturating_sub(start);
        let n = buf.len().min(available);
        buf[..n].copy_from_slice(&self.data[start..start + n]);
        self.pos += n as u64;
        Ok(n)
    }
}

impl embedded_io::Write for RamBackend<'_> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        let start = self.pos as usize;
        let available = self.data.len().saturating_sub(start);
        let n = buf.len().min(available);
        self.data[start..start + n].copy_from_slice(&buf[..n]);
        self.pos += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl embedded_io::Seek for RamBackend<'_> {
    fn seek(&mut self, pos: embedded_io::SeekFrom) -> Result<u64, Self::Error> {
        let new_pos = match pos {
            embedded_io::SeekFrom::Start(off) => off,
            embedded_io::SeekFrom::Current(off) => {
                if off >= 0 {
                    self.pos.saturating_add(off as u64)
                } else {
                    self.pos.saturating_sub((-off) as u64)
                }
            }
            embedded_io::SeekFrom::End(off) => {
                let end = self.data.len() as u64;
                if off >= 0 {
                    end.saturating_add(off as u64)
                } else {
                    end.saturating_sub((-off) as u64)
                }
            }
        };
        self.pos = new_pos.min(self.data.len() as u64);
        Ok(self.pos)
    }
}

impl SeekableStorage for RamBackend<'_> {
    fn capacity(&self) -> u64 {
        self.data.len() as u64
    }

    fn sync(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    /// `memset` — no chunk buffer, no loop. The [`WritableFlatData`] blanket
    /// bounds-checks before delegating; re-check defensively for direct
    /// callers (embedded-io has no `OutOfBounds` kind, so `Other`).
    fn fill_at(&mut self, off: u64, len: u64, byte: u8) -> Result<(), Self::Error> {
        let start = usize::try_from(off).map_err(|_| embedded_io::ErrorKind::Other)?;
        let len = usize::try_from(len).map_err(|_| embedded_io::ErrorKind::Other)?;
        let end = start
            .checked_add(len)
            .filter(|&e| e <= self.data.len())
            .ok_or(embedded_io::ErrorKind::Other)?;
        self.data[start..end].fill(byte);
        Ok(())
    }
}

/// All-zero backend. Models an unbounded all-zero byte plane truncated to a
/// caller-supplied capacity and implements `embedded_io::Read + Write + Seek`
/// + [`SeekableStorage`].
///
/// Useful as a synthetic disc/block plane (e.g. a scratch device or a
/// placeholder LUN) with no resident storage: every read yields `0x00`, every
/// write is discarded, and only the cursor plus the configured capacity are
/// kept. Bounds are enforced exactly like [`RamBackend`]: the
/// [`FlatData`]/[`WritableFlatData`] blankets reject `off + len` overflow and
/// past-capacity ranges with [`StorageError::OutOfBounds`].
#[derive(Debug)]
pub struct ZeroBackend {
    capacity: u64,
    pos: u64,
}

impl ZeroBackend {
    /// Create a new all-zero backend with the given capacity in bytes.
    pub const fn new(capacity: u64) -> Self {
        Self { capacity, pos: 0 }
    }
}

impl embedded_io::ErrorType for ZeroBackend {
    type Error = embedded_io::ErrorKind;
}

impl embedded_io::Read for ZeroBackend {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        let available = self.capacity.saturating_sub(self.pos);
        let n = (buf.len() as u64).min(available) as usize;
        buf[..n].fill(0);
        self.pos += n as u64;
        Ok(n)
    }
}

impl embedded_io::Write for ZeroBackend {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        // Accept (and discard) as many bytes as remain before capacity so the
        // short-write arithmetic matches `RamBackend`; nothing is stored.
        let available = self.capacity.saturating_sub(self.pos);
        let n = (buf.len() as u64).min(available) as usize;
        self.pos += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl embedded_io::Seek for ZeroBackend {
    fn seek(&mut self, pos: embedded_io::SeekFrom) -> Result<u64, Self::Error> {
        let new_pos = match pos {
            embedded_io::SeekFrom::Start(off) => off,
            embedded_io::SeekFrom::Current(off) => {
                if off >= 0 {
                    self.pos.saturating_add(off as u64)
                } else {
                    self.pos.saturating_sub((-off) as u64)
                }
            }
            embedded_io::SeekFrom::End(off) => {
                let end = self.capacity;
                if off >= 0 {
                    end.saturating_add(off as u64)
                } else {
                    end.saturating_sub((-off) as u64)
                }
            }
        };
        self.pos = new_pos.min(self.capacity);
        Ok(self.pos)
    }
}

impl SeekableStorage for ZeroBackend {
    fn capacity(&self) -> u64 {
        self.capacity
    }

    fn sync(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    /// All writes are discarded, so filling with zero is a no-op and any other
    /// byte has no effect. The [`WritableFlatData`] blanket bounds-checks
    /// before delegating; re-check defensively for direct callers (embedded-io
    /// has no `OutOfBounds` kind, so `Other`).
    fn fill_at(&mut self, off: u64, len: u64, _byte: u8) -> Result<(), Self::Error> {
        off.checked_add(len)
            .filter(|&end| end <= self.capacity)
            .ok_or(embedded_io::ErrorKind::Other)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ram_roundtrip() {
        let mut ram = [0u8; 512];
        let mut b = RamBackend::new(&mut ram);
        let mut pattern = [0u8; 512];
        for (i, byte) in pattern.iter_mut().enumerate() {
            *byte = (i & 0xFF) as u8;
        }
        use embedded_io::Write;
        embedded_io::Seek::seek(&mut b, embedded_io::SeekFrom::Start(0)).unwrap();
        b.write_all(&pattern).unwrap();
        let mut out = [0u8; 512];
        embedded_io::Seek::seek(&mut b, embedded_io::SeekFrom::Start(0)).unwrap();
        use embedded_io::Read;
        b.read_exact(&mut out).unwrap();
        assert_eq!(out, pattern);
        assert_eq!(SeekableStorage::capacity(&b), 512);
    }

    #[test]
    fn ram_offset_read() {
        let mut ram = [0u8; 1024];
        let mut b = RamBackend::new(&mut ram);
        use embedded_io::Write;
        embedded_io::Seek::seek(&mut b, embedded_io::SeekFrom::Start(100)).unwrap();
        b.write_all(&[1u8, 2, 3, 4]).unwrap();
        let mut out = [0u8; 4];
        embedded_io::Seek::seek(&mut b, embedded_io::SeekFrom::Start(100)).unwrap();
        use embedded_io::Read;
        b.read_exact(&mut out).unwrap();
        assert_eq!(out, [1, 2, 3, 4]);
    }

    #[test]
    fn ram_sync_is_noop() {
        let mut ram = [0u8; 8];
        let mut b = RamBackend::new(&mut ram);
        assert_eq!(SeekableStorage::sync(&mut b), Ok(()));
    }

    #[test]
    fn empty_ram() {
        let mut ram: [u8; 0] = [];
        let b = RamBackend::new(&mut ram);
        assert_eq!(SeekableStorage::capacity(&b), 0);
    }

    #[test]
    fn ram_fill_at_is_memset() {
        let mut ram = [0xFFu8; 64];
        let mut b = RamBackend::new(&mut ram);
        // Raw `SeekableStorage` primitive (no bounds check).
        SeekableStorage::fill_at(&mut b, 8, 16, 0).unwrap();
        assert!(ram[..8].iter().all(|&x| x == 0xFF));
        assert!(ram[8..24].iter().all(|&x| x == 0));
        assert!(ram[24..].iter().all(|&x| x == 0xFF));
    }

    #[test]
    fn fill_at_via_writable_flat_data_bounds_checked() {
        let mut ram = [0u8; 64];
        {
            let mut b = RamBackend::new(&mut ram);
            // In-bounds: blanket → `SeekableStorage::fill_at` → RAM `memset`.
            assert_eq!(WritableFlatData::fill_at(&mut b, 0, 64, 0x5A), Ok(()));
            // Past capacity → OutOfBounds (never an implicit grow).
            assert_eq!(
                WritableFlatData::fill_at(&mut b, 60, 8, 0),
                Err(StorageError::OutOfBounds)
            );
            // `off + len` overflow → OutOfBounds.
            assert_eq!(
                WritableFlatData::fill_at(&mut b, u64::MAX, 2, 0),
                Err(StorageError::OutOfBounds)
            );
        }
        assert!(ram.iter().all(|&x| x == 0x5A));
    }

    #[test]
    fn writable_flat_data_default_fill_loops() {
        // A *direct* impl (not reached through `SeekableStorage`) exercises the
        // default `fill_at` loop, which chunks over `write_at` — here spanning
        // more than one 512-byte `FILL_CHUNK`.
        struct Mem([u8; 1500]);
        impl FlatData for Mem {
            fn read_at(&mut self, off: u64, buf: &mut [u8]) -> Result<(), StorageError> {
                let s = off as usize;
                buf.copy_from_slice(&self.0[s..s + buf.len()]);
                Ok(())
            }
            fn capacity(&self) -> u64 {
                self.0.len() as u64
            }
        }
        impl WritableFlatData for Mem {
            fn write_at(&mut self, off: u64, buf: &[u8]) -> Result<(), StorageError> {
                let s = off as usize;
                self.0[s..s + buf.len()].copy_from_slice(buf);
                Ok(())
            }
            fn sync(&mut self) -> Result<(), StorageError> {
                Ok(())
            }
        }

        let mut m = Mem([0u8; 1500]);
        assert_eq!(m.fill_at(0, 1500, 0x7E), Ok(())); // 512 + 512 + 476
        assert!(m.0.iter().all(|&x| x == 0x7E));
        assert_eq!(m.fill_at(1499, 2, 0), Err(StorageError::OutOfBounds));
        assert_eq!(m.fill_at(u64::MAX, 2, 0), Err(StorageError::OutOfBounds));
    }

    #[test]
    fn zero_read_returns_zeros() {
        let mut b = ZeroBackend::new(512);
        let mut out = [0xAAu8; 16];
        embedded_io::Seek::seek(&mut b, embedded_io::SeekFrom::Start(200)).unwrap();
        use embedded_io::Read;
        b.read_exact(&mut out).unwrap();
        assert!(out.iter().all(|&x| x == 0));
        assert_eq!(SeekableStorage::capacity(&b), 512);
        assert_eq!(SeekableStorage::sync(&mut b), Ok(()));
    }

    #[test]
    fn zero_capacity_enforced() {
        let mut b = ZeroBackend::new(64);
        let mut out = [0u8; 8];
        // In-bounds read fills zeros.
        assert_eq!(FlatData::read_at(&mut b, 0, &mut out), Ok(()));
        assert!(out.iter().all(|&x| x == 0));
        // Past capacity and `off + len` overflow both reject.
        assert_eq!(
            FlatData::read_at(&mut b, 60, &mut out),
            Err(StorageError::OutOfBounds)
        );
        assert_eq!(
            FlatData::read_at(&mut b, u64::MAX, &mut out),
            Err(StorageError::OutOfBounds)
        );
        assert_eq!(
            WritableFlatData::write_at(&mut b, 60, &[0u8; 8]),
            Err(StorageError::OutOfBounds)
        );
        assert_eq!(
            WritableFlatData::write_at(&mut b, u64::MAX, &[0u8; 2]),
            Err(StorageError::OutOfBounds)
        );
    }

    #[test]
    fn zero_writes_are_discarded() {
        let mut b = ZeroBackend::new(512);
        // Accepted in-bounds, but nothing is retained.
        assert_eq!(
            WritableFlatData::write_at(&mut b, 10, &[0xFFu8; 32]),
            Ok(())
        );
        assert_eq!(WritableFlatData::sync(&mut b), Ok(()));
        let mut out = [0xAAu8; 32];
        assert_eq!(FlatData::read_at(&mut b, 10, &mut out), Ok(()));
        assert!(out.iter().all(|&x| x == 0));
    }

    #[test]
    fn zero_fill_at_is_discarded_and_bounds_checked() {
        let mut b = ZeroBackend::new(64);
        // In-bounds fill (any byte) is accepted and discarded.
        assert_eq!(WritableFlatData::fill_at(&mut b, 0, 64, 0x5A), Ok(()));
        // Past capacity and `off + len` overflow both reject.
        assert_eq!(
            WritableFlatData::fill_at(&mut b, 60, 8, 0),
            Err(StorageError::OutOfBounds)
        );
        assert_eq!(
            WritableFlatData::fill_at(&mut b, u64::MAX, 2, 0),
            Err(StorageError::OutOfBounds)
        );
        let mut out = [0xAAu8; 64];
        assert_eq!(FlatData::read_at(&mut b, 0, &mut out), Ok(()));
        assert!(out.iter().all(|&x| x == 0));
    }

    #[test]
    fn empty_zero() {
        let b = ZeroBackend::new(0);
        assert_eq!(SeekableStorage::capacity(&b), 0);
    }
}
