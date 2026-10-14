//! Two-store operation vocabulary (`__ASYNC_SEP_PLAN.md` §1.1).
//!
//! A [`StoreOp`] is a single unit of storage work addressed either **by byte
//! offset** on a block plane (`Read`/`Write`/`Fill`) or **by path** on a
//! filesystem plane (`FileRead`/`FileWrite`/`FileRemove`), plus a plane-level
//! `Sync`. [`StorePlane`] binds one of the three plane kinds to the concrete
//! seam and executes the op.
//!
//! Object-safe by construction: the plane erases to `&mut dyn` over the
//! existing seams, so a driver can hold a heterogeneous `[StorePlane]` without
//! naming the backend type.

use crate::fs_plane::FsPlane;
use crate::seekable_storage::{FlatData, StorageError, WritableFlatData};

/// One unit of storage work.
#[derive(Debug)]
pub enum StoreOp<'a> {
    // ── Block: byte-addressed ───────────────────────────────────────
    /// Read `buf.len()` bytes at byte offset `off`.
    Read { off: u64, buf: &'a mut [u8] },
    /// Write `buf` at byte offset `off`.
    Write { off: u64, buf: &'a [u8] },
    /// Fill `len` bytes at byte offset `off` with `byte`.
    Fill { off: u64, len: u64, byte: u8 },

    // ── FS: path-addressed ──────────────────────────────────────────
    /// Read `buf.len()` bytes at byte offset `off` of the file at `path`.
    FileRead {
        path: &'a str,
        off: u64,
        buf: &'a mut [u8],
    },
    /// Write `buf` at byte offset `off` of the file at `path`.
    FileWrite {
        path: &'a str,
        off: u64,
        buf: &'a [u8],
    },
    /// Remove the file at `path`.
    FileRemove { path: &'a str },

    // ── Plane-level (Block/FS) ──────────────────────────────────────
    /// Persist pending writes for the addressed plane.
    Sync,
}

/// A store plane: a block plane (read-only or read-write) or a filesystem
/// plane, erased so drivers can mix them.
pub enum StorePlane<'a> {
    /// Read-only byte plane.
    BlockRo(&'a mut dyn FlatData),
    /// Writable byte plane.
    BlockRw(&'a mut dyn WritableFlatData),
    /// Path-addressed filesystem plane.
    Fs(&'a mut dyn FsPlane),
}

impl StorePlane<'_> {
    /// Execute `op` on this plane.
    ///
    /// A block op on an FS plane (or an FS op on a block plane) is a model
    /// mismatch → [`StorageError::Unsupported`]. A `Write`/`Fill` on
    /// [`Self::BlockRo`] is a policy rejection → [`StorageError::NotWritable`].
    pub fn do_op(&mut self, op: StoreOp<'_>) -> Result<(), StorageError> {
        match self {
            // ── Read-only block plane ───────────────────────────────────
            StorePlane::BlockRo(p) => match op {
                StoreOp::Read { off, buf } => p.read_at(off, buf),
                StoreOp::Write { .. } | StoreOp::Fill { .. } => Err(StorageError::NotWritable),
                StoreOp::FileRead { .. }
                | StoreOp::FileWrite { .. }
                | StoreOp::FileRemove { .. } => Err(StorageError::Unsupported),
                StoreOp::Sync => Ok(()),
            },

            // ── Writable block plane ────────────────────────────────────
            StorePlane::BlockRw(p) => match op {
                StoreOp::Read { off, buf } => p.read_at(off, buf),
                StoreOp::Write { off, buf } => p.write_at(off, buf),
                StoreOp::Fill { off, len, byte } => {
                    // Reject `off + len` wrapping before touching the backend;
                    // a raw `WritableFlatData` impl need not bounds-check.
                    let _end = off.checked_add(len).ok_or(StorageError::OutOfBounds)?;
                    // Stack chunk buffer: a whole-disc Fill must not require
                    // `alloc`. `write_at` re-checks against capacity per chunk.
                    let chunk = [byte; 4096];
                    let mut pos = off;
                    let mut remaining = len;
                    while remaining > 0 {
                        let n = core::cmp::min(remaining, chunk.len() as u64) as usize;
                        p.write_at(pos, &chunk[..n])?;
                        pos += n as u64;
                        remaining -= n as u64;
                    }
                    Ok(())
                }
                StoreOp::FileRead { .. }
                | StoreOp::FileWrite { .. }
                | StoreOp::FileRemove { .. } => Err(StorageError::Unsupported),
                StoreOp::Sync => p.sync(),
            },

            // ── Filesystem plane ────────────────────────────────────────
            StorePlane::Fs(p) => match op {
                StoreOp::FileRead { path, off, buf } => {
                    p.read(path, off, buf).map_err(StorageError::from)
                }
                StoreOp::FileWrite { path, off, buf } => {
                    p.write(path, off, buf).map_err(StorageError::from)
                }
                StoreOp::FileRemove { path } => p.remove(path).map_err(StorageError::from),
                StoreOp::Read { .. } | StoreOp::Write { .. } | StoreOp::Fill { .. } => {
                    Err(StorageError::Unsupported)
                }
                StoreOp::Sync => p.sync().map_err(StorageError::from),
            },
        }
    }

    /// Persist the plane (plane-level [`StoreOp::Sync`]).
    pub fn sync(&mut self) -> Result<(), StorageError> {
        match self {
            // Read-only: nothing to persist.
            StorePlane::BlockRo(_) => Ok(()),
            StorePlane::BlockRw(p) => p.sync(),
            StorePlane::Fs(p) => p.sync().map_err(StorageError::from),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs_plane::FsPlane;
    use crate::fs_storage::{DirEntry, FsError};
    use crate::seekable_storage::RamBackend;

    /// Minimal in-test [`FsPlane`] backing one small in-memory file plus call
    /// counters, so `StorePlane::Fs` dispatch can be observed without pulling
    /// in `FsPlaneAdapter` (which owns its own LRU and lives elsewhere).
    struct FakeFs {
        data: [u8; 32],
        len: usize,
        removed: bool,
        sync_calls: usize,
        read_err: Option<FsError>,
    }

    impl FakeFs {
        fn new() -> Self {
            Self {
                data: [0; 32],
                len: 0,
                removed: false,
                sync_calls: 0,
                read_err: None,
            }
        }
    }

    impl FsPlane for FakeFs {
        fn read_dir(&mut self, _path: &str, _out: &mut [DirEntry]) -> Result<usize, FsError> {
            Ok(0)
        }

        fn read(&mut self, _path: &str, off: u64, buf: &mut [u8]) -> Result<(), FsError> {
            if let Some(e) = self.read_err {
                return Err(e);
            }
            let start = off as usize;
            let end = start.checked_add(buf.len()).ok_or(FsError::OutOfBounds)?;
            if end > self.len {
                return Err(FsError::OutOfBounds);
            }
            buf.copy_from_slice(&self.data[start..end]);
            Ok(())
        }

        fn write(&mut self, _path: &str, off: u64, buf: &[u8]) -> Result<(), FsError> {
            let start = off as usize;
            let end = start.checked_add(buf.len()).ok_or(FsError::OutOfBounds)?;
            if end > self.data.len() {
                return Err(FsError::OutOfBounds);
            }
            self.data[start..end].copy_from_slice(buf);
            if end > self.len {
                self.len = end;
            }
            Ok(())
        }

        fn remove(&mut self, _path: &str) -> Result<(), FsError> {
            self.removed = true;
            Ok(())
        }

        fn sync(&mut self) -> Result<(), FsError> {
            self.sync_calls += 1;
            Ok(())
        }
    }

    #[test]
    fn block_rw_read_write_fill_and_sync() {
        // Large enough that a `Fill` spans more than one 4096-byte chunk.
        let mut ram = [0u8; 5000];
        let mut backend = RamBackend::new(&mut ram);
        let mut plane = StorePlane::BlockRw(&mut backend);

        // Write / read roundtrip.
        let payload = [0xABu8; 8];
        plane
            .do_op(StoreOp::Write {
                off: 16,
                buf: &payload,
            })
            .unwrap();
        let mut out = [0u8; 8];
        plane
            .do_op(StoreOp::Read {
                off: 16,
                buf: &mut out,
            })
            .unwrap();
        assert_eq!(out, payload);

        // Fill (chunked: 4096 + 404) then read back.
        plane
            .do_op(StoreOp::Fill {
                off: 0,
                len: 4500,
                byte: 0x5A,
            })
            .unwrap();
        let mut check = [0u8; 4500];
        plane
            .do_op(StoreOp::Read {
                off: 0,
                buf: &mut check,
            })
            .unwrap();
        assert!(check.iter().all(|&b| b == 0x5A));
        // The write/read at off=16 was overwritten by the fill.
        assert_eq!(check[16], 0x5A);

        // Both sync spellings succeed.
        assert_eq!(plane.sync(), Ok(()));
        assert_eq!(plane.do_op(StoreOp::Sync), Ok(()));
    }

    #[test]
    fn fill_overflow_and_past_capacity() {
        let mut ram = [0u8; 16];
        let mut backend = RamBackend::new(&mut ram);
        let mut plane = StorePlane::BlockRw(&mut backend);

        // `off + len` wraps u64 → explicit overflow guard.
        assert_eq!(
            plane.do_op(StoreOp::Fill {
                off: u64::MAX,
                len: 2,
                byte: 0,
            }),
            Err(StorageError::OutOfBounds)
        );
        // In-range offset but past capacity → backend bounds check.
        assert_eq!(
            plane.do_op(StoreOp::Fill {
                off: 8,
                len: 100,
                byte: 0,
            }),
            Err(StorageError::OutOfBounds)
        );
    }

    #[test]
    fn block_ro_reads_and_rejects_writes() {
        let mut ram = [0u8; 64];
        for (i, b) in ram.iter_mut().enumerate() {
            *b = i as u8;
        }
        let mut backend = RamBackend::new(&mut ram);
        let mut plane = StorePlane::BlockRo(&mut backend);

        let mut out = [0u8; 4];
        plane
            .do_op(StoreOp::Read {
                off: 4,
                buf: &mut out,
            })
            .unwrap();
        assert_eq!(out, [4, 5, 6, 7]);

        // Policy rejection, not an I/O error.
        assert_eq!(
            plane.do_op(StoreOp::Write {
                off: 0,
                buf: &[1, 2, 3, 4],
            }),
            Err(StorageError::NotWritable)
        );
        assert_eq!(
            plane.do_op(StoreOp::Fill {
                off: 0,
                len: 4,
                byte: 0,
            }),
            Err(StorageError::NotWritable)
        );
    }

    #[test]
    fn sync_on_block_ro_is_ok() {
        let mut ram = [0u8; 8];
        let mut backend = RamBackend::new(&mut ram);
        let mut plane = StorePlane::BlockRo(&mut backend);

        assert_eq!(plane.sync(), Ok(()));
        assert_eq!(plane.do_op(StoreOp::Sync), Ok(()));
    }

    #[test]
    fn fs_dispatch_and_sync() {
        let mut fake = FakeFs::new();
        {
            let mut plane = StorePlane::Fs(&mut fake);

            let payload = [1u8, 2, 3, 4];
            plane
                .do_op(StoreOp::FileWrite {
                    path: "a",
                    off: 0,
                    buf: &payload,
                })
                .unwrap();

            let mut out = [0u8; 4];
            plane
                .do_op(StoreOp::FileRead {
                    path: "a",
                    off: 0,
                    buf: &mut out,
                })
                .unwrap();
            assert_eq!(out, payload);

            plane.do_op(StoreOp::FileRemove { path: "a" }).unwrap();

            // Plane-level sync (both spellings) reach the fake.
            assert_eq!(plane.sync(), Ok(()));
            assert_eq!(plane.do_op(StoreOp::Sync), Ok(()));
        }
        assert!(fake.removed);
        assert_eq!(fake.sync_calls, 2);
    }

    #[test]
    fn fs_error_maps_to_storage_error() {
        let mut fake = FakeFs::new();
        fake.read_err = Some(FsError::NotFound);
        let mut plane = StorePlane::Fs(&mut fake);

        let mut out = [0u8; 4];
        assert_eq!(
            plane.do_op(StoreOp::FileRead {
                path: "missing",
                off: 0,
                buf: &mut out,
            }),
            Err(StorageError::OutOfBounds)
        );
    }

    #[test]
    fn op_plane_mismatch_is_unsupported() {
        // FS op on a block plane.
        let mut ram = [0u8; 64];
        let mut backend = RamBackend::new(&mut ram);
        {
            let mut plane = StorePlane::BlockRw(&mut backend);
            let mut out = [0u8; 4];
            assert_eq!(
                plane.do_op(StoreOp::FileRead {
                    path: "x",
                    off: 0,
                    buf: &mut out,
                }),
                Err(StorageError::Unsupported)
            );
            assert_eq!(
                plane.do_op(StoreOp::FileWrite {
                    path: "x",
                    off: 0,
                    buf: &[0],
                }),
                Err(StorageError::Unsupported)
            );
            assert_eq!(
                plane.do_op(StoreOp::FileRemove { path: "x" }),
                Err(StorageError::Unsupported)
            );
        }

        // Block op on an FS plane.
        let mut fake = FakeFs::new();
        let mut plane = StorePlane::Fs(&mut fake);
        let mut out = [0u8; 4];
        assert_eq!(
            plane.do_op(StoreOp::Read {
                off: 0,
                buf: &mut out,
            }),
            Err(StorageError::Unsupported)
        );
        assert_eq!(
            plane.do_op(StoreOp::Write { off: 0, buf: &[0] }),
            Err(StorageError::Unsupported)
        );
        assert_eq!(
            plane.do_op(StoreOp::Fill {
                off: 0,
                len: 1,
                byte: 0,
            }),
            Err(StorageError::Unsupported)
        );
    }
}
