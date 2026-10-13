//! Live ISO9660 generation algorithms.
//!
//! Pure algorithms: **no storage, no FS, no alloc**. The device layer
//! (`CdLiveFsDevice`) scans the host directory with `FsStorage::read_dir`,
//! builds a `&[FileEntry]` slice, and calls [`compute_layout`] to get an
//! LBA layout.  During READ(10), the device calls [`gen_sector`] for
//! metadata LBAs and [`resolve`] for file-data LBAs.
//!
//! # ISO 9660 Layout
//!
//! The image carries **two directory trees** (ECMA-119 §6.8.1 / Joliet):
//! the PVD tree uses ISO-9660 Level 1 identifiers (8.3 uppercase, with the
//! `;1` file version), the SVD (Joliet) tree uses UCS-2BE names. Each tree
//! has its own Path Table and directory extents; both reference the same
//! file-data extents.
//!
//! ```text
//! LBA 0-15        System Area (zeros)
//! LBA 16          PVD (Primary Volume Descriptor)
//! LBA 17          SVD (Supplementary Volume Descriptor, Joliet UCS-2BE)
//! LBA 18          Volume Descriptor Set Terminator
//! LBA 19..        PVD Path Table L, then PVD Path Table M
//! then            PVD root directory, sub-directories (8.3 identifiers)
//! then            Joliet Path Table L, then Joliet Path Table M
//! then            Joliet root directory, sub-directories (UCS-2BE names)
//! then            File data (padded to 2048-byte sectors)
//! ```
//!
//! Every sub-directory becomes its own extent with ".", "..", child
//! directory and file records; each Path Table holds one record per
//! directory of its tree (both-endian numeric fields per table type).
//!
//! # Name limits
//!
//! - [`MAX_JOLIET_NAME_CHARS`] — Joliet identifier width (default 64
//!   UCS-2 chars, the ECMA-119 Annex J Level 1 limit). Longer names are
//!   truncated in the generated metadata; raise the constant to widen.
//! - [`MAX_PATH_LEN`] — maximum relative host path accepted by the live
//!   scanner (default 512 bytes); deeper paths fail the layout build.
//! - Host FS component names are bounded by `DirEntry.name`
//!   (`String<256>`, the `FsStorage` seam).

use core::cmp::Ordering;
use heapless::{String, Vec};

use snowscsi_common::fs_storage::{DirEntry, FsError, FsStorage, OpenOptions};
use snowscsi_common::seekable_storage::{FlatData, StorageError};

/// Sector size for ISO 9660.
pub const SECTOR_SIZE: u32 = 2048;

/// System area sectors (LBA 0-15).
const SYSTEM_AREA_SECTORS: u32 = 16;

/// PVD is always at LBA 16.
const PVD_LBA: u32 = 16;

/// SVD (Joliet) is always at LBA 17.
const SVD_LBA: u32 = 17;

/// Terminator is always at LBA 18.
const TERMINATOR_LBA: u32 = 18;

/// Maximum number of files the layout can track.
pub const MAX_FILES: usize = 128;

/// Maximum number of directories (each `files` entry may be a directory,
/// plus the implicit root).
pub const MAX_DIRS: usize = MAX_FILES + 1;

/// Maximum label length (ASCII chars).
pub const MAX_LABEL_LEN: usize = 16;

/// Maximum length of a Joliet (UCS-2BE) file or directory identifier, in
/// characters.
///
/// ECMA-119 Annex J (Joliet) allows identifiers up to **64** UCS-2
/// characters — the Level 1 limit matching the `%/@` escape sequence we
/// emit. Identifiers longer than this are **truncated** in the generated
/// ISO9660 metadata (the host-side name is untouched). Raise this constant
/// (and rebuild) for wider names; all buffers, record sizes and `Vec`
/// capacities below are derived from it, so no other edit is required.
///
/// The related host-side limits — `DirEntry.name` (`String<256>`, the FS
/// seam) and [`MAX_PATH_LEN`] — sit above this value, so the Joliet
/// identifier width is the binding constraint.
pub const MAX_JOLIET_NAME_CHARS: usize = 64;

/// Byte length of a Joliet identifier (2 bytes per character).
pub const MAX_JOLIET_NAME_BYTES: usize = MAX_JOLIET_NAME_CHARS * 2;

/// Maximum relative path length (bytes) accepted by the live scanner.
///
/// Deeper paths fail to build the layout (`TooManyFiles`) rather than
/// silently truncating. The host `DirEntry.name` capacity (256 bytes)
/// bounds a single component; `MAX_PATH_LEN` bounds the whole relative
/// path.
pub const MAX_PATH_LEN: usize = 512;

/// Largest directory record: 33-byte header + identifier + pad-to-even.
const MAX_DIR_REC_LEN: usize = 33 + MAX_JOLIET_NAME_BYTES + 1;

/// Largest path-table record: 8-byte header + identifier + pad-to-even.
const MAX_PT_REC_LEN: usize = 8 + MAX_JOLIET_NAME_BYTES + 1;

/// Fixed recording date for directory records (7 bytes: year-1900, month,
/// day, hour, minute, second, GMT offset in 15-min units). The generator
/// has no clock, so a valid sentinel (1980-01-01 00:00:00 +0, the FAT
/// epoch) is recorded; all-zero dates display as garbage (e.g. 1899).
const FIXED_RECORDING_DATE: [u8; 7] = [80, 1, 1, 0, 0, 0, 0];

// ── Input types ─────────────────────────────────────────────────────

/// File tree entry provided by the device layer.
///
/// Paths are relative to the root (e.g. `"README.TXT"`, `"DOCS/MANUAL.PDF"`).
/// Directories must appear before their children.
#[derive(Debug, Clone)]
pub struct FileEntry {
    /// Relative path from root (e.g. `"README.TXT"`, `"SUB/FILE.BIN"`).
    pub path: String<MAX_PATH_LEN>,
    /// File size in bytes (0 for directories).
    pub size: u64,
    /// `true` if this entry is a directory.
    pub is_dir: bool,
}

// ── Output types ────────────────────────────────────────────────────

/// A directory in one of the two ISO9660 trees (one Path Table record).
#[derive(Debug, Clone)]
pub struct DirNode {
    /// Path table number (1-based; root = 1).
    pub number: u16,
    /// Parent directory's path table number (root's parent = itself, 1).
    pub parent: u16,
    /// Identifier bytes for this tree (ISO-9660 8.3 ASCII for the PVD
    /// tree, Joliet UCS-2BE for the SVD tree; "" for root).
    pub name: Vec<u8, MAX_JOLIET_NAME_BYTES>,
    /// LBA of this directory's extent.
    pub lba: u32,
    /// Sectors occupied by this directory's records.
    pub sectors: u32,
}

/// Per-file extent information within the layout.
#[derive(Debug, Clone)]
pub struct FileExtent {
    /// Index into the original `files` slice.
    pub file_index: usize,
    /// Starting LBA of the file data.
    pub lba: u32,
    /// Number of sectors occupied.
    pub sectors: u32,
    /// File size in bytes (may be less than `sectors * SECTOR_SIZE`).
    pub size: u64,
    /// PVD-tree identifier: ISO-9660 8.3 ASCII name **with** the ";1"
    /// file version (e.g. `README.TXT;1`), as recorded in the PVD tree.
    pub pvd_name: Vec<u8, MAX_JOLIET_NAME_BYTES>,
    /// PVD-tree parent directory's path table number.
    pub pvd_parent: u16,
    /// Joliet-tree identifier: UCS-2BE encoded file name (without ";1").
    pub name: Vec<u8, MAX_JOLIET_NAME_BYTES>,
    /// Joliet-tree parent directory's path table number.
    pub parent: u16,
}

/// One directory tree: its Path Table metadata and directory records.
#[derive(Debug)]
pub struct DirTree {
    /// LBA of the Type L path table.
    pub path_table_lba: u32,
    /// Sectors occupied by each path table (L and M have the same size).
    pub path_table_sectors: u32,
    /// Path table size in bytes (one table).
    pub path_table_size: u32,
    /// Root directory LBA.
    pub root_dir_lba: u32,
    /// Number of sectors for the root directory.
    pub root_dir_sectors: u32,
    /// Directories in path-table order (root first, breadth-first).
    pub dirs: Vec<DirNode, MAX_DIRS>,
}

/// Complete LBA layout for a live ISO9660 image.
#[derive(Debug)]
pub struct Layout {
    /// Volume label (ASCII, up to 16 chars).
    pub label: String<MAX_LABEL_LEN>,
    /// Volume metadata (PVD/SVD identifiers, dates).
    pub vol: VolumeMetadata,
    /// PVD directory tree (ISO-9660 8.3 identifiers).
    pub pvd: DirTree,
    /// SVD / Joliet directory tree (UCS-2BE identifiers).
    pub joliet: DirTree,
    /// File extents (one per non-directory FileEntry).
    pub extents: Vec<FileExtent, MAX_FILES>,
    /// LBA where the file data area begins (after all directories).
    pub first_file_lba: u32,
    /// Total number of sectors in the image.
    pub total: u32,
    /// Whether Joliet SVD is included (affects geometry).
    pub joliet_enabled: bool,
}

/// Volume metadata for PVD/SVD identifiers (ECMA-119 §8.4.4).
///
/// String fields are space-padded ASCII (ECMA-119 a-characters).
/// Lengths match the PVD byte ranges:
/// - `system_id`: 32 bytes (BP 9-40)
/// - `volume_set_id`: 128 bytes (BP 191-318)
/// - `publisher`: 128 bytes (BP 319-446)
/// - `data_preparer`: 128 bytes (BP 447-574)
/// - `application_id`: 128 bytes (BP 575-702)
#[derive(Debug, Clone)]
pub struct VolumeMetadata {
    pub system_id: String<32>,
    pub volume_set_id: String<128>,
    pub publisher: String<128>,
    pub data_preparer: String<128>,
    pub application_id: String<128>,
}

impl Default for VolumeMetadata {
    fn default() -> Self {
        Self {
            system_id: String::new(),
            volume_set_id: String::new(),
            publisher: String::new(),
            data_preparer: String::new(),
            application_id: String::new(),
        }
    }
}

/// ISO9660 generation options (typed newtype fields, structurally valid).
///
/// `IsoOptions` carries the configurable volume metadata and format
/// switches for `compute_layout_opts`.  Validation (length checks,
/// character set) happens at construction via `TryFrom<&str>`.
///
/// The `label` field is mandatory (non-empty after validation).
/// All other fields default to empty/sentinel values.
#[derive(Debug, Clone)]
pub struct IsoOptions {
    /// Volume label (mandatory, 1-16 ASCII chars).
    pub label: String<MAX_LABEL_LEN>,
    /// System identifier (ECMA-119 §8.4.4 BP 9-40, 32 bytes max).
    pub system_id: String<32>,
    /// Volume set identifier (BP 191-318, 128 bytes max).
    pub volume_set_id: String<128>,
    /// Publisher identifier (BP 319-446, 128 bytes max).
    pub publisher: String<128>,
    /// Data preparer identifier (BP 447-574, 128 bytes max).
    pub data_preparer: String<128>,
    /// Application identifier (BP 575-702, 128 bytes max).
    pub application_id: String<128>,
    /// Whether to include Joliet SVD (UCS-2BE tree).  Default: `true`.
    pub joliet: bool,
}

impl IsoOptions {
    /// Create options with a label and all other fields at defaults.
    /// Empty or invalid labels default to "SNOWSCSI".
    pub fn with_label(label: &str) -> Result<Self, IsoError> {
        let mut lbl = String::<MAX_LABEL_LEN>::new();
        for ch in label.chars().take(MAX_LABEL_LEN) {
            if ch.is_ascii() && !ch.is_control() {
                let _ = lbl.push(ch);
            }
        }
        if lbl.is_empty() {
            let _ = lbl.push_str("SNOWSCSI");
        }
        Ok(Self {
            label: lbl,
            system_id: String::new(),
            volume_set_id: String::new(),
            publisher: String::new(),
            data_preparer: String::new(),
            application_id: String::new(),
            joliet: true,
        })
    }
}

impl From<&IsoOptions> for VolumeMetadata {
    fn from(opts: &IsoOptions) -> Self {
        Self {
            system_id: opts.system_id.clone(),
            volume_set_id: opts.volume_set_id.clone(),
            publisher: opts.publisher.clone(),
            data_preparer: opts.data_preparer.clone(),
            application_id: opts.application_id.clone(),
        }
    }
}

// ── Public API ──────────────────────────────────────────────────────

/// Internal directory node during layout construction.
#[derive(Debug)]
struct DirReg {
    /// Registry index of the parent directory (0 = root's self reference).
    parent: u16,
    /// ISO-9660 Level 1 (8.3) identifier, ASCII ("" for root).
    pvd_name: Vec<u8, MAX_JOLIET_NAME_BYTES>,
    /// Joliet UCS-2BE identifier ("" for root).
    name: Vec<u8, MAX_JOLIET_NAME_BYTES>,
    /// Depth in the tree (root = 0).
    depth: u16,
}

/// ISO-9660 Level 1 allowed char → byte: `A-Z 0-9 _` kept (uppercased),
/// everything else mapped to `_` (ECMA-119 §7.4.3.1 d-characters).
fn map_pvd_char(ch: char) -> u8 {
    if ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_' {
        ch as u8
    } else if ch.is_ascii_lowercase() {
        ch.to_ascii_uppercase() as u8
    } else {
        b'_'
    }
}

/// Split an 8.3 identifier into `(base, ext, has_dot)` per ECMA-119 Level 1:
/// base ≤ 8 bytes, extension ≤ 3 bytes (from the last '.'). Dots inside the
/// base map to `_` (so "multi.dot.name" → "MULTI_DO.NAM").
fn pvd_83_parts(name: &str) -> (Vec<u8, 8>, Vec<u8, 3>, bool) {
    let (base, ext) = match name.rfind('.') {
        Some(i) => (&name[..i], Some(&name[i + 1..])),
        None => (name, None),
    };
    let mut b = Vec::new();
    for ch in base.chars() {
        if b.len() >= 8 {
            break;
        }
        let _ = b.push(map_pvd_char(ch));
    }
    let mut e = Vec::new();
    let mut has_dot = false;
    if let Some(ext) = ext {
        has_dot = true;
        for ch in ext.chars() {
            if e.len() >= 3 {
                break;
            }
            let _ = e.push(map_pvd_char(ch));
        }
    }
    (b, e, has_dot)
}

/// ISO-9660 Level 1 file identifier with the `;1` version: `BASE.EXT;1`.
/// Files without an extension still carry the separator (`NOEXT.;1`, the
/// genisoimage convention), so the '.' is always present.
fn to_pvd_file_name(name: &str) -> Vec<u8, MAX_JOLIET_NAME_BYTES> {
    let (base, ext, _) = pvd_83_parts(name);
    let mut out = Vec::new();
    let _ = out.extend_from_slice(&base);
    let _ = out.push(b'.');
    let _ = out.extend_from_slice(&ext);
    let _ = out.extend_from_slice(b";1");
    out
}

/// ISO-9660 Level 1 directory identifier: `BASE` or `BASE.EXT` (no version).
fn to_pvd_dir_name(name: &str) -> Vec<u8, MAX_JOLIET_NAME_BYTES> {
    let (base, ext, has_dot) = pvd_83_parts(name);
    let mut out = Vec::new();
    let _ = out.extend_from_slice(&base);
    if has_dot {
        let _ = out.push(b'.');
        let _ = out.extend_from_slice(&ext);
    }
    out
}

/// Number of path components in a relative path ("" → 0, "A/B" → 2).
fn path_depth(path: &str) -> u32 {
    path.split('/').filter(|s| !s.is_empty()).count() as u32
}

/// Last path component ("A/B.txt" → "B.txt", "" → "").
fn last_component(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or("")
}

/// Length of a directory record for a name of `name_len` bytes.
///
/// 33-byte header + identifier; a (00) padding byte is added **only when
/// the identifier length is even** so the record length stays even
/// (ECMA-119 §9.1.12: "present only if the number in the Length of the
/// File Identifier field is an even number").
fn record_len(name_len: usize) -> u64 {
    let l = name_len as u64;
    33 + l + if l.is_multiple_of(2) { 1 } else { 0 }
}

/// Compute the LBA layout for a set of files.
///
/// Files must be provided in DFS pre-order: a directory entry before its
/// children, children before the next sibling.  The label is truncated to
/// 16 ASCII characters.  The directory hierarchy is preserved: every
/// sub-directory gets its own extent and a Path Table record.
/// Path table order (ECMA-119 §6.9.1): ascending level, then parent
/// directory number, then identifier.  `use_pvd` selects the PVD 8.3
/// identifiers vs the Joliet UCS-2BE ones (each tree sorts independently).
/// Returns `(order, number_of)` — `order` is registry indices in path
/// table order, `number_of` maps registry index → path table number.
fn tree_order(
    regs: &[DirReg],
    use_pvd: bool,
) -> Result<(Vec<u16, MAX_DIRS>, [u16; MAX_DIRS]), IsoError> {
    let max_depth = regs.iter().map(|r| r.depth).max().unwrap_or(0);
    let mut order = Vec::<u16, MAX_DIRS>::new(); // registry indices
    let mut number_of = [0u16; MAX_DIRS]; // registry index → path table number
    for level in 0..=max_depth {
        let mut level_regs = Vec::<u16, MAX_DIRS>::new();
        for (i, r) in regs.iter().enumerate() {
            if r.depth == level {
                level_regs
                    .push(i as u16)
                    .map_err(|_| IsoError::TooManyFiles)?;
            }
        }
        // Insertion sort by (parent number, identifier).
        for i in 1..level_regs.len() {
            let mut j = i;
            while j > 0 {
                let a = level_regs[j - 1] as usize;
                let b = level_regs[j] as usize;
                let pa = number_of[regs[a].parent as usize];
                let pb = number_of[regs[b].parent as usize];
                let cmp = match pa.cmp(&pb) {
                    Ordering::Equal => {
                        let (na, nb) = if use_pvd {
                            (regs[a].pvd_name.as_slice(), regs[b].pvd_name.as_slice())
                        } else {
                            (regs[a].name.as_slice(), regs[b].name.as_slice())
                        };
                        na.cmp(nb)
                    }
                    other => other,
                };
                if cmp == Ordering::Greater {
                    level_regs.swap(j - 1, j);
                    j -= 1;
                } else {
                    break;
                }
            }
        }
        for &r in &level_regs {
            number_of[r as usize] = order.len() as u16 + 1;
            order.push(r).map_err(|_| IsoError::TooManyFiles)?;
        }
    }
    Ok((order, number_of))
}

/// PVD 8.3 collision disambiguation within one parent directory.
///
/// ISO-9660 identifiers are case-insensitive 8.3, so two host names like
/// `readme.txt` / `README.TXT` map to the same `README.TXT;1`.  Keep the
/// first natural name; for each later duplicate, truncate the base to 5
/// chars and append a 3-digit counter (genisoimage's `READM000` scheme).
fn disambiguate_pvd_83(regs: &mut [DirReg], extents: &mut [FileExtent], ext_parent_reg: &[u16]) {
    // Indexed iteration because children are looked up by parent index and
    // mutated in place.
    #[allow(clippy::needless_range_loop)]
    for p in 0..regs.len() {
        // Used identifiers among this parent's children (dirs + files
        // share the namespace of the containing directory record set).
        let mut used: Vec<Vec<u8, MAX_JOLIET_NAME_BYTES>, MAX_FILES> = Vec::new();
        #[allow(clippy::needless_range_loop)]
        for i in 0..regs.len() {
            if i != p && regs[i].parent == p as u16 {
                let name = regs[i].pvd_name.clone();
                let unique = unique_83(name.as_slice(), &mut used);
                regs[i].pvd_name = unique;
            }
        }
        for (i, &pp) in ext_parent_reg.iter().enumerate() {
            if pp == p as u16 {
                extents[i].pvd_name = unique_83(extents[i].pvd_name.as_slice(), &mut used);
            }
        }
    }
}

/// Unique 8.3 identifier within `used`; mangle duplicates with a truncated
/// base + 3-digit counter (genisoimage style).
fn unique_83(
    name: &[u8],
    used: &mut Vec<Vec<u8, MAX_JOLIET_NAME_BYTES>, MAX_FILES>,
) -> Vec<u8, MAX_JOLIET_NAME_BYTES> {
    let own = Vec::from_slice(name).unwrap_or_default();
    if !used.iter().any(|u| u.as_slice() == name) {
        let _ = used.push(own.clone());
        return own;
    }
    // Split at the last '.': `BASE[.EXT;1]` → base + (".EXT;1" | ".;1" | "").
    let dot = name.iter().rposition(|&b| b == b'.');
    let (base, suffix) = match dot {
        Some(i) => (&name[..i], &name[i..]),
        None => (name, &[][..]),
    };
    let keep = base.len().min(5);
    for counter in 0..1000u16 {
        let d0 = b'0' + (counter / 100) as u8;
        let d1 = b'0' + ((counter / 10) % 10) as u8;
        let d2 = b'0' + (counter % 10) as u8;
        let mut cand = Vec::new();
        let _ = cand.extend_from_slice(&base[..keep]);
        let _ = cand.push(d0);
        let _ = cand.push(d1);
        let _ = cand.push(d2);
        let _ = cand.extend_from_slice(suffix);
        if !used.iter().any(|u| u.as_slice() == cand.as_slice()) {
            let _ = used.push(cand.clone());
            return cand;
        }
    }
    // Unreachable for MAX_FILES ≤ 128 children; keep the raw name.
    own
}

/// Compute the LBA layout for a set of files.
///
/// Files must be provided in DFS pre-order: a directory entry before its
/// children, children before the next sibling.  The label is truncated to
/// 16 ASCII characters.  The directory hierarchy is preserved: every
/// sub-directory gets its own extent and a Path Table record.
/// Path table order (ECMA-119 §6.9.1): ascending level, then parent
/// directory number, then identifier.  `use_pvd` selects the PVD 8.3
/// identifiers vs the Joliet UCS-2BE ones (each tree sorts independently).
/// Returns `(order, number_of)` — `order` is registry indices in path
/// table order, `number_of` maps registry index → path table number.
pub fn compute_layout(files: &[FileEntry], label: &str) -> Result<Layout, IsoError> {
    let opts = IsoOptions::with_label(label)?;
    compute_layout_opts(files, &opts)
}

/// Compute the LBA layout with explicit options.
///
/// `compute_layout` is a convenience wrapper that calls this with default
/// options.  The options' `label` overrides the `label` parameter when
/// calling through `compute_layout`; here the label comes from `opts`.
pub fn compute_layout_opts(files: &[FileEntry], opts: &IsoOptions) -> Result<Layout, IsoError> {
    if files.len() > MAX_FILES {
        return Err(IsoError::TooManyFiles);
    }

    // Use opts.label as the layout label.
    let lbl = opts.label.clone();

    // ── 1. Build the directory registry (root + every dir entry) ─────
    // The input is DFS pre-order, so the parent of each entry is the top
    // of a stack of open directories, found by popping to the entry's
    // depth.
    let mut regs = Vec::<DirReg, MAX_DIRS>::new();
    regs.push(DirReg {
        parent: 0,
        pvd_name: Vec::new(),
        name: Vec::new(),
        depth: 0,
    })
    .map_err(|_| IsoError::TooManyFiles)?;
    let mut stack = Vec::<u16, MAX_DIRS>::new();
    stack.push(0).map_err(|_| IsoError::TooManyFiles)?;

    let mut extents = Vec::<FileExtent, MAX_FILES>::new();
    // Parent registry index per extent, resolved to a path table number
    // after the directory ordering below.
    let mut ext_parent_reg = Vec::<u16, MAX_FILES>::new();

    for (idx, entry) in files.iter().enumerate() {
        let depth = path_depth(entry.path.as_str());
        let parent_depth = depth.saturating_sub(1) as u16;
        // `stack` starts with the root (pushed above) and is only ever
        // popped while len > 1, so it always has a top entry.
        while stack.len() > 1
            && regs[*stack.last().expect("stack holds the root") as usize].depth > parent_depth
        {
            stack.pop();
        }
        let parent_reg = *stack.last().expect("stack holds the root");
        let component = last_component(entry.path.as_str());

        if entry.is_dir {
            if regs.len() >= MAX_DIRS {
                return Err(IsoError::TooManyFiles);
            }
            let n = regs.len() as u16;
            regs.push(DirReg {
                parent: parent_reg,
                pvd_name: to_pvd_dir_name(component),
                name: to_joliet_name(component),
                depth: depth as u16,
            })
            .map_err(|_| IsoError::TooManyFiles)?;
            stack.push(n).map_err(|_| IsoError::TooManyFiles)?;
        } else {
            extents
                .push(FileExtent {
                    file_index: idx,
                    lba: 0, // assigned below
                    sectors: entry.size.div_ceil(u64::from(SECTOR_SIZE)) as u32,
                    size: entry.size,
                    pvd_name: to_pvd_file_name(component),
                    pvd_parent: 0, // resolved below
                    name: to_joliet_name(component),
                    parent: 0, // resolved below
                })
                .map_err(|_| IsoError::TooManyFiles)?;
            ext_parent_reg
                .push(parent_reg)
                .map_err(|_| IsoError::TooManyFiles)?;
        }
    }

    // PVD 8.3 collisions within a parent must be disambiguated before
    // ordering (the identifiers drive the sort).
    disambiguate_pvd_83(&mut regs, &mut extents, &ext_parent_reg);

    // ── 2. Independent orderings for the two trees ────────────────────
    let (pvd_order, pvd_number_of) = tree_order(&regs, true)?;
    let (jol_order, jol_number_of) = tree_order(&regs, false)?;

    // ── 3. Path table sizes ───────────────────────────────────────────
    // Each record: 8 + identifier + pad-to-even (root identifier = 1 byte).
    let pt_size = |order: &[u16], use_pvd: bool| -> u64 {
        let mut s: u64 = 0;
        for &r in order {
            let name_len = if r == 0 {
                1
            } else if use_pvd {
                regs[r as usize].pvd_name.len() as u64
            } else {
                regs[r as usize].name.len() as u64
            };
            s += 8 + name_len + (name_len % 2);
        }
        s
    };
    let pvd_pt_size = pt_size(&pvd_order, true);
    let jol_pt_size = pt_size(&jol_order, false);

    // ── 4. Directory extents per tree, then file LBAs ─────────────────
    // Layout: PVD path tables, PVD directories, Joliet path tables,
    // Joliet directories, file data.
    let pvd_pt_lba = SYSTEM_AREA_SECTORS + 3; // 19
    let pvd_pt_sectors = pvd_pt_size.div_ceil(u64::from(SECTOR_SIZE)) as u32;
    let mut next_lba = pvd_pt_lba + pvd_pt_sectors * 2;

    let mut pvd_dirs = Vec::<DirNode, MAX_DIRS>::new();
    for (oi, &r) in pvd_order.iter().enumerate() {
        let num = oi as u16 + 1;
        let mut bytes: u64 = 70; // "." and ".."
        for &c in &pvd_order {
            if c == r {
                continue;
            }
            if pvd_number_of[regs[c as usize].parent as usize] == num {
                bytes += record_len(regs[c as usize].pvd_name.len());
            }
        }
        for (i, ext) in extents.iter().enumerate() {
            if pvd_number_of[ext_parent_reg[i] as usize] == num {
                bytes += record_len(ext.pvd_name.len());
            }
        }
        let sectors = bytes.div_ceil(u64::from(SECTOR_SIZE)) as u32;
        let is_root = r == 0;
        pvd_dirs
            .push(DirNode {
                number: num,
                parent: if is_root {
                    1
                } else {
                    pvd_number_of[regs[r as usize].parent as usize]
                },
                name: if is_root {
                    Vec::new()
                } else {
                    regs[r as usize].pvd_name.clone()
                },
                lba: next_lba,
                sectors,
            })
            .map_err(|_| IsoError::TooManyFiles)?;
        next_lba += sectors;
    }

    let jol_pt_lba = next_lba;
    let jol_pt_sectors = jol_pt_size.div_ceil(u64::from(SECTOR_SIZE)) as u32;
    next_lba += jol_pt_sectors * 2;

    let mut jol_dirs = Vec::<DirNode, MAX_DIRS>::new();
    for (oi, &r) in jol_order.iter().enumerate() {
        let num = oi as u16 + 1;
        let mut bytes: u64 = 70; // "." and ".."
        for &c in &jol_order {
            if c == r {
                continue;
            }
            if jol_number_of[regs[c as usize].parent as usize] == num {
                bytes += record_len(regs[c as usize].name.len());
            }
        }
        for (i, ext) in extents.iter().enumerate() {
            if jol_number_of[ext_parent_reg[i] as usize] == num {
                bytes += record_len(ext.name.len());
            }
        }
        let sectors = bytes.div_ceil(u64::from(SECTOR_SIZE)) as u32;
        let is_root = r == 0;
        jol_dirs
            .push(DirNode {
                number: num,
                parent: if is_root {
                    1
                } else {
                    jol_number_of[regs[r as usize].parent as usize]
                },
                name: if is_root {
                    Vec::new()
                } else {
                    regs[r as usize].name.clone()
                },
                lba: next_lba,
                sectors,
            })
            .map_err(|_| IsoError::TooManyFiles)?;
        next_lba += sectors;
    }

    // ── 5. File LBAs (shared by both trees) ──────────────────────────
    for (i, ext) in extents.iter_mut().enumerate() {
        ext.lba = next_lba;
        ext.pvd_parent = pvd_number_of[ext_parent_reg[i] as usize];
        ext.parent = jol_number_of[ext_parent_reg[i] as usize];
        next_lba += ext.sectors;
    }
    let total = next_lba;
    let first_file_lba = extents.first().map_or(total, |e| e.lba);

    Ok(Layout {
        label: lbl,
        vol: VolumeMetadata::from(opts),
        pvd: DirTree {
            path_table_lba: pvd_pt_lba,
            path_table_sectors: pvd_pt_sectors,
            path_table_size: pvd_pt_size as u32,
            root_dir_lba: pvd_dirs[0].lba,
            root_dir_sectors: pvd_dirs[0].sectors,
            dirs: pvd_dirs,
        },
        joliet: DirTree {
            path_table_lba: jol_pt_lba,
            path_table_sectors: jol_pt_sectors,
            path_table_size: jol_pt_size as u32,
            root_dir_lba: jol_dirs[0].lba,
            root_dir_sectors: jol_dirs[0].sectors,
            dirs: jol_dirs,
        },
        extents,
        first_file_lba,
        total,
        joliet_enabled: opts.joliet,
    })
}

/// Generate the sector at `lba` into `out` (must be exactly 2048 bytes).
///
/// Returns `true` if `lba` is in the metadata area (caller should send
/// `out` as the sector data).  Returns `false` if `lba` is in the file
/// data area (caller should use [`resolve`] to find the file and read
/// from the host FS).
pub fn gen_sector(layout: &Layout, lba: u32, out: &mut [u8]) -> bool {
    assert!(out.len() >= SECTOR_SIZE as usize);
    out.fill(0);

    match lba {
        PVD_LBA => {
            write_pvd(layout, out);
            true
        }
        SVD_LBA => {
            write_svd(layout, out);
            true
        }
        TERMINATOR_LBA => {
            write_terminator(out);
            true
        }
        // PVD path tables (L then M).
        l if l >= layout.pvd.path_table_lba
            && l < layout.pvd.path_table_lba + layout.pvd.path_table_sectors =>
        {
            write_path_table(&layout.pvd, l, out, false);
            true
        }
        l if l >= layout.pvd.path_table_lba + layout.pvd.path_table_sectors
            && l < layout.pvd.path_table_lba + 2 * layout.pvd.path_table_sectors =>
        {
            write_path_table(&layout.pvd, l, out, true);
            true
        }
        // Joliet path tables (L then M).
        l if l >= layout.joliet.path_table_lba
            && l < layout.joliet.path_table_lba + layout.joliet.path_table_sectors =>
        {
            write_path_table(&layout.joliet, l, out, false);
            true
        }
        l if l >= layout.joliet.path_table_lba + layout.joliet.path_table_sectors
            && l < layout.joliet.path_table_lba + 2 * layout.joliet.path_table_sectors =>
        {
            write_path_table(&layout.joliet, l, out, true);
            true
        }
        l => {
            for dir in &layout.pvd.dirs {
                if l >= dir.lba && l < dir.lba + dir.sectors {
                    write_dir_directory(layout, &layout.pvd, dir, l, out, true);
                    return true;
                }
            }
            for dir in &layout.joliet.dirs {
                if l >= dir.lba && l < dir.lba + dir.sectors {
                    write_dir_directory(layout, &layout.joliet, dir, l, out, false);
                    return true;
                }
            }
            false
        }
    }
}

/// Map a file-data LBA to `(file_index, byte_offset_within_file, bytes_remaining_in_file)`.
///
/// Returns `None` if `lba` is not in the file data area or is past the
/// end of all files.
pub fn resolve(layout: &Layout, lba: u32) -> Option<(usize, u64, u64)> {
    for extent in &layout.extents {
        let end_lba = extent.lba + extent.sectors;
        if lba >= extent.lba && lba < end_lba {
            let sector_offset = (lba - extent.lba) as u64 * u64::from(SECTOR_SIZE);
            let bytes_remaining = extent.size.saturating_sub(sector_offset);
            return Some((extent.file_index, sector_offset, bytes_remaining));
        }
    }
    None
}

/// Total number of sectors in the image (for READ CAPACITY / READ TOC
/// lead-out).
pub fn total_sectors(layout: &Layout) -> u32 {
    layout.total
}

// ── Joliet name encoding ────────────────────────────────────────────

/// Encode an ASCII file name to Joliet UCS-2BE (0x00 + char for each ASCII
/// byte). Identifiers longer than [`MAX_JOLIET_NAME_CHARS`] are truncated.
fn to_joliet_name(name: &str) -> Vec<u8, MAX_JOLIET_NAME_BYTES> {
    let mut out = Vec::new();
    for ch in name.chars().take(MAX_JOLIET_NAME_CHARS) {
        if ch.is_ascii() && !ch.is_control() {
            let _ = out.push(0x00);
            let _ = out.push(ch as u8);
        }
    }
    out
}

// ── ISO9660 structure writers ───────────────────────────────────────

/// Write PVD (Primary Volume Descriptor) at LBA 16.
fn write_pvd(layout: &Layout, out: &mut [u8]) {
    out[0] = 0x01; // PVD type
    out[1..6].copy_from_slice(b"CD001");
    out[6] = 0x01; // version

    // Volume Space Size (LE at 80, BE at 84)
    out[80..84].copy_from_slice(&layout.total.to_le_bytes());
    out[84..88].copy_from_slice(&layout.total.to_be_bytes());

    // Volume Set Size = 1 (LE 120..122, BE 122..124)
    out[120..122].copy_from_slice(&1u16.to_le_bytes());
    out[122..124].copy_from_slice(&1u16.to_be_bytes());

    // Volume Sequence Number = 1 (LE 124..126, BE 126..128)
    out[124..126].copy_from_slice(&1u16.to_le_bytes());
    out[126..128].copy_from_slice(&1u16.to_be_bytes());

    // Logical Block Size = 2048 (LE 128..130, BE 130..132)
    out[128..130].copy_from_slice(&(SECTOR_SIZE as u16).to_le_bytes());
    out[130..132].copy_from_slice(&(SECTOR_SIZE as u16).to_be_bytes());

    // Path Table Size (LE 132..136, BE 136..140)
    out[132..136].copy_from_slice(&layout.pvd.path_table_size.to_le_bytes());
    out[136..140].copy_from_slice(&layout.pvd.path_table_size.to_be_bytes());

    // Location of LE Path Table (140..144)
    out[140..144].copy_from_slice(&layout.pvd.path_table_lba.to_le_bytes());

    // Location of BE (Type M) Path Table (148..152)
    out[148..152].copy_from_slice(
        &(layout.pvd.path_table_lba + layout.pvd.path_table_sectors).to_be_bytes(),
    );

    // Root Directory Record (34 bytes at 156)
    write_dir_record_root_pvd(
        out,
        156,
        layout.pvd.root_dir_lba,
        layout.pvd.root_dir_sectors,
    );

    // System Identifier (BP 9-40 → bytes 8-39): space-filled.
    for i in 0..32 {
        out[8 + i] = b' ';
    }
    let sys_id = layout.vol.system_id.as_bytes();
    let sys_len = sys_id.len().min(32);
    out[8..8 + sys_len].copy_from_slice(&sys_id[..sys_len]);

    // Volume Identifier (BP 41-72 → bytes 40-71): label padded with spaces.
    for i in 0..32 {
        out[40 + i] = b' ';
    }
    let label_bytes = layout.label.as_bytes();
    let copy_len = label_bytes.len().min(32);
    out[40..40 + copy_len].copy_from_slice(&label_bytes[..copy_len]);

    // Volume Set Identifier (BP 191-318 → bytes 190-317): 128 bytes.
    for i in 0..128 {
        out[190 + i] = b' ';
    }
    let vs_id = layout.vol.volume_set_id.as_bytes();
    let vs_len = vs_id.len().min(128);
    out[190..190 + vs_len].copy_from_slice(&vs_id[..vs_len]);

    // Publisher Identifier (BP 319-446 → bytes 318-445): 128 bytes.
    let pub_id = if layout.vol.publisher.is_empty() {
        b"SnowSCSI"
    } else {
        layout.vol.publisher.as_bytes()
    };
    for i in 0..128 {
        out[318 + i] = b' ';
    }
    out[318..318 + pub_id.len().min(128)].copy_from_slice(&pub_id[..pub_id.len().min(128)]);

    // Data Preparer Identifier (BP 447-574 → bytes 446-573): 128 bytes.
    let dp_id = if layout.vol.data_preparer.is_empty() {
        pub_id
    } else {
        layout.vol.data_preparer.as_bytes()
    };
    for i in 0..128 {
        out[446 + i] = b' ';
    }
    out[446..446 + dp_id.len().min(128)].copy_from_slice(&dp_id[..dp_id.len().min(128)]);

    // Application Identifier (BP 575-702 → bytes 574-701): 128 bytes.
    let app_id = if layout.vol.application_id.is_empty() {
        b"snowscsi"
    } else {
        layout.vol.application_id.as_bytes()
    };
    for i in 0..128 {
        out[574 + i] = b' ';
    }
    out[574..574 + app_id.len().min(128)].copy_from_slice(&app_id[..app_id.len().min(128)]);

    // Volume date fields (17 bytes each, BP 814-830 / 831-847 / 848-864 /
    // 865-881 → bytes 813-829 / 830-846 / 847-863 / 864-880): 16 ASCII
    // digits "YYYYMMDDHHMMSScc" + a GMT-offset byte. The generator has no
    // clock, so a fixed sentinel is recorded (strict readers reject a
    // zero-filled field).
    for i in 0..4 {
        let o = 813 + i * 17;
        out[o..o + 16].copy_from_slice(b"1980010100000000");
        out[o + 16] = 0x00; // GMT offset: +0 (in 15-minute units)
    }

    // File Structure Version
    out[881] = 0x01;
}

/// Write SVD (Supplementary Volume Descriptor / Joliet) at LBA 17.
fn write_svd(layout: &Layout, out: &mut [u8]) {
    out[0] = 0x02; // SVD type
    out[1..6].copy_from_slice(b"CD001");
    out[6] = 0x01; // version
                   // Escape sequences (BP 89-120 → bytes 88-119): UCS-2 Level 1 `%/@`
                   // (Joliet Annex C.3.1, Table C.1). The remaining bytes stay (00) —
                   // ECMA-119 §8.5.6 requires unused positions in this field to be (00),
                   // and `gen_sector` zero-fills the sector first.
    out[88] = 0x25; // %
    out[89] = 0x2F; // /
    out[90] = 0x40; // @

    // Volume Space Size
    out[80..84].copy_from_slice(&layout.total.to_le_bytes());
    out[84..88].copy_from_slice(&layout.total.to_be_bytes());

    // Volume Set Size = 1 (LE 120..122, BE 122..124)
    out[120..122].copy_from_slice(&1u16.to_le_bytes());
    out[122..124].copy_from_slice(&1u16.to_be_bytes());

    // Volume Sequence Number = 1 (LE 124..126, BE 126..128)
    out[124..126].copy_from_slice(&1u16.to_le_bytes());
    out[126..128].copy_from_slice(&1u16.to_be_bytes());

    // Logical Block Size = 2048 (LE 128..130, BE 130..132)
    out[128..130].copy_from_slice(&(SECTOR_SIZE as u16).to_le_bytes());
    out[130..132].copy_from_slice(&(SECTOR_SIZE as u16).to_be_bytes());

    // Path Table Size (LE 132..136, BE 136..140)
    out[132..136].copy_from_slice(&layout.joliet.path_table_size.to_le_bytes());
    out[136..140].copy_from_slice(&layout.joliet.path_table_size.to_be_bytes());

    // Location of LE Path Table (140..144)
    out[140..144].copy_from_slice(&layout.joliet.path_table_lba.to_le_bytes());

    // Location of BE (Type M) Path Table (148..152)
    out[148..152].copy_from_slice(
        &(layout.joliet.path_table_lba + layout.joliet.path_table_sectors).to_be_bytes(),
    );

    // Root Directory Record
    write_dir_record_root_pvd(
        out,
        156,
        layout.joliet.root_dir_lba,
        layout.joliet.root_dir_sectors,
    );

    // Volume Identifier (BP 41-72 → bytes 40-71): UCS-2BE label (16 chars).
    for i in 0..32 {
        out[40 + i] = 0;
    }
    let label_bytes = layout.label.as_bytes();
    let ucs2_len = label_bytes.len().min(16);
    for (i, &ch) in label_bytes[..ucs2_len].iter().enumerate() {
        out[40 + i * 2] = 0x00;
        out[40 + i * 2 + 1] = ch;
    }

    // File Structure Version
    out[881] = 0x01;
}

/// Write Volume Descriptor Set Terminator at LBA 18.
fn write_terminator(out: &mut [u8]) {
    out[0] = 0xFF;
    out[1..6].copy_from_slice(b"CD001");
    out[6] = 0x01;
}

/// Write one Path Table sector at `lba` (Type L when `is_m` is false,
/// Type M when true).  Only the records overlapping this sector are
/// written; the rest of `out` is zeroed.
fn write_path_table(tree: &DirTree, lba: u32, out: &mut [u8], is_m: bool) {
    out.fill(0);
    let table_start = tree.path_table_lba + if is_m { tree.path_table_sectors } else { 0 };
    let sector_start = (lba - table_start) as usize * SECTOR_SIZE as usize;

    let mut offset = 0usize;
    for (i, dir) in tree.dirs.iter().enumerate() {
        let is_root = i == 0;
        // Root identifier is a single 0x00 byte; others use the UCS-2BE name.
        let name: &[u8] = if is_root { &[0x00] } else { &dir.name };
        let name_len = name.len();
        let rec_len = 8 + name_len + (name_len % 2);
        let rec_start = offset;
        offset += rec_len;

        let sect_end = sector_start + out.len();
        if rec_start + rec_len <= sector_start || rec_start >= sect_end {
            continue;
        }

        let mut rec = [0u8; MAX_PT_REC_LEN];
        rec[0] = name_len as u8;
        rec[1] = 0x00; // extended attribute record length
        if is_m {
            rec[2..6].copy_from_slice(&dir.lba.to_be_bytes());
            rec[6..8].copy_from_slice(&dir.parent.to_be_bytes());
        } else {
            rec[2..6].copy_from_slice(&dir.lba.to_le_bytes());
            rec[6..8].copy_from_slice(&dir.parent.to_le_bytes());
        }
        rec[8..8 + name_len].copy_from_slice(name);
        if name_len % 2 == 1 {
            rec[8 + name_len] = 0x00; // pad to even record length
        }

        let from = sector_start.max(rec_start);
        let to = (rec_start + rec_len).min(sect_end);
        out[from - sector_start..to - sector_start]
            .copy_from_slice(&rec[from - rec_start..to - rec_start]);
    }
}

/// Write one directory sector at `lba` (which must lie within `dir`'s
/// extent).
///
/// Contains ".", "..", one record per child directory and one per file.
/// When `is_pvd` the tree's 8.3 identifiers are used (`dir.name` /
/// `extent.pvd_name`), otherwise the Joliet UCS-2BE names.  Only the
/// records overlapping this sector are written; the rest of `out` is
/// zeroed.
fn write_dir_directory(
    layout: &Layout,
    tree: &DirTree,
    dir: &DirNode,
    lba: u32,
    out: &mut [u8],
    is_pvd: bool,
) {
    out.fill(0);
    let sector_start = (lba - dir.lba) as usize * SECTOR_SIZE as usize;

    // Emit one record, tracking its byte offset within the directory
    // extent and copying only the part that overlaps `out`'s sector.
    let mut offset = 0usize;
    let mut emit = |offset: &mut usize, extent_lba: u32, data_len: u32, flags: u8, name: &[u8]| {
        let rec_len = 33 + name.len() + if name.len().is_multiple_of(2) { 1 } else { 0 };
        let rec_start = *offset;
        *offset += rec_len;

        let sect_end = sector_start + out.len();
        if rec_start + rec_len <= sector_start || rec_start >= sect_end {
            return;
        }

        // Build the record into a scratch buffer sized from
        // MAX_JOLIET_NAME_BYTES.
        let mut rec = [0u8; MAX_DIR_REC_LEN];
        write_dir_record(&mut rec[..rec_len], 0, extent_lba, data_len, flags, name);

        let from = sector_start.max(rec_start);
        let to = (rec_start + rec_len).min(sect_end);
        out[from - sector_start..to - sector_start]
            .copy_from_slice(&rec[from - rec_start..to - rec_start]);
    };

    // "." entry (self)
    emit(
        &mut offset,
        dir.lba,
        dir.sectors * SECTOR_SIZE,
        0x02,
        &[0x00],
    );

    // ".." entry (parent; root points to itself)
    let (p_lba, p_sectors) = if dir.number == 1 {
        (dir.lba, dir.sectors)
    } else {
        let parent = tree
            .dirs
            .iter()
            .find(|d| d.number == dir.parent)
            .expect("parent directory present in layout");
        (parent.lba, parent.sectors)
    };
    emit(&mut offset, p_lba, p_sectors * SECTOR_SIZE, 0x02, &[0x01]);

    // Child directories.
    for child in &tree.dirs {
        if child.number != dir.number && child.parent == dir.number {
            emit(
                &mut offset,
                child.lba,
                child.sectors * SECTOR_SIZE,
                0x02,
                &child.name,
            );
        }
    }

    // File entries: data length = actual file size (ECMA-119 §9.1.5).
    for extent in &layout.extents {
        let (parent, name) = if is_pvd {
            (extent.pvd_parent, extent.pvd_name.as_slice())
        } else {
            (extent.parent, extent.name.as_slice())
        };
        if parent == dir.number {
            emit(&mut offset, extent.lba, extent.size as u32, 0x00, name);
        }
    }
}

/// Write a directory record into `out` at `offset`.
/// Returns the number of bytes written.
///
/// `flags`: 0x00 = file, 0x02 = directory
/// `name`: raw identifier bytes (Joliet UCS-2BE for file names,
///          0x00 for ".", 0x01 for "..")
fn write_dir_record(
    out: &mut [u8],
    offset: usize,
    extent_lba: u32,
    data_len: u32,
    flags: u8,
    name: &[u8],
) -> usize {
    let name_len = name.len();
    // Padding is added only when the identifier length is even (ECMA-119
    // §9.1.12), keeping the record length even.
    let rec_len = 33 + name_len + if name_len.is_multiple_of(2) { 1 } else { 0 };
    let o = offset;

    out[o] = rec_len as u8; // Length of Directory Record
    out[o + 1] = 0x00; // Extended Attribute Record Length
                       // Location of Extent (both-endian: LE 2..6, BE 6..10)
    out[o + 2..o + 6].copy_from_slice(&extent_lba.to_le_bytes());
    out[o + 6..o + 10].copy_from_slice(&extent_lba.to_be_bytes());
    // Data Length (both-endian: LE 10..14, BE 14..18)
    out[o + 10..o + 14].copy_from_slice(&data_len.to_le_bytes());
    out[o + 14..o + 18].copy_from_slice(&data_len.to_be_bytes());
    // Recording Date and Time (7 bytes at o+18): fixed sentinel.
    out[o + 18..o + 25].copy_from_slice(&FIXED_RECORDING_DATE);
    // File Flags
    out[o + 25] = flags;
    // File Unit Size
    out[o + 26] = 0x00;
    // Interleave Gap Size
    out[o + 27] = 0x00;
    // Volume Sequence Number (LE + BE)
    out[o + 28..o + 30].copy_from_slice(&1u16.to_le_bytes());
    out[o + 30..o + 32].copy_from_slice(&1u16.to_be_bytes());
    // Length of File Identifier
    out[o + 32] = name_len as u8;
    // File Identifier
    out[o + 33..o + 33 + name_len].copy_from_slice(name);
    // Padding (only when name_len is even, ECMA-119 §9.1.12)
    if name_len.is_multiple_of(2) {
        out[o + 33 + name_len] = 0x00;
    }

    rec_len
}

/// Write the root directory record (for PVD/SVD at byte 156).
fn write_dir_record_root_pvd(out: &mut [u8], offset: usize, root_lba: u32, root_sectors: u32) {
    let data_len = root_sectors * SECTOR_SIZE;
    let o = offset;

    out[o] = 34; // Length (33 + 1 for "\0" name)
    out[o + 1] = 0x00; // Ext Attr Length
    out[o + 2..o + 6].copy_from_slice(&root_lba.to_le_bytes());
    out[o + 6..o + 10].copy_from_slice(&root_lba.to_be_bytes());
    out[o + 10..o + 14].copy_from_slice(&data_len.to_le_bytes());
    out[o + 14..o + 18].copy_from_slice(&data_len.to_be_bytes());
    // Recording Date and Time (7 bytes at o+18): fixed sentinel.
    out[o + 18..o + 25].copy_from_slice(&FIXED_RECORDING_DATE);
    out[o + 25] = 0x02; // Flags: directory
    out[o + 26] = 0x00; // File Unit Size
    out[o + 27] = 0x00; // Interleave Gap Size
    out[o + 28..o + 30].copy_from_slice(&1u16.to_le_bytes());
    out[o + 30..o + 32].copy_from_slice(&1u16.to_be_bytes());
    out[o + 32] = 0x01; // Name length
    out[o + 33] = 0x00; // Name: root ("\0")
}

// ── Error type ──────────────────────────────────────────────────────

/// snow9660 error type (no_std).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsoError {
    /// Too many files for the layout (exceeds MAX_FILES).
    TooManyFiles,
    /// Volume label is empty or contains only non-ASCII/control chars.
    InvalidLabel,
}

impl core::fmt::Display for IsoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooManyFiles => write!(f, "too many files for ISO9660 layout"),
            Self::InvalidLabel => write!(f, "volume label is empty or invalid"),
        }
    }
}

impl core::error::Error for IsoError {}

// ── LiveData: live ISO9660 over FsStorage ───────────────────────

/// Directory-scan buffer size (entries per `read_dir` call).
const SCAN_BUF: usize = 32;

/// Error opening a live FS device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CdLiveFsError {
    /// Filesystem failure during the tree scan.
    Fs(FsError),
    /// The tree exceeds the layout capacity (MAX_FILES).
    TooManyFiles,
    /// A directory has more entries than the scan buffer can hold.
    DirTooLarge,
}

impl core::fmt::Display for CdLiveFsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Fs(e) => write!(f, "filesystem error: {e}"),
            Self::TooManyFiles => write!(f, "too many files for the live layout"),
            Self::DirTooLarge => write!(f, "directory exceeds the live scan buffer"),
        }
    }
}

impl core::error::Error for CdLiveFsError {}

impl From<FsError> for CdLiveFsError {
    fn from(e: FsError) -> Self {
        Self::Fs(e)
    }
}

impl From<IsoError> for CdLiveFsError {
    fn from(e: IsoError) -> Self {
        match e {
            IsoError::TooManyFiles => Self::TooManyFiles,
            IsoError::InvalidLabel => Self::TooManyFiles,
        }
    }
}

/// Live ISO9660 data plane: scans a host directory tree, computes an
/// ISO9660/Joliet LBA layout, and serves sectors on the fly.
///
/// Implements [`embedded_io::Read`] + [`embedded_io::Seek`] so it can be
/// used as a standalone ISO image reader without any SCSI dependency, and
/// [`FlatData`] so it slots into a CD-ROM media tray like any image.
pub struct LiveData<F: FsStorage> {
    #[allow(dead_code)] // kept for lifetime / ownership
    fs: F,
    layout: Layout,
    handles: Vec<Option<F::File>, MAX_FILES>,
    pos: u64,
}

impl<F: FsStorage> LiveData<F> {
    /// Scan the tree under `fs`'s root and build the live layout.
    pub fn new(mut fs: F, label: &str) -> Result<Self, CdLiveFsError> {
        let mut files = Vec::<FileEntry, MAX_FILES>::new();
        let mut handles = Vec::<Option<F::File>, MAX_FILES>::new();
        scan_dir(&mut fs, "", &mut files, &mut handles)?;
        let layout = compute_layout(&files, label)?;
        Ok(Self {
            fs,
            layout,
            handles,
            pos: 0,
        })
    }

    /// Create from pre-built options (validated before scan).
    pub fn with_opts(mut fs: F, opts: &IsoOptions) -> Result<Self, CdLiveFsError> {
        let mut files = Vec::<FileEntry, MAX_FILES>::new();
        let mut handles = Vec::<Option<F::File>, MAX_FILES>::new();
        scan_dir(&mut fs, "", &mut files, &mut handles)?;
        let layout = compute_layout_opts(&files, opts)?;
        Ok(Self {
            fs,
            layout,
            handles,
            pos: 0,
        })
    }

    pub fn layout(&self) -> &Layout {
        &self.layout
    }

    /// Total image size in bytes.
    pub fn size(&self) -> u64 {
        u64::from(self.layout.total) * u64::from(SECTOR_SIZE)
    }

    /// Fill one 2048-byte sector at `lba` (metadata or file data).
    fn fill_sector(
        &mut self,
        lba: u32,
        sector: &mut [u8; SECTOR_SIZE as usize],
    ) -> Result<(), embedded_io::ErrorKind> {
        let metadata_end = self.layout.first_file_lba;
        if lba < metadata_end {
            gen_sector(&self.layout, lba, sector);
            return Ok(());
        }
        let (file_index, file_offset, remaining) = match resolve(&self.layout, lba) {
            Some(v) => v,
            None => return Err(embedded_io::ErrorKind::InvalidData),
        };
        let file = self.handles[file_index]
            .as_mut()
            .ok_or(embedded_io::ErrorKind::NotFound)?;
        let need = (remaining as usize).min(SECTOR_SIZE as usize);
        use embedded_io::{Read, Seek};
        file.seek(embedded_io::SeekFrom::Start(file_offset))
            .map_err(|_| embedded_io::ErrorKind::Other)?;
        let got = file
            .read(&mut sector[..need])
            .map_err(|_| embedded_io::ErrorKind::Other)?;
        sector[got..need].fill(0);
        Ok(())
    }
}

// ── FlatData: slot-usable read-only plane ──────────────────

impl<F: FsStorage> FlatData for LiveData<F> {
    fn read_at(&mut self, byte_offset: u64, buf: &mut [u8]) -> Result<(), StorageError> {
        use embedded_io::{Read, Seek};
        let mut off = byte_offset;
        let mut dst = buf;
        while !dst.is_empty() {
            let lba = (off / u64::from(crate::SECTOR_SIZE)) as u32;
            let within = (off % u64::from(crate::SECTOR_SIZE)) as usize;
            let n = (crate::SECTOR_SIZE as usize - within).min(dst.len());
            let mut tmp = [0u8; crate::SECTOR_SIZE as usize];
            self.seek(embedded_io::SeekFrom::Start(
                lba as u64 * u64::from(crate::SECTOR_SIZE),
            ))
            .map_err(|_| StorageError::OutOfBounds)?;
            // read_exact, not read: a short read at the EOF tail would
            // otherwise silently zero-fill the rest of the sector and
            // corrupt the generated image.
            Read::read_exact(self, &mut tmp).map_err(|_| StorageError::OutOfBounds)?;
            dst[..n].copy_from_slice(&tmp[within..within + n]);
            off += n as u64;
            dst = &mut dst[n..];
        }
        Ok(())
    }

    fn capacity(&self) -> u64 {
        self.size()
    }
}

impl<F: FsStorage> embedded_io::ErrorType for LiveData<F> {
    type Error = embedded_io::ErrorKind;
}

impl<F: FsStorage> embedded_io::Read for LiveData<F> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        if self.pos >= self.size() {
            return Ok(0);
        }
        let mut off = self.pos;
        let mut dst = buf;
        let mut total = 0usize;
        while !dst.is_empty() {
            let lba = (off / u64::from(SECTOR_SIZE)) as u32;
            let within = (off % u64::from(SECTOR_SIZE)) as usize;
            let n = (SECTOR_SIZE as usize - within).min(dst.len());
            let mut sector = [0u8; SECTOR_SIZE as usize];
            self.fill_sector(lba, &mut sector)?;
            dst[..n].copy_from_slice(&sector[within..within + n]);
            off += n as u64;
            dst = &mut dst[n..];
            total += n;
        }
        self.pos += total as u64;
        Ok(total)
    }
}

impl<F: FsStorage> embedded_io::Seek for LiveData<F> {
    fn seek(&mut self, pos: embedded_io::SeekFrom) -> Result<u64, Self::Error> {
        self.pos = match pos {
            embedded_io::SeekFrom::Start(s) => s.min(self.size()),
            embedded_io::SeekFrom::Current(d) => {
                let new = (self.pos as i64).saturating_add(d);
                if new < 0 {
                    0
                } else {
                    (new as u64).min(self.size())
                }
            }
            embedded_io::SeekFrom::End(d) => {
                let base = self.size() as i64;
                let new = base.saturating_add(d);
                if new < 0 {
                    0
                } else {
                    (new as u64).min(self.size())
                }
            }
        };
        Ok(self.pos)
    }
}

/// Recursively scan `dir_rel` ("" = root), appending entries and opening
/// files.  Directories appear before their children.
fn scan_dir<F: FsStorage>(
    fs: &mut F,
    dir_rel: &str,
    files: &mut Vec<FileEntry, MAX_FILES>,
    handles: &mut Vec<Option<F::File>, MAX_FILES>,
) -> Result<(), CdLiveFsError> {
    let mut buf: [DirEntry; SCAN_BUF] = core::array::from_fn(|_| DirEntry {
        name: heapless::String::new(),
        is_dir: false,
        size: 0,
    });
    let n = fs.read_dir(dir_rel, &mut buf)?;
    if n == SCAN_BUF {
        return Err(CdLiveFsError::DirTooLarge);
    }
    for entry in &buf[..n] {
        let mut path = heapless::String::<MAX_PATH_LEN>::new();
        if !dir_rel.is_empty() {
            path.push_str(dir_rel)
                .map_err(|_| CdLiveFsError::TooManyFiles)?;
            path.push('/').map_err(|_| CdLiveFsError::TooManyFiles)?;
        }
        path.push_str(entry.name.as_str())
            .map_err(|_| CdLiveFsError::TooManyFiles)?;

        files
            .push(FileEntry {
                path: path.clone(),
                size: entry.size,
                is_dir: entry.is_dir,
            })
            .map_err(|_| CdLiveFsError::TooManyFiles)?;

        if entry.is_dir {
            handles
                .push(None)
                .map_err(|_| CdLiveFsError::TooManyFiles)?;
            scan_dir(fs, path.as_str(), files, handles)?;
        } else {
            let h = fs.open(path.as_str(), OpenOptions::read_only())?;
            handles
                .push(Some(h))
                .map_err(|_| CdLiveFsError::TooManyFiles)?;
        }
    }
    Ok(())
}

// ── LiveDataBuilder ─────────────────────────────────────────

/// Builder for constructing [`LiveData`] with configurable ISO options.
///
/// The builder validates all options at `build()` time — **before** the
/// directory scan — so invalid inputs fail fast without touching the
/// filesystem.
pub struct LiveDataBuilder<F: FsStorage> {
    fs: F,
    opts: Result<IsoOptions, IsoError>,
}

impl<F: FsStorage> LiveDataBuilder<F> {
    /// Start building with a filesystem backend.
    pub fn new(fs: F) -> Self {
        Self {
            fs,
            opts: Err(IsoError::InvalidLabel), // must set label
        }
    }

    /// Set the volume label (1-16 ASCII chars).
    pub fn label(mut self, label: &str) -> Self {
        self.opts = IsoOptions::with_label(label);
        self
    }

    /// Set the system identifier (ECMA-119 §8.4.4 BP 9-40).
    pub fn system_id(mut self, id: &str) -> Self {
        if let Ok(ref mut opts) = self.opts {
            let _ = opts.system_id.push_str(id);
        }
        self
    }

    /// Set the publisher identifier (BP 319-446).
    pub fn publisher(mut self, name: &str) -> Self {
        if let Ok(ref mut opts) = self.opts {
            let _ = opts.publisher.push_str(name);
        }
        self
    }

    /// Set the data preparer identifier (BP 447-574).
    pub fn data_preparer(mut self, name: &str) -> Self {
        if let Ok(ref mut opts) = self.opts {
            let _ = opts.data_preparer.push_str(name);
        }
        self
    }

    /// Set the application identifier (BP 575-702).
    pub fn application_id(mut self, name: &str) -> Self {
        if let Ok(ref mut opts) = self.opts {
            let _ = opts.application_id.push_str(name);
        }
        self
    }

    /// Set the volume set identifier (BP 191-318).
    pub fn volume_set_id(mut self, id: &str) -> Self {
        if let Ok(ref mut opts) = self.opts {
            let _ = opts.volume_set_id.push_str(id);
        }
        self
    }

    /// Enable or disable Joliet (UCS-2BE) tree.  Default: `true`.
    pub fn joliet(mut self, enabled: bool) -> Self {
        if let Ok(ref mut opts) = self.opts {
            opts.joliet = enabled;
        }
        self
    }

    /// Build the [`LiveData`] by scanning the filesystem and computing
    /// the layout.
    pub fn build(self) -> Result<LiveData<F>, CdLiveFsError> {
        let opts = self.opts?;
        let mut fs = self.fs;
        let mut files = Vec::<FileEntry, MAX_FILES>::new();
        let mut handles = Vec::<Option<F::File>, MAX_FILES>::new();
        scan_dir(&mut fs, "", &mut files, &mut handles)?;
        let layout = compute_layout_opts(&files, &opts)?;
        Ok(LiveData {
            fs,
            layout,
            handles,
            pos: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(path: &str, size: u64, is_dir: bool) -> FileEntry {
        let mut p = String::<MAX_PATH_LEN>::new();
        p.push_str(path).unwrap();
        FileEntry {
            path: p,
            size,
            is_dir,
        }
    }

    fn make_entries() -> Vec<FileEntry, MAX_FILES> {
        let mut v = Vec::new();
        v.push(make_entry("README.TXT", 1000, false)).unwrap();
        v.push(make_entry("DATA.BIN", 4096, false)).unwrap();
        v
    }

    /// Nested tree in DFS pre-order: root file, DOCS dir + child, TOOLS
    /// dir + children (one nested SUB).
    fn make_tree() -> Vec<FileEntry, MAX_FILES> {
        let mut v = Vec::new();
        v.push(make_entry("README.TXT", 1000, false)).unwrap();
        v.push(make_entry("DOCS", 0, true)).unwrap();
        v.push(make_entry("DOCS/MANUAL.PDF", 2000, false)).unwrap();
        v.push(make_entry("TOOLS", 0, true)).unwrap();
        v.push(make_entry("TOOLS/SETUP.EXE", 3000, false)).unwrap();
        v.push(make_entry("TOOLS/SUB", 0, true)).unwrap();
        v.push(make_entry("TOOLS/SUB/X.BIN", 100, false)).unwrap();
        v
    }

    // ── compute_layout ──────────────────────────────────────────────

    #[test]
    fn layout_basic() {
        let files = make_entries();
        let layout = compute_layout(&files, "TEST").unwrap();
        assert_eq!(layout.label.as_str(), "TEST");
        // PVD tree: path table L at 19 (1 sector, only the root dir), root
        // dir at 21; Joliet tree: path table at 22, root dir at 24.
        assert_eq!(layout.pvd.path_table_lba, 19);
        assert_eq!(layout.pvd.root_dir_lba, 21);
        assert_eq!(layout.pvd.dirs.len(), 1); // root only
        assert_eq!(layout.joliet.path_table_lba, 22);
        assert_eq!(layout.joliet.root_dir_lba, 24);
        assert_eq!(layout.joliet.dirs.len(), 1); // root only
                                                 // Files follow both trees' directories: 25, 26-27.
        assert_eq!(layout.extents.len(), 2);
        assert_eq!(layout.extents[0].lba, 25);
        assert_eq!(layout.extents[0].sectors, 1); // 1000 bytes = 1 sector
        assert_eq!(layout.extents[0].size, 1000);
        assert_eq!(layout.extents[1].lba, 26);
        assert_eq!(layout.extents[1].sectors, 2); // 4096 bytes = 2 sectors
        assert_eq!(layout.extents[1].size, 4096);
        assert_eq!(layout.total, 28);
        assert_eq!(layout.first_file_lba, 25);
    }

    #[test]
    fn layout_empty() {
        let files: Vec<FileEntry, MAX_FILES> = Vec::new();
        let layout = compute_layout(&files, "EMPTY").unwrap();
        assert_eq!(layout.extents.len(), 0);
        assert_eq!(layout.pvd.dirs.len(), 1);
        assert_eq!(layout.joliet.dirs.len(), 1);
        // 16-18 desc, 19 PVD PT-L, 20 PVD PT-M, 21 PVD root,
        // 22 Joliet PT-L, 23 Joliet PT-M, 24 Joliet root.
        assert_eq!(layout.total, 25);
    }

    #[test]
    fn layout_label_truncated() {
        let files: Vec<FileEntry, MAX_FILES> = Vec::new();
        let layout = compute_layout(&files, "A_VERY_LONG_LABEL_NAME").unwrap();
        assert_eq!(layout.label.as_str(), "A_VERY_LONG_LABE");
    }

    #[test]
    fn layout_empty_label_default() {
        let files: Vec<FileEntry, MAX_FILES> = Vec::new();
        let layout = compute_layout(&files, "").unwrap();
        assert_eq!(layout.label.as_str(), "SNOWSCSI");
    }

    #[test]
    fn layout_label_no_control_chars() {
        let files: Vec<FileEntry, MAX_FILES> = Vec::new();
        let layout = compute_layout(&files, "AB\x01CD").unwrap();
        assert_eq!(layout.label.as_str(), "ABCD");
    }

    #[test]
    fn layout_max_files_ok() {
        let mut files = Vec::<FileEntry, MAX_FILES>::new();
        for i in 0..MAX_FILES {
            let mut path = String::<MAX_PATH_LEN>::new();
            core::fmt::Write::write_fmt(&mut path, format_args!("F{i}.BIN")).unwrap();
            files
                .push(FileEntry {
                    path,
                    size: 100,
                    is_dir: false,
                })
                .unwrap();
        }
        let layout = compute_layout(&files, "MAX").unwrap();
        assert_eq!(layout.extents.len(), MAX_FILES);
    }

    /// Regression: the root directory record table must be allowed to span
    /// multiple sectors (a large flat tree overflows one 2048-byte sector).
    #[test]
    fn layout_root_dir_spans_multiple_sectors() {
        let mut files = Vec::<FileEntry, MAX_FILES>::new();
        for i in 0..MAX_FILES {
            let mut path = String::<MAX_PATH_LEN>::new();
            core::fmt::Write::write_fmt(&mut path, format_args!("F{i:03}.BIN")).unwrap();
            files
                .push(FileEntry {
                    path,
                    size: 100,
                    is_dir: false,
                })
                .unwrap();
        }
        let layout = compute_layout(&files, "BIG").unwrap();
        // 128 Joliet records × (33 + 16-byte UCS-2BE name + pad) ≫ 2048.
        assert!(
            layout.joliet.root_dir_sectors > 1,
            "root dir should span {} sectors",
            layout.joliet.root_dir_sectors
        );
        // File data starts right after the Joliet root directory extent.
        assert_eq!(
            layout.extents[0].lba,
            layout.joliet.root_dir_lba + layout.joliet.root_dir_sectors
        );

        // Every Joliet root directory sector must generate without panicking
        // and the first sector must begin with the "." record.
        for i in 0..layout.joliet.root_dir_sectors {
            let mut sector = [0u8; 2048];
            assert!(gen_sector(
                &layout,
                layout.joliet.root_dir_lba + i,
                &mut sector
            ));
        }
        let mut sector = [0u8; 2048];
        gen_sector(&layout, layout.joliet.root_dir_lba, &mut sector);
        assert_eq!(sector[0], 34); // "." record length (33 + 1 name, odd → no pad)
        assert_eq!(sector[32], 1); // "." name length
                                   // Sector 0 holds "." and ".." records.
        assert_eq!(sector[34], 34); // ".." record length
                                    // The last Joliet root dir sector still carries
                                    // (parts of) file records.
        let last = layout.joliet.root_dir_lba + layout.joliet.root_dir_sectors - 1;
        let mut sector = [0u8; 2048];
        gen_sector(&layout, last, &mut sector);
        // A record crosses the sector boundary, so the sector is not empty
        // (it may start mid-record with zero bytes).
        assert!(sector.iter().any(|&b| b != 0));
    }

    #[test]
    fn layout_joliet_name_encoded() {
        let files = make_entries();
        let layout = compute_layout(&files, "T").unwrap();
        // README.TXT → UCS-2BE: 00 52 00 45 00 41 00 44 00 4D 00 45 00 2E 00 54 00 58 00 54
        let name = &layout.extents[0].name;
        assert_eq!(name.len(), 20); // 10 chars × 2 bytes
        assert_eq!(name[0], 0x00);
        assert_eq!(name[1], b'R');
        assert_eq!(name[2], 0x00);
        assert_eq!(name[3], b'E');
    }

    /// Names longer than MAX_JOLIET_NAME_CHARS are truncated in the ISO
    /// metadata (documented limit); shorter names pass through whole.
    #[test]
    fn joliet_name_truncated_at_max_chars() {
        // Exactly MAX_JOLIET_NAME_CHARS 'A's: preserved whole.
        let exact: std::string::String = "A".repeat(MAX_JOLIET_NAME_CHARS);
        let n = to_joliet_name(&exact);
        assert_eq!(n.len(), MAX_JOLIET_NAME_BYTES);
        // One char over: truncated to MAX_JOLIET_NAME_CHARS.
        let over: std::string::String = "B".repeat(MAX_JOLIET_NAME_CHARS + 1);
        let n = to_joliet_name(&over);
        assert_eq!(n.len(), MAX_JOLIET_NAME_BYTES);
        // Non-ASCII characters are skipped (not counted toward the limit).
        let mixed = "AB\u{4e2d}CD";
        let n = to_joliet_name(mixed);
        assert_eq!(n.len(), 8); // 'A','B','C','D'
    }

    // ── PVD 8.3 identifiers ──────────────────────────────────────────

    #[test]
    fn pvd_file_name_83_with_version() {
        // Ordinary: base + "." + ext + ";1".
        assert_eq!(to_pvd_file_name("readme.txt").as_slice(), b"README.TXT;1");
        // No extension: still carries the separator and version (NOEXT.;1).
        assert_eq!(to_pvd_file_name("noext").as_slice(), b"NOEXT.;1");
        // Long base truncated to 8, long ext to 3, last dot splits.
        assert_eq!(
            to_pvd_file_name("averylongfilename.with.ext").as_slice(),
            b"AVERYLON.EXT;1"
        );
        // Dots inside the base map to '_'.
        assert_eq!(
            to_pvd_file_name("multi.dot.name").as_slice(),
            b"MULTI_DO.NAM;1"
        );
        // Lowercase / mixed case are uppercased.
        assert_eq!(to_pvd_file_name("Data.Bin").as_slice(), b"DATA.BIN;1");
    }

    #[test]
    fn pvd_dir_name_83_no_version() {
        // Directory identifier: no version.
        assert_eq!(to_pvd_dir_name("docs").as_slice(), b"DOCS");
        // Extension kept when present.
        assert_eq!(to_pvd_dir_name("sub.dir").as_slice(), b"SUB.DIR");
        // No extension → base only (no trailing dot).
        assert_eq!(to_pvd_dir_name("with space").as_slice(), b"WITH_SPA");
    }

    #[test]
    fn pvd_83_collision_disambiguation() {
        // Two host names mapping to the same 8.3 identifier: the first
        // keeps the natural name, the second gets base[:5] + 3-digit counter.
        let mut regs = Vec::<DirReg, MAX_DIRS>::new();
        regs.push(DirReg {
            parent: 0,
            pvd_name: Vec::new(),
            name: Vec::new(),
            depth: 0,
        })
        .unwrap();
        let mut extents = Vec::<FileExtent, MAX_FILES>::new();
        let mk = |n: &str| FileExtent {
            file_index: 0,
            lba: 0,
            sectors: 1,
            size: 1,
            pvd_name: to_pvd_file_name(n),
            pvd_parent: 0,
            name: to_joliet_name(n),
            parent: 0,
        };
        extents.push(mk("readme.txt")).unwrap();
        extents.push(mk("README.TXT")).unwrap();
        extents.push(mk("abcdefgh1.dat")).unwrap();
        extents.push(mk("abcdefgh2.dat")).unwrap();
        extents.push(mk("abcdefgh3.dat")).unwrap();
        let parents = [0u16, 0, 0, 0, 0];
        disambiguate_pvd_83(&mut regs, &mut extents, &parents);
        let names: std::vec::Vec<&[u8]> = extents.iter().map(|e| e.pvd_name.as_slice()).collect();
        // Natural name kept once; the duplicate is mangled.
        assert_eq!(names[0], b"README.TXT;1");
        assert_ne!(names[1], names[0]);
        assert!(names[1].ends_with(b";1"));
        // Three-way collision on ABCDEFGH.DAT: one keeps the natural name,
        // the other two get ABCDE000/ABCDE001.
        assert_eq!(names[2], b"ABCDEFGH.DAT;1");
        assert_eq!(names[3], b"ABCDE000.DAT;1");
        assert_eq!(names[4], b"ABCDE001.DAT;1");
        assert!(names.contains(&b"README.TXT;1".as_slice()));
        assert!(names.contains(&b"ABCDEFGH.DAT;1".as_slice()));
        assert!(names.contains(&b"ABCDE000.DAT;1".as_slice()));
        assert!(names.contains(&b"ABCDE001.DAT;1".as_slice()));
    }

    // ── sub-directory hierarchy ──────────────────────────────────────

    #[test]
    fn layout_preserves_subdirectories() {
        let files = make_tree();
        let layout = compute_layout(&files, "T").unwrap();
        // Both trees carry root + DOCS + TOOLS + SUB = 4 directories.
        assert_eq!(layout.pvd.dirs.len(), 4);
        assert_eq!(layout.joliet.dirs.len(), 4);
        // PVD tree: root, then level-1 DOCS/TOOLS (sorted by 8.3 name), SUB.
        assert_eq!(layout.pvd.dirs[0].number, 1); // root
        assert_eq!(layout.pvd.dirs[0].parent, 1); // root points to itself
        assert_eq!(layout.pvd.dirs[0].lba, 21);
        assert_eq!(layout.pvd.dirs[1].number, 2);
        assert_eq!(layout.pvd.dirs[1].name.as_slice(), b"DOCS");
        assert_eq!(layout.pvd.dirs[2].number, 3);
        assert_eq!(layout.pvd.dirs[2].name.as_slice(), b"TOOLS");
        assert_eq!(layout.pvd.dirs[3].number, 4);
        assert_eq!(layout.pvd.dirs[3].parent, 3);
        // PVD directory LBAs: root 21, DOCS 22, TOOLS 23, SUB 24.
        assert_eq!(layout.pvd.dirs[1].lba, 22);
        assert_eq!(layout.pvd.dirs[2].lba, 23);
        assert_eq!(layout.pvd.dirs[3].lba, 24);
        // Joliet tree has its own extents after the PVD tree.
        assert_eq!(layout.joliet.dirs[0].lba, 27);
        assert_eq!(layout.joliet.dirs[1].lba, 28);
        assert_eq!(layout.joliet.dirs[2].lba, 29);
        assert_eq!(layout.joliet.dirs[3].lba, 30);
        // Files are assigned after both trees, each under its parent.
        assert_eq!(layout.first_file_lba, 31);
        assert_eq!(layout.extents.len(), 4);
        assert_eq!(layout.extents[0].parent, 1); // README.TXT
        assert_eq!(layout.extents[1].parent, 2); // DOCS/MANUAL.PDF
        assert_eq!(layout.extents[2].parent, 3); // TOOLS/SETUP.EXE
        assert_eq!(layout.extents[3].parent, 4); // TOOLS/SUB/X.BIN
        assert_eq!(layout.extents[0].pvd_parent, 1); // same numbering here
        assert_eq!(layout.extents[3].pvd_parent, 4);
        assert_eq!(layout.extents[0].lba, 31);
        assert_eq!(layout.extents[1].lba, 32);
        assert_eq!(layout.extents[2].lba, 33);
        assert_eq!(layout.extents[2].sectors, 2); // 3000 bytes = 2 sectors
        assert_eq!(layout.extents[3].lba, 35);
        assert_eq!(layout.total, 36);
    }

    #[test]
    fn gen_path_table_has_all_dirs() {
        let files = make_tree();
        let layout = compute_layout(&files, "T").unwrap();
        let mut l = [0u8; 2048];
        let mut m = [0u8; 2048];
        // PVD path table L at 19, M at 20 (both 1 sector: root+DOCS+TOOLS+SUB
        // = 10 + 12 + 14 + 12 = 48 bytes).
        assert_eq!(layout.pvd.path_table_sectors, 1);
        assert!(gen_sector(&layout, layout.pvd.path_table_lba, &mut l));
        assert!(gen_sector(
            &layout,
            layout.pvd.path_table_lba + layout.pvd.path_table_sectors,
            &mut m
        ));

        // Type L record 1 (root): name len 1, location = root, parent = 1.
        let o0 = 0usize;
        assert_eq!(l[o0], 1);
        assert_eq!(
            u32::from_le_bytes(l[o0 + 2..o0 + 6].try_into().unwrap()),
            layout.pvd.root_dir_lba
        );
        assert_eq!(u16::from_le_bytes(l[o0 + 6..o0 + 8].try_into().unwrap()), 1);
        assert_eq!(l[o0 + 8], 0x00);

        // Type L record 2 (DOCS): 8.3 name "DOCS" (4 bytes), lba 22, parent 1.
        let o1 = 10usize;
        assert_eq!(l[o1], 4);
        assert_eq!(
            u32::from_le_bytes(l[o1 + 2..o1 + 6].try_into().unwrap()),
            22
        );
        assert_eq!(u16::from_le_bytes(l[o1 + 6..o1 + 8].try_into().unwrap()), 1);
        assert_eq!(&l[o1 + 8..o1 + 12], b"DOCS");

        // Type M table holds the same records with big-endian fields.
        assert_eq!(m[0], 1);
        assert_eq!(
            u32::from_be_bytes(m[2..6].try_into().unwrap()),
            layout.pvd.root_dir_lba
        );
        assert_eq!(u16::from_be_bytes(m[6..8].try_into().unwrap()), 1);
        let o1 = 10usize;
        assert_eq!(
            u32::from_be_bytes(m[o1 + 2..o1 + 6].try_into().unwrap()),
            22
        );
        assert_eq!(u16::from_be_bytes(m[o1 + 6..o1 + 8].try_into().unwrap()), 1);
        assert_eq!(&m[o1 + 8..o1 + 12], b"DOCS");

        // SUB record (4th; offsets 10 + 12 + 14 = 36): name "SUB", parent 3.
        let o3 = 36usize;
        assert_eq!(l[o3], 3);
        assert_eq!(u16::from_le_bytes(l[o3 + 6..o3 + 8].try_into().unwrap()), 3);
        assert_eq!(&l[o3 + 8..o3 + 11], b"SUB");

        // The Joliet path table (at 25) uses UCS-2BE names instead.
        assert_eq!(layout.joliet.path_table_lba, 25);
        let mut j = [0u8; 2048];
        assert!(gen_sector(&layout, layout.joliet.path_table_lba, &mut j));
        let o1 = 10usize;
        assert_eq!(j[o1], 8); // UCS-2 "DOCS" is 8 bytes
        assert_eq!(&j[o1 + 8..o1 + 16], &[0, b'D', 0, b'O', 0, b'C', 0, b'S']);
    }

    #[test]
    fn gen_subdir_directory_records() {
        let files = make_tree();
        let layout = compute_layout(&files, "T").unwrap();
        // SUB (number 4, Joliet lba 30): ".", ".." (→ TOOLS at 29), X.BIN.
        let sub = layout.joliet.dirs[3].clone();
        let tools = layout.joliet.dirs[2].clone();
        let mut sector = [0u8; 2048];
        assert!(gen_sector(&layout, sub.lba, &mut sector));
        // "." record: lba = SUB's own lba.
        assert_eq!(sector[0], 34);
        assert_eq!(
            u32::from_le_bytes(sector[2..6].try_into().unwrap()),
            sub.lba
        );
        // ".." points to SUB's parent, TOOLS.
        assert_eq!(
            u32::from_le_bytes(sector[36..40].try_into().unwrap()),
            tools.lba
        );
        // X.BIN is a file (flag 0x00) and the only non-dot record.
        let mut off = 68usize;
        let mut saw_file = false;
        while off < 2048 && sector[off] != 0 {
            let flags = sector[off + 25];
            if flags == 0x00 {
                saw_file = true;
            }
            off += sector[off] as usize;
        }
        assert!(saw_file, "expected the X.BIN file record");
        // No child directory records in a leaf directory.
        let mut off = 68usize;
        while off < 2048 && sector[off] != 0 {
            assert_ne!(sector[off + 25], 0x02, "leaf dir must not list a child dir");
            off += sector[off] as usize;
        }
    }

    // ── total_sectors ───────────────────────────────────────────────

    #[test]
    fn total_sectors_matches() {
        let files = make_entries();
        let layout = compute_layout(&files, "T").unwrap();
        assert_eq!(total_sectors(&layout), layout.total);
    }

    // ── gen_sector ──────────────────────────────────────────────────

    #[test]
    fn gen_pvd() {
        let files = make_entries();
        let layout = compute_layout(&files, "TEST").unwrap();
        let mut sector = [0u8; 2048];
        assert!(gen_sector(&layout, PVD_LBA, &mut sector));
        assert_eq!(sector[0], 0x01);
        assert_eq!(&sector[1..6], b"CD001");
        assert_eq!(sector[6], 0x01);
        assert_eq!(
            u32::from_le_bytes([sector[80], sector[81], sector[82], sector[83]]),
            layout.total
        );
        assert_eq!(u16::from_le_bytes([sector[128], sector[129]]), 2048);
        assert_eq!(
            u32::from_le_bytes([sector[158], sector[159], sector[160], sector[161]]),
            layout.pvd.root_dir_lba
        );
        // Volume identifier (BP 41-72 → byte 40) = "TEST", space-padded.
        assert_eq!(&sector[40..44], b"TEST");
        assert_eq!(sector[44], b' ');
    }

    #[test]
    fn gen_svd_joliet() {
        let files = make_entries();
        let layout = compute_layout(&files, "JOL").unwrap();
        let mut sector = [0u8; 2048];
        assert!(gen_sector(&layout, SVD_LBA, &mut sector));
        assert_eq!(sector[0], 0x02);
        assert_eq!(&sector[1..6], b"CD001");
        // Joliet escape sequences
        assert_eq!(sector[88], 0x25);
        assert_eq!(sector[89], 0x2F);
        assert_eq!(sector[90], 0x40);
        // Remainder of the field is (00) per ECMA-119 §8.5.6 (strict
        // readers compare the whole 32-byte escape sequence field).
        assert_eq!(&sector[91..120], &[0u8; 29]);
        // UCS-2BE volume ID "JOL" (BP 41-72 → byte 40).
        assert_eq!(sector[40], 0x00);
        assert_eq!(sector[41], b'J');
        assert_eq!(sector[42], 0x00);
        assert_eq!(sector[43], b'O');
        assert_eq!(sector[44], 0x00);
        assert_eq!(sector[45], b'L');
    }

    #[test]
    fn gen_terminator() {
        let files = make_entries();
        let layout = compute_layout(&files, "T").unwrap();
        let mut sector = [0u8; 2048];
        assert!(gen_sector(&layout, TERMINATOR_LBA, &mut sector));
        assert_eq!(sector[0], 0xFF);
        assert_eq!(&sector[1..6], b"CD001");
    }

    #[test]
    fn gen_path_table() {
        let files = make_entries();
        let layout = compute_layout(&files, "T").unwrap();
        let mut sector = [0u8; 2048];
        assert!(gen_sector(&layout, layout.pvd.path_table_lba, &mut sector));
        assert_eq!(sector[0], 0x01); // name length
        assert_eq!(sector[1], 0x00); // ext attr
        assert_eq!(
            u32::from_le_bytes([sector[2], sector[3], sector[4], sector[5]]),
            layout.pvd.root_dir_lba
        );
        assert_eq!(u16::from_le_bytes([sector[6], sector[7]]), 1);
        assert_eq!(sector[8], 0x00);
    }

    #[test]
    fn gen_root_directory_dot_entries() {
        let files = make_entries();
        let layout = compute_layout(&files, "T").unwrap();
        let mut sector = [0u8; 2048];
        gen_sector(&layout, layout.joliet.root_dir_lba, &mut sector);
        // "." entry: name [0x00] is 1 byte (odd) → no padding → rec_len = 34
        assert_eq!(sector[0], 34); // 33 + 1 name (odd, unpadded)
        assert_eq!(sector[25], 0x02); // directory flag
        assert_eq!(sector[32], 0x01); // name length
        assert_eq!(sector[33], 0x00); // root name
                                      // Fixed sentinel recording date (1980-01-01 +0), not zeros.
        assert_eq!(&sector[18..25], &FIXED_RECORDING_DATE);
        // ".." entry starts at offset 34
        assert_eq!(sector[34], 34);
        assert_eq!(sector[34 + 25], 0x02);
        assert_eq!(sector[34 + 33], 0x01); // parent name
        assert_eq!(&sector[34 + 18..34 + 25], &FIXED_RECORDING_DATE);
    }

    #[test]
    fn gen_root_directory_file_entries() {
        let files = make_entries();
        let layout = compute_layout(&files, "T").unwrap();
        let mut sector = [0u8; 2048];
        assert!(gen_sector(&layout, layout.joliet.root_dir_lba, &mut sector));
        // "." (34) + ".." (34) = 68 → first file entry at offset 68
        let o = 68;
        assert_eq!(sector[o + 25], 0x00); // file flag
                                          // Extent LBA = first file (README.TXT)
        assert_eq!(
            u32::from_le_bytes([sector[o + 2], sector[o + 3], sector[o + 4], sector[o + 5]]),
            layout.extents[0].lba
        );
        // Name is Joliet UCS-2BE "README.TXT" (20 bytes)
        assert_eq!(sector[o + 32], 20); // name length
        assert_eq!(sector[o + 33], 0x00); // 'R' high byte
        assert_eq!(sector[o + 34], b'R'); // 'R' low byte
    }

    /// ECMA-119 §9.1: both-endian extent LBA and data length must sit at
    /// record offsets 2/6 and 10/14 respectively. A previous swap put the
    /// data length at 6..10 and the LBA big-endian half at 10..14, so
    /// readers (kernel/isoinfo) reported garbage sizes and corrupted
    /// directory entries.
    #[test]
    fn dir_record_both_endian_layout() {
        let files = make_entries();
        let layout = compute_layout(&files, "T").unwrap();
        let mut sector = [0u8; 2048];
        gen_sector(&layout, layout.joliet.root_dir_lba, &mut sector);
        let o = 68; // first file record ("README.TXT", 1000 B) after "." (34) + ".." (34)
                    // LBA: LE at 2..6, BE at 6..10.
        assert_eq!(
            u32::from_le_bytes(sector[o + 2..o + 6].try_into().unwrap()),
            layout.extents[0].lba
        );
        assert_eq!(
            u32::from_be_bytes(sector[o + 6..o + 10].try_into().unwrap()),
            layout.extents[0].lba
        );
        // Data length (actual file size): LE at 10..14, BE at 14..18.
        assert_eq!(
            u32::from_le_bytes(sector[o + 10..o + 14].try_into().unwrap()),
            1000
        );
        assert_eq!(
            u32::from_be_bytes(sector[o + 14..o + 18].try_into().unwrap()),
            1000
        );
    }

    /// PVD/SVD both-endian 16-bit fields must be interleaved (LE then BE
    /// within the same 4-byte slot), not shifted by a full 4 bytes.
    #[test]
    fn pvd_both_endian_16bit_fields() {
        let files = make_entries();
        let layout = compute_layout(&files, "T").unwrap();
        let mut sector = [0u8; 2048];
        gen_sector(&layout, PVD_LBA, &mut sector);
        // Volume set size (120..124), volume seq number (124..128),
        // logical block size (128..132).
        assert_eq!(u16::from_le_bytes(sector[120..122].try_into().unwrap()), 1);
        assert_eq!(u16::from_be_bytes(sector[122..124].try_into().unwrap()), 1);
        assert_eq!(u16::from_le_bytes(sector[124..126].try_into().unwrap()), 1);
        assert_eq!(u16::from_be_bytes(sector[126..128].try_into().unwrap()), 1);
        assert_eq!(
            u16::from_le_bytes(sector[128..130].try_into().unwrap()),
            SECTOR_SIZE as u16
        );
        assert_eq!(
            u16::from_be_bytes(sector[130..132].try_into().unwrap()),
            SECTOR_SIZE as u16
        );
        // Path table size (132..140): 10 bytes.
        assert_eq!(u32::from_le_bytes(sector[132..136].try_into().unwrap()), 10);
        assert_eq!(u32::from_be_bytes(sector[136..140].try_into().unwrap()), 10);
        // SVD uses the same layout.
        gen_sector(&layout, SVD_LBA, &mut sector);
        assert_eq!(
            u16::from_le_bytes(sector[128..130].try_into().unwrap()),
            2048
        );
        assert_eq!(
            u16::from_be_bytes(sector[130..132].try_into().unwrap()),
            2048
        );
    }

    #[test]
    fn gen_file_data_returns_false() {
        let files = make_entries();
        let layout = compute_layout(&files, "T").unwrap();
        let mut sector = [0u8; 2048];
        assert!(!gen_sector(&layout, layout.first_file_lba, &mut sector));
    }

    #[test]
    fn gen_beyond_image_returns_false() {
        let files = make_entries();
        let layout = compute_layout(&files, "T").unwrap();
        let mut sector = [0u8; 2048];
        assert!(!gen_sector(&layout, layout.total + 100, &mut sector));
    }

    #[test]
    fn gen_system_area_returns_false() {
        let files = make_entries();
        let layout = compute_layout(&files, "T").unwrap();
        let mut sector = [0u8; 2048];
        assert!(!gen_sector(&layout, 5, &mut sector));
    }

    // ── resolve ─────────────────────────────────────────────────────

    #[test]
    fn resolve_first_file() {
        let files = make_entries();
        let layout = compute_layout(&files, "T").unwrap();
        let (idx, offset, remaining) = resolve(&layout, layout.extents[0].lba).unwrap();
        assert_eq!(idx, 0);
        assert_eq!(offset, 0);
        assert_eq!(remaining, 1000);
    }

    #[test]
    fn resolve_second_file() {
        let files = make_entries();
        let layout = compute_layout(&files, "T").unwrap();
        let (idx, offset, remaining) = resolve(&layout, layout.extents[1].lba).unwrap();
        assert_eq!(idx, 1);
        assert_eq!(offset, 0);
        assert_eq!(remaining, 4096);
    }

    #[test]
    fn resolve_second_sector_of_file() {
        let files = make_entries();
        let layout = compute_layout(&files, "T").unwrap();
        let (idx, offset, remaining) = resolve(&layout, layout.extents[1].lba + 1).unwrap();
        assert_eq!(idx, 1);
        assert_eq!(offset, 2048);
        assert_eq!(remaining, 2048); // 4096 - 2048
    }

    #[test]
    fn resolve_metadata_returns_none() {
        let files = make_entries();
        let layout = compute_layout(&files, "T").unwrap();
        assert!(resolve(&layout, PVD_LBA).is_none());
    }

    #[test]
    fn resolve_system_area_returns_none() {
        let files = make_entries();
        let layout = compute_layout(&files, "T").unwrap();
        assert!(resolve(&layout, 5).is_none());
    }

    #[test]
    fn resolve_beyond_returns_none() {
        let files = make_entries();
        let layout = compute_layout(&files, "T").unwrap();
        assert!(resolve(&layout, layout.total + 100).is_none());
    }

    // ── IsoError ────────────────────────────────────────────────────

    #[test]
    fn iso_error_display() {
        // Verify Display impl doesn't panic (no alloc in no_std, so we
        // can't easily capture the string; just call fmt directly).
        let err = IsoError::TooManyFiles;
        let mut buf = [0u8; 64];
        let mut writer = BufWriter(&mut buf);
        core::fmt::Write::write_fmt(&mut writer, format_args!("{err}")).ok();
        // At least check it wrote something.
        assert!(writer.0.iter().any(|&b| b != 0));
    }

    struct BufWriter<'a>(&'a mut [u8]);
    impl core::fmt::Write for BufWriter<'_> {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            let bytes = s.as_bytes();
            let len = bytes.len().min(self.0.len());
            self.0[..len].copy_from_slice(&bytes[..len]);
            Ok(())
        }
    }
}
