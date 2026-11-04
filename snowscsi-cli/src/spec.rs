//! `snowscsi serve` device/backing spec parsing.
//!
//! Two flags share one grammar: `--block` drives [`DeviceRole::BlockDisk`]
//! (or [`DeviceRole::BlockCd`] with `profile=cd`), `--cdrom` drives
//! [`DeviceRole::MmcCd`]. The surface is:
//!
//! ```text
//! SPEC    := <backing>[=<value>][,<opt>...]
//! backing := img=<file> | bundle=<dir> | ram=<size> | live=<dir>
//!          | dvdram=<path|ram:<size>> | empty
//! opt     := profile=block|cd | ro | sector=512|2048 | size=<size> | removable
//!          | cipher[=<manifest|sidecar>] | key=<path>
//! ```
//!
//! `bundle=<dir>` names a directory that must already contain a canonical
//! `SNOWBUNDLE` manifest; the manifest's `kind` selects between a flat
//! chunked disk and a recordable CD. `serve` never creates the bundle
//! directory, manifest or TOC: `snowscsi bundle-create` is the only creator,
//! although serving does create chunk/track files and write TOC snapshots.
//! `snowscsi bundle-info` reports what a directory or sidecar describes.
//!
//! `cipher` marks an `img=` or `bundle=` LUN as encrypted; its key material
//! comes from the manifest (KDF + salt + nonce) and either a password or a
//! `key=<path>` file. `cipher=<path>` overrides the manifest location (the
//! default is `<dir>/SNOWBUNDLE` for a bundle and `<file>.SNOWBUNDLE` for an
//! image). `removable` and the non-file backings cannot carry a cipher.
//!
//! Parsing is a pure function (no filesystem access): whether an `img=` path
//! exists, or which `kind` a `bundle=` manifest carries, is decided when the
//! device is built.

/// The flag a spec came from (which fixes the legal backing set).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DeviceFamily {
    Block,
    Cdrom,
}

impl DeviceFamily {
    fn flag(self) -> &'static str {
        match self {
            Self::Block => "--block",
            Self::Cdrom => "--cdrom",
        }
    }
}

/// Which SCSI device a spec constructs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DeviceRole {
    /// `BlockDevice::disk` — writable PDT 0x00.
    BlockDisk,
    /// `BlockDevice::cdrom` — read-only PDT 0x05 (`profile=cd`).
    BlockCd,
    /// Core `MmcDrive` — full MMC optical drive (`--cdrom`).
    MmcCd,
}

/// Where the bytes come from.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Backing {
    /// `img=<file>` — a flat file (FileBackend), or a flat ISO for MMC.
    Img { path: String },
    /// `bundle=<dir>` — a directory carrying a canonical `SNOWBUNDLE`
    /// manifest. Its `kind` selects a directory-chunked flat plane or a
    /// recordable CD (alternating `toc.0`/`toc.1` slots plus
    /// `track_<n>.bin`). The directory and manifest must already exist.
    Bundle { dir: String },
    /// `ram=<size>` — a memory-backed device.
    Ram { size: u64 },
    /// `live=<dir>` — live ISO9660 over a directory (MMC only).
    Live { dir: String },
    /// `dvdram=<path>` or `dvdram=ram:<size>` — DVD-RAM (MMC only).
    /// `path = None` means memory (the size lives in [`PlaneOpts`]).
    DvdRam { path: Option<String> },
    /// `empty` — an enumerated drive with no medium (MMC only). The first
    /// medium is installed by the application; the LUN has no byte plane.
    Empty,
}

/// Plane/geometry options common to a device spec.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PlaneOpts {
    /// Read-only plane (implied for the optical roles).
    pub read_only: bool,
    /// Logical sector size (512 default; only used by the block-disk role).
    pub sector: u32,
    /// Size of a new `dvdram=` file. A `bundle=` manifest owns all geometry.
    pub size: Option<u64>,
}

/// Cipher selection for a device, if any.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CipherSpec {
    /// Explicit manifest/sidecar path (`cipher=<path>`), or `None` for the
    /// backing's default location.
    pub meta: Option<String>,
}

/// One parsed device, ready to be built.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DeviceSpec {
    /// The raw flag value, for diagnostics.
    pub raw: String,
    pub role: DeviceRole,
    pub backing: Backing,
    pub plane: PlaneOpts,
    /// The LUN's medium is removable (INQUIRY RMB; host START STOP UNIT
    /// ejects it). Only legal for `--block img=<file>` without
    /// `profile=cd`; the `--usb` demo uses it for a card reader.
    pub removable: bool,
    /// The LUN is encrypted (`cipher` / `cipher=<path>`).
    pub cipher: Option<CipherSpec>,
    /// Raw key file (`key=<path>`); only meaningful with [`Self::cipher`].
    /// The password is never stored here.
    pub key: Option<String>,
}

/// Parse every `--block` then every `--cdrom` value into LUN order.
///
/// The returned vector is ordered block-first, matching the LUN numbering.
pub fn parse_all(block: &[String], cdrom: &[String]) -> Result<Vec<DeviceSpec>, String> {
    let mut specs = Vec::with_capacity(block.len() + cdrom.len());
    for raw in block {
        let spec = parse_device_spec(raw, DeviceFamily::Block)
            .map_err(|e| format!("invalid --block spec '{raw}': {e}"))?;
        specs.push(spec);
    }
    for raw in cdrom {
        let spec = parse_device_spec(raw, DeviceFamily::Cdrom)
            .map_err(|e| format!("invalid --cdrom spec '{raw}': {e}"))?;
        specs.push(spec);
    }
    if let Some(dir) = duplicate_bundle_dir(&specs) {
        return Err(format!(
            "bundle directory '{dir}' is served by more than one LUN; \
             use one directory per bundle"
        ));
    }
    Ok(specs)
}

/// The first bundle directory served by more than one LUN, if any.
///
/// Two writers over one directory would interleave TOC saves (or chunk
/// writes) and corrupt the bundle, so this is an error rather than the
/// dual-mount warning.
pub fn duplicate_bundle_dir(specs: &[DeviceSpec]) -> Option<&str> {
    let mut seen = std::collections::HashSet::new();
    for spec in specs {
        if let Backing::Bundle { dir } = &spec.backing {
            if !seen.insert(dir.as_str()) {
                return Some(dir.as_str());
            }
        }
    }
    None
}

/// Parse one `<backing>[=<value>][,<opt>...]` value for `family`.
pub fn parse_device_spec(input: &str, family: DeviceFamily) -> Result<DeviceSpec, String> {
    let (backing_expr, opts_str) = match input.split_once(',') {
        Some((b, o)) => (b, o),
        None => (input, ""),
    };
    let opts = parse_opts(opts_str)?;
    let (backing, implicit_size) = parse_backing(backing_expr)?;

    // `dvdram=ram:<size>` carries its own size and takes no options at all.
    if matches!(backing, Backing::DvdRam { path: None }) && !opts_str.is_empty() {
        return Err("dvdram=ram:<size> takes no options".to_string());
    }
    // An empty drive has no plane, so plane/geometry options are meaningless.
    if matches!(backing, Backing::Empty) && !opts_str.is_empty() {
        return Err("empty takes no options".to_string());
    }
    if implicit_size.is_some() && opts.size.is_some() {
        return Err("size= is not allowed with dvdram=ram:<size>".to_string());
    }

    let profile = parse_block_profile(family, opts.profile.as_deref())?;
    let role = match (family, profile) {
        (DeviceFamily::Block, Some(BlockProfile::Disk)) => DeviceRole::BlockDisk,
        (DeviceFamily::Block, Some(BlockProfile::Cd)) => DeviceRole::BlockCd,
        (DeviceFamily::Block, None) => unreachable!("--block always has a profile"),
        (DeviceFamily::Cdrom, None) => DeviceRole::MmcCd,
        (DeviceFamily::Cdrom, Some(_)) => unreachable!("--cdrom rejects profile="),
    };

    check_backing(family, &backing)?;
    check_opts(family, profile, &backing, &opts)?;

    let size = opts.size.or(implicit_size);

    // The optical roles are read-only for flat media. A `bundle=` under
    // `--cdrom` is left writable here because its manifest may describe a
    // recordable CD; once the kind is known, `build_planes` forces a flat
    // bundle read-only while a CD-R keeps its writable-only policy.
    let implicit_read_only = match role {
        DeviceRole::BlockCd => true,
        DeviceRole::MmcCd => !matches!(backing, Backing::Bundle { .. }),
        DeviceRole::BlockDisk => false,
    };
    let read_only = implicit_read_only || opts.read_only;
    Ok(DeviceSpec {
        raw: input.to_string(),
        role,
        backing,
        plane: PlaneOpts {
            read_only,
            sector: opts.sector.unwrap_or(512),
            size,
        },
        removable: opts.removable,
        cipher: opts.cipher.map(|meta| CipherSpec { meta }),
        key: opts.key,
    })
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum BlockProfile {
    Disk,
    Cd,
}

fn parse_block_profile(
    family: DeviceFamily,
    raw: Option<&str>,
) -> Result<Option<BlockProfile>, String> {
    match family {
        DeviceFamily::Block => match raw.unwrap_or("block") {
            "block" => Ok(Some(BlockProfile::Disk)),
            "cd" => Ok(Some(BlockProfile::Cd)),
            other => Err(format!("invalid profile '{other}' (block or cd)")),
        },
        DeviceFamily::Cdrom => match raw {
            None => Ok(None),
            Some(p) => Err(format!("profile={p} is only valid for --block")),
        },
    }
}

fn parse_backing(expr: &str) -> Result<(Backing, Option<u64>), String> {
    if expr == "empty" {
        Ok((Backing::Empty, None))
    } else if let Some(v) = expr.strip_prefix("img=") {
        if v.is_empty() {
            return Err("empty img= path".to_string());
        }
        Ok((
            Backing::Img {
                path: v.to_string(),
            },
            None,
        ))
    } else if let Some(v) = expr.strip_prefix("bundle=") {
        if v.is_empty() {
            return Err("empty bundle= path".to_string());
        }
        Ok((Backing::Bundle { dir: v.to_string() }, None))
    } else if let Some(v) = expr.strip_prefix("ram=") {
        let n = parse_size(v).ok_or_else(|| format!("invalid RAM size '{v}'"))?;
        Ok((Backing::Ram { size: n }, None))
    } else if let Some(v) = expr.strip_prefix("live=") {
        if v.is_empty() {
            return Err("empty live= path".to_string());
        }
        Ok((Backing::Live { dir: v.to_string() }, None))
    } else if let Some(v) = expr.strip_prefix("dvdram=") {
        if let Some(sz) = v.strip_prefix("ram:") {
            let n = parse_size(sz).ok_or_else(|| format!("invalid dvdram RAM size '{sz}'"))?;
            Ok((Backing::DvdRam { path: None }, Some(n)))
        } else {
            if v.is_empty() {
                return Err("empty dvdram= path".to_string());
            }
            Ok((
                Backing::DvdRam {
                    path: Some(v.to_string()),
                },
                None,
            ))
        }
    } else {
        Err(format!(
            "unknown backing '{expr}'; expected img=, bundle=, ram=, live=, dvdram=, or empty"
        ))
    }
}

fn check_backing(family: DeviceFamily, backing: &Backing) -> Result<(), String> {
    let ok = match family {
        DeviceFamily::Block => matches!(
            backing,
            Backing::Img { .. } | Backing::Bundle { .. } | Backing::Ram { .. }
        ),
        DeviceFamily::Cdrom => matches!(
            backing,
            Backing::Img { .. }
                | Backing::Bundle { .. }
                | Backing::Live { .. }
                | Backing::DvdRam { .. }
                | Backing::Empty
        ),
    };
    if ok {
        return Ok(());
    }
    let key = match backing {
        Backing::Img { .. } => "img",
        Backing::Bundle { .. } => "bundle",
        Backing::Ram { .. } => "ram",
        Backing::Live { .. } => "live",
        Backing::DvdRam { .. } => "dvdram",
        Backing::Empty => "empty",
    };
    Err(format!("{key}= is not valid for {}", family.flag()))
}

fn check_opts(
    family: DeviceFamily,
    profile: Option<BlockProfile>,
    backing: &Backing,
    opts: &RawOpts,
) -> Result<(), String> {
    // A build without the cipher layer keeps the spec fields but rejects the
    // options: the plane decorator and key derivation are compiled out.
    #[cfg(not(feature = "cipher"))]
    if opts.cipher.is_some() || opts.key.is_some() {
        return Err(
            "cipher/key= requires the `cipher` feature: rebuild with --features cipher".to_string(),
        );
    }
    #[cfg(feature = "cipher")]
    {
        if opts.cipher.is_some() && !matches!(backing, Backing::Img { .. } | Backing::Bundle { .. })
        {
            return Err("cipher is only valid with img= or bundle=<dir>".to_string());
        }
        if opts.cipher.is_some() && opts.removable {
            // The card-insert path runs after the password is gone, so an
            // encrypted removable card cannot be re-opened in place.
            return Err(
                "removable is not supported with cipher (the password would be gone after \
                 the card is inserted)"
                    .to_string(),
            );
        }
        if opts.key.is_some() && opts.cipher.is_none() {
            return Err("key= requires cipher".to_string());
        }
    }

    let is_bundle = matches!(backing, Backing::Bundle { .. });
    let is_dvdram_file = matches!(backing, Backing::DvdRam { path: Some(_) });

    if is_bundle {
        // The manifest owns the bundle geometry and media kind: neither a
        // block/geometry override nor a size applies. `ro` is accepted here;
        // `build_planes` rejects it for a recordable CD, which is
        // writable-only, and opens a flat bundle read-only.
        if opts.sector.is_some() {
            return Err(
                "sector= is not valid with bundle=<dir> (the manifest owns the geometry)"
                    .to_string(),
            );
        }
        if opts.size.is_some() {
            return Err("size= is not valid with bundle=<dir>".to_string());
        }
    }

    if opts.sector.is_some() {
        match (family, profile) {
            (DeviceFamily::Cdrom, _) => return Err("sector= is only valid for --block".to_string()),
            (DeviceFamily::Block, Some(BlockProfile::Cd)) => {
                return Err("sector= is fixed at 2048 for profile=cd".to_string())
            }
            _ => {}
        }
    }
    if opts.size.is_some() && !(family == DeviceFamily::Cdrom && is_dvdram_file) {
        return Err(
            "size= is only valid for --cdrom dvdram=<path> (creating a missing file)".to_string(),
        );
    }
    if opts.ro_seen && family == DeviceFamily::Cdrom && matches!(backing, Backing::DvdRam { .. }) {
        return Err(
            "ro is not valid with --cdrom dvdram= (DVD-RAM is random-writable)".to_string(),
        );
    }
    if opts.removable {
        if family != DeviceFamily::Block {
            return Err("removable is only valid for --block".to_string());
        }
        if profile != Some(BlockProfile::Disk) {
            return Err("removable requires --block profile=block".to_string());
        }
        if !matches!(backing, Backing::Img { .. }) {
            return Err("removable requires --block img=<file>".to_string());
        }
    }
    Ok(())
}

#[derive(Default)]
struct RawOpts {
    profile: Option<String>,
    read_only: bool,
    ro_seen: bool,
    sector: Option<u32>,
    size: Option<u64>,
    removable: bool,
    removable_seen: bool,
    /// `None` = absent, `Some(None)` = bare `cipher`, `Some(Some(path))` =
    /// `cipher=<path>`.
    cipher: Option<Option<String>>,
    key: Option<String>,
}

fn parse_opts(s: &str) -> Result<RawOpts, String> {
    let mut o = RawOpts::default();
    for opt in s.split(',') {
        if opt.is_empty() {
            continue;
        }
        if let Some(v) = opt.strip_prefix("profile=") {
            if o.profile.is_some() {
                return Err("duplicate profile=".to_string());
            }
            o.profile = Some(v.to_string());
        } else if opt == "ro" {
            if o.ro_seen {
                return Err("duplicate ro".to_string());
            }
            o.ro_seen = true;
            o.read_only = true;
        } else if let Some(v) = opt.strip_prefix("sector=") {
            if o.sector.is_some() {
                return Err("duplicate sector=".to_string());
            }
            let n: u32 = v.parse().map_err(|_| format!("invalid sector '{v}'"))?;
            if n != 512 && n != 2048 {
                return Err(format!("invalid sector size {n} (512 or 2048)"));
            }
            o.sector = Some(n);
        } else if let Some(v) = opt.strip_prefix("size=") {
            if o.size.is_some() {
                return Err("duplicate size=".to_string());
            }
            o.size = Some(parse_size(v).ok_or_else(|| format!("invalid size '{v}'"))?);
        } else if opt == "removable" {
            if o.removable_seen {
                return Err("duplicate removable".to_string());
            }
            o.removable_seen = true;
            o.removable = true;
        } else if opt == "cipher" {
            if o.cipher.is_some() {
                return Err("duplicate cipher".to_string());
            }
            o.cipher = Some(None);
        } else if let Some(v) = opt.strip_prefix("cipher=") {
            if o.cipher.is_some() {
                return Err("duplicate cipher".to_string());
            }
            if v.is_empty() {
                return Err("empty cipher= path".to_string());
            }
            o.cipher = Some(Some(v.to_string()));
        } else if let Some(v) = opt.strip_prefix("key=") {
            if o.key.is_some() {
                return Err("duplicate key=".to_string());
            }
            if v.is_empty() {
                return Err("empty key= path".to_string());
            }
            o.key = Some(v.to_string());
        } else {
            // The old bundle-creation knobs live on `snowscsi bundle-create`
            // now; name them so a stale command line is actionable.
            if let Some((key, _)) = opt.split_once('=') {
                if matches!(key, "chunk" | "medium" | "slot" | "recovery") {
                    return Err(format!(
                        "{key}= is not a serve option; create the bundle with \
                         `snowscsi bundle-create`"
                    ));
                }
            }
            return Err(format!("unknown option '{opt}'"));
        }
    }
    Ok(o)
}

/// Parse a size with an optional K/M/G suffix (C `parse_size`).
/// Returns `None` for empty, non-numeric, unsupported-suffix, zero, or
/// overflowing input (C's convention: 0 == invalid).
pub fn parse_size(s: &str) -> Option<u64> {
    let digit_len = s.bytes().take_while(|b| b.is_ascii_digit()).count();
    let digits = &s[..digit_len];
    if digits.is_empty() {
        return None;
    }
    let mut val: u64 = digits.parse().ok()?;
    let suffix = &s[digit_len..];
    match suffix {
        "" => {}
        "K" | "k" => val = val.checked_mul(1 << 10)?,
        "M" | "m" => val = val.checked_mul(1 << 20)?,
        "G" | "g" => val = val.checked_mul(1 << 30)?,
        _ => return None,
    }
    (val != 0).then_some(val)
}

/// A `(path, role label)` pair for every spec that names a host path.
type MountedPath<'a> = (&'a str, &'a str);

fn role_label(role: DeviceRole) -> &'static str {
    match role {
        DeviceRole::BlockDisk => "block",
        DeviceRole::BlockCd => "cdblock",
        DeviceRole::MmcCd => "cdrom",
    }
}

/// Collect `(path, role)` for every spec that names a host path (RAM devices
/// have none).
pub fn mounted_paths(specs: &[DeviceSpec]) -> Vec<MountedPath<'_>> {
    specs
        .iter()
        .filter_map(|s| {
            let kind = role_label(s.role);
            match &s.backing {
                Backing::Img { path } => Some((path.as_str(), kind)),
                Backing::Bundle { dir } => Some((dir.as_str(), kind)),
                Backing::Live { dir } => Some((dir.as_str(), kind)),
                Backing::DvdRam { path: Some(p) } => Some((p.as_str(), kind)),
                Backing::DvdRam { path: None } | Backing::Ram { .. } | Backing::Empty => None,
            }
        })
        .collect()
}

/// Detect the same path mounted as multiple independent SCSI devices and
/// return the stderr warning lines. A path appearing more than once in total
/// (same or different roles) is warned: each occurrence is a distinct LUN
/// with its own LBA semantics.
pub fn check_dual_mount(specs: &[DeviceSpec]) -> Vec<String> {
    let mut seen: std::collections::HashMap<&str, Vec<&str>> = std::collections::HashMap::new();
    for (path, kind) in mounted_paths(specs) {
        seen.entry(path).or_default().push(kind);
    }
    let mut warnings = Vec::new();
    for (path, kinds) in seen {
        if kinds.len() > 1 {
            warnings.push(format!(
                "warning: path '{path}' is mounted as {kinds:?}; these are \
                 independent SCSI devices with different LBA semantics"
            ));
        }
    }
    warnings
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(spec: &str) -> Result<DeviceSpec, String> {
        parse_device_spec(spec, DeviceFamily::Block)
    }

    fn cdrom(spec: &str) -> Result<DeviceSpec, String> {
        parse_device_spec(spec, DeviceFamily::Cdrom)
    }

    #[test]
    fn parse_size_plain_and_suffixes() {
        assert_eq!(parse_size("512"), Some(512));
        assert_eq!(parse_size("1K"), Some(1024));
        assert_eq!(parse_size("1k"), Some(1024));
        assert_eq!(parse_size("2M"), Some(2 * 1024 * 1024));
        assert_eq!(parse_size("1G"), Some(1024 * 1024 * 1024));
        assert_eq!(parse_size("256M"), Some(256 * 1024 * 1024));
    }

    #[test]
    fn parse_size_invalid() {
        assert_eq!(parse_size(""), None);
        assert_eq!(parse_size("abc"), None);
        assert_eq!(parse_size("12X"), None);
        assert_eq!(parse_size("0"), None); // C: size 0 → invalid
        assert_eq!(parse_size("0M"), None);
        assert_eq!(parse_size("-5"), None);
        assert_eq!(parse_size("18446744073709551615G"), None); // overflow
    }

    #[test]
    fn block_disk_img() {
        let s = block("img=disk.img").unwrap();
        assert_eq!(s.role, DeviceRole::BlockDisk);
        assert_eq!(
            s.backing,
            Backing::Img {
                path: "disk.img".to_string()
            }
        );
        assert!(!s.plane.read_only);
        assert_eq!(s.plane.sector, 512);
    }

    #[test]
    fn block_disk_img_read_only() {
        let s = block("img=disk.img,ro").unwrap();
        assert!(s.plane.read_only);
    }

    #[test]
    fn block_img_honours_sector() {
        let s = block("img=card.img,sector=2048,removable").unwrap();
        assert_eq!(s.plane.sector, 2048);
        assert!(s.removable);
    }

    #[test]
    fn block_img_can_be_removable() {
        let s = block("img=card.img,removable").unwrap();
        assert!(s.removable);
        assert_eq!(s.role, DeviceRole::BlockDisk);
        let explicit = block("img=card.img,profile=block,removable,ro").unwrap();
        assert!(explicit.removable);
        assert_eq!(explicit.role, DeviceRole::BlockDisk);
        assert!(!block("img=card.img").unwrap().removable);
    }

    #[test]
    fn removable_is_only_valid_for_block_img() {
        assert!(block("img=x,profile=cd,removable").is_err());
        assert!(block("bundle=tree,removable").is_err());
        assert!(block("ram=1M,removable").is_err());
        assert!(cdrom("img=x,removable").is_err());
        assert!(block("img=x,removable,removable").is_err());
    }

    #[test]
    fn block_disk_ram() {
        let s = block("ram=8M").unwrap();
        assert_eq!(
            s.backing,
            Backing::Ram {
                size: 8 * 1024 * 1024
            }
        );
    }

    #[test]
    fn block_disk_ram_invalid() {
        assert!(block("ram=bogus").is_err());
        assert!(block("ram=").is_err());
        assert!(block("ram=0").is_err());
    }

    #[test]
    fn block_disk_bundle() {
        let s = block("bundle=tree").unwrap();
        assert_eq!(s.role, DeviceRole::BlockDisk);
        assert_eq!(
            s.backing,
            Backing::Bundle {
                dir: "tree".to_string()
            }
        );
        // The manifest owns the geometry: no spec-level sector/size override.
        assert_eq!(s.plane.sector, 512);
        assert!(!s.plane.read_only);
        assert!(s.plane.size.is_none());

        let ro = block("bundle=tree,ro").unwrap();
        assert!(ro.plane.read_only);

        let cd = block("bundle=tree,profile=cd").unwrap();
        assert_eq!(cd.role, DeviceRole::BlockCd);
        assert!(cd.plane.read_only);
        assert!(block("bundle=tree,profile=cd,ro").is_ok());
    }

    #[test]
    fn block_bundle_rejects_geometry_overrides() {
        assert!(block("bundle=tree,sector=2048").is_err());
        assert!(block("bundle=tree,size=8M").is_err());
        assert!(block("bundle=tree,chunk=1M").is_err());
        assert!(block("bundle=tree,medium=cdr74").is_err());
    }

    #[test]
    fn block_cd_profile() {
        let s = block("img=boot.iso,profile=cd").unwrap();
        assert_eq!(s.role, DeviceRole::BlockCd);
        // The optical profile is always read-only; `ro` is an explicit no-op.
        assert!(s.plane.read_only);
        assert!(block("img=boot.iso,profile=cd,ro").is_ok());
        assert!(block("bundle=tree,profile=cd").is_ok());
        assert!(block("ram=1M,profile=cd").is_ok());
    }

    #[test]
    fn block_profile_rejects_sector() {
        assert!(block("img=x,profile=cd,sector=2048").is_err());
        assert!(block("img=x,profile=bogus").is_err());
    }

    #[test]
    fn block_rejects_cdrom_backings() {
        assert!(block("live=tree").is_err());
        assert!(block("dvdram=disc.img").is_err());
    }

    #[test]
    fn block_img_rejects_bundle_opts() {
        assert!(block("img=disk.img,chunk=1M").is_err());
        assert!(block("img=disk.img,size=8M").is_err());
        assert!(block("img=disk.img,mkfs").is_err());
    }

    #[test]
    fn cdrom_flat_and_live() {
        let flat = cdrom("img=boot.iso").unwrap();
        assert_eq!(flat.role, DeviceRole::MmcCd);
        assert_eq!(
            flat.backing,
            Backing::Img {
                path: "boot.iso".to_string()
            }
        );
        assert!(flat.plane.read_only);

        let live = cdrom("live=tree").unwrap();
        assert_eq!(
            live.backing,
            Backing::Live {
                dir: "tree".to_string()
            }
        );
    }

    #[test]
    fn cdrom_accepts_a_bundle() {
        let s = cdrom("bundle=tree").unwrap();
        assert_eq!(s.role, DeviceRole::MmcCd);
        assert_eq!(
            s.backing,
            Backing::Bundle {
                dir: "tree".to_string()
            }
        );
        // A bundle may be a writable recordable CD; `ro` is explicit.
        assert!(!s.plane.read_only);
        assert!(cdrom("bundle=tree,ro").unwrap().plane.read_only);
    }

    #[test]
    fn cdrom_dvdram_file_and_ram() {
        let file = cdrom("dvdram=disc.img").unwrap();
        assert_eq!(
            file.backing,
            Backing::DvdRam {
                path: Some("disc.img".to_string())
            }
        );

        let new = cdrom("dvdram=disc.img,size=4G").unwrap();
        assert_eq!(new.plane.size, Some(4 << 30));

        let ram = cdrom("dvdram=ram:16M").unwrap();
        assert_eq!(ram.backing, Backing::DvdRam { path: None });
        assert_eq!(ram.plane.size, Some(16 << 20));

        // DVD-RAM is random-writable; a read-only plane is meaningless.
        assert!(cdrom("dvdram=disc.img,ro").is_err());
        assert!(cdrom("dvdram=ram:16M,ro").is_err());
    }

    #[test]
    fn cdrom_rejects_block_backings_and_opts() {
        assert!(cdrom("ram=16M").is_err());
        assert!(cdrom("img=boot.iso,profile=block").is_err());
        assert!(cdrom("img=boot.iso,sector=512").is_err());
        assert!(cdrom("img=boot.iso,chunk=1M").is_err());
        assert!(cdrom("bundle=tree,sector=2048").is_err());
        assert!(cdrom("bundle=tree,size=1M").is_err());
        assert!(cdrom("bundle=tree,chunk=1M").is_err());
    }

    #[test]
    fn dvdram_ram_takes_no_options() {
        assert!(cdrom("dvdram=ram:16M,size=8M").is_err());
    }

    #[test]
    fn size_is_only_for_a_new_dvdram_file() {
        assert!(cdrom("dvdram=disc.img,size=1M").is_ok());
        assert!(cdrom("bundle=tree,size=1M").is_err());
        assert!(block("bundle=tree,size=1M").is_err());
        assert!(block("img=x,size=1M").is_err());
        assert!(block("ram=1M,size=1M").is_err());
        assert!(cdrom("img=x,size=1M").is_err());
        assert!(cdrom("live=x,size=1M").is_err());
        assert!(cdrom("empty,size=1M").is_err());
    }

    #[test]
    fn removed_serve_options_are_rejected() {
        for opt in ["chunk=1M", "medium=cdr74", "slot=8K", "recovery=delete"] {
            for spec in [format!("bundle=d,{opt}"), format!("img=x,{opt}")] {
                let err = block(&spec).expect_err("removed serve option must be rejected");
                assert!(err.contains("bundle-create"), "{spec}: {err}");
            }
        }
    }

    #[test]
    fn bare_and_unknown_specs_rejected() {
        // No suffix/key auto-typing: a bare value has no backing key.
        assert!(cdrom("boot.iso").is_err());
        assert!(block("disk.img").is_err());
        assert!(block("img=x,bogus").is_err());
        assert!(cdrom("img=x,whatever").is_err());
        assert!(block("").is_err());
    }

    #[test]
    fn duplicates_rejected() {
        assert!(block("img=x,ro,ro").is_err());
        assert!(block("bundle=d,size=1M,size=2M").is_err());
        assert!(block("bundle=d,chunk=1M,chunk=2M").is_err());
        assert!(block("img=x,profile=block,profile=cd").is_err());
        assert!(cdrom("dvdram=x,size=1M,size=2M").is_err());
    }

    #[test]
    fn parse_all_orders_block_before_cdrom() {
        let block = vec!["img=a.img".to_string(), "ram=1M".to_string()];
        let cdrom = vec!["img=b.iso".to_string()];
        let specs = parse_all(&block, &cdrom).unwrap();
        assert_eq!(specs.len(), 3);
        assert_eq!(specs[0].role, DeviceRole::BlockDisk);
        assert_eq!(specs[1].role, DeviceRole::BlockDisk);
        assert_eq!(specs[2].role, DeviceRole::MmcCd);
    }

    #[test]
    fn parse_all_reports_flag() {
        let err = parse_all(&["img=a,bogus".to_string()], &[]).unwrap_err();
        assert!(err.contains("--block"), "{err}");
        let err = parse_all(&[], &["img=a,bogus".to_string()]).unwrap_err();
        assert!(err.contains("--cdrom"), "{err}");
    }

    #[test]
    fn dual_mount_same_path_warns() {
        let specs = parse_all(&["img=a.img".to_string(), "img=a.img".to_string()], &[]).unwrap();
        let w = check_dual_mount(&specs);
        assert_eq!(w.len(), 1);
        assert!(w[0].contains("a.img"));
        assert!(w[0].starts_with("warning:"));
    }

    #[test]
    fn dual_mount_distinct_paths_do_not_warn() {
        let specs = parse_all(&["img=a.img".to_string(), "img=b.img".to_string()], &[]).unwrap();
        assert!(check_dual_mount(&specs).is_empty());
    }

    #[test]
    fn dual_mount_block_and_cdrom_warns() {
        let specs =
            parse_all(&["img=boot.iso".to_string()], &["img=boot.iso".to_string()]).unwrap();
        let w = check_dual_mount(&specs);
        assert_eq!(w.len(), 1);
        assert!(w[0].contains("boot.iso"));
    }

    #[test]
    fn dual_mount_ram_not_collected() {
        let specs = parse_all(
            &["ram=1M".to_string(), "bundle=d".to_string()],
            &["dvdram=ram:16M".to_string()],
        )
        .unwrap();
        // Only the bundle directory carries a path.
        assert_eq!(mounted_paths(&specs), vec![("d", "block")]);
        assert!(check_dual_mount(&specs).is_empty());
    }

    #[test]
    fn empty_is_a_cdrom_only_backing() {
        let spec = cdrom("empty").expect("empty cdrom");
        assert_eq!(spec.role, DeviceRole::MmcCd);
        assert_eq!(spec.backing, Backing::Empty);
        assert!(block("empty").is_err(), "a block LUN always has bytes");
        assert!(cdrom("empty,ro").is_err(), "an empty tray has no plane");
    }

    #[test]
    fn bundle_dir_is_a_mounted_path() {
        let specs = parse_all(&[], &["bundle=/tmp/disc".to_string()]).unwrap();
        assert_eq!(mounted_paths(&specs), vec![("/tmp/disc", "cdrom")]);
        assert!(check_dual_mount(&specs).is_empty());

        let specs = parse_all(
            &["bundle=/tmp/a".to_string()],
            &["bundle=/tmp/b".to_string()],
        )
        .unwrap();
        assert!(check_dual_mount(&specs).is_empty());
    }

    #[test]
    fn duplicate_bundle_dirs_are_rejected() {
        let err = parse_all(
            &[],
            &[
                "bundle=/tmp/disc".to_string(),
                "bundle=/tmp/disc".to_string(),
            ],
        )
        .unwrap_err();
        assert!(err.contains("more than one LUN"), "{err}");

        assert!(parse_all(
            &[],
            &["bundle=/tmp/a".to_string(), "bundle=/tmp/b".to_string()]
        )
        .is_ok());
        // The same directory is a single writer even across the two flags.
        let err = parse_all(
            &["bundle=/tmp/disc".to_string()],
            &["bundle=/tmp/disc".to_string()],
        )
        .unwrap_err();
        assert!(err.contains("more than one LUN"), "{err}");
    }

    #[cfg(feature = "cipher")]
    #[test]
    fn cipher_grammar_accepts_img_and_bundle() {
        let img = block("img=disk.img,cipher").unwrap();
        assert_eq!(img.cipher, Some(CipherSpec { meta: None }));
        assert_eq!(img.key, None);

        let bundle = block("bundle=tree,cipher=/tmp/m").unwrap();
        assert_eq!(
            bundle.cipher,
            Some(CipherSpec {
                meta: Some("/tmp/m".to_string())
            })
        );

        let keyed = cdrom("img=boot.iso,cipher,key=/tmp/key.bin").unwrap();
        assert_eq!(keyed.cipher, Some(CipherSpec { meta: None }));
        assert_eq!(keyed.key.as_deref(), Some("/tmp/key.bin"));

        let cd = cdrom("bundle=tree,cipher").unwrap();
        assert_eq!(cd.cipher, Some(CipherSpec { meta: None }));
    }

    #[cfg(feature = "cipher")]
    #[test]
    fn cipher_grammar_rejects_illegal_backings() {
        // `ram=` is block-only, the other two are cdrom-only.
        for (parse, spec) in [
            (
                block as fn(&str) -> Result<DeviceSpec, String>,
                "ram=1M,cipher",
            ),
            (cdrom, "live=tree,cipher"),
            (cdrom, "dvdram=disc.img,cipher"),
        ] {
            let err = parse(spec).expect_err("illegal cipher backing must be rejected");
            assert!(
                err.contains("only valid with img= or bundle="),
                "{spec}: {err}"
            );
        }
        // `empty` takes no options at all, so the generic option gate wins.
        assert!(cdrom("empty,cipher").is_err());

        let err = block("img=card.img,removable,cipher").unwrap_err();
        assert!(
            err.contains("removable is not supported with cipher"),
            "{err}"
        );
    }

    #[cfg(feature = "cipher")]
    #[test]
    fn cipher_grammar_rejects_key_alone_duplicates_and_empty_paths() {
        assert!(block("img=x,key=/tmp/k")
            .unwrap_err()
            .contains("requires cipher"));
        assert!(block("img=x,cipher,cipher=/tmp/m").is_err());
        assert!(block("img=x,cipher=/tmp/a,cipher=/tmp/b").is_err());
        assert!(block("img=x,cipher,key=/tmp/a,key=/tmp/b").is_err());
        assert!(block("img=x,cipher=").is_err());
        assert!(block("img=x,cipher,key=").is_err());
    }

    #[cfg(not(feature = "cipher"))]
    #[test]
    fn cipher_options_require_the_feature() {
        for spec in ["img=disk.img,cipher", "bundle=tree,cipher=/tmp/m"] {
            let err = block(spec).expect_err("cipher is compiled out");
            assert!(
                err.contains("requires the `cipher` feature"),
                "{spec}: {err}"
            );
        }
        let err = block("img=disk.img,cipher,key=/tmp/k").expect_err("key is compiled out");
        assert!(err.contains("requires the `cipher` feature"), "{err}");
    }
}
