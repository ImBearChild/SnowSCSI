//! `snowdrive serve` device/backing spec parsing.
//!
//! Two flags share one grammar: `--block` drives [`DeviceRole::BlockDisk`]
//! (or [`DeviceRole::BlockCd`] with `profile=cd`), `--cdrom` drives
//! [`DeviceRole::MmcCd`]. The surface is:
//!
//! ```text
//! SPEC    := <backing>[=<value>][,<opt>...]
//! backing := img=<file> | imgdir=<dir> | ram=<size> | live=<dir>
//!          | dvdram=<path|ram:<size>>
//! opt     := profile=block|cd | ro | sector=512|2048 | chunk=<size>
//!          | size=<size>
//! ```
//!
//! Parsing is a pure function (no filesystem access): whether an `img=` path
//! exists, or whether an `imgdir=` directory is a new or existing bundle, is
//! decided when the device is built. Legality is also feature-independent —
//! a backing that needs a disabled feature parses fine and is rejected at
//! build time with a feature-specific error.

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
    /// `CdromDrive` — full MMC optical drive (`--cdrom`).
    MmcCd,
}

/// Where the bytes come from.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Backing {
    /// `img=<file>` — a flat file (FileBackend), or a flat ISO for MMC.
    Img { path: String },
    /// `imgdir=<dir>` — a directory-chunked FlatBundle.
    ImgDir { dir: String },
    /// `ram=<size>` — a memory-backed device.
    Ram { size: u64 },
    /// `live=<dir>` — live ISO9660 over a directory (MMC only).
    Live { dir: String },
    /// `dvdram=<path>` or `dvdram=ram:<size>` — DVD-RAM (MMC only).
    /// `path = None` means memory (the size lives in [`PlaneOpts`]).
    DvdRam { path: Option<String> },
}

/// Plane/geometry options common to a device spec.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PlaneOpts {
    /// Read-only plane (implied for the optical roles).
    pub read_only: bool,
    /// Logical sector size (512 default; only used by the block-disk role).
    pub sector: u32,
    /// Chunk size override (`--block imgdir=`).
    pub chunk: Option<u64>,
    /// Virtual size for a new `imgdir=` bundle, or the size of a new
    /// `dvdram=` file.
    pub size: Option<u64>,
}

/// One parsed device, ready to be built.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DeviceSpec {
    /// The raw flag value, for diagnostics.
    pub raw: String,
    pub role: DeviceRole,
    pub backing: Backing,
    pub plane: PlaneOpts,
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
    Ok(specs)
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

    let read_only = matches!(role, DeviceRole::BlockCd | DeviceRole::MmcCd) || opts.read_only;
    Ok(DeviceSpec {
        raw: input.to_string(),
        role,
        backing,
        plane: PlaneOpts {
            read_only,
            sector: opts.sector.unwrap_or(512),
            chunk: opts.chunk,
            size,
        },
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
    if let Some(v) = expr.strip_prefix("img=") {
        if v.is_empty() {
            return Err("empty img= path".to_string());
        }
        Ok((
            Backing::Img {
                path: v.to_string(),
            },
            None,
        ))
    } else if let Some(v) = expr.strip_prefix("imgdir=") {
        if v.is_empty() {
            return Err("empty imgdir= path".to_string());
        }
        Ok((Backing::ImgDir { dir: v.to_string() }, None))
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
            "unknown backing '{expr}'; expected img=, imgdir=, ram=, live=, or dvdram="
        ))
    }
}

fn check_backing(family: DeviceFamily, backing: &Backing) -> Result<(), String> {
    let ok = match family {
        DeviceFamily::Block => matches!(
            backing,
            Backing::Img { .. } | Backing::ImgDir { .. } | Backing::Ram { .. }
        ),
        DeviceFamily::Cdrom => matches!(
            backing,
            Backing::Img { .. } | Backing::Live { .. } | Backing::DvdRam { .. }
        ),
    };
    if ok {
        return Ok(());
    }
    let key = match backing {
        Backing::Img { .. } => "img",
        Backing::ImgDir { .. } => "imgdir",
        Backing::Ram { .. } => "ram",
        Backing::Live { .. } => "live",
        Backing::DvdRam { .. } => "dvdram",
    };
    Err(format!("{key}= is not valid for {}", family.flag()))
}

fn check_opts(
    family: DeviceFamily,
    profile: Option<BlockProfile>,
    backing: &Backing,
    opts: &RawOpts,
) -> Result<(), String> {
    let is_imgdir = matches!(backing, Backing::ImgDir { .. });
    let is_dvdram_file = matches!(backing, Backing::DvdRam { path: Some(_) });

    if opts.sector.is_some() {
        match (family, profile) {
            (DeviceFamily::Cdrom, _) => return Err("sector= is only valid for --block".to_string()),
            (DeviceFamily::Block, Some(BlockProfile::Cd)) => {
                return Err("sector= is fixed at 2048 for profile=cd".to_string())
            }
            _ => {}
        }
    }
    if opts.chunk.is_some() && !(family == DeviceFamily::Block && is_imgdir) {
        return Err("chunk= is only valid for --block imgdir=<dir>".to_string());
    }
    if opts.size.is_some()
        && !((family == DeviceFamily::Block && is_imgdir)
            || (family == DeviceFamily::Cdrom && is_dvdram_file))
    {
        return Err(
            "size= is only valid for --block imgdir=<dir> or --cdrom dvdram=<path>".to_string(),
        );
    }
    Ok(())
}

#[derive(Default)]
struct RawOpts {
    profile: Option<String>,
    read_only: bool,
    ro_seen: bool,
    sector: Option<u32>,
    chunk: Option<u64>,
    size: Option<u64>,
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
        } else if let Some(v) = opt.strip_prefix("chunk=") {
            if o.chunk.is_some() {
                return Err("duplicate chunk=".to_string());
            }
            o.chunk = Some(parse_size(v).ok_or_else(|| format!("invalid chunk size '{v}'"))?);
        } else if let Some(v) = opt.strip_prefix("size=") {
            if o.size.is_some() {
                return Err("duplicate size=".to_string());
            }
            o.size = Some(parse_size(v).ok_or_else(|| format!("invalid size '{v}'"))?);
        } else {
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
                Backing::ImgDir { dir } => Some((dir.as_str(), kind)),
                Backing::Live { dir } => Some((dir.as_str(), kind)),
                Backing::DvdRam { path: Some(p) } => Some((p.as_str(), kind)),
                Backing::DvdRam { path: None } | Backing::Ram { .. } => None,
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
    fn block_disk_imgdir() {
        let s = block("imgdir=tree,size=8M,chunk=1M,sector=2048,ro").unwrap();
        assert_eq!(s.role, DeviceRole::BlockDisk);
        assert_eq!(
            s.backing,
            Backing::ImgDir {
                dir: "tree".to_string()
            }
        );
        assert_eq!(s.plane.chunk, Some(1 << 20));
        assert_eq!(s.plane.size, Some(8 << 20));
        assert_eq!(s.plane.sector, 2048);
        assert!(s.plane.read_only);
    }

    #[test]
    fn block_cd_profile() {
        let s = block("img=boot.iso,profile=cd").unwrap();
        assert_eq!(s.role, DeviceRole::BlockCd);
        // The optical profile is always read-only; `ro` is an explicit no-op.
        assert!(s.plane.read_only);
        assert!(block("img=boot.iso,profile=cd,ro").is_ok());
        assert!(block("imgdir=tree,profile=cd").is_ok());
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
    fn block_img_rejects_imgdir_opts() {
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
    }

    #[test]
    fn cdrom_rejects_block_backings_and_opts() {
        assert!(cdrom("imgdir=tree").is_err());
        assert!(cdrom("ram=16M").is_err());
        assert!(cdrom("img=boot.iso,profile=block").is_err());
        assert!(cdrom("img=boot.iso,sector=512").is_err());
        assert!(cdrom("img=boot.iso,chunk=1M").is_err());
    }

    #[test]
    fn dvdram_ram_takes_no_options() {
        assert!(cdrom("dvdram=ram:16M,size=8M").is_err());
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
        assert!(block("imgdir=d,size=1M,size=2M").is_err());
        assert!(block("imgdir=d,chunk=1M,chunk=2M").is_err());
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
            &["ram=1M".to_string(), "imgdir=d".to_string()],
            &["dvdram=ram:16M".to_string()],
        )
        .unwrap();
        // Only the bundle directory carries a path.
        assert_eq!(mounted_paths(&specs), vec![("d", "block")]);
        assert!(check_dual_mount(&specs).is_empty());
    }

    #[test]
    fn dual_mount_bundle_dir_warns() {
        let specs = parse_all(&["imgdir=d".to_string(), "imgdir=d".to_string()], &[]).unwrap();
        let w = check_dual_mount(&specs);
        assert_eq!(w.len(), 1);
        assert!(w[0].contains("'d'"));
    }
}
