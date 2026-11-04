//! Canonical bundle manifest (`SNOWBUNDLE`).
//!
//! Every bundle kind — a flat image, a directory-chunked flat plane, a
//! recordable CD — describes itself with one strict, canonical text manifest.
//! The format is a deliberately tiny INI subset (fixed key order, single
//! spaces around `=`, `\n` line endings, no comments, no blank lines) so that
//! it can be parsed allocation-free and byte-for-byte reproduced.
//!
//! # Grammar
//!
//! ```text
//! magic = snow_bundle
//! version = 1
//! kind = image | flat | cdr
//! <kind-specific geometry>
//! <optional cipher block>
//! <optional crc line>
//! ```
//!
//! Geometry:
//!
//! - `kind = image`: `size = <u64>`
//! - `kind = flat`: `virtual_size = <u64>`, `chunk_size = <u64>`,
//!   `sector_size = <512|2048>`
//! - `kind = cdr`: none
//!
//! The optional cipher block has a fixed order: `cipher`, `kdf`, `iterations`
//! + `salt` (only for `kdf = pbkdf2-hmac-sha256`), `nonce`.
//!
//! A trailing `crc = <8 lowercase hex>` line is optional on read and always
//! emitted by [`BundleMeta::encode`]. It is a CRC-32 (the same polynomial,
//! init and final XOR as the CD-R TOC) over every byte before the `crc` line,
//! newlines included.
//!
//! The parser is format-only: geometry zero/alignment and chunk-count checks
//! belong to the caller that installs the medium.

use core::fmt::Write as _;

/// Canonical manifest file name inside a bundle directory.
pub const MANIFEST_NAME: &str = "SNOWBUNDLE";

/// Suffix of a sidecar manifest next to a single-file image.
pub const SIDECAR_SUFFIX: &str = ".SNOWBUNDLE";

/// Manifest `magic` value.
pub const MAGIC: &str = "snow_bundle";

/// Manifest format version.
pub const VERSION: u32 = 1;

/// Maximum accepted / emitted manifest length in bytes.
pub const MAX_MANIFEST: usize = 512;

/// Lowest accepted PBKDF2 iteration count.
const MIN_ITERATIONS: u32 = 1_000;

/// Highest accepted PBKDF2 iteration count.
const MAX_ITERATIONS: u32 = 2_000_000;

/// What the bundle holds and how its geometry is laid out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum BundleKind {
    /// One plain image file of `size` bytes.
    Image {
        /// Image length in bytes.
        size: u64,
    },
    /// A directory of fixed-size chunk files.
    Flat {
        /// Logical device size in bytes.
        virtual_size: u64,
        /// Chunk file size in bytes.
        chunk_size: u64,
        /// Sector size (`512` or `2048`).
        sector_size: u32,
    },
    /// A recordable CD bundle (the TOC owns the geometry).
    Cdr,
}

/// Stream cipher used by an encrypted bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum CipherAlg {
    /// ChaCha with 8 rounds.
    ChaCha8,
    /// ChaCha with 12 rounds.
    ChaCha12,
    /// ChaCha with 20 rounds.
    ChaCha20,
    /// AES in counter mode.
    AesCtr,
    /// XOR keystream (obfuscation only).
    Xor,
}

/// Password-to-key derivation used by an encrypted bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum KdfKind {
    /// PBKDF2-HMAC-SHA256 with an iteration count and salt.
    Pbkdf2HmacSha256,
    /// No key derivation (the key is supplied directly).
    None,
}

/// Cipher description carried by a manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct CipherMeta {
    /// Stream cipher.
    pub cipher: CipherAlg,
    /// Key derivation.
    pub kdf: KdfKind,
    /// `Some` iff `kdf == Pbkdf2HmacSha256`.
    pub iterations: Option<u32>,
    /// `Some` iff `kdf == Pbkdf2HmacSha256`.
    pub salt: Option<[u8; 16]>,
    /// Per-image nonce.
    pub nonce: [u8; 8],
}

/// Parsed bundle manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct BundleMeta {
    /// Bundle kind and geometry.
    pub kind: BundleKind,
    /// Cipher block, or `None` for a plaintext bundle.
    pub cipher: Option<CipherMeta>,
    /// True when the parsed source carried a `crc` line.
    pub has_crc: bool,
}

/// Manifest parse/encode failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ManifestError {
    /// The input is longer than [`MAX_MANIFEST`].
    TooLarge,
    /// The `magic` value is not [`MAGIC`].
    BadMagic,
    /// The `version` value is not [`VERSION`].
    BadVersion,
    /// A key outside the manifest grammar.
    UnknownKey,
    /// A key appears more than once.
    DuplicateKey,
    /// A key appears in the wrong position.
    FieldOrder,
    /// A required key is absent.
    MissingField,
    /// A key is present but not valid for the active kind/block.
    UnexpectedField,
    /// A value is not in its expected textual form.
    BadValue,
    /// A hexadecimal value has the wrong length or an invalid digit.
    BadHex,
    /// The `crc` value does not match the preceding bytes.
    BadCrc,
    /// The manifest does not end with a final `\n`.
    MissingFinalNewline,
}

impl core::fmt::Display for ManifestError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooLarge => write!(f, "manifest is too large"),
            Self::BadMagic => write!(f, "invalid manifest magic"),
            Self::BadVersion => write!(f, "unsupported manifest version"),
            Self::UnknownKey => write!(f, "unknown manifest key"),
            Self::DuplicateKey => write!(f, "duplicate manifest key"),
            Self::FieldOrder => write!(f, "manifest fields are out of order"),
            Self::MissingField => write!(f, "manifest is missing a required field"),
            Self::UnexpectedField => write!(f, "unexpected manifest field"),
            Self::BadValue => write!(f, "invalid manifest value"),
            Self::BadHex => write!(f, "invalid manifest hex value"),
            Self::BadCrc => write!(f, "manifest CRC mismatch"),
            Self::MissingFinalNewline => write!(f, "manifest must end with a newline"),
        }
    }
}

impl core::error::Error for ManifestError {}

/// Parser state (field position), not the bundle kind.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    Magic,
    Version,
    Kind,
    ImageSize,
    FlatVirtual,
    FlatChunk,
    FlatSector,
    AfterGeometry,
    Kdf,
    Iterations,
    Salt,
    Nonce,
    CrcOrEnd,
    End,
}

impl BundleMeta {
    /// Encode the canonical manifest, always ending with a `crc` line.
    ///
    /// The result is at most [`MAX_MANIFEST`] bytes and always ends with a
    /// trailing newline.
    pub fn encode(&self) -> Result<heapless::Vec<u8, MAX_MANIFEST>, ManifestError> {
        let mut text = heapless::String::<MAX_MANIFEST>::new();
        writeln!(text, "magic = {MAGIC}").map_err(|_| ManifestError::TooLarge)?;
        writeln!(text, "version = {VERSION}").map_err(|_| ManifestError::TooLarge)?;
        writeln!(text, "kind = {}", kind_text(self.kind)).map_err(|_| ManifestError::TooLarge)?;
        match self.kind {
            BundleKind::Image { size } => {
                writeln!(text, "size = {size}").map_err(|_| ManifestError::TooLarge)?;
            }
            BundleKind::Flat {
                virtual_size,
                chunk_size,
                sector_size,
            } => {
                if sector_size != 512 && sector_size != 2048 {
                    return Err(ManifestError::BadValue);
                }
                writeln!(text, "virtual_size = {virtual_size}")
                    .map_err(|_| ManifestError::TooLarge)?;
                writeln!(text, "chunk_size = {chunk_size}").map_err(|_| ManifestError::TooLarge)?;
                writeln!(text, "sector_size = {sector_size}")
                    .map_err(|_| ManifestError::TooLarge)?;
            }
            BundleKind::Cdr => {}
        }
        if let Some(cipher) = self.cipher {
            writeln!(text, "cipher = {}", cipher_text(cipher.cipher))
                .map_err(|_| ManifestError::TooLarge)?;
            writeln!(text, "kdf = {}", kdf_text(cipher.kdf))
                .map_err(|_| ManifestError::TooLarge)?;
            match cipher.kdf {
                KdfKind::Pbkdf2HmacSha256 => {
                    let iterations = cipher.iterations.ok_or(ManifestError::MissingField)?;
                    let salt = cipher.salt.ok_or(ManifestError::MissingField)?;
                    if !(MIN_ITERATIONS..=MAX_ITERATIONS).contains(&iterations) {
                        return Err(ManifestError::BadValue);
                    }
                    writeln!(text, "iterations = {iterations}")
                        .map_err(|_| ManifestError::TooLarge)?;
                    write!(text, "salt = ").map_err(|_| ManifestError::TooLarge)?;
                    write_hex(&mut text, &salt)?;
                    text.push('\n').map_err(|_| ManifestError::TooLarge)?;
                }
                KdfKind::None => {
                    if cipher.iterations.is_some() || cipher.salt.is_some() {
                        return Err(ManifestError::UnexpectedField);
                    }
                }
            }
            write!(text, "nonce = ").map_err(|_| ManifestError::TooLarge)?;
            write_hex(&mut text, &cipher.nonce)?;
            text.push('\n').map_err(|_| ManifestError::TooLarge)?;
        }
        let crc = checksum(text.as_bytes());
        writeln!(text, "crc = {crc:08x}").map_err(|_| ManifestError::TooLarge)?;

        let mut out = heapless::Vec::<u8, MAX_MANIFEST>::new();
        out.extend_from_slice(text.as_bytes())
            .map_err(|_| ManifestError::TooLarge)?;
        Ok(out)
    }

    /// Strictly parse a canonical manifest.
    ///
    /// A missing `crc` line is accepted (`has_crc == false`); everything else
    /// outside the canonical grammar is rejected.
    pub fn parse(bytes: &[u8]) -> Result<Self, ManifestError> {
        if bytes.len() > MAX_MANIFEST {
            return Err(ManifestError::TooLarge);
        }
        if bytes.is_empty() {
            return Err(ManifestError::MissingFinalNewline);
        }
        if bytes[bytes.len() - 1] != b'\n' {
            return Err(ManifestError::MissingFinalNewline);
        }

        let body = &bytes[..bytes.len() - 1];
        let mut stage = Stage::Magic;
        let mut kind_tag: Option<u8> = None;
        let mut image_size = 0u64;
        let mut flat_virtual = 0u64;
        let mut flat_chunk = 0u64;
        let mut flat_sector = 0u32;
        let mut cipher_alg: Option<CipherAlg> = None;
        let mut kdf: Option<KdfKind> = None;
        let mut iterations: Option<u32> = None;
        let mut salt: Option<[u8; 16]> = None;
        let mut nonce: Option<[u8; 8]> = None;
        let mut crc_seen = false;
        let mut seen = 0u16;
        let mut offset = 0usize;

        for line in body.split(|&byte| byte == b'\n') {
            let line_start = offset;
            offset += line.len() + 1;
            let (key, value) = split_line(line)?;
            let index = key_index(key).ok_or(ManifestError::UnknownKey)?;
            let bit = 1u16 << index;
            if seen & bit != 0 {
                return Err(ManifestError::DuplicateKey);
            }
            seen |= bit;

            match stage {
                Stage::Magic => {
                    if key != "magic" {
                        return Err(ManifestError::FieldOrder);
                    }
                    if value != MAGIC {
                        return Err(ManifestError::BadMagic);
                    }
                    stage = Stage::Version;
                }
                Stage::Version => {
                    if key != "version" {
                        return Err(ManifestError::FieldOrder);
                    }
                    let version = parse_decimal_u32(value)?;
                    if version != VERSION {
                        return Err(ManifestError::BadVersion);
                    }
                    stage = Stage::Kind;
                }
                Stage::Kind => {
                    if key != "kind" {
                        return Err(ManifestError::FieldOrder);
                    }
                    match value {
                        "image" => {
                            kind_tag = Some(0);
                            stage = Stage::ImageSize;
                        }
                        "flat" => {
                            kind_tag = Some(1);
                            stage = Stage::FlatVirtual;
                        }
                        "cdr" => {
                            kind_tag = Some(2);
                            stage = Stage::AfterGeometry;
                        }
                        _ => return Err(ManifestError::BadValue),
                    }
                }
                Stage::ImageSize => {
                    if key != "size" {
                        return Err(wrong_geometry_key(key, kind_tag));
                    }
                    image_size = parse_decimal_u64(value)?;
                    stage = Stage::AfterGeometry;
                }
                Stage::FlatVirtual => {
                    if key != "virtual_size" {
                        return Err(wrong_geometry_key(key, kind_tag));
                    }
                    flat_virtual = parse_decimal_u64(value)?;
                    stage = Stage::FlatChunk;
                }
                Stage::FlatChunk => {
                    if key != "chunk_size" {
                        return Err(wrong_geometry_key(key, kind_tag));
                    }
                    flat_chunk = parse_decimal_u64(value)?;
                    stage = Stage::FlatSector;
                }
                Stage::FlatSector => {
                    if key != "sector_size" {
                        return Err(wrong_geometry_key(key, kind_tag));
                    }
                    flat_sector = parse_decimal_u32(value)?;
                    if flat_sector != 512 && flat_sector != 2048 {
                        return Err(ManifestError::BadValue);
                    }
                    stage = Stage::AfterGeometry;
                }
                Stage::AfterGeometry => match key {
                    "cipher" => {
                        cipher_alg = Some(parse_cipher(value)?);
                        stage = Stage::Kdf;
                    }
                    "crc" => {
                        verify_crc(&bytes[..line_start], value)?;
                        crc_seen = true;
                        stage = Stage::End;
                    }
                    "kdf" | "iterations" | "salt" | "nonce" => {
                        return Err(ManifestError::MissingField)
                    }
                    _ => return Err(wrong_geometry_key(key, kind_tag)),
                },
                Stage::Kdf => match key {
                    "kdf" => {
                        let parsed = parse_kdf(value)?;
                        kdf = Some(parsed);
                        stage = if parsed == KdfKind::Pbkdf2HmacSha256 {
                            Stage::Iterations
                        } else {
                            Stage::Nonce
                        };
                    }
                    "iterations" | "salt" | "nonce" | "crc" => {
                        return Err(ManifestError::MissingField)
                    }
                    _ => return Err(wrong_geometry_key(key, kind_tag)),
                },
                Stage::Iterations => match key {
                    "iterations" => {
                        let parsed = parse_decimal_u32(value)?;
                        if !(MIN_ITERATIONS..=MAX_ITERATIONS).contains(&parsed) {
                            return Err(ManifestError::BadValue);
                        }
                        iterations = Some(parsed);
                        stage = Stage::Salt;
                    }
                    "salt" | "nonce" | "crc" => return Err(ManifestError::MissingField),
                    _ => return Err(wrong_geometry_key(key, kind_tag)),
                },
                Stage::Salt => match key {
                    "salt" => {
                        salt = Some(decode_hex::<16>(value)?);
                        stage = Stage::Nonce;
                    }
                    "nonce" | "crc" => return Err(ManifestError::MissingField),
                    _ => return Err(wrong_geometry_key(key, kind_tag)),
                },
                Stage::Nonce => match key {
                    "nonce" => {
                        nonce = Some(decode_hex::<8>(value)?);
                        stage = Stage::CrcOrEnd;
                    }
                    // `kdf = none` forbids these fields.
                    "iterations" | "salt" => return Err(ManifestError::UnexpectedField),
                    "crc" => return Err(ManifestError::MissingField),
                    _ => return Err(wrong_geometry_key(key, kind_tag)),
                },
                Stage::CrcOrEnd => {
                    if key != "crc" {
                        return Err(if matches!(key, "iterations" | "salt") {
                            ManifestError::UnexpectedField
                        } else {
                            ManifestError::FieldOrder
                        });
                    }
                    verify_crc(&bytes[..line_start], value)?;
                    crc_seen = true;
                    stage = Stage::End;
                }
                Stage::End => return Err(ManifestError::FieldOrder),
            }
        }

        if !matches!(stage, Stage::AfterGeometry | Stage::CrcOrEnd | Stage::End) {
            return Err(ManifestError::MissingField);
        }

        let kind = match kind_tag {
            Some(0) => BundleKind::Image { size: image_size },
            Some(1) => BundleKind::Flat {
                virtual_size: flat_virtual,
                chunk_size: flat_chunk,
                sector_size: flat_sector,
            },
            _ => BundleKind::Cdr,
        };

        let cipher = match (cipher_alg, kdf) {
            (None, None) => None,
            (Some(cipher), Some(kdf)) => Some(CipherMeta {
                cipher,
                kdf,
                iterations,
                salt,
                nonce: nonce.ok_or(ManifestError::MissingField)?,
            }),
            _ => return Err(ManifestError::MissingField),
        };

        Ok(Self {
            kind,
            cipher,
            has_crc: crc_seen,
        })
    }
}

/// Split one canonical `key = value` line.
fn split_line(line: &[u8]) -> Result<(&str, &str), ManifestError> {
    if line.is_empty() {
        return Err(ManifestError::BadValue);
    }
    if line[0] == b';' || line[0] == b'#' {
        return Err(ManifestError::BadValue);
    }
    let eq = line
        .iter()
        .position(|&byte| byte == b'=')
        .ok_or(ManifestError::BadValue)?;
    if eq < 2 || eq + 2 >= line.len() || line[eq - 1] != b' ' || line[eq + 1] != b' ' {
        return Err(ManifestError::BadValue);
    }
    let key = &line[..eq - 1];
    let value = &line[eq + 2..];
    if key
        .iter()
        .chain(value.iter())
        .any(|&byte| byte == b' ' || byte == b'=' || !(0x21..=0x7E).contains(&byte))
    {
        return Err(ManifestError::BadValue);
    }
    // Every byte is printable ASCII, so both conversions are infallible.
    let key = core::str::from_utf8(key).map_err(|_| ManifestError::BadValue)?;
    let value = core::str::from_utf8(value).map_err(|_| ManifestError::BadValue)?;
    Ok((key, value))
}

/// Index of a known key in the duplicate-detection bitmask.
fn key_index(key: &str) -> Option<u8> {
    Some(match key {
        "magic" => 0,
        "version" => 1,
        "kind" => 2,
        "size" => 3,
        "virtual_size" => 4,
        "chunk_size" => 5,
        "sector_size" => 6,
        "cipher" => 7,
        "kdf" => 8,
        "iterations" => 9,
        "salt" => 10,
        "nonce" => 11,
        "crc" => 12,
        _ => return None,
    })
}

/// Classify a known key that does not fit the current geometry stage.
fn wrong_geometry_key(key: &str, kind_tag: Option<u8>) -> ManifestError {
    let image_key = key == "size";
    let flat_key = matches!(key, "virtual_size" | "chunk_size" | "sector_size");
    let belongs_to_other_kind = match kind_tag {
        Some(0) => flat_key,
        Some(1) => image_key,
        Some(2) => image_key || flat_key,
        _ => false,
    };
    if belongs_to_other_kind {
        ManifestError::UnexpectedField
    } else {
        ManifestError::FieldOrder
    }
}

/// Parse a canonical decimal `u64` (no leading zeros, no sign, no garbage).
fn parse_decimal_u64(value: &str) -> Result<u64, ManifestError> {
    let bytes = value.as_bytes();
    if bytes.is_empty() {
        return Err(ManifestError::BadValue);
    }
    if bytes.len() > 1 && bytes[0] == b'0' {
        return Err(ManifestError::BadValue);
    }
    let mut out = 0u64;
    for &byte in bytes {
        if !byte.is_ascii_digit() {
            return Err(ManifestError::BadValue);
        }
        out = out
            .checked_mul(10)
            .and_then(|v| v.checked_add(u64::from(byte - b'0')))
            .ok_or(ManifestError::BadValue)?;
    }
    Ok(out)
}

/// Parse a canonical decimal `u32` (no leading zeros, no sign, no garbage).
fn parse_decimal_u32(value: &str) -> Result<u32, ManifestError> {
    let bytes = value.as_bytes();
    if bytes.is_empty() {
        return Err(ManifestError::BadValue);
    }
    if bytes.len() > 1 && bytes[0] == b'0' {
        return Err(ManifestError::BadValue);
    }
    let mut out = 0u32;
    for &byte in bytes {
        if !byte.is_ascii_digit() {
            return Err(ManifestError::BadValue);
        }
        out = out
            .checked_mul(10)
            .and_then(|v| v.checked_add(u32::from(byte - b'0')))
            .ok_or(ManifestError::BadValue)?;
    }
    Ok(out)
}

/// Decode exactly `N` bytes from `2 * N` lowercase hex digits.
fn decode_hex<const N: usize>(value: &str) -> Result<[u8; N], ManifestError> {
    let bytes = value.as_bytes();
    if bytes.len() != N * 2 {
        return Err(ManifestError::BadHex);
    }
    let mut out = [0u8; N];
    for (index, slot) in out.iter_mut().enumerate() {
        let high = hex_nibble(bytes[index * 2])?;
        let low = hex_nibble(bytes[index * 2 + 1])?;
        *slot = (high << 4) | low;
    }
    Ok(out)
}

fn hex_nibble(byte: u8) -> Result<u8, ManifestError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(ManifestError::BadHex),
    }
}

/// Verify a `crc` line against every byte before it.
fn verify_crc(prefix: &[u8], value: &str) -> Result<(), ManifestError> {
    let expected = u32::from_be_bytes(decode_hex::<4>(value)?);
    if checksum(prefix) != expected {
        return Err(ManifestError::BadCrc);
    }
    Ok(())
}

/// Append lowercase hex digits for `bytes`.
fn write_hex<const N: usize>(
    text: &mut heapless::String<N>,
    bytes: &[u8],
) -> Result<(), ManifestError> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for &byte in bytes {
        text.push(HEX[(byte >> 4) as usize] as char)
            .map_err(|_| ManifestError::TooLarge)?;
        text.push(HEX[(byte & 0x0F) as usize] as char)
            .map_err(|_| ManifestError::TooLarge)?;
    }
    Ok(())
}

fn parse_cipher(value: &str) -> Result<CipherAlg, ManifestError> {
    match value {
        "chacha8" => Ok(CipherAlg::ChaCha8),
        "chacha12" => Ok(CipherAlg::ChaCha12),
        "chacha20" => Ok(CipherAlg::ChaCha20),
        "aes-ctr" => Ok(CipherAlg::AesCtr),
        "xor" => Ok(CipherAlg::Xor),
        _ => Err(ManifestError::BadValue),
    }
}

fn parse_kdf(value: &str) -> Result<KdfKind, ManifestError> {
    match value {
        "pbkdf2-hmac-sha256" => Ok(KdfKind::Pbkdf2HmacSha256),
        "none" => Ok(KdfKind::None),
        _ => Err(ManifestError::BadValue),
    }
}

const fn kind_text(kind: BundleKind) -> &'static str {
    match kind {
        BundleKind::Image { .. } => "image",
        BundleKind::Flat { .. } => "flat",
        BundleKind::Cdr => "cdr",
    }
}

const fn cipher_text(cipher: CipherAlg) -> &'static str {
    match cipher {
        CipherAlg::ChaCha8 => "chacha8",
        CipherAlg::ChaCha12 => "chacha12",
        CipherAlg::ChaCha20 => "chacha20",
        CipherAlg::AesCtr => "aes-ctr",
        CipherAlg::Xor => "xor",
    }
}

const fn kdf_text(kdf: KdfKind) -> &'static str {
    match kdf {
        KdfKind::Pbkdf2HmacSha256 => "pbkdf2-hmac-sha256",
        KdfKind::None => "none",
    }
}

const fn crc_update(mut crc: u32, byte: u8) -> u32 {
    crc ^= byte as u32;
    let mut bit = 0;
    while bit < 8 {
        let mask = 0u32.wrapping_sub(crc & 1);
        crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        bit += 1;
    }
    crc
}

/// CRC-32 of an arbitrary byte slice.
///
/// Same polynomial, init and final XOR as the CD-R TOC checksum.
fn checksum(bytes: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for byte in bytes {
        crc = crc_update(crc, *byte);
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    const FLAT: BundleKind = BundleKind::Flat {
        virtual_size: 8 << 20,
        chunk_size: 1 << 20,
        sector_size: 512,
    };

    const CIPHER_PBKDF2: CipherMeta = CipherMeta {
        cipher: CipherAlg::ChaCha20,
        kdf: KdfKind::Pbkdf2HmacSha256,
        iterations: Some(100_000),
        salt: Some([0x11; 16]),
        nonce: [0x22; 8],
    };

    fn encode_text(meta: &BundleMeta) -> String {
        String::from_utf8(meta.encode().unwrap().to_vec()).unwrap()
    }

    #[test]
    fn encodes_flat_plaintext() {
        let meta = BundleMeta {
            kind: FLAT,
            cipher: None,
            has_crc: false,
        };
        let text = encode_text(&meta);
        let (body, crc) = text.split_at(text.find("crc = ").unwrap());
        assert_eq!(
            body,
            "magic = snow_bundle\n\
             version = 1\n\
             kind = flat\n\
             virtual_size = 8388608\n\
             chunk_size = 1048576\n\
             sector_size = 512\n"
        );
        assert_eq!(crc.len(), "crc = 00000000\n".len());
        assert!(crc.starts_with("crc = "));
        assert!(text.ends_with('\n'));
        assert!(!text.contains('\r'));
        assert_eq!(text.lines().filter(|l| l.starts_with("crc = ")).count(), 1);
    }

    #[test]
    fn encodes_image() {
        let meta = BundleMeta {
            kind: BundleKind::Image { size: 1234 },
            cipher: None,
            has_crc: false,
        };
        let text = encode_text(&meta);
        assert!(text.contains("kind = image\n"));
        assert!(text.contains("size = 1234\n"));
        assert!(!text.contains("virtual_size"));
    }

    #[test]
    fn encodes_cdr() {
        let meta = BundleMeta {
            kind: BundleKind::Cdr,
            cipher: None,
            has_crc: false,
        };
        let text = encode_text(&meta);
        assert!(text.contains("kind = cdr\n"));
        assert!(!text.contains("size = "));
        assert!(!text.contains("virtual_size = "));
    }

    #[test]
    fn roundtrip_all_kinds_with_and_without_cipher() {
        let bases = [
            BundleMeta {
                kind: BundleKind::Image { size: u64::MAX },
                cipher: None,
                has_crc: false,
            },
            BundleMeta {
                kind: FLAT,
                cipher: None,
                has_crc: false,
            },
            BundleMeta {
                kind: BundleKind::Cdr,
                cipher: None,
                has_crc: false,
            },
        ];
        let ciphers = [
            None,
            Some(CIPHER_PBKDF2),
            Some(CipherMeta {
                cipher: CipherAlg::ChaCha8,
                kdf: KdfKind::None,
                iterations: None,
                salt: None,
                nonce: [0xFF; 8],
            }),
        ];
        for base in bases {
            for cipher in ciphers {
                for has_crc in [false, true] {
                    let meta = BundleMeta {
                        cipher,
                        has_crc,
                        ..base
                    };
                    let encoded = meta.encode().unwrap();
                    let parsed = BundleMeta::parse(&encoded).unwrap();
                    assert_eq!(parsed.cipher, meta.cipher);
                    assert_eq!(parsed.kind, meta.kind);
                    // The encoder always writes a CRC, so the parse reports it.
                    assert!(parsed.has_crc);
                    assert_eq!(parsed.encode().unwrap(), encoded);
                }
            }
        }
    }

    #[test]
    fn encode_parse_is_idempotent_and_exact_for_crc_input() {
        let bodies: &[&[u8]] = &[
            b"magic = snow_bundle\nversion = 1\nkind = cdr\n",
            b"magic = snow_bundle\nversion = 1\nkind = image\nsize = 0\n",
            b"magic = snow_bundle\nversion = 1\nkind = flat\nvirtual_size = 1\nchunk_size = 1\nsector_size = 512\n",
        ];
        for body in bodies {
            let mut bytes = body.to_vec();
            bytes.extend_from_slice(format!("crc = {:08x}\n", checksum(body)).as_bytes());
            let parsed = BundleMeta::parse(&bytes).unwrap();
            assert!(parsed.has_crc);
            assert_eq!(parsed.encode().unwrap(), bytes.as_slice());
            let reparsed = BundleMeta::parse(&parsed.encode().unwrap()).unwrap();
            assert_eq!(reparsed, parsed);
        }
    }

    #[test]
    fn parse_accepts_missing_crc() {
        let meta = BundleMeta::parse(b"magic = snow_bundle\nversion = 1\nkind = cdr\n").unwrap();
        assert!(!meta.has_crc);
        assert_eq!(meta.kind, BundleKind::Cdr);
    }

    #[test]
    fn parse_rejects_wrong_crc() {
        assert_eq!(
            BundleMeta::parse(b"magic = snow_bundle\nversion = 1\nkind = cdr\ncrc = 00000000\n"),
            Err(ManifestError::BadCrc)
        );
    }

    #[test]
    fn crc_covers_every_preceding_byte() {
        let body = "magic = snow_bundle\nversion = 1\nkind = flat\nvirtual_size = 8\nchunk_size = 1\nsector_size = 512\ncipher = xor\nkdf = none\nnonce = 0000000000000000\n";
        let crc = checksum(body.as_bytes());
        let input = format!("{body}crc = {crc:08x}\n");
        assert!(BundleMeta::parse(input.as_bytes()).is_ok());

        // Every replacement keeps the manifest grammatically valid, so the
        // parser must reach the CRC check and reject the stale value.
        for (from, to) in [
            ("virtual_size = 8", "virtual_size = 9"),
            ("chunk_size = 1", "chunk_size = 2"),
            ("sector_size = 512", "sector_size = 2048"),
            ("cipher = xor", "cipher = chacha8"),
            ("nonce = 0000000000000000", "nonce = 0000000000000001"),
        ] {
            let broken = input.replace(from, to);
            assert_eq!(
                BundleMeta::parse(broken.as_bytes()),
                Err(ManifestError::BadCrc),
                "changing {from:?} must invalidate the CRC"
            );
        }

        // The CRC value itself is covered by nothing, so it is edited directly.
        let mut broken = input.clone();
        let start = broken.rfind("= ").unwrap() + 2;
        let digit = if &broken[start..start + 1] == "f" {
            "0"
        } else {
            "f"
        };
        broken.replace_range(start..start + 1, digit);
        assert_eq!(
            BundleMeta::parse(broken.as_bytes()),
            Err(ManifestError::BadCrc)
        );
    }

    #[test]
    fn rejects_empty_input_and_duplicate_crc() {
        assert_eq!(
            BundleMeta::parse(b""),
            Err(ManifestError::MissingFinalNewline)
        );
        let body = "magic = snow_bundle\nversion = 1\nkind = cdr\n";
        let crc = checksum(body.as_bytes());
        let input = format!("{body}crc = {crc:08x}\ncrc = {crc:08x}\n");
        assert_eq!(
            BundleMeta::parse(input.as_bytes()),
            Err(ManifestError::DuplicateKey)
        );
    }

    #[test]
    fn rejects_uppercase_and_invalid_hex_at_exact_length() {
        let body = "magic = snow_bundle\nversion = 1\nkind = flat\nvirtual_size = 8\nchunk_size = 1\nsector_size = 512\ncipher = chacha12\nkdf = pbkdf2-hmac-sha256\niterations = 1000\nsalt = 0000000000000000000000000000000f\nnonce = 0000000000000000\n";
        let crc = checksum(body.as_bytes());
        let input = format!("{body}crc = {crc:08x}\n");
        assert!(BundleMeta::parse(input.as_bytes()).is_ok());

        // Correct length, uppercase digit.
        let upper = input.replace(
            "salt = 0000000000000000000000000000000f",
            "salt = 0000000000000000000000000000000F",
        );
        assert_eq!(
            BundleMeta::parse(upper.as_bytes()),
            Err(ManifestError::BadHex)
        );

        // Correct length, non-hex digit.
        let invalid = input.replace(
            "salt = 0000000000000000000000000000000f",
            "salt = 0000000000000000000000000000000g",
        );
        assert_eq!(
            BundleMeta::parse(invalid.as_bytes()),
            Err(ManifestError::BadHex)
        );

        // 16-character nonce (correct length), invalid digit.
        let nonce = input.replace("nonce = 0000000000000000", "nonce = 000000000000000g");
        assert_eq!(
            BundleMeta::parse(nonce.as_bytes()),
            Err(ManifestError::BadHex)
        );
    }

    #[test]
    fn rejects_oversized_input() {
        let mut input = vec![b' '; MAX_MANIFEST + 1];
        input[MAX_MANIFEST] = b'\n';
        assert_eq!(BundleMeta::parse(&input), Err(ManifestError::TooLarge));
    }

    #[test]
    fn rejects_bad_magic_version_and_kind() {
        assert_eq!(
            BundleMeta::parse(b"magic = nope\nversion = 1\nkind = cdr\n"),
            Err(ManifestError::BadMagic)
        );
        assert_eq!(
            BundleMeta::parse(b"magic = snow_bundle\nversion = 2\nkind = cdr\n"),
            Err(ManifestError::BadVersion)
        );
        assert_eq!(
            BundleMeta::parse(b"magic = snow_bundle\nversion = 1\nkind = tape\n"),
            Err(ManifestError::BadValue)
        );
    }

    #[test]
    fn rejects_unknown_duplicate_and_out_of_order_keys() {
        assert_eq!(
            BundleMeta::parse(b"magic = snow_bundle\nversion = 1\nkind = cdr\nfoo = 1\n"),
            Err(ManifestError::UnknownKey)
        );
        assert_eq!(
            BundleMeta::parse(b"magic = snow_bundle\nversion = 1\nkind = cdr\nkind = cdr\n"),
            Err(ManifestError::DuplicateKey)
        );
        assert_eq!(
            BundleMeta::parse(b"magic = snow_bundle\nkind = cdr\nversion = 1\n"),
            Err(ManifestError::FieldOrder)
        );
    }

    #[test]
    fn rejects_comments_blanks_and_crlf() {
        assert_eq!(
            BundleMeta::parse(b"magic = snow_bundle\n; comment\nversion = 1\nkind = cdr\n"),
            Err(ManifestError::BadValue)
        );
        assert_eq!(
            BundleMeta::parse(b"magic = snow_bundle\n\nversion = 1\nkind = cdr\n"),
            Err(ManifestError::BadValue)
        );
        assert_eq!(
            BundleMeta::parse(b"magic = snow_bundle\r\nversion = 1\r\nkind = cdr\r\n"),
            Err(ManifestError::BadValue)
        );
        assert_eq!(
            BundleMeta::parse(b"\xEF\xBB\xBFmagic = snow_bundle\nversion = 1\nkind = cdr\n"),
            Err(ManifestError::BadValue)
        );
    }

    #[test]
    fn rejects_missing_final_newline() {
        assert_eq!(
            BundleMeta::parse(b"magic = snow_bundle\nversion = 1\nkind = cdr"),
            Err(ManifestError::MissingFinalNewline)
        );
    }

    #[test]
    fn rejects_missing_fields() {
        assert_eq!(
            BundleMeta::parse(b"magic = snow_bundle\n"),
            Err(ManifestError::MissingField)
        );
        assert_eq!(
            BundleMeta::parse(b"magic = snow_bundle\nversion = 1\n"),
            Err(ManifestError::MissingField)
        );
        assert_eq!(
            BundleMeta::parse(b"magic = snow_bundle\nversion = 1\nkind = image\n"),
            Err(ManifestError::MissingField)
        );
        assert_eq!(
            BundleMeta::parse(
                b"magic = snow_bundle\nversion = 1\nkind = flat\nvirtual_size = 8\nchunk_size = 1\n"
            ),
            Err(ManifestError::MissingField)
        );
    }

    #[test]
    fn rejects_extra_fields_for_kind() {
        assert_eq!(
            BundleMeta::parse(
                b"magic = snow_bundle\nversion = 1\nkind = image\nsize = 1\nvirtual_size = 8\n"
            ),
            Err(ManifestError::UnexpectedField)
        );
        assert_eq!(
            BundleMeta::parse(b"magic = snow_bundle\nversion = 1\nkind = cdr\nsize = 1\n"),
            Err(ManifestError::UnexpectedField)
        );
    }

    #[test]
    fn rejects_bad_decimal_values() {
        for value in ["01", "00", "+1", "1x", "", "18446744073709551616"] {
            let input = format!("magic = snow_bundle\nversion = 1\nkind = image\nsize = {value}\n");
            assert_eq!(
                BundleMeta::parse(input.as_bytes()),
                Err(ManifestError::BadValue),
                "value {value:?}"
            );
        }
    }

    #[test]
    fn rejects_bad_hex_values() {
        // Uppercase, short, long and non-hex salts are all rejected.
        for value in ["AA", "11", "112233445566778899aabbccddeeff00ff", "zz"] {
            let input = format!(
                "magic = snow_bundle\nversion = 1\nkind = cdr\ncipher = xor\nkdf = pbkdf2-hmac-sha256\niterations = 1000\nsalt = {value}\nnonce = 0000000000000000\n"
            );
            assert_eq!(
                BundleMeta::parse(input.as_bytes()),
                Err(ManifestError::BadHex),
                "value {value:?}"
            );
        }
    }

    #[test]
    fn rejects_unknown_cipher_and_kdf() {
        assert_eq!(
            BundleMeta::parse(
                b"magic = snow_bundle\nversion = 1\nkind = cdr\ncipher = rot13\nkdf = none\nnonce = 0000000000000000\n"
            ),
            Err(ManifestError::BadValue)
        );
        assert_eq!(
            BundleMeta::parse(
                b"magic = snow_bundle\nversion = 1\nkind = cdr\ncipher = xor\nkdf = scrypt\n"
            ),
            Err(ManifestError::BadValue)
        );
    }

    #[test]
    fn rejects_partial_cipher_block() {
        assert_eq!(
            BundleMeta::parse(b"magic = snow_bundle\nversion = 1\nkind = cdr\nkdf = none\n"),
            Err(ManifestError::MissingField)
        );
        assert_eq!(
            BundleMeta::parse(b"magic = snow_bundle\nversion = 1\nkind = cdr\ncipher = xor\n"),
            Err(ManifestError::MissingField)
        );
        assert_eq!(
            BundleMeta::parse(
                b"magic = snow_bundle\nversion = 1\nkind = cdr\ncipher = xor\nkdf = none\n"
            ),
            Err(ManifestError::MissingField)
        );
        assert_eq!(
            BundleMeta::parse(
                b"magic = snow_bundle\nversion = 1\nkind = cdr\ncipher = xor\nkdf = pbkdf2-hmac-sha256\niterations = 1000\nnonce = 0000000000000000\n"
            ),
            Err(ManifestError::MissingField)
        );
    }

    #[test]
    fn pbkdf2_requires_iterations_and_salt() {
        let base =
            "magic = snow_bundle\nversion = 1\nkind = cdr\ncipher = xor\nkdf = pbkdf2-hmac-sha256\n";
        assert_eq!(
            BundleMeta::parse(
                format!(
                    "{base}salt = 00000000000000000000000000000000\nnonce = 0000000000000000\n"
                )
                .as_bytes()
            ),
            Err(ManifestError::MissingField)
        );
        assert_eq!(
            BundleMeta::parse(
                format!("{base}iterations = 1000\nnonce = 0000000000000000\n").as_bytes()
            ),
            Err(ManifestError::MissingField)
        );
    }

    #[test]
    fn none_kdf_rejects_iterations_and_salt() {
        assert_eq!(
            BundleMeta::parse(
                b"magic = snow_bundle\nversion = 1\nkind = cdr\ncipher = xor\nkdf = none\niterations = 1000\nnonce = 0000000000000000\n"
            ),
            Err(ManifestError::UnexpectedField)
        );
        assert_eq!(
            BundleMeta::parse(
                b"magic = snow_bundle\nversion = 1\nkind = cdr\ncipher = xor\nkdf = none\nsalt = 00000000000000000000000000000000\nnonce = 0000000000000000\n"
            ),
            Err(ManifestError::UnexpectedField)
        );
    }

    #[test]
    fn enforces_iteration_window() {
        for iterations in ["999", "2000001"] {
            let input = format!(
                "magic = snow_bundle\nversion = 1\nkind = cdr\ncipher = xor\nkdf = pbkdf2-hmac-sha256\niterations = {iterations}\nsalt = 00000000000000000000000000000000\nnonce = 0000000000000000\n"
            );
            assert_eq!(
                BundleMeta::parse(input.as_bytes()),
                Err(ManifestError::BadValue),
                "iterations {iterations}"
            );
        }
    }

    #[test]
    fn value_trailing_garbage_is_rejected() {
        assert_eq!(
            BundleMeta::parse(b"magic = snow_bundle\nversion = 1\nkind = cdr extra\n"),
            Err(ManifestError::BadValue)
        );
        assert_eq!(
            BundleMeta::parse(b"magic = snow_bundle\nversion = 1\nkind = cdr \n"),
            Err(ManifestError::BadValue)
        );
    }

    #[test]
    fn encode_rejects_inconsistent_cipher_metadata() {
        let meta = BundleMeta {
            kind: BundleKind::Cdr,
            cipher: Some(CipherMeta {
                cipher: CipherAlg::Xor,
                kdf: KdfKind::Pbkdf2HmacSha256,
                iterations: None,
                salt: None,
                nonce: [0; 8],
            }),
            has_crc: false,
        };
        assert_eq!(meta.encode(), Err(ManifestError::MissingField));

        let meta = BundleMeta {
            cipher: Some(CipherMeta {
                cipher: CipherAlg::Xor,
                kdf: KdfKind::None,
                iterations: Some(1000),
                salt: None,
                nonce: [0; 8],
            }),
            ..meta
        };
        assert_eq!(meta.encode(), Err(ManifestError::UnexpectedField));

        let meta = BundleMeta {
            cipher: Some(CipherMeta {
                cipher: CipherAlg::Xor,
                kdf: KdfKind::Pbkdf2HmacSha256,
                iterations: Some(999),
                salt: Some([0; 16]),
                nonce: [0; 8],
            }),
            ..meta
        };
        assert_eq!(meta.encode(), Err(ManifestError::BadValue));
    }

    #[test]
    fn encode_rejects_bad_sector_size() {
        let meta = BundleMeta {
            kind: BundleKind::Flat {
                virtual_size: 8,
                chunk_size: 1,
                sector_size: 4096,
            },
            cipher: None,
            has_crc: false,
        };
        assert_eq!(meta.encode(), Err(ManifestError::BadValue));
    }

    #[test]
    fn display_and_error_impls() {
        fn assert_error<T: core::error::Error>() {}
        assert_error::<ManifestError>();
        assert!(!ManifestError::BadCrc.to_string().is_empty());
    }
}
