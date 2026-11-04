//! Process-level tests for `snowscsi crypt` and `bundle-create --cipher`.
//!
//! They drive the built binary as a black box, need no root and no mount, and
//! check the plaintext sidecar grammar directly.

#![cfg(feature = "cipher")]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_snowscsi"))
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("run snowscsi")
}

fn run_ok(args: &[&str]) -> Output {
    let out = run(args);
    assert!(
        out.status.success(),
        "snowscsi {args:?} failed:\n{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

fn run_fail(args: &[&str], needle: &str) -> Output {
    let out = run(args);
    assert!(
        !out.status.success(),
        "snowscsi {args:?} unexpectedly succeeded:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains(needle), "expected {needle:?} in:\n{err}");
    out
}

static NEXT: AtomicUsize = AtomicUsize::new(0);

/// Unique temporary directory, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "snowscsi_crypt_{tag}_{}_{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        Self(dir)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    fn str(&self, name: &str) -> String {
        self.path(name).to_string_lossy().into_owned()
    }

    fn write(&self, name: &str, bytes: &[u8]) -> String {
        let path = self.path(name);
        std::fs::write(&path, bytes).expect("write temp file");
        path.to_string_lossy().into_owned()
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Deterministic pseudo-random bytes (xorshift64), so a roundtrip compares a
/// non-trivial 64 KiB payload without depending on the OS source.
fn pseudo_random(len: usize, seed: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut x = seed | 1;
    for _ in 0..len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        out.push((x & 0xff) as u8);
    }
    out
}

/// CRC-32 over every byte before the `crc` line (same polynomial as the
/// manifest encoder).
fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

fn read_manifest(sidecar: &str) -> String {
    std::fs::read_to_string(sidecar).expect("read sidecar")
}

fn manifest_value<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    let prefix = format!("{key} = ");
    text.lines().find_map(|line| line.strip_prefix(&prefix))
}

/// Assert the canonical image manifest, including a valid final CRC line.
fn assert_manifest(text: &str, size: u64, cipher: &str) {
    assert!(text.starts_with("magic = snow_bundle\n"), "{text}");
    assert_eq!(manifest_value(text, "version"), Some("1"));
    assert_eq!(manifest_value(text, "kind"), Some("image"));
    let expected_size = size.to_string();
    assert_eq!(manifest_value(text, "size"), Some(expected_size.as_str()));
    assert_eq!(manifest_value(text, "cipher"), Some(cipher));
    assert_eq!(
        manifest_value(text, "kdf"),
        Some("pbkdf2-hmac-sha256"),
        "{text}"
    );
    assert!(manifest_value(text, "iterations").is_some(), "{text}");
    assert!(manifest_value(text, "salt").is_some(), "{text}");
    assert!(manifest_value(text, "nonce").is_some(), "{text}");

    let crc_start = text.find("crc = ").expect("crc line");
    let crc = &text[crc_start + "crc = ".len()..];
    let crc = crc.trim_end();
    assert_eq!(crc.len(), 8, "{text}");
    assert_eq!(
        u32::from_str_radix(crc, 16).unwrap(),
        crc32(&text.as_bytes()[..crc_start]),
        "manifest CRC must cover every preceding byte:\n{text}"
    );
}

fn assert_no_temps(dir: &Path) {
    for entry in std::fs::read_dir(dir).expect("read temp dir").flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        assert!(
            !name.contains(".tmp.") && !name.ends_with(".lock"),
            "temporary or lock file left behind: {name}"
        );
    }
}

fn password_file(dir: &TempDir) -> String {
    dir.write("pw", b"correct horse battery staple\n")
}

#[test]
fn crypt_roundtrip_with_password_file() {
    let dir = TempDir::new("roundtrip");
    let plain = pseudo_random(64 * 1024, 0x5EED_1234);
    let input = dir.write("in.img", &plain);
    let enc = dir.str("enc.img");
    let dec = dir.str("dec.img");
    let pw = password_file(&dir);

    run_ok(&[
        "crypt",
        "--cipher",
        "chacha12",
        "--password-file",
        &pw,
        "--force",
        &input,
        &enc,
    ]);

    let ciphertext = std::fs::read(&enc).expect("read ciphertext");
    assert_eq!(ciphertext.len(), plain.len());
    assert_ne!(ciphertext, plain, "encryption must change the bytes");
    let sidecar = format!("{enc}.SNOWBUNDLE");
    let text = read_manifest(&sidecar);
    assert_manifest(&text, plain.len() as u64, "chacha12");

    run_ok(&[
        "crypt",
        "--decrypt",
        "--password-file",
        &pw,
        "--force",
        &enc,
        &dec,
    ]);
    assert_eq!(std::fs::read(&dec).expect("read plaintext"), plain);
    assert!(
        !Path::new(&format!("{dec}.SNOWBUNDLE")).exists(),
        "decryption never writes a sidecar"
    );
    assert_no_temps(&dir.0);
}

#[test]
fn every_algorithm_round_trips_at_an_unaligned_size() {
    const SIZE: usize = 65_537; // not a multiple of 16 or 64
    let dir = TempDir::new("algorithms");
    let plain = pseudo_random(SIZE, 0xC0FF_EE00);
    let pw = password_file(&dir);

    for alg in ["chacha8", "chacha12", "chacha20", "aes-ctr", "xor"] {
        let input = dir.write(&format!("{alg}.in"), &plain);
        let enc = dir.str(&format!("{alg}.enc"));
        let dec = dir.str(&format!("{alg}.dec"));
        run_ok(&[
            "crypt",
            "--cipher",
            alg,
            "--iterations",
            "1000",
            "--password-file",
            &pw,
            "--force",
            &input,
            &enc,
        ]);
        assert_ne!(
            std::fs::read(&enc).unwrap(),
            plain,
            "{alg} must encrypt the payload"
        );
        assert_manifest(
            &read_manifest(&format!("{enc}.SNOWBUNDLE")),
            SIZE as u64,
            alg,
        );

        run_ok(&[
            "crypt",
            "--decrypt",
            "--password-file",
            &pw,
            "--force",
            &enc,
            &dec,
        ]);
        assert_eq!(
            std::fs::read(&dec).unwrap(),
            plain,
            "{alg} must round-trip unaligned head/tail"
        );
    }
    assert_no_temps(&dir.0);
}

#[test]
fn key_file_roundtrip_uses_kdf_none() {
    let dir = TempDir::new("keyfile");
    let plain = pseudo_random(65_537, 0xABCD_0001);
    let input = dir.write("in.img", &plain);
    let key = dir.write("key.bin", &[0x42u8; 32]);
    let enc = dir.str("enc.img");
    let dec = dir.str("dec.img");

    run_ok(&[
        "crypt",
        "--cipher",
        "aes-ctr",
        "--key-file",
        &key,
        "--force",
        &input,
        &enc,
    ]);
    let text = read_manifest(&format!("{enc}.SNOWBUNDLE"));
    assert_eq!(manifest_value(&text, "kind"), Some("image"));
    assert_eq!(manifest_value(&text, "cipher"), Some("aes-ctr"));
    assert_eq!(manifest_value(&text, "kdf"), Some("none"));
    assert_eq!(manifest_value(&text, "iterations"), None);
    assert_eq!(manifest_value(&text, "salt"), None);
    assert!(manifest_value(&text, "nonce").is_some());
    let crc_start = text.find("crc = ").unwrap();
    assert_eq!(
        u32::from_str_radix(text[crc_start + 6..].trim_end(), 16).unwrap(),
        crc32(&text.as_bytes()[..crc_start])
    );

    run_ok(&[
        "crypt",
        "--decrypt",
        "--key-file",
        &key,
        "--force",
        &enc,
        &dec,
    ]);
    assert_eq!(std::fs::read(&dec).unwrap(), plain);
    assert_no_temps(&dir.0);
}

#[test]
fn crypt_rejects_bad_invocations() {
    let dir = TempDir::new("rejects");
    let input = dir.write("in.img", &pseudo_random(4096, 7));
    let key = dir.write("key.bin", &[0x11u8; 32]);
    let short_key = dir.write("short.bin", &[0x11u8; 31]);
    let pw = password_file(&dir);
    let two_lines = dir.write("two", b"first\nsecond\n");
    let out = dir.str("out.img");

    // Encryption requires the algorithm.
    run_fail(&["crypt", &input, &out], "--cipher");

    // Decryption mode decides the algorithm from the sidecar.
    run_fail(
        &[
            "crypt",
            "--decrypt",
            "--cipher",
            "chacha12",
            "--password-file",
            &pw,
            &input,
            &out,
        ],
        "does not take --cipher",
    );

    // Existing output/sidecar needs --force.
    std::fs::write(&out, b"existing").unwrap();
    run_fail(
        &[
            "crypt",
            "--cipher",
            "xor",
            "--password-file",
            &pw,
            &input,
            &out,
        ],
        "already exists",
    );
    std::fs::remove_file(&out).unwrap();
    std::fs::write(format!("{out}.SNOWBUNDLE"), b"stale").unwrap();
    run_fail(
        &[
            "crypt",
            "--cipher",
            "xor",
            "--password-file",
            &pw,
            &input,
            &out,
        ],
        "already exists",
    );
    std::fs::remove_file(format!("{out}.SNOWBUNDLE")).unwrap();

    // Out-of-place encryption never overwrites its input.
    run_fail(
        &[
            "crypt",
            "--cipher",
            "xor",
            "--password-file",
            &pw,
            &input,
            &input,
        ],
        "must differ",
    );

    // In-place is encryption-only.
    run_fail(&["crypt", "--decrypt", "--in-place", &input], "--in-place");
    run_fail(
        &[
            "crypt",
            "--cipher",
            "xor",
            "--password-file",
            &pw,
            "--in-place",
            &input,
            &out,
        ],
        "takes no output",
    );

    // In-place refuses an existing sidecar (no --force override).
    let sidecar = format!("{input}.SNOWBUNDLE");
    std::fs::write(&sidecar, b"stale").unwrap();
    run_fail(
        &[
            "crypt",
            "--cipher",
            "xor",
            "--password-file",
            &pw,
            "--in-place",
            &input,
        ],
        "already exists",
    );
    std::fs::remove_file(&sidecar).unwrap();

    // --force is meaningless for --in-place and is rejected.
    run_fail(
        &[
            "crypt",
            "--cipher",
            "xor",
            "--password-file",
            &pw,
            "--force",
            "--in-place",
            &input,
        ],
        "--force cannot be used with --in-place",
    );

    // A key file is exact and exclusive with the other key sources.
    run_fail(
        &[
            "crypt",
            "--cipher",
            "xor",
            "--key-file",
            &short_key,
            &input,
            &out,
        ],
        "32 bytes",
    );
    run_fail(
        &[
            "crypt",
            "--cipher",
            "xor",
            "--key-file",
            &key,
            "--password-file",
            &pw,
            &input,
            &out,
        ],
        "mutually exclusive",
    );
    run_fail(
        &[
            "crypt",
            "--cipher",
            "xor",
            "--key-file",
            &key,
            "--iterations",
            "1000",
            &input,
            &out,
        ],
        "mutually exclusive",
    );

    // Password files are one line.
    run_fail(
        &[
            "crypt",
            "--cipher",
            "xor",
            "--password-file",
            &two_lines,
            &input,
            &out,
        ],
        "one line",
    );
    assert_no_temps(&dir.0);
}

#[test]
fn in_place_roundtrip_and_no_temps() {
    let dir = TempDir::new("inplace");
    let plain = pseudo_random(65_537, 0x1357_9BDF);
    let input = dir.write("disk.img", &plain);
    let restored = dir.str("restored.img");
    let pw = password_file(&dir);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&input, std::fs::Permissions::from_mode(0o640)).unwrap();
    }

    run_ok(&[
        "crypt",
        "--cipher",
        "chacha20",
        "--iterations",
        "1000",
        "--password-file",
        &pw,
        "--in-place",
        &input,
    ]);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            std::fs::metadata(&input).unwrap().permissions().mode() & 0o777,
            0o640,
            "--in-place must preserve the input's permissions"
        );
    }
    assert!(Path::new(&format!("{input}.SNOWBUNDLE")).is_file());
    let ciphertext = std::fs::read(&input).unwrap();
    assert_ne!(ciphertext, plain);
    assert_manifest(
        &read_manifest(&format!("{input}.SNOWBUNDLE")),
        plain.len() as u64,
        "chacha20",
    );

    run_ok(&[
        "crypt",
        "--decrypt",
        "--password-file",
        &pw,
        "--force",
        &input,
        &restored,
    ]);
    assert_eq!(std::fs::read(&restored).unwrap(), plain);
    assert_no_temps(&dir.0);
}

#[test]
fn decrypt_refuses_a_sidecar_size_mismatch() {
    let dir = TempDir::new("size_mismatch");
    let plain = pseudo_random(65_537, 0x2468_ACE0);
    let input = dir.write("in.img", &plain);
    let key = dir.write("key.bin", &[0x5Au8; 32]);
    let enc = dir.str("enc.img");
    let out = dir.str("out.img");

    run_ok(&[
        "crypt",
        "--cipher",
        "xor",
        "--key-file",
        &key,
        "--force",
        &input,
        &enc,
    ]);
    let sidecar = format!("{enc}.SNOWBUNDLE");
    let text = read_manifest(&sidecar);
    assert!(manifest_value(&text, "size").is_some());

    // Hand-edit the size and drop the now-stale CRC line; a CRC-less manifest
    // is accepted by the parser, so the size check itself must refuse.
    let mut lines: Vec<String> = text
        .lines()
        .filter(|line| !line.starts_with("crc = "))
        .map(|line| {
            if line.starts_with("size = ") {
                format!("size = {}", plain.len() as u64 + 1)
            } else {
                line.to_string()
            }
        })
        .collect();
    lines.push(String::new());
    std::fs::write(&sidecar, lines.join("\n")).unwrap();

    run_fail(
        &[
            "crypt",
            "--decrypt",
            "--key-file",
            &key,
            "--force",
            &enc,
            &out,
        ],
        "declares image size",
    );
    assert!(!Path::new(&out).exists(), "no plaintext on a size mismatch");
    assert_no_temps(&dir.0);
}

#[cfg(unix)]
#[test]
fn crypt_rejects_aliased_paths() {
    use std::os::unix::fs::symlink;

    let dir = TempDir::new("alias");
    let plain = pseudo_random(4096, 0xA11A_5000);
    let input = dir.write("in.img", &plain);
    let pw = password_file(&dir);

    let reject = |out: &str| {
        run_fail(
            &[
                "crypt",
                "--cipher",
                "xor",
                "--password-file",
                &pw,
                &input,
                out,
            ],
            "same file",
        );
    };

    // The exact path, a `./` spelling and a `sub/..` spelling all resolve to
    // the input.
    reject(&input);
    reject(&format!("{}/./in.img", dir.0.display()));
    std::fs::create_dir(dir.path("sub")).unwrap();
    reject(&format!("{}/sub/../in.img", dir.0.display()));

    // An output equal to the input sidecar would destroy the cipher
    // parameters written for the input.
    reject(&format!("{input}.SNOWBUNDLE"));

    // A hard link has a different path but the same inode.
    let hard = dir.str("hard.img");
    std::fs::hard_link(&input, &hard).unwrap();
    reject(&hard);

    // A symlink resolves to the input's canonical path.
    let sym = dir.str("sym.img");
    symlink(&input, &sym).unwrap();
    reject(&sym);

    assert_no_temps(&dir.0);
}

#[cfg(unix)]
#[test]
fn in_place_refuses_symlink_and_hard_link() {
    use std::os::unix::fs::symlink;

    let dir = TempDir::new("inplace_links");
    let input = dir.write("in.img", &pseudo_random(4096, 0x1A2B_3C4D));
    let pw = password_file(&dir);

    let sym = dir.str("sym.img");
    symlink(&input, &sym).unwrap();
    run_fail(
        &[
            "crypt",
            "--cipher",
            "xor",
            "--password-file",
            &pw,
            "--in-place",
            &sym,
        ],
        "symbolic link",
    );

    let hard = dir.str("hard.img");
    std::fs::hard_link(&input, &hard).unwrap();
    run_fail(
        &[
            "crypt",
            "--cipher",
            "xor",
            "--password-file",
            &pw,
            "--in-place",
            &hard,
        ],
        "hard links",
    );

    // Neither refusal may have touched the original or left a sidecar/temp.
    assert_eq!(
        std::fs::read(&input).unwrap(),
        pseudo_random(4096, 0x1A2B_3C4D)
    );
    assert!(!Path::new(&format!("{input}.SNOWBUNDLE")).exists());
    assert_no_temps(&dir.0);
}

#[test]
fn forced_decrypt_removes_a_stale_output_sidecar() {
    let dir = TempDir::new("stale_decrypt_sidecar");
    let plain = pseudo_random(65_537, 0x0BAD_F00D);
    let input = dir.write("in.img", &plain);
    let key = dir.write("key.bin", &[0x77u8; 32]);
    let enc = dir.str("enc.img");
    let out = dir.str("out.img");
    let out_sidecar = format!("{out}.SNOWBUNDLE");

    run_ok(&[
        "crypt",
        "--cipher",
        "aes-ctr",
        "--key-file",
        &key,
        "--force",
        &input,
        &enc,
    ]);
    std::fs::write(&out_sidecar, b"stale cipher parameters").unwrap();

    run_ok(&[
        "crypt",
        "--decrypt",
        "--key-file",
        &key,
        "--force",
        &enc,
        &out,
    ]);
    assert_eq!(std::fs::read(&out).unwrap(), plain);
    assert!(
        !Path::new(&out_sidecar).exists(),
        "a forced decrypt must remove a stale output sidecar"
    );
    assert_no_temps(&dir.0);
}

#[test]
fn encryption_refuses_an_input_that_already_has_a_sidecar() {
    let dir = TempDir::new("already_encrypted");
    let input = dir.write("in.img", &pseudo_random(4096, 0xFEED_0001));
    let pw = password_file(&dir);
    let out = dir.str("out.img");
    let input_sidecar = format!("{input}.SNOWBUNDLE");
    std::fs::write(&input_sidecar, b"stale cipher parameters").unwrap();

    run_fail(
        &[
            "crypt",
            "--cipher",
            "xor",
            "--password-file",
            &pw,
            &input,
            &out,
        ],
        "already has",
    );
    assert!(!Path::new(&out).exists(), "must not double-encrypt");
    assert!(
        Path::new(&input_sidecar).exists(),
        "the pre-existing sidecar is left alone"
    );
    assert_no_temps(&dir.0);
}

#[test]
fn wrong_password_produces_garbage_not_an_error() {
    let dir = TempDir::new("wrong_password");
    let plain = pseudo_random(65_537, 0xDEAD_BEEF);
    let input = dir.write("in.img", &plain);
    let enc = dir.str("enc.img");
    let out = dir.str("out.img");
    let right = dir.write("right", b"correct horse battery staple\n");
    let wrong = dir.write("wrong", b"the wrong password\n");

    run_ok(&[
        "crypt",
        "--cipher",
        "chacha20",
        "--iterations",
        "1000",
        "--password-file",
        &right,
        "--force",
        &input,
        &enc,
    ]);
    // There is no payload authentication: this succeeds and writes garbage.
    run_ok(&[
        "crypt",
        "--decrypt",
        "--password-file",
        &wrong,
        "--force",
        &enc,
        &out,
    ]);
    let garbage = std::fs::read(&out).unwrap();
    assert_eq!(garbage.len(), plain.len());
    assert_ne!(
        garbage, plain,
        "a wrong password must not recover plaintext"
    );
    assert_no_temps(&dir.0);
}

#[test]
fn chunk_boundary_payload_round_trips_for_every_algorithm() {
    const SIZE: usize = 2 * 1024 * 1024 + 12_345;
    let dir = TempDir::new("chunk_boundary");
    let plain = pseudo_random(SIZE, 0xC0DE_1234);
    let pw = password_file(&dir);

    for alg in ["chacha8", "chacha12", "chacha20", "aes-ctr", "xor"] {
        let input = dir.write(&format!("{alg}.in"), &plain);
        let enc = dir.str(&format!("{alg}.enc"));
        let dec = dir.str(&format!("{alg}.dec"));
        run_ok(&[
            "crypt",
            "--cipher",
            alg,
            "--iterations",
            "1000",
            "--password-file",
            &pw,
            "--force",
            &input,
            &enc,
        ]);
        assert_ne!(
            std::fs::read(&enc).unwrap(),
            plain,
            "{alg} must change the payload"
        );
        run_ok(&[
            "crypt",
            "--decrypt",
            "--password-file",
            &pw,
            "--force",
            &enc,
            &dec,
        ]);
        assert_eq!(
            std::fs::read(&dec).unwrap(),
            plain,
            "{alg} must round-trip across 1 MiB chunk boundaries"
        );
    }
    assert_no_temps(&dir.0);
}

#[cfg(feature = "bundle")]
#[test]
fn bundle_create_flat_with_cipher_writes_and_reports_it() {
    let dir = TempDir::new("bundle_cipher");
    let mutations = dir.str("mut");
    let pw = password_file(&dir);
    let out = run_ok(&[
        "bundle-create",
        "flat",
        "--dir",
        &mutations,
        "--size",
        "8M",
        "--cipher",
        "chacha12",
        "--iterations",
        "1000",
        "--password-file",
        &pw,
    ]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("encrypted with chacha12"), "{stdout}");
    assert!(
        !String::from_utf8_lossy(&out.stderr).contains("password:"),
        "--password-file must not prompt"
    );

    let text = read_manifest(&format!("{mutations}/SNOWBUNDLE"));
    assert_eq!(manifest_value(&text, "kind"), Some("flat"));
    assert_eq!(manifest_value(&text, "cipher"), Some("chacha12"));
    assert_eq!(manifest_value(&text, "kdf"), Some("pbkdf2-hmac-sha256"));
    assert_eq!(manifest_value(&text, "iterations"), Some("1000"));
    assert!(manifest_value(&text, "salt").is_some());
    assert!(manifest_value(&text, "nonce").is_some());
    let crc_start = text.find("crc = ").unwrap();
    assert_eq!(
        u32::from_str_radix(text[crc_start + 6..].trim_end(), 16).unwrap(),
        crc32(&text.as_bytes()[..crc_start])
    );

    let info = run_ok(&["bundle-info", &mutations]);
    let info = String::from_utf8_lossy(&info.stdout);
    assert!(info.contains("kind = flat"), "{info}");
    assert!(info.contains("cipher = chacha12"), "{info}");
    assert!(info.contains("kdf = pbkdf2-hmac-sha256"), "{info}");
    assert!(info.contains("iterations = 1000"), "{info}");
    assert!(info.contains("crc = present"), "{info}");

    // A key-file bundle carries no salt/iterations.
    let keyed = dir.str("keyed");
    let key = dir.write("key.bin", &[0x33u8; 32]);
    run_ok(&[
        "bundle-create",
        "flat",
        "--dir",
        &keyed,
        "--size",
        "8M",
        "--cipher",
        "aes-ctr",
        "--key-file",
        &key,
    ]);
    let text = read_manifest(&format!("{keyed}/SNOWBUNDLE"));
    assert_eq!(manifest_value(&text, "cipher"), Some("aes-ctr"));
    assert_eq!(manifest_value(&text, "kdf"), Some("none"));
    assert_eq!(manifest_value(&text, "iterations"), None);
    assert_eq!(manifest_value(&text, "salt"), None);
    let info = run_ok(&["bundle-info", &keyed]);
    assert!(String::from_utf8_lossy(&info.stdout).contains("cipher = aes-ctr"));
    assert_no_temps(&dir.0);
}

#[cfg(feature = "bundle")]
#[test]
fn bundle_create_rejects_bad_cipher_flags() {
    let dir = TempDir::new("bundle_bad");
    let pw = password_file(&dir);
    let key = dir.write("key.bin", &[0x22u8; 32]);

    for target in [dir.str("a"), dir.str("b")] {
        run_fail(
            &[
                "bundle-create",
                "flat",
                "--dir",
                &target,
                "--size",
                "8M",
                "--cipher",
            ],
            "",
        );
    }
    run_fail(
        &[
            "bundle-create",
            "flat",
            "--dir",
            &dir.str("c"),
            "--size",
            "8M",
            "--cipher",
            "rot13",
        ],
        "unknown cipher",
    );
    run_fail(
        &[
            "bundle-create",
            "flat",
            "--dir",
            &dir.str("d"),
            "--size",
            "8M",
            "--iterations",
            "1000",
        ],
        "requires --cipher",
    );
    run_fail(
        &[
            "bundle-create",
            "flat",
            "--dir",
            &dir.str("e"),
            "--size",
            "8M",
            "--key-file",
            &key,
        ],
        "requires --cipher",
    );
    run_fail(
        &[
            "bundle-create",
            "flat",
            "--dir",
            &dir.str("f"),
            "--size",
            "8M",
            "--password-file",
            &pw,
        ],
        "requires --cipher",
    );
    assert_no_temps(&dir.0);
}

#[cfg(feature = "cdr-bundle")]
#[test]
fn cdr_cipher_manifest_is_created_and_serves_with_its_key() {
    let dir = TempDir::new("cdr_cipher");
    let bundle = dir.str("cdr");
    let key = dir.write("key.bin", &[0x44u8; 32]);

    let out = run_ok(&[
        "bundle-create",
        "cdr",
        "--dir",
        &bundle,
        "--cipher",
        "xor",
        "--key-file",
        &key,
    ]);
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("obfuscated with xor"),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    let text = read_manifest(&format!("{bundle}/SNOWBUNDLE"));
    assert_eq!(manifest_value(&text, "kind"), Some("cdr"));
    assert_eq!(manifest_value(&text, "cipher"), Some("xor"));
    assert_eq!(manifest_value(&text, "kdf"), Some("none"));

    // The recordable bundle is now servable with its key: `--print-config`
    // identifies it without deriving the key, and a real serve without the
    // key material is a hard error, never a plaintext fallback.
    let out = run_ok(&[
        "serve",
        "--cdrom",
        &format!("bundle={bundle},cipher,key={key}"),
        "--usb",
        "--print-config",
    ]);
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("backing=bundle"),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    run_fail(
        &[
            "serve",
            "--cdrom",
            &format!("bundle={bundle},cipher"),
            "--password-file",
            &dir.write("pw", b"secret\n"),
            "--iscsi",
            "127.0.0.1:0",
        ],
        "key=<path>",
    );
    assert_no_temps(&dir.0);
}

#[cfg(feature = "cdr-bundle")]
#[test]
fn cdr_create_refuses_an_encrypted_cdrw() {
    let dir = TempDir::new("cdr_cdrw_create");
    let key = dir.write("key.bin", &[0x55u8; 32]);
    let bundle = dir.str("cdrw");

    run_fail(
        &[
            "bundle-create",
            "cdr",
            "--dir",
            &bundle,
            "--medium",
            "cdrw80",
            "--cipher",
            "xor",
            "--key-file",
            &key,
        ],
        "write-once CD-R",
    );
    assert!(
        !Path::new(&bundle).exists(),
        "a refused encrypted CD-RW must not create the bundle directory"
    );
    assert_no_temps(&dir.0);
}

#[cfg(feature = "cdr-bundle")]
#[test]
fn cdr_serve_refuses_a_stored_cdrw_with_a_cipher() {
    let dir = TempDir::new("cdr_cdrw_serve");
    let bundle = dir.str("cdrw");
    let key = dir.write("key.bin", &[0x66u8; 32]);

    // Create a plaintext CD-RW, then add a cipher block to its manifest. The
    // stored TOC (not the manifest) says cdrw; the refusal happens after the
    // medium is opened.
    run_ok(&[
        "bundle-create",
        "cdr",
        "--dir",
        &bundle,
        "--medium",
        "cdrw80",
    ]);
    std::fs::write(
        Path::new(&bundle).join("SNOWBUNDLE"),
        "magic = snow_bundle\n\
         version = 1\n\
         kind = cdr\n\
         cipher = xor\n\
         kdf = none\n\
         nonce = 5a5a5a5a5a5a5a5a\n",
    )
    .unwrap();

    run_fail(
        &[
            "serve",
            "--cdrom",
            &format!("bundle={bundle},cipher,key={key}"),
            "--iscsi",
            "127.0.0.1:0",
        ],
        "write-once CD-R",
    );
    assert_no_temps(&dir.0);
}
