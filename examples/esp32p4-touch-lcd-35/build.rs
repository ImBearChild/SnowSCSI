//! Build script: wires the linker scripts the Espressif crates provide into
//! the final link (mirrors the esp-generate project template, with the
//! `defmt` option selected).
//!
//! ESP32-P4 is RISC-V: it links with the bundled `rust-lld` (no Espressif GCC,
//! hence no `check_xtensa_linker_available` here, unlike the S3 example).
//!
//! - `defmt.x` provides `PROVIDE(_defmt_timestamp = __defmt_default_timestamp)`.
//! - `linkall.x` (emitted by `esp-hal` into its `OUT_DIR`, on the search path
//!   esp-hal adds) must be the **last** linker script.

fn main() {
    // `--error-handling-script` is a GNU-ld feature. ESP32-P4 is RISC-V and
    // links with the bundled `rust-lld`, which rejects it, so only emit the
    // nice-error hook on Xtensa (where the S3 example links via Espressif GCC).
    if std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("xtensa") {
        linker_be_nice();
    }

    // defmt: default timestamp / panic handlers.
    println!("cargo:rustc-link-arg=-Tdefmt.x");
    // linkall.x must come last.
    println!("cargo:rustc-link-arg=-Tlinkall.x");
}

/// Turns cryptic "undefined symbol" linker errors into actionable hints.
fn linker_be_nice() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 {
        let kind = &args[1];
        let what = &args[2];

        match kind.as_str() {
            "undefined-symbol" => match what.as_str() {
                what if what.starts_with("_defmt_") => {
                    eprintln!();
                    eprintln!(
                        "`defmt` not found - make sure `defmt.x` is added as a linker script and you have included `use defmt;`"
                    );
                    eprintln!();
                }
                "_stack_start" => {
                    eprintln!();
                    eprintln!("Is the linker script `linkall.x` missing?");
                    eprintln!();
                }
                what if what.starts_with("esp_rtos_") => {
                    eprintln!();
                    eprintln!(
                        "`esp-rtos` has no scheduler enabled. Make sure you have initialized `esp-rtos`."
                    );
                    eprintln!();
                }
                _ => (),
            },
            _ => {
                std::process::exit(1);
            }
        }

        std::process::exit(0);
    }

    println!(
        "cargo:rustc-link-arg=-Wl,--error-handling-script={}",
        std::env::current_exe().unwrap().display()
    );
}
