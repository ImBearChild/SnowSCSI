fn main() {
    if cfg!(target_os = "linux") {
        println!("cargo:rustc-check-cfg=cfg(has_libiscsi)");
        match pkg_config::probe_library("libiscsi") {
            Ok(lib) => {
                println!("cargo:rustc-cfg=has_libiscsi");
                println!("cargo:warning=libiscsi found, integration tests enabled");
                cc::Build::new()
                    .file("c/iscsi_access.c")
                    .includes(&lib.include_paths)
                    .compile("snow_iscsi_access");
            }
            Err(_) => {
                println!("cargo:warning=libiscsi not found, integration tests skipped");
            }
        }
    }
}
