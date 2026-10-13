pub mod live;

/// Library version (SemVer), like `snow9660_version()` in the C stub.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Returns the library version string.
pub fn version() -> &'static str {
    VERSION
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_not_null() {
        assert!(!version().is_empty());
    }
}
