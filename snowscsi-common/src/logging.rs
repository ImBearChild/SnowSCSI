//! Unified logging macros for the SnowSCSI workspace crates.
//!
//! Dispatched by feature:
//! - `log` feature  — `::log::trace!()` etc.
//! - `defmt` feature — `::defmt::trace!()` etc.
//! - (neither)      — every call is compiled to a no-op.
//!
//! The design follows the Embassy pattern: the library never chooses a
//! backend; the final binary enables the feature it wants.  Capturing
//! or routing log output is the caller's responsibility (e.g. an upper
//! layer implements `log::Log` or provides a `defmt` logger).

#[cfg(all(feature = "log", feature = "defmt"))]
compile_error!("You may not enable both `log` and `defmt` features.");

// `std` + `defmt` is unsupported: `std::io::Error` (formatted by the std-only
// backends) cannot implement `defmt::Format`. The macro definitions below also
// fall back to the no-op branch in this combination, so this is the *only*
// error the build reports.
#[cfg(all(feature = "std", feature = "defmt"))]
compile_error!(
    "defmt is no_std-only: `std` + `defmt` is unsupported (`std::io::Error` \
     cannot implement `defmt::Format`). Disable `std` or `defmt`."
);

#[macro_export]
macro_rules! trace {
    ($s:literal $(, $x:expr)* $(,)?) => {{
        #[cfg(feature = "log")]
        ::log::trace!($s $(, $x)*);
        #[cfg(all(feature = "defmt", not(feature = "std")))]
        ::defmt::trace!($s $(, $x)*);
        // `if false` keeps the branch type-checked (so implicit format-string
        // captures like `info!("{peer}")` still count as *uses* of the
        // variables — a plain `let _ = (&$x,)*` would leave them unused) at
        // zero runtime cost.
        #[cfg(not(any(feature = "log", all(feature = "defmt", not(feature = "std")))))]
        if false {
            ::core::panic!($s $(, $x)*);
        }
    }};
}

#[macro_export]
macro_rules! debug {
    ($s:literal $(, $x:expr)* $(,)?) => {{
        #[cfg(feature = "log")]
        ::log::debug!($s $(, $x)*);
        #[cfg(all(feature = "defmt", not(feature = "std")))]
        ::defmt::debug!($s $(, $x)*);
        #[cfg(not(any(feature = "log", all(feature = "defmt", not(feature = "std")))))]
        if false {
            ::core::panic!($s $(, $x)*);
        }
    }};
}

#[macro_export]
macro_rules! info {
    ($s:literal $(, $x:expr)* $(,)?) => {{
        #[cfg(feature = "log")]
        ::log::info!($s $(, $x)*);
        #[cfg(all(feature = "defmt", not(feature = "std")))]
        ::defmt::info!($s $(, $x)*);
        #[cfg(not(any(feature = "log", all(feature = "defmt", not(feature = "std")))))]
        if false {
            ::core::panic!($s $(, $x)*);
        }
    }};
}

#[macro_export]
macro_rules! warn {
    ($s:literal $(, $x:expr)* $(,)?) => {{
        #[cfg(feature = "log")]
        ::log::warn!($s $(, $x)*);
        #[cfg(all(feature = "defmt", not(feature = "std")))]
        ::defmt::warn!($s $(, $x)*);
        #[cfg(not(any(feature = "log", all(feature = "defmt", not(feature = "std")))))]
        if false {
            ::core::panic!($s $(, $x)*);
        }
    }};
}

#[macro_export]
macro_rules! error {
    ($s:literal $(, $x:expr)* $(,)?) => {{
        #[cfg(feature = "log")]
        ::log::error!($s $(, $x)*);
        #[cfg(all(feature = "defmt", not(feature = "std")))]
        ::defmt::error!($s $(, $x)*);
        #[cfg(not(any(feature = "log", all(feature = "defmt", not(feature = "std")))))]
        if false {
            ::core::panic!($s $(, $x)*);
        }
    }};
}

#[cfg(test)]
mod tests {
    /// When neither `log` nor `defmt` is enabled, macros are no-ops.
    #[cfg(not(any(feature = "log", feature = "defmt")))]
    #[test]
    fn macros_noop_without_feature() {
        info!("hello");
        warn!("hello");
        error!("hello");
        debug!("hello");
        trace!("hello");
    }

    /// When neither feature is enabled, macros with format args are
    /// still no-ops (no unused-variable warnings).
    #[cfg(not(any(feature = "log", feature = "defmt")))]
    #[test]
    fn macros_noop_with_args() {
        let x = 42;
        let y = "foo";
        info!("x={} y={}", x, y);
        debug!("x={}", x);
    }

    /// With `log` enabled, macros compile and dispatch (actual dispatch
    /// validated by downstream integration tests with a real logger).
    #[cfg(feature = "log")]
    #[test]
    fn macros_compile_with_log() {
        let x = 42;
        info!("hello");
        warn!("world");
        error!("CmdSN={}", x);
        debug!("debug={}", x);
        trace!("trace");
    }
}
