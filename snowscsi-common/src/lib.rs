//! SnowSCSI common: zero-alloc storage seams + unified logging macros.
//!
//! Always available — no feature gate on this crate.

#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
#![deny(unsafe_code)]

pub mod flat_bundle;
pub mod fs_plane;
pub mod fs_storage;
pub mod logging;
pub mod seekable_storage;
pub mod store;
