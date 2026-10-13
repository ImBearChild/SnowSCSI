//! SnowSCSI disc: ISO9660/Joliet live-generation algorithms.

#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
#![deny(unsafe_code)]

pub mod live;

pub use live::{
    compute_layout, compute_layout_opts, CdLiveFsError, FileEntry, IsoError, IsoOptions, Layout,
    LiveData, LiveDataBuilder, VolumeMetadata, MAX_FILES, MAX_PATH_LEN, SECTOR_SIZE,
};
