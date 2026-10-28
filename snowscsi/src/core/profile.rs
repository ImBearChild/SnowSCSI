//! Optional SPC profile capabilities for the public query commands.
//!
//! Authority: `__ARCH__/design/02-api-core.md` §4.19 (extension clause):
//! Defaulted capability methods let MODE SENSE, READ
//! CAPACITY, GET CONFIGURATION and GET EVENT STATUS NOTIFICATION can be
//! served by [`Spc`](super::spc::Spc) without changing the six-command
//! semantics or forcing existing [`Device`](super::device::Device)
//! implementors to add methods.
//!
//! Every method is **defaulted to "not supported"**. A device opts in by
//! overriding [`Device::spc_profile`](super::device::Device::spc_profile) to
//! return `Some(self)`. When it returns `None`, `Spc` delegates the opcode to
//! the inner device unchanged.
//!
//! Encoding convention: each command method returns the **complete response
//! length** and writes `min(length, out.len())` bytes when `out` is `Some`.
//! The caller (`Spc`) passes `None` while preparing to learn the length and
//! `Some(&mut data[..n])` while polling. Implementations must make the header
//! length fields describe the complete response even when the caller's buffer
//! is shorter; truncation never changes the declared length.

/// Capacity reported by READ CAPACITY(10).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capacity {
    /// Last addressable logical block (zero-based).
    pub last_lba: u32,
    /// Logical block length in bytes.
    pub block_len: u32,
}

impl Capacity {
    /// Build a capacity value.
    #[must_use]
    pub const fn new(last_lba: u32, block_len: u32) -> Self {
        Self {
            last_lba,
            block_len,
        }
    }
}

/// Profile-owned answers for the public SPC query commands.
///
/// Implementors: [`BlockDevice`](crate::block::BlockDevice) (MODE SENSE,
/// READ CAPACITY) and [`MmcDrive`](crate::mmc::MmcDrive) (all four). The
/// trait lives in core because the public wrapper serves the commands; it
/// carries no storage IO and no executor.
pub trait SpcProfile {
    /// Medium type byte for the MODE SENSE parameter header (MMC: `0x41`).
    fn medium_type(&self) -> u8 {
        0
    }

    /// Runtime write-protect latch for the MODE SENSE WP bit.
    fn write_protected(&self) -> bool {
        false
    }

    /// Encode a MODE SENSE(6/10) response, including its parameter header.
    ///
    /// `ten` selects the 10-byte CDB header layout (4 vs 8 header bytes),
    /// `page` is the page code (`0x3F` = all pages), `dbd` disables block
    /// descriptors, `pc` is the page-control field. Returns the complete
    /// response length, or `None` when the page is unsupported.
    fn mode_sense(
        &self,
        ten: bool,
        page: u8,
        dbd: bool,
        pc: u8,
        out: Option<&mut [u8]>,
    ) -> Option<usize> {
        let _ = (ten, page, dbd, pc, out);
        None
    }

    /// READ CAPACITY(10) geometry. `None` = unsupported/not ready.
    fn read_capacity(&self) -> Option<Capacity> {
        None
    }

    /// Encode a GET CONFIGURATION response (feature header + descriptors).
    ///
    /// `rt` is the RT field, `start_feature` the Starting Feature Number.
    /// Returns the complete response length, or `None` when unsupported.
    fn get_configuration(
        &self,
        rt: u8,
        start_feature: u16,
        out: Option<&mut [u8]>,
    ) -> Option<usize> {
        let _ = (rt, start_feature, out);
        None
    }

    /// Encode a GET EVENT STATUS NOTIFICATION response.
    ///
    /// `class` is the notification class from CDB byte 4. Returns the
    /// complete response length, or `None` when the class is unsupported.
    fn event_status(&self, class: u8, out: Option<&mut [u8]>) -> Option<usize> {
        let _ = (class, out);
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Bare;

    impl SpcProfile for Bare {}

    #[test]
    fn defaults_are_unsupported() {
        let p = Bare;
        assert_eq!(p.medium_type(), 0);
        assert!(!p.write_protected());
        assert_eq!(p.mode_sense(false, 0x08, false, 0, None), None);
        assert_eq!(p.read_capacity(), None);
        assert_eq!(p.get_configuration(0, 0, None), None);
        assert_eq!(p.event_status(0x10, None), None);
    }

    #[test]
    fn capacity_is_a_plain_value() {
        let c = Capacity::new(99, 2048);
        assert_eq!(c.last_lba, 99);
        assert_eq!(c.block_len, 2048);
    }
}
