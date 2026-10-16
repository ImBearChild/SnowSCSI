//! Small cross-cutting helpers with no feature-specific dependencies.
//!
//! Lives under `scsi` (the base every device/transport feature depends on) so
//! the transport layers (`usb`/`iscsi`) do not have to pull in `cdrom` just for
//! a debug-formatting helper.

/// Render `data` as space-separated uppercase hex into `out`; returns the
/// used subslice. Debug-logging helper (no_std, no alloc).
#[cfg(any(feature = "cdrom", feature = "usb"))]
pub(crate) fn hex_of<'o>(out: &'o mut [u8], data: &[u8]) -> &'o [u8] {
    let mut i = 0;
    for (n, b) in data.iter().enumerate() {
        if i + 3 > out.len() {
            break;
        }
        let hi = b >> 4;
        let lo = b & 0x0F;
        out[i] = if hi < 10 { b'0' + hi } else { b'A' + hi - 10 };
        out[i + 1] = if lo < 10 { b'0' + lo } else { b'A' + lo - 10 };
        i += 2;
        if n + 1 < data.len() {
            out[i] = b' ';
            i += 1;
        }
    }
    &out[..i]
}
