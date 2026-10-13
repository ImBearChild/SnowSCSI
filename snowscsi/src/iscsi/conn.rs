//! Connection abstraction and exact byte-stream I/O helpers.
//!
//! [`Conn`] is a blanket trait over `embedded_io::Read + Write` — the core
//! only works on a portable no_std byte stream; the host supplies a concrete
//! transport (BSD `TcpStream`, mock, esp-wifi socket). `read_exact` /
//! `write_all` loop over partial transfers (RFC 3720 §3.1 byte stream).

/// Byte-stream connection (blanket impl of `embedded_io::Read + Write`).
pub trait Conn: embedded_io::Read + embedded_io::Write {}

impl<T: embedded_io::Read + embedded_io::Write> Conn for T {}

/// Read exactly `buf.len()` bytes, looping over partial reads.
///
/// Returns `Err(())` on an I/O error or EOF (0-byte read, peer closed).
/// The error kind is deliberately discarded: any transport failure means the
/// connection must close, and `Conn::Error` is an associated type.
#[allow(clippy::result_unit_err)]
pub fn read_exact<C: Conn + ?Sized>(conn: &mut C, mut buf: &mut [u8]) -> Result<(), ()> {
    while !buf.is_empty() {
        let n = conn.read(buf).map_err(|_| ())?;
        if n == 0 {
            return Err(());
        }
        buf = &mut buf[n..];
    }
    Ok(())
}

/// Write the whole buffer, looping over partial writes.
///
/// Returns `Err(())` on an I/O error or a zero-length write (see
/// `read_exact` for the error-design rationale).
#[allow(clippy::result_unit_err)]
pub fn write_all<C: Conn + ?Sized>(conn: &mut C, mut buf: &[u8]) -> Result<(), ()> {
    while !buf.is_empty() {
        let n = conn.write(buf).map_err(|_| ())?;
        if n == 0 {
            return Err(());
        }
        buf = &buf[n..];
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::RefCell;

    /// Scripted writer for `write_all` tests (reads always EOF).
    struct Sink {
        written: RefCell<Vec<u8>>,
    }

    impl embedded_io::ErrorType for Sink {
        type Error = core::convert::Infallible;
    }

    impl embedded_io::Read for Sink {
        fn read(&mut self, _buf: &mut [u8]) -> Result<usize, Self::Error> {
            Ok(0)
        }
    }

    impl embedded_io::Write for Sink {
        fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
            self.written.borrow_mut().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[test]
    fn write_all_writes_everything() {
        let mut s = Sink {
            written: RefCell::new(Vec::new()),
        };
        let data = [0u8; 48];
        assert!(write_all(&mut s, &data).is_ok());
        assert_eq!(s.written.borrow().len(), 48);
    }

    #[test]
    fn read_exact_returns_err_on_eof() {
        let mut s = Sink {
            written: RefCell::new(Vec::new()),
        };
        let mut buf = [0u8; 48];
        assert!(read_exact(&mut s, &mut buf).is_err());
    }
}
