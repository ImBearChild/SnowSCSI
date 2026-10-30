//! Tokio binding for the library's asynchronous connection seam.
//!
//! [`AsyncConn`] is a plain trait, so the orphan rule keeps the crate from
//! implementing it for `tokio::net::TcpStream` directly. [`TokioConn`] is the
//! newtype that carries the implementation: production wraps a
//! [`tokio::net::TcpStream`], tests can wrap a [`tokio::io::duplex`] pair.

use snowscsi::iscsi::conn::AsyncConn;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// An async byte stream wrapped as an [`AsyncConn`].
pub struct TokioConn<S>(S);

impl<S> TokioConn<S> {
    /// Wrap `inner`.
    pub fn new(inner: S) -> Self {
        Self(inner)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncConn for TokioConn<S> {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, ()> {
        self.0.read(buf).await.map_err(|_| ())
    }

    async fn write_all(&mut self, buf: &[u8]) -> Result<(), ()> {
        self.0.write_all(buf).await.map_err(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_duplex_pair_round_trips() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let (a, b) = tokio::io::duplex(64);
            let mut writer = TokioConn::new(a);
            let mut reader = TokioConn::new(b);
            assert_eq!(writer.write_all(b"ping").await, Ok(()));
            let mut buf = [0u8; 4];
            assert_eq!(reader.read(&mut buf).await, Ok(4));
            assert_eq!(&buf, b"ping");
        });
    }
}
