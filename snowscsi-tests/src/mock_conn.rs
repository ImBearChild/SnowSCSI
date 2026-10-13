//! Mock `embedded_io::Read + Write` connection for deterministic
//! step-level integration testing of the snowscsi iSCSI target.
//!
//! Uses `Vec<u8>` deque semantics — no threads, no globals. Folded in from
//! the former `snowscsi-mock` crate (R6).

#[derive(Default)]
pub struct MockConn {
    rx: std::collections::VecDeque<u8>,
    pub tx: std::vec::Vec<u8>,
}

impl MockConn {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn feed(&mut self, bhs: &[u8; 48], data: &[u8]) {
        self.rx.extend(bhs);
        self.rx.extend(data);
    }

    /// Push raw inbound bytes (for AHS / odd framing in tests).
    pub fn feed_bytes(&mut self, bytes: &[u8]) {
        self.rx.extend(bytes);
    }

    pub fn feed_padded(&mut self, bhs: &[u8; 48], data: &[u8]) {
        let dsl = data.len();
        let total = 48 + dsl;
        let pad = (4 - (total & 3)) & 3;
        self.rx.extend(bhs);
        self.rx.extend(data);
        self.rx.resize(self.rx.len() + pad, 0);
    }

    pub fn feed_login_text(&mut self, text: &str) {
        let t = text.as_bytes();
        let dsl = t.len() as u32;
        let mut bhs = [0u8; 48];
        bhs[0] = 0x03;
        bhs[5] = (dsl >> 16) as u8;
        bhs[6] = (dsl >> 8) as u8;
        bhs[7] = dsl as u8;
        self.feed_padded(&bhs, t);
    }

    pub fn take_pdu(&mut self) -> Option<(std::vec::Vec<u8>, std::vec::Vec<u8>)> {
        if self.tx.len() < 48 {
            return None;
        }
        let bhs = self.tx[..48].to_vec();
        let dsl = (u32::from(bhs[5]) << 16) | (u32::from(bhs[6]) << 8) | u32::from(bhs[7]);
        let total = 48 + dsl as usize;
        let pad = (4 - (total & 3)) & 3;
        let full = total + pad;
        if self.tx.len() < full {
            return None;
        }
        let bhs_out = self.tx[..48].to_vec();
        let data_out = self.tx[48..total].to_vec();
        self.tx.drain(..full);
        Some((bhs_out, data_out))
    }
}

impl embedded_io::ErrorType for MockConn {
    type Error = core::convert::Infallible;
}

impl embedded_io::Read for MockConn {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        let n = buf.len().min(self.rx.len());
        for (out, b) in buf.iter_mut().zip(self.rx.iter()).take(n) {
            *out = *b;
        }
        self.rx.drain(..n);
        Ok(n)
    }
}

impl embedded_io::Write for MockConn {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        self.tx.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}
