//! Resource-addressed stream-cipher decorator for the [`Storage`] seam.
//!
//! A recordable CD stores its TOC and every track behind a numeric resource
//! (`1`/`2` for the two plaintext TOC slots, `16 + n` for track `n`). This
//! decorator encrypts only the **payload** resources: resources below
//! [`CipherStore::new`]'s `encrypt_from` pass through untouched, so the TOC
//! stays readable without a key.
//!
//! # Per-resource nonce domain
//!
//! One key is used for the whole medium, but each resource gets its own
//! nonce:
//!
//! ```text
//! domain(lun, resource) = LE64(base_nonce) XOR resource XOR (lun << 48)
//! ```
//!
//! The same offset in two tracks (or on two LUNs of one multi-LUN adapter)
//! therefore never reuses a keystream. The price is one 64-bit XOR per
//! operation; the key itself is never rebuilt.
//!
//! One instance must still be used for exactly one medium generation: a fresh
//! `(key, nonce)` is required whenever a medium is replaced or re-created
//! (the manifest owns that nonce).
//!
//! The `XorMix` cipher is **obfuscation, not encryption**; see its own docs.
//!
//! # Stream-cipher properties
//!
//! CTR and the built-in ciphers are **malleable**: an attacker who can modify
//! stored bytes can flip the corresponding plaintext bits. Nothing here
//! authenticates a resource, and a modified track simply decrypts to wrong
//! bytes. A caller that needs integrity must add an authenticated layer
//! above this one.
//!
//! # Token/buffer contract
//!
//! The decorator keeps a fixed eight-entry table mapping the token it mints
//! to the inner token and the request. A token must be polled with the
//! **same buffer** across [`Poll::Pending`] polls: the write-side XOR is
//! applied exactly once (on the first poll) and the applied fact is retained
//! until the operation completes or is cancelled.
//!
//! No allocation, no `unsafe` and no runtime dependency: the table and the
//! nonce are plain fields.

use ::core::task::Poll;

use crate::common::cipher::NonceCipher;

use super::async_wake::AsyncWake;
use super::device::Direction;
use super::storage::{
    buf_matches, contract_receipt, IoBuf, IoReq, IoToken, Storage, StorageReceipt,
};

/// Fixed slot table size.
const SLOTS: usize = 8;

/// One live operation.
struct Slot {
    token: IoToken,
    req: IoReq,
    inner: IoToken,
    /// The XOR has already been applied to the caller's buffer.
    applied: bool,
    /// Identity of the write buffer first polled (the seam requires the same
    /// buffer across `Pending` polls; a swap would send plaintext to the
    /// backing because `applied` already suppresses the XOR).
    buf_ptr: usize,
    buf_len: usize,
}

/// [`Storage`] decorator that encrypts resource payloads in place.
///
/// See the [module docs](self) for the nonce domain and the buffer contract.
pub struct CipherStore<S, C> {
    inner: S,
    cipher: C,
    nonce: [u8; 8],
    encrypt_from: u16,
    lun: usize,
    slots: [Option<Slot>; SLOTS],
    next_tag: u32,
}

impl<S, C: NonceCipher> CipherStore<S, C> {
    /// `encrypt_from` is the lowest resource id that is encrypted; lower
    /// resources pass through untouched (CD-R TOC slots 1/2). Use `0` for a
    /// medium where every resource is payload (for example DVD-RAM) and
    /// [`crate::mmc::cdr_bundle::TRACK_RESOURCE_BASE`] (`16`) for CD-R tracks.
    pub fn new(inner: S, cipher: C, nonce: [u8; 8], encrypt_from: u16) -> Self {
        Self {
            inner,
            cipher,
            nonce,
            encrypt_from,
            lun: 0,
            slots: ::core::array::from_fn(|_| None),
            next_tag: 1,
        }
    }

    /// Borrow the wrapped storage.
    pub fn inner(&self) -> &S {
        &self.inner
    }

    /// Mutably borrow the wrapped storage (test/probe inspection).
    pub fn inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    /// Give back the wrapped storage.
    pub fn into_inner(self) -> S {
        self.inner
    }

    /// Whether `resource` is encrypted by this decorator.
    fn encrypts(&self, resource: u16) -> bool {
        resource >= self.encrypt_from
    }

    /// Nonce domain of `resource` on the currently selected LUN.
    fn domain(&self, resource: u16) -> [u8; 8] {
        (u64::from_le_bytes(self.nonce) ^ u64::from(resource) ^ ((self.lun as u64) << 48))
            .to_le_bytes()
    }

    /// Slot index for a token minted by this decorator.
    fn find(&self, token: IoToken) -> Option<usize> {
        self.slots
            .iter()
            .position(|slot| matches!(slot, Some(slot) if slot.token == token))
    }
}

impl<S: Storage, C: NonceCipher> Storage for CipherStore<S, C> {
    fn select_lun(&mut self, lun: usize) {
        self.lun = lun;
        self.inner.select_lun(lun);
    }

    fn resources_released(&mut self, lun: usize) {
        self.inner.resources_released(lun);
    }

    fn begin_exec(&mut self, req: IoReq) -> IoToken {
        let Some(index) = self.slots.iter().position(Option::is_none) else {
            return IoToken::invalid();
        };
        let inner = self.inner.begin_exec(req);
        if !inner.is_valid() {
            return IoToken::invalid();
        }
        let tag = self.next_tag;
        self.next_tag = self.next_tag.wrapping_add(1).max(1);
        let token = IoToken::new(index as u8, tag);
        self.slots[index] = Some(Slot {
            token,
            req,
            inner,
            applied: false,
            buf_ptr: 0,
            buf_len: 0,
        });
        token
    }

    fn poll_exec(&mut self, token: IoToken, buf: IoBuf<'_>) -> Poll<StorageReceipt> {
        let Some(index) = self.find(token) else {
            return Poll::Ready(contract_receipt());
        };
        let (req, inner_token, applied, buf_ptr, buf_len) = match self.slots[index].as_ref() {
            Some(slot) => (
                slot.req,
                slot.inner,
                slot.applied,
                slot.buf_ptr,
                slot.buf_len,
            ),
            None => return Poll::Ready(contract_receipt()),
        };

        // A contract-violating call must not transform the caller's buffer.
        if !buf_matches(req, &buf) {
            self.inner.cancel(inner_token);
            self.slots[index] = None;
            return Poll::Ready(contract_receipt());
        }

        match (req.dir, buf) {
            (Direction::FromHost, IoBuf::Write(bytes)) => {
                let ptr = bytes.as_ptr() as usize;
                let len = bytes.len();
                if !applied {
                    if self.encrypts(req.resource) {
                        let nonce = self.domain(req.resource);
                        self.cipher.set_nonce(nonce);
                        if let Err(error) = self.cipher.xor(req.offset, bytes) {
                            self.inner.cancel(inner_token);
                            self.slots[index] = None;
                            return Poll::Ready(StorageReceipt::failed_for(req.dir, error.into()));
                        }
                        if let Some(slot) = self.slots[index].as_mut() {
                            slot.applied = true;
                            slot.buf_ptr = ptr;
                            slot.buf_len = len;
                        }
                    }
                } else if (ptr, len) != (buf_ptr, buf_len) {
                    // The seam requires the same buffer across `Pending`
                    // polls; a fresh buffer would reach the backing as
                    // plaintext because the XOR already ran.
                    self.inner.cancel(inner_token);
                    self.slots[index] = None;
                    return Poll::Ready(contract_receipt());
                }
                match self.inner.poll_exec(inner_token, IoBuf::Write(bytes)) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(receipt) => {
                        self.slots[index] = None;
                        Poll::Ready(receipt)
                    }
                }
            }
            (Direction::ToHost, IoBuf::Read(bytes)) => {
                let polled = self.inner.poll_exec(inner_token, IoBuf::Read(&mut *bytes));
                match polled {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(receipt) => {
                        self.slots[index] = None;
                        if !self.encrypts(req.resource) {
                            return Poll::Ready(receipt);
                        }
                        // `confirmed` is a byte prefix even when the receipt
                        // carries an error; decrypting it keeps the caller
                        // from seeing ciphertext.
                        let confirmed = receipt.confirmed.min(bytes.len());
                        if confirmed == 0 {
                            return Poll::Ready(receipt);
                        }
                        let nonce = self.domain(req.resource);
                        self.cipher.set_nonce(nonce);
                        match self.cipher.xor(req.offset, &mut bytes[..confirmed]) {
                            Ok(()) => Poll::Ready(receipt),
                            Err(error) => {
                                Poll::Ready(StorageReceipt::failed_for(req.dir, error.into()))
                            }
                        }
                    }
                }
            }
            (_, buf) => match self.inner.poll_exec(inner_token, buf) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(receipt) => {
                    self.slots[index] = None;
                    Poll::Ready(receipt)
                }
            },
        }
    }

    fn cancel(&mut self, token: IoToken) {
        if let Some(index) = self.find(token) {
            if let Some(slot) = self.slots[index].take() {
                self.inner.cancel(slot.inner);
            }
        }
    }
}

impl<S: AsyncWake, C> AsyncWake for CipherStore<S, C> {
    fn poll_wake(&mut self, cx: &mut ::core::task::Context<'_>) -> Poll<()> {
        self.inner.poll_wake(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::cipher::{CipherError, CipherKey, StreamCipher, XorMix};
    use crate::core::errors::{Effect, Fault};
    use crate::core::storage::IoToken;
    use std::vec::Vec;

    const BASE_NONCE: [u8; 8] = [0x11; 8];
    const ENCRYPT_FROM: u16 = 16;

    #[derive(Default)]
    struct MockStorage {
        regions: Vec<(u16, Vec<u8>)>,
        slots: [Option<(IoReq, u32)>; 16],
        next_tag: u32,
        begin_calls: usize,
        pending_once: bool,
        read_error_confirmed: Option<usize>,
        wakes: usize,
        write_seen: Vec<Vec<u8>>,
        syncs: Vec<u16>,
        last_lun: Option<usize>,
        released: Option<usize>,
    }

    impl MockStorage {
        fn new() -> Self {
            Self {
                slots: ::core::array::from_fn(|_| None),
                next_tag: 1,
                ..Self::default()
            }
        }

        fn region(&self, resource: u16) -> &[u8] {
            self.regions
                .iter()
                .find(|(id, _)| *id == resource)
                .map_or(&[], |(_, data)| data.as_slice())
        }

        fn region_mut(&mut self, resource: u16) -> &mut Vec<u8> {
            if let Some(index) = self.regions.iter().position(|(id, _)| *id == resource) {
                return &mut self.regions[index].1;
            }
            self.regions.push((resource, Vec::new()));
            &mut self.regions.last_mut().unwrap().1
        }

        fn find(&self, token: IoToken) -> Option<usize> {
            self.slots.iter().enumerate().position(|(index, slot)| {
                matches!(slot, Some((_, tag)) if IoToken::new(index as u8, *tag) == token)
            })
        }
    }

    impl Storage for MockStorage {
        fn select_lun(&mut self, lun: usize) {
            self.last_lun = Some(lun);
        }

        fn resources_released(&mut self, lun: usize) {
            self.released = Some(lun);
        }

        fn begin_exec(&mut self, req: IoReq) -> IoToken {
            self.begin_calls += 1;
            for index in 0..self.slots.len() {
                if self.slots[index].is_none() {
                    let tag = self.next_tag;
                    self.next_tag = self.next_tag.wrapping_add(1).max(1);
                    self.slots[index] = Some((req, tag));
                    return IoToken::new(index as u8, tag);
                }
            }
            IoToken::invalid()
        }

        fn poll_exec(&mut self, token: IoToken, buf: IoBuf<'_>) -> Poll<StorageReceipt> {
            let Some(index) = self.find(token) else {
                return Poll::Ready(contract_receipt());
            };
            let (req, _) = self.slots[index].unwrap();
            if self.pending_once {
                self.pending_once = false;
                if let IoBuf::Write(bytes) = &buf {
                    self.write_seen.push(bytes.to_vec());
                }
                return Poll::Pending;
            }
            self.slots[index] = None;
            match (req.dir, buf) {
                (Direction::ToHost, IoBuf::Read(out)) => {
                    let start = req.offset as usize;
                    let confirmed = self
                        .read_error_confirmed
                        .unwrap_or(out.len())
                        .min(out.len());
                    let end = start + confirmed;
                    let region = self.region_mut(req.resource);
                    if region.len() < end {
                        region.resize(end, 0);
                    }
                    out[..confirmed].copy_from_slice(&region[start..end]);
                    if self.read_error_confirmed.is_some() {
                        Poll::Ready(StorageReceipt::failed(
                            Fault::Io,
                            confirmed,
                            Effect::UnknownRemainder,
                        ))
                    } else {
                        Poll::Ready(StorageReceipt::ok(out.len()))
                    }
                }
                (Direction::FromHost, IoBuf::Write(bytes)) => {
                    self.write_seen.push(bytes.to_vec());
                    let start = req.offset as usize;
                    let end = start + bytes.len();
                    let region = self.region_mut(req.resource);
                    if region.len() < end {
                        region.resize(end, 0);
                    }
                    region[start..end].copy_from_slice(bytes);
                    Poll::Ready(StorageReceipt::ok(bytes.len()))
                }
                (Direction::None, IoBuf::None) => {
                    self.syncs.push(req.resource);
                    Poll::Ready(StorageReceipt::ok(0))
                }
                _ => Poll::Ready(contract_receipt()),
            }
        }

        fn cancel(&mut self, token: IoToken) {
            if let Some(index) = self.find(token) {
                self.slots[index] = None;
            }
        }
    }

    fn cipher() -> XorMix {
        let key = CipherKey::from_bytes(&[0x5Au8; 32]).unwrap();
        XorMix::new(&key, BASE_NONCE)
    }

    fn store() -> CipherStore<MockStorage, XorMix> {
        CipherStore::new(MockStorage::new(), cipher(), BASE_NONCE, ENCRYPT_FROM)
    }

    fn write(
        store: &mut CipherStore<MockStorage, XorMix>,
        resource: u16,
        offset: u64,
        data: &mut [u8],
    ) -> StorageReceipt {
        let req = IoReq {
            resource,
            offset,
            len: data.len() as u32,
            dir: Direction::FromHost,
        };
        let token = store.begin_exec(req);
        assert!(token.is_valid());
        match store.poll_exec(token, IoBuf::Write(data)) {
            Poll::Ready(receipt) => receipt,
            Poll::Pending => panic!("mock must complete"),
        }
    }

    fn read(
        store: &mut CipherStore<MockStorage, XorMix>,
        resource: u16,
        offset: u64,
        data: &mut [u8],
    ) -> StorageReceipt {
        let req = IoReq {
            resource,
            offset,
            len: data.len() as u32,
            dir: Direction::ToHost,
        };
        let token = store.begin_exec(req);
        assert!(token.is_valid());
        match store.poll_exec(token, IoBuf::Read(data)) {
            Poll::Ready(receipt) => receipt,
            Poll::Pending => panic!("mock must complete"),
        }
    }

    fn sync(store: &mut CipherStore<MockStorage, XorMix>, resource: u16) -> StorageReceipt {
        let req = IoReq {
            resource,
            offset: 0,
            len: 0,
            dir: Direction::None,
        };
        let token = store.begin_exec(req);
        assert!(token.is_valid());
        match store.poll_exec(token, IoBuf::None) {
            Poll::Ready(receipt) => receipt,
            Poll::Pending => panic!("mock must complete"),
        }
    }

    #[test]
    fn toc_resources_pass_through_unchanged() {
        let mut store = store();
        for resource in [1, 2] {
            let plain = [0x10u8, 0x20, 0x30, 0x40];
            let mut input = plain;
            assert_eq!(
                write(&mut store, resource, 7, &mut input),
                StorageReceipt::ok(4)
            );
            assert_eq!(input, plain, "TOC write must not be transformed");
            assert_eq!(&store.inner().region(resource)[7..11], &plain[..]);

            let mut out = [0u8; 4];
            assert_eq!(
                read(&mut store, resource, 7, &mut out),
                StorageReceipt::ok(4)
            );
            assert_eq!(out, plain, "TOC read must not be transformed");
        }
    }

    #[test]
    fn track_is_encrypted_at_rest_and_decrypts() {
        let mut store = store();
        let plain = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let mut input = plain;
        assert_eq!(
            write(&mut store, 16, 100, &mut input),
            StorageReceipt::ok(8)
        );
        let at_rest = &store.inner().region(16)[100..108];
        assert_ne!(at_rest, &plain, "track payload must be ciphertext at rest");

        let mut out = [0u8; 8];
        assert_eq!(read(&mut store, 16, 100, &mut out), StorageReceipt::ok(8));
        assert_eq!(out, plain);
    }

    #[test]
    fn aggregate_sync_passes_through() {
        let mut store = store();
        assert_eq!(sync(&mut store, 0), StorageReceipt::ok(0));
        assert_eq!(store.inner().syncs, vec![0u16]);
    }

    #[test]
    fn resources_use_separate_nonce_domains() {
        let mut first = store();
        let plain = [9u8; 8];

        let mut a = plain;
        write(&mut first, 16, 0, &mut a);
        let mut b = plain;
        write(&mut first, 17, 0, &mut b);

        let track_16 = first.inner().region(16).to_vec();
        let track_17 = first.inner().region(17).to_vec();
        assert_ne!(
            track_16, track_17,
            "the same offset in two tracks must not reuse the keystream"
        );

        let mut again = plain;
        write(&mut first, 16, 0, &mut again);
        assert_eq!(first.inner().region(16), track_16);
    }

    #[test]
    fn read_split_across_pending_decrypts_once() {
        let mut store = store();
        let plain = [0x33u8; 16];
        let mut input = plain;
        write(&mut store, 16, 0, &mut input);

        store.inner_mut().pending_once = true;
        let req = IoReq {
            resource: 16,
            offset: 0,
            len: 16,
            dir: Direction::ToHost,
        };
        let token = store.begin_exec(req);
        let mut out = [0u8; 16];
        match store.poll_exec(token, IoBuf::Read(&mut out)) {
            Poll::Pending => assert_eq!(out, [0u8; 16], "Pending must not touch the buffer"),
            Poll::Ready(_) => panic!("first poll must be Pending"),
        }
        match store.poll_exec(token, IoBuf::Read(&mut out)) {
            Poll::Ready(receipt) => assert_eq!(receipt, StorageReceipt::ok(16)),
            Poll::Pending => panic!("second poll must complete"),
        }
        assert_eq!(out, plain, "the ciphertext must be decrypted exactly once");
    }

    #[test]
    fn write_split_across_pending_encrypts_once() {
        let mut store = store();
        let plain = [0x44u8; 16];
        store.inner_mut().pending_once = true;
        let req = IoReq {
            resource: 16,
            offset: 0,
            len: 16,
            dir: Direction::FromHost,
        };
        let token = store.begin_exec(req);
        let mut buf = plain;
        match store.poll_exec(token, IoBuf::Write(&mut buf)) {
            Poll::Pending => {}
            Poll::Ready(_) => panic!("first poll must be Pending"),
        }
        let after_first = buf;
        assert_ne!(after_first, plain, "the first poll encrypts in place");

        match store.poll_exec(token, IoBuf::Write(&mut buf)) {
            Poll::Ready(receipt) => assert_eq!(receipt, StorageReceipt::ok(16)),
            Poll::Pending => panic!("second poll must complete"),
        }

        let seen = &store.inner().write_seen;
        assert_eq!(seen.len(), 2, "the mock saw both polls");
        assert_eq!(seen[0], after_first);
        assert_eq!(seen[1], after_first, "the write must be encrypted once");
        assert_ne!(seen[1], plain);
        assert_eq!(store.inner().region(16), after_first);
    }

    #[test]
    fn slot_exhaustion_returns_invalid_without_touching_inner() {
        let mut store = store();
        let mut tokens = [IoToken::invalid(); SLOTS];
        for token in &mut tokens {
            *token = store.begin_exec(IoReq {
                resource: 0,
                offset: 0,
                len: 0,
                dir: Direction::None,
            });
            assert!(token.is_valid());
        }
        let before = store.inner().begin_calls;
        let ninth = store.begin_exec(IoReq {
            resource: 0,
            offset: 0,
            len: 0,
            dir: Direction::None,
        });
        assert!(!ninth.is_valid(), "ninth operation must exhaust the table");
        assert_eq!(
            store.inner().begin_calls,
            before,
            "inner must not be called when the table is full"
        );
        for token in tokens {
            store.cancel(token);
        }
    }

    #[test]
    fn unknown_token_poll_is_contract_and_cancel_is_a_no_op() {
        let mut store = store();
        let receipt = match store.poll_exec(IoToken::new(3, 1234), IoBuf::None) {
            Poll::Ready(receipt) => receipt,
            Poll::Pending => panic!("unknown token must settle immediately"),
        };
        assert_eq!(
            receipt,
            StorageReceipt::failed(Fault::Contract, 0, Effect::Known)
        );
        store.cancel(IoToken::new(3, 1234));
        assert_eq!(store.inner().begin_calls, 0);
    }

    #[test]
    fn lun_selection_and_release_forward_to_inner() {
        let mut store = store();
        store.select_lun(3);
        assert_eq!(store.inner().last_lun, Some(3));
        store.resources_released(2);
        assert_eq!(store.inner().released, Some(2));
    }

    /// Cipher that fails before changing the buffer.
    struct FailingCipher;

    impl StreamCipher for FailingCipher {
        fn xor(&mut self, _off: u64, _buf: &mut [u8]) -> Result<(), CipherError> {
            Err(CipherError::Backend)
        }
    }

    impl NonceCipher for FailingCipher {
        fn set_nonce(&mut self, _nonce: [u8; 8]) {}
    }

    impl crate::core::async_wake::AsyncWake for MockStorage {
        fn poll_wake(&mut self, _cx: &mut ::core::task::Context<'_>) -> Poll<()> {
            self.wakes += 1;
            Poll::Ready(())
        }
    }

    #[test]
    fn async_wake_is_forwarded() {
        let mut store = store();
        let mut cx = ::core::task::Context::from_waker(::core::task::Waker::noop());
        assert!(store.poll_wake(&mut cx).is_ready());
        assert_eq!(store.inner().wakes, 1);
    }

    #[test]
    fn cancel_forwards_and_frees_both_tables() {
        let mut store = store();
        let mut tokens = [IoToken::invalid(); SLOTS];
        for token in &mut tokens {
            *token = store.begin_exec(IoReq {
                resource: 0,
                offset: 0,
                len: 0,
                dir: Direction::None,
            });
        }
        for token in tokens {
            store.cancel(token);
        }
        // Cancelling again is a no-op.
        store.cancel(tokens[0]);
        // All eight slots are usable again (both here and in the inner mock).
        for _ in 0..SLOTS {
            let token = store.begin_exec(IoReq {
                resource: 0,
                offset: 0,
                len: 0,
                dir: Direction::None,
            });
            assert!(token.is_valid());
            store.cancel(token);
        }
    }

    #[test]
    fn mismatched_buffer_is_a_contract_without_mutation() {
        let mut store = store();
        let req = IoReq {
            resource: 16,
            offset: 0,
            len: 4,
            dir: Direction::FromHost,
        };
        let token = store.begin_exec(req);
        let mut wrong = [0x7Au8; 8];
        assert_eq!(
            store.poll_exec(token, IoBuf::Write(&mut wrong)),
            Poll::Ready(contract_receipt())
        );
        assert_eq!(wrong, [0x7Au8; 8], "a contract call must not transform");

        // The slot was released, so a new operation is accepted.
        let again = store.begin_exec(IoReq {
            resource: 0,
            offset: 0,
            len: 0,
            dir: Direction::None,
        });
        assert!(again.is_valid());
    }

    #[test]
    fn buffer_swap_across_pending_is_a_contract() {
        let mut store = store();
        store.inner_mut().pending_once = true;
        let req = IoReq {
            resource: 16,
            offset: 0,
            len: 4,
            dir: Direction::FromHost,
        };
        let token = store.begin_exec(req);
        let mut first = [1u8; 4];
        assert!(matches!(
            store.poll_exec(token, IoBuf::Write(&mut first)),
            Poll::Pending
        ));
        let mut second = [2u8; 4];
        assert_eq!(
            store.poll_exec(token, IoBuf::Write(&mut second)),
            Poll::Ready(contract_receipt())
        );
    }

    #[test]
    fn read_error_with_confirmed_prefix_is_decrypted() {
        let mut store = store();
        let plain = [0x66u8; 16];
        let mut input = plain;
        write(&mut store, 16, 0, &mut input);

        store.inner_mut().read_error_confirmed = Some(8);
        let mut out = [0u8; 16];
        let receipt = read(&mut store, 16, 0, &mut out);
        assert_eq!(
            receipt,
            StorageReceipt::failed(Fault::Io, 8, Effect::UnknownRemainder)
        );
        assert_eq!(&out[..8], &plain[..8], "the confirmed prefix is plaintext");
        assert_eq!(&out[8..], &[0u8; 8], "the tail was never read");
    }

    #[test]
    fn cipher_failure_maps_to_io_and_frees_the_slot() {
        let mut store = CipherStore::new(MockStorage::new(), FailingCipher, BASE_NONCE, 16);
        let req = IoReq {
            resource: 16,
            offset: 0,
            len: 4,
            dir: Direction::FromHost,
        };
        let token = store.begin_exec(req);
        let mut buf = [0u8; 4];
        let receipt = match store.poll_exec(token, IoBuf::Write(&mut buf)) {
            Poll::Ready(receipt) => receipt,
            Poll::Pending => panic!("cipher failure must settle"),
        };
        assert_eq!(
            receipt,
            StorageReceipt::failed(Fault::Io, 0, Effect::UnknownRemainder)
        );
        // The slot was released: the next begin gets a fresh token.
        let again = store.begin_exec(IoReq {
            resource: 0,
            offset: 0,
            len: 0,
            dir: Direction::None,
        });
        assert!(again.is_valid());
    }
}
