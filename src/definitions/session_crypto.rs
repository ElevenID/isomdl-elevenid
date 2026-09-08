// Copyright 2026 ElevenID
// SPDX-License-Identifier: Apache-2.0 OR MIT

use sha2::{compress256, digest::generic_array::GenericArray};
use zeroize::{Zeroize, Zeroizing};

const SHA256_BLOCK_BYTES: usize = 64;
const SHA256_INITIAL_STATE: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

pub(super) struct SecureSha256 {
    state: [u32; 8],
    buffer: [u8; SHA256_BLOCK_BYTES],
    buffer_len: usize,
    message_len: u64,
    #[cfg(test)]
    cleanup_observer: Option<HashCleanupObserver>,
}

#[cfg(test)]
#[derive(Clone, Default)]
struct HashCleanupObserver(std::sync::Arc<std::sync::atomic::AtomicUsize>);

#[cfg(test)]
impl HashCleanupObserver {
    fn cleanup_count(&self) -> usize {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl SecureSha256 {
    pub(super) fn new() -> Self {
        Self {
            state: SHA256_INITIAL_STATE,
            buffer: [0; SHA256_BLOCK_BYTES],
            buffer_len: 0,
            message_len: 0,
            #[cfg(test)]
            cleanup_observer: None,
        }
    }

    #[cfg(test)]
    fn new_with_cleanup_observer(observer: HashCleanupObserver) -> Self {
        Self {
            cleanup_observer: Some(observer),
            ..Self::new()
        }
    }

    pub(super) fn update(&mut self, mut data: &[u8]) {
        self.message_len = self
            .message_len
            .checked_add(u64::try_from(data.len()).expect("SHA-256 input exceeds u64"))
            .expect("SHA-256 input length overflow");

        if self.buffer_len != 0 {
            let copied = (SHA256_BLOCK_BYTES - self.buffer_len).min(data.len());
            self.buffer[self.buffer_len..self.buffer_len + copied].copy_from_slice(&data[..copied]);
            self.buffer_len += copied;
            data = &data[copied..];
            if self.buffer_len == SHA256_BLOCK_BYTES {
                self.compress_buffer();
            }
        }

        while data.len() >= SHA256_BLOCK_BYTES {
            let (block, remaining) = data.split_at(SHA256_BLOCK_BYTES);
            compress256(
                &mut self.state,
                core::slice::from_ref(GenericArray::from_slice(block)),
            );
            data = remaining;
        }

        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.buffer_len = data.len();
        }
    }

    pub(super) fn finish(mut self) -> Zeroizing<[u8; 32]> {
        let bit_len = self
            .message_len
            .checked_mul(8)
            .expect("SHA-256 bit length overflow");
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;
        if self.buffer_len > 56 {
            self.buffer[self.buffer_len..].fill(0);
            self.compress_buffer();
        }
        self.buffer[self.buffer_len..56].fill(0);
        self.buffer[56..].copy_from_slice(&bit_len.to_be_bytes());
        self.buffer_len = SHA256_BLOCK_BYTES;
        self.compress_buffer();

        let mut digest = Zeroizing::new([0u8; 32]);
        for (index, word) in self.state.into_iter().enumerate() {
            digest[index * 4..(index + 1) * 4].copy_from_slice(&word.to_be_bytes());
        }
        self.clear();
        digest
    }

    fn compress_buffer(&mut self) {
        compress256(
            &mut self.state,
            core::slice::from_ref(GenericArray::from_slice(&self.buffer)),
        );
        self.buffer.zeroize();
        self.buffer_len.zeroize();
    }

    fn clear(&mut self) {
        self.state.zeroize();
        self.buffer.zeroize();
        self.buffer_len.zeroize();
        self.message_len.zeroize();
    }
}

impl Drop for SecureSha256 {
    fn drop(&mut self) {
        self.clear();
        #[cfg(test)]
        if let Some(observer) = &self.cleanup_observer {
            assert!(self.state.iter().all(|word| *word == 0));
            assert!(self.buffer.iter().all(|byte| *byte == 0));
            assert_eq!(self.buffer_len, 0);
            assert_eq!(self.message_len, 0);
            observer.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
}

#[derive(Zeroize)]
pub(super) struct HkdfScratch {
    key_block: [u8; SHA256_BLOCK_BYTES],
    inner_digest: [u8; 32],
    prk: [u8; 32],
}

impl Default for HkdfScratch {
    fn default() -> Self {
        Self {
            key_block: [0; SHA256_BLOCK_BYTES],
            inner_digest: [0; 32],
            prk: [0; 32],
        }
    }
}

struct HkdfScratchGuard<'a>(&'a mut HkdfScratch);

impl Drop for HkdfScratchGuard<'_> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

fn hmac_sha256_into(
    key: &[u8],
    message_parts: &[&[u8]],
    key_block: &mut [u8; SHA256_BLOCK_BYTES],
    inner_digest_scratch: &mut [u8; 32],
    output: &mut [u8; 32],
) {
    key_block.zeroize();
    inner_digest_scratch.zeroize();
    output.zeroize();

    if key.len() > SHA256_BLOCK_BYTES {
        let mut hash = SecureSha256::new();
        hash.update(key);
        let hashed_key = hash.finish();
        key_block[..32].copy_from_slice(&*hashed_key);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    for byte in key_block.iter_mut() {
        *byte ^= 0x36;
    }
    let mut inner = SecureSha256::new();
    inner.update(key_block);
    for part in message_parts {
        inner.update(part);
    }
    let inner_digest = inner.finish();
    inner_digest_scratch.copy_from_slice(&*inner_digest);

    for byte in key_block.iter_mut() {
        *byte ^= 0x36 ^ 0x5c;
    }
    let mut outer = SecureSha256::new();
    outer.update(key_block);
    outer.update(inner_digest_scratch);
    let digest = outer.finish();
    output.copy_from_slice(&*digest);
}

#[derive(Zeroize)]
pub(crate) struct HmacSha256Scratch {
    key_block: [u8; SHA256_BLOCK_BYTES],
    inner_digest: [u8; 32],
}

impl Default for HmacSha256Scratch {
    fn default() -> Self {
        Self {
            key_block: [0; SHA256_BLOCK_BYTES],
            inner_digest: [0; 32],
        }
    }
}

struct HmacSha256ScratchGuard<'a>(&'a mut HmacSha256Scratch);

impl Drop for HmacSha256ScratchGuard<'_> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

struct OutputGuard<'a> {
    output: &'a mut [u8; 32],
    keep: bool,
}

impl Drop for OutputGuard<'_> {
    fn drop(&mut self) {
        if !self.keep {
            self.output.zeroize();
        }
    }
}

pub(crate) fn hmac_sha256_with_scratch<F>(
    key: &[u8],
    message_parts: &[&[u8]],
    output: &mut [u8; 32],
    scratch: &mut HmacSha256Scratch,
    after_compute: F,
) -> Result<(), ()>
where
    F: FnOnce() -> Result<(), ()>,
{
    output.zeroize();
    let guarded_scratch = HmacSha256ScratchGuard(scratch);
    let mut guarded_output = OutputGuard {
        output,
        keep: false,
    };
    hmac_sha256_into(
        key,
        message_parts,
        &mut guarded_scratch.0.key_block,
        &mut guarded_scratch.0.inner_digest,
        guarded_output.output,
    );
    after_compute()?;
    guarded_output.keep = true;
    Ok(())
}

#[cfg(test)]
impl HmacSha256Scratch {
    pub(crate) fn is_zero(&self) -> bool {
        self.key_block.iter().all(|byte| *byte == 0)
            && self.inner_digest.iter().all(|byte| *byte == 0)
    }
}

pub(super) fn hkdf_sha256_32_with_scratch<F>(
    input_key_material: &[u8],
    salt: &[u8],
    info: &[u8],
    output: &mut [u8; 32],
    scratch: &mut HkdfScratch,
    after_extract: F,
) -> Result<(), ()>
where
    F: FnOnce() -> Result<(), ()>,
{
    output.zeroize();
    let guarded_scratch = HkdfScratchGuard(scratch);
    let mut guarded_output = OutputGuard {
        output,
        keep: false,
    };
    let HkdfScratch {
        key_block,
        inner_digest,
        prk,
    } = guarded_scratch.0;
    hmac_sha256_into(salt, &[input_key_material], key_block, inner_digest, prk);
    after_extract()?;
    let counter = [1u8];
    hmac_sha256_into(
        prk,
        &[info, &counter],
        key_block,
        inner_digest,
        guarded_output.output,
    );
    guarded_output.keep = true;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{hkdf_sha256_32_with_scratch, HashCleanupObserver, HkdfScratch, SecureSha256};
    use sha2::{Digest, Sha256};

    fn scratch_is_zero(scratch: &HkdfScratch) -> bool {
        scratch.key_block.iter().all(|byte| *byte == 0)
            && scratch.inner_digest.iter().all(|byte| *byte == 0)
            && scratch.prk.iter().all(|byte| *byte == 0)
    }

    #[test]
    fn secure_sha256_matches_reference_at_padding_boundaries() {
        for len in [0, 1, 55, 56, 63, 64, 65, 127, 128, 129, 65_537] {
            let input: Vec<u8> = (0..len)
                .map(|index| (index as u8).wrapping_mul(29).wrapping_add(7))
                .collect();
            let expected = Sha256::digest(&input);
            let mut actual = SecureSha256::new();
            for chunk in input.chunks(19) {
                actual.update(chunk);
            }
            assert_eq!(&*actual.finish(), expected.as_slice(), "length {len}");
        }
    }

    #[test]
    fn secure_sha256_wipes_owned_state_on_finish_and_unwind() {
        let finish_observer = HashCleanupObserver::default();
        let mut finishing_hash = SecureSha256::new_with_cleanup_observer(finish_observer.clone());
        finishing_hash.update(&[0xa5; 31]);
        let digest = finishing_hash.finish();
        assert!(digest.iter().any(|byte| *byte != 0));
        assert_eq!(finish_observer.cleanup_count(), 1);

        let unwind_observer = HashCleanupObserver::default();
        let unwind = std::panic::catch_unwind({
            let observer = unwind_observer.clone();
            move || {
                let mut unwinding_hash = SecureSha256::new_with_cleanup_observer(observer);
                unwinding_hash.update(&[0x5a; 31]);
                panic!("injected SHA-256 unwind");
            }
        });
        assert!(unwind.is_err());
        assert_eq!(unwind_observer.cleanup_count(), 1);
    }

    #[test]
    fn hkdf_matches_rfc5869_and_wipes_scratch_on_success_and_error() {
        let ikm = [0x0b; 22];
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let expected =
            hex::decode("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf")
                .unwrap();
        let mut output = [0u8; 32];
        let mut scratch = HkdfScratch::default();
        hkdf_sha256_32_with_scratch(&ikm, &salt, &info, &mut output, &mut scratch, || Ok(()))
            .unwrap();
        assert_eq!(output.as_slice(), expected);
        assert!(scratch_is_zero(&scratch));

        output.fill(0xa5);
        scratch.key_block.fill(0xa5);
        scratch.inner_digest.fill(0xa5);
        scratch.prk.fill(0xa5);
        assert!(hkdf_sha256_32_with_scratch(
            &ikm,
            &salt,
            &info,
            &mut output,
            &mut scratch,
            || Err(())
        )
        .is_err());
        assert_eq!(output, [0; 32]);
        assert!(scratch_is_zero(&scratch));

        output.fill(0xa5);
        scratch.key_block.fill(0xa5);
        scratch.inner_digest.fill(0xa5);
        scratch.prk.fill(0xa5);
        let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ =
                hkdf_sha256_32_with_scratch(&ikm, &salt, &info, &mut output, &mut scratch, || {
                    panic!("injected HKDF unwind after extract")
                });
        }));
        assert!(unwind.is_err());
        assert_eq!(output, [0; 32]);
        assert!(scratch_is_zero(&scratch));
    }

    #[test]
    fn session_key_derivation_does_not_instantiate_rustcrypto_hkdf_or_hmac() {
        let session_source = include_str!("session.rs");
        assert!(!session_source.contains("use hkdf::"));
        assert!(!session_source.contains("Hkdf::"));
        assert!(!session_source.contains("use hmac::"));
        assert!(!session_source.contains("Hmac::<"));
    }
}
