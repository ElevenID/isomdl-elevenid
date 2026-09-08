//! This module contains the definitions and functions related to session establishment and management.
//!
//! The [get_initialization_vector] function generates an initialization vector for encryption/decryption
//! based on a message count and a flag indicating whether the vector is for the reader or the device.
use super::helpers::Tag24;
use super::DeviceEngagement;
use crate::definitions::device_engagement::EReaderKeyBytes;
#[cfg(feature = "session-key-agreement")]
use crate::definitions::device_key::cose_key::EC2Y;
use crate::definitions::device_key::CoseKey;
#[cfg(feature = "session-key-agreement")]
use crate::definitions::device_key::EC2Curve;
use crate::definitions::helpers::bytestr::ByteStr;
#[cfg(feature = "session-key-agreement")]
use crate::definitions::session::EncodedPoints::{Ep256, Ep384};

#[cfg(feature = "session-key-agreement")]
use crate::definitions::session_crypto::{hkdf_sha256_32_with_scratch, HkdfScratch, SecureSha256};
#[cfg(all(feature = "session-key-agreement", target_family = "wasm"))]
use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes256Gcm,
    Nonce, // Or `Aes128Gcm`
};
use anyhow::Result;
#[cfg(all(feature = "session-key-agreement", not(target_family = "wasm")))]
use aws_lc_rs::aead::{
    Aad as AwsAad, LessSafeKey as AwsLessSafeKey, Nonce as AwsNonce, UnboundKey as AwsUnboundKey,
    AES_256_GCM,
};
#[cfg(feature = "session-key-agreement")]
use ecdsa::EncodedPoint;
#[cfg(feature = "session-key-agreement")]
use elliptic_curve::{
    ecdh::EphemeralSecret,
    ecdh::SharedSecret,
    generic_array::{sequence::Concat, typenum::U32, GenericArray},
    sec1::FromEncodedPoint,
};
#[cfg(feature = "session-key-agreement")]
use p256::NistP256;
#[cfg(feature = "session-key-agreement")]
use p384::NistP384;
#[cfg(feature = "session-key-agreement")]
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
#[cfg(feature = "session-key-agreement")]
use zeroize::{Zeroize, Zeroizing};

pub type EReaderKey = CoseKey;
pub type EDeviceKey = CoseKey;
pub type DeviceEngagementBytes = Tag24<DeviceEngagement>;
pub type SessionTranscriptBytes = Tag24<SessionTranscript180135>;
pub type NfcHandover = (ByteStr, Option<ByteStr>);

/// An in-memory session encryption key that zeroizes on drop and never exposes
/// its bytes through diagnostic formatting.
#[cfg(feature = "session-key-agreement")]
pub struct SessionKey(Zeroizing<[u8; 32]>);

#[cfg(feature = "session-key-agreement")]
impl AsRef<[u8]> for SessionKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

#[cfg(feature = "session-key-agreement")]
impl std::fmt::Debug for SessionKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_tuple("SessionKey")
            .field(&"[REDACTED]")
            .finish()
    }
}

#[cfg(all(feature = "session-key-agreement", not(target_family = "wasm")))]
struct NativeSessionAeadKey {
    key: Option<AwsLessSafeKey>,
    #[cfg(test)]
    cleanup_observer: Option<NativeAeadCleanupObserver>,
}

#[cfg(all(test, feature = "session-key-agreement", not(target_family = "wasm")))]
#[derive(Clone, Default)]
struct NativeAeadCleanupObserver {
    key_drops: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    buffers: AeadBufferCleanupObserver,
}

#[cfg(all(test, feature = "session-key-agreement", not(target_family = "wasm")))]
impl NativeAeadCleanupObserver {
    fn key_drop_count(&self) -> usize {
        self.key_drops.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn wiped_buffers(&self) -> Vec<Vec<u8>> {
        self.buffers.snapshots()
    }
}

#[cfg(all(test, feature = "session-key-agreement"))]
#[derive(Clone, Default)]
struct AeadBufferCleanupObserver(std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>);

#[cfg(all(test, feature = "session-key-agreement"))]
impl AeadBufferCleanupObserver {
    fn snapshots(&self) -> Vec<Vec<u8>> {
        self.0.lock().unwrap().clone()
    }
}

#[cfg(feature = "session-key-agreement")]
struct SensitiveAeadBuffer {
    bytes: Vec<u8>,
    #[cfg(test)]
    cleanup_observer: Option<AeadBufferCleanupObserver>,
}

#[cfg(feature = "session-key-agreement")]
impl SensitiveAeadBuffer {
    fn copied_from(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.to_vec(),
            #[cfg(test)]
            cleanup_observer: None,
        }
    }

    #[cfg(test)]
    fn copied_from_with_observer(bytes: &[u8], observer: AeadBufferCleanupObserver) -> Self {
        Self {
            bytes: bytes.to_vec(),
            cleanup_observer: Some(observer),
        }
    }

    fn into_vec(mut self) -> Vec<u8> {
        std::mem::take(&mut self.bytes)
    }
}

#[cfg(feature = "session-key-agreement")]
impl Drop for SensitiveAeadBuffer {
    fn drop(&mut self) {
        // Wipe initialized bytes and spare capacity, since the backend may have
        // written plaintext beyond the resulting logical length before failing.
        self.bytes.resize(self.bytes.capacity(), 0);
        self.bytes.fill(0);
        #[cfg(test)]
        if let Some(observer) = &self.cleanup_observer {
            observer.0.lock().unwrap().push(self.bytes.clone());
        }
        self.bytes.zeroize();
    }
}

#[cfg(all(feature = "session-key-agreement", not(target_family = "wasm")))]
impl NativeSessionAeadKey {
    fn new(key_bytes: &[u8]) -> Result<Self, aes_gcm::Error> {
        let key = AwsUnboundKey::new(&AES_256_GCM, key_bytes)
            .map(AwsLessSafeKey::new)
            .map_err(|_| aes_gcm::Error)?;
        Ok(Self {
            key: Some(key),
            #[cfg(test)]
            cleanup_observer: None,
        })
    }

    #[cfg(test)]
    fn new_with_cleanup_observer(
        key_bytes: &[u8],
        observer: NativeAeadCleanupObserver,
    ) -> Result<Self, aes_gcm::Error> {
        let mut key = Self::new(key_bytes)?;
        key.cleanup_observer = Some(observer);
        Ok(key)
    }

    fn seal(&self, nonce: [u8; 12], plaintext: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
        self.seal_with_post_copy(nonce, plaintext, |_| Ok(()))
    }

    fn seal_with_post_copy<F>(
        &self,
        nonce: [u8; 12],
        plaintext: &[u8],
        post_copy: F,
    ) -> Result<Vec<u8>, aes_gcm::Error>
    where
        F: FnOnce(&mut [u8]) -> Result<(), aes_gcm::Error>,
    {
        #[cfg(not(test))]
        let mut output = SensitiveAeadBuffer::copied_from(plaintext);
        #[cfg(test)]
        let mut output = match &self.cleanup_observer {
            Some(observer) => {
                SensitiveAeadBuffer::copied_from_with_observer(plaintext, observer.buffers.clone())
            }
            None => SensitiveAeadBuffer::copied_from(plaintext),
        };
        post_copy(&mut output.bytes)?;
        self.key
            .as_ref()
            .expect("native AEAD key must exist before drop")
            .seal_in_place_append_tag(
                AwsNonce::assume_unique_for_key(nonce),
                AwsAad::empty(),
                &mut output.bytes,
            )
            .map_err(|_| aes_gcm::Error)?;
        Ok(output.into_vec())
    }

    fn open(&self, nonce: [u8; 12], ciphertext: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
        #[cfg(not(test))]
        let mut output = SensitiveAeadBuffer::copied_from(ciphertext);
        #[cfg(test)]
        let mut output = match &self.cleanup_observer {
            Some(observer) => {
                SensitiveAeadBuffer::copied_from_with_observer(ciphertext, observer.buffers.clone())
            }
            None => SensitiveAeadBuffer::copied_from(ciphertext),
        };
        let plaintext_len = self
            .key
            .as_ref()
            .expect("native AEAD key must exist before drop")
            .open_in_place(
                AwsNonce::assume_unique_for_key(nonce),
                AwsAad::empty(),
                &mut output.bytes,
            )
            .map_err(|_| aes_gcm::Error)?
            .len();
        output.bytes.truncate(plaintext_len);
        Ok(output.into_vec())
    }
}

#[cfg(all(feature = "session-key-agreement", not(target_family = "wasm")))]
impl Drop for NativeSessionAeadKey {
    fn drop(&mut self) {
        self.key = None;
        #[cfg(test)]
        if let Some(observer) = &self.cleanup_observer {
            observer
                .key_drops
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
}

#[cfg(all(feature = "session-key-agreement", not(target_family = "wasm")))]
fn encrypt_with_backend(
    session_key: &GenericArray<u8, U32>,
    nonce: [u8; 12],
    plaintext: &[u8],
) -> Result<Vec<u8>, aes_gcm::Error> {
    NativeSessionAeadKey::new(session_key)?.seal(nonce, plaintext)
}

#[cfg(all(feature = "session-key-agreement", not(target_family = "wasm")))]
fn decrypt_with_backend(
    session_key: &GenericArray<u8, U32>,
    nonce: [u8; 12],
    ciphertext: &[u8],
) -> Result<Vec<u8>, aes_gcm::Error> {
    NativeSessionAeadKey::new(session_key)?.open(nonce, ciphertext)
}

#[cfg(all(feature = "session-key-agreement", target_family = "wasm"))]
struct WasmSessionAeadKey {
    key: Option<Aes256Gcm>,
    #[cfg(test)]
    cleanup_observer: Option<WasmAeadCleanupObserver>,
}

// `wasm32-unknown-unknown` uses aborting panics in the supported build, so a
// panic terminates the instance and cannot run Rust destructors. All returned
// error paths are guarded and wiped; native unwind paths are exercised above.

#[cfg(all(test, feature = "session-key-agreement", target_family = "wasm"))]
#[derive(Clone, Default)]
struct WasmAeadCleanupObserver {
    key_drops: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    buffers: AeadBufferCleanupObserver,
}

#[cfg(all(test, feature = "session-key-agreement", target_family = "wasm"))]
impl WasmAeadCleanupObserver {
    fn key_drop_count(&self) -> usize {
        self.key_drops.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[cfg(all(feature = "session-key-agreement", target_family = "wasm"))]
impl WasmSessionAeadKey {
    fn new(key_bytes: &GenericArray<u8, U32>) -> Self {
        Self {
            key: Some(Aes256Gcm::new(key_bytes)),
            #[cfg(test)]
            cleanup_observer: None,
        }
    }

    #[cfg(test)]
    fn new_with_cleanup_observer(
        key_bytes: &GenericArray<u8, U32>,
        observer: WasmAeadCleanupObserver,
    ) -> Self {
        let mut key = Self::new(key_bytes);
        key.cleanup_observer = Some(observer);
        key
    }

    fn seal(&self, nonce: [u8; 12], plaintext: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
        self.seal_with_post_copy(nonce, plaintext, |_| Ok(()))
    }

    fn seal_with_post_copy<F>(
        &self,
        nonce: [u8; 12],
        plaintext: &[u8],
        post_copy: F,
    ) -> Result<Vec<u8>, aes_gcm::Error>
    where
        F: FnOnce(&mut [u8]) -> Result<(), aes_gcm::Error>,
    {
        #[cfg(not(test))]
        let mut output = SensitiveAeadBuffer::copied_from(plaintext);
        #[cfg(test)]
        let mut output = match &self.cleanup_observer {
            Some(observer) => {
                SensitiveAeadBuffer::copied_from_with_observer(plaintext, observer.buffers.clone())
            }
            None => SensitiveAeadBuffer::copied_from(plaintext),
        };
        post_copy(&mut output.bytes)?;
        self.key
            .as_ref()
            .expect("WASM AEAD key must exist before drop")
            .encrypt_in_place(&Nonce::from(nonce), b"", &mut output.bytes)?;
        Ok(output.into_vec())
    }

    fn open(&self, nonce: [u8; 12], ciphertext: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
        #[cfg(not(test))]
        let mut output = SensitiveAeadBuffer::copied_from(ciphertext);
        #[cfg(test)]
        let mut output = match &self.cleanup_observer {
            Some(observer) => {
                SensitiveAeadBuffer::copied_from_with_observer(ciphertext, observer.buffers.clone())
            }
            None => SensitiveAeadBuffer::copied_from(ciphertext),
        };
        self.key
            .as_ref()
            .expect("WASM AEAD key must exist before drop")
            .decrypt_in_place(&Nonce::from(nonce), b"", &mut output.bytes)?;
        Ok(output.into_vec())
    }
}

#[cfg(all(feature = "session-key-agreement", target_family = "wasm"))]
impl Drop for WasmSessionAeadKey {
    fn drop(&mut self) {
        self.key = None;
        #[cfg(test)]
        if let Some(observer) = &self.cleanup_observer {
            observer
                .key_drops
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
}

#[cfg(all(feature = "session-key-agreement", target_family = "wasm"))]
fn encrypt_with_backend(
    session_key: &GenericArray<u8, U32>,
    nonce: [u8; 12],
    plaintext: &[u8],
) -> Result<Vec<u8>, aes_gcm::Error> {
    WasmSessionAeadKey::new(session_key).seal(nonce, plaintext)
}

#[cfg(all(feature = "session-key-agreement", target_family = "wasm"))]
fn decrypt_with_backend(
    session_key: &GenericArray<u8, U32>,
    nonce: [u8; 12],
    ciphertext: &[u8],
) -> Result<Vec<u8>, aes_gcm::Error> {
    WasmSessionAeadKey::new(session_key).open(nonce, ciphertext)
}

/// Represents the establishment of a session.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionEstablishment {
    /// The EReader key used for session establishment.
    pub e_reader_key: EReaderKeyBytes,

    /// The data associated with the session establishment.
    pub data: ByteStr,
}

/// Represents session data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionData {
    /// An optional [ByteStr] that represents the data associated with the session.
    /// The field is skipped during serialization if it is [None].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<ByteStr>,

    /// An optional [Status] that represents the status of the session.
    /// Similarly, the field is skipped during serialization if it is [None].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<Status>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(try_from = "u64", into = "u64")]
pub enum Status {
    SessionEncryptionError,
    CborDecodingError,
    SessionTermination,
}

impl From<Status> for u64 {
    fn from(s: Status) -> u64 {
        match s {
            Status::SessionEncryptionError => 10,
            Status::CborDecodingError => 11,
            Status::SessionTermination => 20,
        }
    }
}

impl TryFrom<u64> for Status {
    type Error = String;

    fn try_from(n: u64) -> Result<Status, String> {
        match n {
            10 => Ok(Status::SessionEncryptionError),
            11 => Ok(Status::CborDecodingError),
            20 => Ok(Status::SessionTermination),
            _ => Err(format!("unrecognised error code: {n}")),
        }
    }
}

pub trait SessionTranscript: Serialize + for<'a> Deserialize<'a> {}

/// Represents the device engagement bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionTranscript180135(
    pub DeviceEngagementBytes,
    pub Tag24<EReaderKey>,
    pub Handover,
);

impl SessionTranscript for SessionTranscript180135 {}

#[cfg(feature = "session-key-agreement")]
#[derive(Debug, Clone, thiserror::Error)]
pub enum Error {
    #[error("Curve not supported for DH exchange")]
    UnsupportedCurve,
    #[error("Not a NistP256 Shared Secret")]
    SharedSecretError,
    #[error("Could not derive Shared Secret")]
    SessionKeyError,
    #[error("Something went wrong generating ephemeral keys")]
    EphemeralKeyError,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Handover {
    QR,
    NFC(ByteStr, Option<ByteStr>),
    OID4VP(String, String),
}

#[cfg(feature = "session-key-agreement")]
pub enum EphemeralSecrets {
    /// Represents an Eph256 session.
    /// This enum variant holds an `EphemeralSecret` of type `NistP256`.
    Eph256(EphemeralSecret<NistP256>),

    /// Represents an ephemeral secret using the NIST P-384 elliptic curve.
    Eph384(EphemeralSecret<NistP384>),
}

#[cfg(feature = "session-key-agreement")]
pub enum EncodedPoints {
    /// Represents a session with an Ep256 encoded point.
    Ep256(EncodedPoint<NistP256>),

    /// Represents an Ep384 session.
    /// This struct holds an encoded point of type `EncodedPoint<NistP384>`.
    Ep384(EncodedPoint<NistP384>),
}

#[cfg(feature = "session-key-agreement")]
pub enum SharedSecrets {
    /// Represents a session with a shared secret using the `SS256` algorithm.
    /// The shared secret is generated using the `NistP256` elliptic curve.
    Ss256(SharedSecret<NistP256>),

    /// Represents a session with a shared secret using the `Ss384` algorithm.
    /// The shared secret is of type [`SharedSecret<NistP384>`].
    Ss384(SharedSecret<NistP384>),
}

#[cfg(feature = "session-key-agreement")]
impl From<EncodedPoints> for Vec<u8> {
    fn from(ep: EncodedPoints) -> Vec<u8> {
        match ep {
            Ep256(encoded_point) => encoded_point.as_bytes().to_vec(),
            Ep384(encoded_point) => encoded_point.as_bytes().to_vec(),
        }
    }
}

#[cfg(feature = "session-key-agreement")]
pub fn create_p256_ephemeral_keys() -> Result<(p256::SecretKey, CoseKey), Error> {
    let private_key = p256::SecretKey::random(&mut OsRng);

    let encoded_point = ecdsa::EncodedPoint::<NistP256>::from(private_key.public_key());
    let x_coordinate = encoded_point.x().ok_or(Error::EphemeralKeyError)?;
    let y_coordinate = encoded_point.y().ok_or(Error::EphemeralKeyError)?;

    let crv = EC2Curve::try_from(1).map_err(|_e| Error::EphemeralKeyError)?;
    let public_key = CoseKey::EC2 {
        crv,
        x: x_coordinate.to_vec(),
        y: EC2Y::Value(y_coordinate.to_vec()),
    };

    Ok((private_key, public_key))
}

#[cfg(feature = "session-key-agreement")]
pub fn get_shared_secret(
    cose_key: CoseKey,
    e_device_key_priv: &p256::NonZeroScalar,
) -> Result<SharedSecret<NistP256>> {
    let encoded_point: EncodedPoint<NistP256> = EncodedPoint::<NistP256>::try_from(cose_key)?;
    let public_key_opt = p256::PublicKey::from_encoded_point(&encoded_point);
    if public_key_opt.is_none().into() {
        return Err(anyhow::anyhow!(
            "reader's public key could not be constructed"
        ));
    }
    let public_key = public_key_opt.unwrap();
    let shared_secret = p256::ecdh::diffie_hellman(e_device_key_priv, public_key.as_affine());
    Ok(shared_secret)
}

#[cfg(feature = "session-key-agreement")]
pub fn derive_session_key(
    shared_secret: &SharedSecret<NistP256>,
    session_transcript: &SessionTranscriptBytes,
    reader: bool,
) -> Result<SessionKey> {
    let transcript = crate::cbor::to_vec(session_transcript)
        .map_err(|e| anyhow::anyhow!("failed to serialize session transcript: {e}"))?;
    let mut salt_hash = SecureSha256::new();
    salt_hash.update(&transcript);
    let salt = salt_hash.finish();
    let mut okm = Zeroizing::new([0u8; 32]);
    let info = if reader { b"SKReader" } else { b"SKDevice" };
    let mut scratch = HkdfScratch::default();
    hkdf_sha256_32_with_scratch(
        shared_secret.raw_secret_bytes(),
        &*salt,
        info,
        &mut okm,
        &mut scratch,
        || Ok(()),
    )
    .map_err(|()| anyhow::anyhow!("failed to expand session key"))?;

    Ok(SessionKey(okm))
}

#[cfg(feature = "session-key-agreement")]
pub fn encrypt_device_data(
    sk_device: &GenericArray<u8, U32>,
    plaintext: &[u8],
    message_count: &mut u32,
) -> Result<Vec<u8>, aes_gcm::Error> {
    encrypt(sk_device, plaintext, message_count, false)
}

#[cfg(feature = "session-key-agreement")]
pub fn encrypt_reader_data(
    sk_reader: &GenericArray<u8, U32>,
    plaintext: &[u8],
    message_count: &mut u32,
) -> Result<Vec<u8>, aes_gcm::Error> {
    encrypt(sk_reader, plaintext, message_count, true)
}

#[cfg(feature = "session-key-agreement")]
fn encrypt(
    session_key: &GenericArray<u8, U32>,
    plaintext: &[u8],
    message_count: &mut u32,
    reader: bool,
) -> Result<Vec<u8>, aes_gcm::Error> {
    let previous_message_count = *message_count;
    let initialization_vector = get_initialization_vector(message_count, reader)?;
    match encrypt_with_backend(session_key, initialization_vector, plaintext) {
        Ok(ciphertext) => Ok(ciphertext),
        Err(error) => {
            *message_count = previous_message_count;
            Err(error)
        }
    }
}

#[cfg(feature = "session-key-agreement")]
pub fn decrypt_device_data(
    sk_device: &GenericArray<u8, U32>,
    ciphertext: &[u8],
    message_count: &mut u32,
) -> Result<Vec<u8>, aes_gcm::Error> {
    decrypt(sk_device, ciphertext, message_count, false)
}

#[cfg(feature = "session-key-agreement")]
pub fn decrypt_reader_data(
    sk_reader: &GenericArray<u8, U32>,
    ciphertext: &[u8],
    message_count: &mut u32,
) -> Result<Vec<u8>, aes_gcm::Error> {
    decrypt(sk_reader, ciphertext, message_count, true)
}

#[cfg(feature = "session-key-agreement")]
fn decrypt(
    session_key: &GenericArray<u8, U32>,
    ciphertext: &[u8],
    message_count: &mut u32,
    reader: bool,
) -> Result<Vec<u8>, aes_gcm::Error> {
    let previous_message_count = *message_count;
    let initialization_vector = get_initialization_vector(message_count, reader)?;
    match decrypt_with_backend(session_key, initialization_vector, ciphertext) {
        Ok(plaintext) => Ok(plaintext),
        Err(error) => {
            *message_count = previous_message_count;
            Err(error)
        }
    }
}

#[cfg(feature = "session-key-agreement")]
pub fn get_initialization_vector(
    message_count: &mut u32,
    reader: bool,
) -> Result<[u8; 12], aes_gcm::Error> {
    *message_count = message_count.checked_add(1).ok_or(aes_gcm::Error)?;
    let counter = GenericArray::from(message_count.to_be_bytes());
    let identifier = if reader {
        GenericArray::from([0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8])
    } else {
        GenericArray::from([0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 1u8])
    };

    Ok(identifier.concat(counter).into())
}

#[cfg(all(test, feature = "session-key-agreement"))]
mod test {
    use super::*;
    use crate::cbor;
    use crate::definitions::device_engagement::Security;
    use crate::definitions::device_request::DeviceRequest;

    #[test]
    fn initialization_vector_fails_closed_at_counter_exhaustion() {
        let mut counter = u32::MAX;

        assert!(get_initialization_vector(&mut counter, true).is_err());
        assert_eq!(counter, u32::MAX);
    }

    #[test]
    fn failed_authenticated_decryption_does_not_advance_counter() {
        let session_key = GenericArray::from([0u8; 32]);
        let mut counter = 0;

        assert!(decrypt_reader_data(&session_key, &[0u8; 16], &mut counter).is_err());
        assert_eq!(counter, 0);
    }

    #[cfg(not(target_family = "wasm"))]
    #[test]
    fn native_aes_256_gcm_matches_known_answer_and_drops_key() {
        let observer = NativeAeadCleanupObserver::default();
        let key =
            NativeSessionAeadKey::new_with_cleanup_observer(&[0u8; 32], observer.clone()).unwrap();
        let ciphertext = key.seal([0u8; 12], &[]).unwrap();
        assert_eq!(hex::encode(&ciphertext), "530f8afbc74536b9a963b4f1c4cb738b");
        assert_eq!(key.open([0u8; 12], &ciphertext).unwrap(), Vec::<u8>::new());
        drop(key);
        assert_eq!(observer.key_drop_count(), 1);
    }

    #[cfg(not(target_family = "wasm"))]
    #[test]
    fn native_aead_wipes_copied_plaintext_on_error_and_unwind() {
        let error_observer = NativeAeadCleanupObserver::default();
        {
            let key = NativeSessionAeadKey::new_with_cleanup_observer(
                &[0x11; 32],
                error_observer.clone(),
            )
            .unwrap();
            let result = key.seal_with_post_copy(
                [0x22; 12],
                b"recognizable plaintext",
                |copied_plaintext| {
                    copied_plaintext[0] ^= 0xff;
                    Err(aes_gcm::Error)
                },
            );
            assert!(result.is_err());
        }
        assert_eq!(error_observer.key_drop_count(), 1);
        let error_buffers = error_observer.wiped_buffers();
        assert_eq!(error_buffers.len(), 1);
        assert!(!error_buffers[0].is_empty());
        assert!(error_buffers[0].iter().all(|byte| *byte == 0));

        let unwind_observer = NativeAeadCleanupObserver::default();
        let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe({
            let observer = unwind_observer.clone();
            move || {
                let key =
                    NativeSessionAeadKey::new_with_cleanup_observer(&[0x33; 32], observer).unwrap();
                let _ = key.seal_with_post_copy(
                    [0x44; 12],
                    b"second recognizable plaintext",
                    |copied_plaintext| {
                        copied_plaintext[1] ^= 0xff;
                        panic!("injected AEAD unwind after plaintext copy")
                    },
                );
            }
        }));
        assert!(unwind.is_err());
        assert_eq!(unwind_observer.key_drop_count(), 1);
        let unwind_buffers = unwind_observer.wiped_buffers();
        assert_eq!(unwind_buffers.len(), 1);
        assert!(!unwind_buffers[0].is_empty());
        assert!(unwind_buffers[0].iter().all(|byte| *byte == 0));
    }

    #[cfg(not(target_family = "wasm"))]
    #[test]
    fn native_aead_wipes_failed_open_scratch() {
        let observer = NativeAeadCleanupObserver::default();
        {
            let key =
                NativeSessionAeadKey::new_with_cleanup_observer(&[0x55; 32], observer.clone())
                    .unwrap();
            assert!(key.open([0x66; 12], &[0xa5; 32]).is_err());
        }
        assert_eq!(observer.key_drop_count(), 1);
        let buffers = observer.wiped_buffers();
        assert_eq!(buffers.len(), 1);
        assert!(!buffers[0].is_empty());
        assert!(buffers[0].iter().all(|byte| *byte == 0));
    }

    #[cfg(target_family = "wasm")]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn wasm_aes_256_gcm_kat_roundtrip_and_forged_tag_cleanup() {
        let observer = WasmAeadCleanupObserver::default();
        let session_key = GenericArray::from([0u8; 32]);
        let key = WasmSessionAeadKey::new_with_cleanup_observer(&session_key, observer.clone());
        let ciphertext = key.seal([0u8; 12], &[]).unwrap();
        assert_eq!(hex::encode(&ciphertext), "530f8afbc74536b9a963b4f1c4cb738b");
        assert_eq!(key.open([0u8; 12], &ciphertext).unwrap(), Vec::<u8>::new());

        let mut forged = ciphertext;
        forged[0] ^= 1;
        assert!(key.open([0u8; 12], &forged).is_err());
        drop(key);
        assert_eq!(observer.key_drop_count(), 1);
        let buffers = observer.buffers.snapshots();
        assert!(buffers.iter().any(|buffer| !buffer.is_empty()));
        assert!(buffers
            .iter()
            .all(|buffer| buffer.iter().all(|byte| *byte == 0)));
    }

    #[cfg(target_family = "wasm")]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn wasm_aead_wipes_copied_plaintext_on_returned_error() {
        let error_observer = WasmAeadCleanupObserver::default();
        {
            let session_key = GenericArray::from([0x11; 32]);
            let key =
                WasmSessionAeadKey::new_with_cleanup_observer(&session_key, error_observer.clone());
            let result = key.seal_with_post_copy(
                [0x22; 12],
                b"recognizable browser plaintext",
                |copied_plaintext| {
                    copied_plaintext[0] ^= 0xff;
                    Err(aes_gcm::Error)
                },
            );
            assert!(result.is_err());
        }
        assert_eq!(error_observer.key_drop_count(), 1);
        let buffers = error_observer.buffers.snapshots();
        assert_eq!(buffers.len(), 1);
        assert!(!buffers[0].is_empty());
        assert!(buffers[0].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn qr_handover() {
        // null
        let cbor = hex::decode("F6").expect("failed to decode hex");
        let handover: Handover =
            cbor::from_slice(&cbor).expect("failed to deserialize as handover");
        if !matches!(handover, Handover::QR) {
            panic!("expected 'Handover::QR', received {handover:?}")
        } else {
            let roundtripped =
                cbor::to_vec(&handover).expect("failed to serialize handover as cbor");
            assert_eq!(
                cbor, roundtripped,
                "re-serialized handover did not match initial bytes"
            )
        }
    }

    #[test]
    #[should_panic]
    fn qr_handover_empty_array() {
        // []
        let cbor = hex::decode("80").expect("failed to decode hex");
        let handover: Handover =
            cbor::from_slice(&cbor).expect("failed to deserialize as handover");
        if !matches!(handover, Handover::QR) {
            panic!("expected 'Handover::QR', received {handover:?}")
        } else {
            let roundtripped =
                cbor::to_vec(&handover).expect("failed to serialize handover as cbor");
            assert_eq!(
                cbor, roundtripped,
                "re-serialized handover did not match initial bytes"
            )
        }
    }

    #[test]
    #[should_panic]
    fn qr_handover_empty_object() {
        // {}
        let cbor = hex::decode("A0").expect("failed to decode hex");
        let handover: Handover =
            cbor::from_slice(&cbor).expect("failed to deserialize as handover");
        if !matches!(handover, Handover::QR) {
            panic!("expected 'Handover::QR', received {handover:?}")
        } else {
            let roundtripped =
                cbor::to_vec(&handover).expect("failed to serialize handover as cbor");
            assert_eq!(
                cbor, roundtripped,
                "re-serialized handover did not match initial bytes"
            )
        }
    }

    #[test]
    fn nfc_static_handover() {
        // ['hello', null]
        let cbor = hex::decode("824568656C6C6FF6").expect("failed to decode hex");
        let handover: Handover =
            cbor::from_slice(&cbor).expect("failed to deserialize as handover");
        if !matches!(handover, Handover::NFC(..)) {
            panic!("expected 'Handover::NFC(..)', received {handover:?}")
        } else {
            let roundtripped =
                cbor::to_vec(&handover).expect("failed to serialize handover as cbor");
            assert_eq!(
                cbor, roundtripped,
                "re-serialized handover did not match initial bytes"
            )
        }
    }

    #[test]
    fn nfc_negotiated_handover() {
        // ['hello', 'world']
        let cbor = hex::decode("824568656C6C6F45776F726C64").expect("failed to decode hex");
        let handover: Handover =
            cbor::from_slice(&cbor).expect("failed to deserialize as handover");
        if !matches!(handover, Handover::NFC(..)) {
            panic!("expected 'Handover::NFC(..)', received {handover:?}")
        } else {
            let roundtripped =
                cbor::to_vec(&handover).expect("failed to serialize handover as cbor");
            assert_eq!(
                cbor, roundtripped,
                "re-serialized handover did not match initial bytes"
            )
        }
    }

    #[test]
    fn oid4vp_handover() {
        // ["aud", "nonce"]
        let cbor = hex::decode("8263617564656E6F6E6365").expect("failed to decode hex");
        let handover: Handover =
            cbor::from_slice(&cbor).expect("failed to deserialize as handover");
        if !matches!(handover, Handover::OID4VP(..)) {
            panic!(
                "expected '{}', received {:?}",
                "Handover::OID4VP(..)", handover
            )
        } else {
            let roundtripped =
                cbor::to_vec(&handover).expect("failed to serialize handover as cbor");
            assert_eq!(
                cbor, roundtripped,
                "re-serialized handover did not match initial bytes"
            )
        }
    }

    #[test]
    fn key_generation() {
        //todo fully test the exchange of keys and the resulting session keys e2e
        create_p256_ephemeral_keys().expect("failed to generate keys");
    }

    #[test]
    fn test_encryption_decryption() {
        let reader_keys = create_p256_ephemeral_keys().expect("failed to generate reader keys");
        let device_keys = create_p256_ephemeral_keys().expect("failed to generate device keys");
        let pub_key_reader = reader_keys.1;
        let pub_key_device = device_keys.1;

        let device_shared_secret =
            get_shared_secret(pub_key_reader.clone(), &device_keys.0.to_nonzero_scalar())
                .expect("failed to derive secrets from public and private key");
        let reader_shared_secret =
            get_shared_secret(pub_key_device.clone(), &reader_keys.0.to_nonzero_scalar())
                .expect("failed to derive secret from public and private key");

        let device_key_bytes = Tag24::new(pub_key_device).unwrap();
        let reader_key_bytes = Tag24::new(pub_key_reader).unwrap();

        let device_engagement = DeviceEngagement {
            version: "1.0".into(),
            security: Security(1, device_key_bytes),
            device_retrieval_methods: None,
            server_retrieval_methods: None,
            protocol_info: None,
        };

        let device_engagement_bytes = Tag24::new(device_engagement).unwrap();
        let session_transcript = Tag24::new(SessionTranscript180135(
            device_engagement_bytes,
            reader_key_bytes,
            Handover::QR,
        ))
        .unwrap();
        let _session_key_device =
            derive_session_key(&device_shared_secret, &session_transcript, false).unwrap();

        let session_key_reader =
            derive_session_key(&reader_shared_secret, &session_transcript, true).unwrap();

        let plaintext = "a message to encrypt!".as_bytes();

        let mut message_count = 0;

        let ciphertext = encrypt_reader_data(
            GenericArray::from_slice(session_key_reader.as_ref()),
            plaintext,
            &mut message_count,
        )
        .unwrap();

        let mut message_count = 0;

        let decrypted_plaintext = decrypt_reader_data(
            GenericArray::from_slice(session_key_reader.as_ref()),
            &ciphertext,
            &mut message_count,
        )
        .unwrap();

        assert_eq!(plaintext, decrypted_plaintext);
    }

    #[test]
    fn handle_session_establishment_and_decrypt_device_request() {
        const E_DEVICE_KEY: &str = include_str!("../../test/definitions/session/e_device_key.cbor");
        const SESSION_ESTABLISHMENT: &str =
            include_str!("../../test/definitions/session/session_establishment.cbor");
        const SHARED_SECRET: &str =
            include_str!("../../test/definitions/session/shared_secret.cbor");
        const SESSION_TRANSCRIPT: &str =
            include_str!("../../test/definitions/session/session_transcript.cbor");
        const READER_SESSION_KEY: &str =
            include_str!("../../test/definitions/session/reader_session_key.cbor");

        let e_device_key_bytes = hex::decode(E_DEVICE_KEY).unwrap();
        let e_device_key = p256::SecretKey::from_slice(&e_device_key_bytes).unwrap();
        let e_device_key_inner = e_device_key.to_nonzero_scalar();

        let session_establishment_bytes = hex::decode(SESSION_ESTABLISHMENT).unwrap();
        let session_establishment: SessionEstablishment =
            cbor::from_slice(&session_establishment_bytes).unwrap();

        let e_reader_key = session_establishment.e_reader_key;
        let encrypted_request = session_establishment.data;

        let shared_secret =
            get_shared_secret(e_reader_key.as_ref().clone(), &e_device_key_inner).unwrap();
        let shared_secret_hex = hex::encode(shared_secret.raw_secret_bytes());
        assert_eq!(shared_secret_hex, SHARED_SECRET);

        let session_transcript_bytes = hex::decode(SESSION_TRANSCRIPT).unwrap();
        let session_transcript: SessionTranscriptBytes =
            cbor::from_slice(&session_transcript_bytes).unwrap();

        let session_key = derive_session_key(&shared_secret, &session_transcript, true).unwrap();
        let session_key_hex = hex::encode(session_key.as_ref());
        assert_eq!(session_key_hex, READER_SESSION_KEY);
        assert_eq!(format!("{session_key:?}"), "SessionKey(\"[REDACTED]\")");
        assert!(!format!("{session_key:?}").contains(READER_SESSION_KEY.trim()));

        let plaintext = decrypt_reader_data(
            GenericArray::from_slice(session_key.as_ref()),
            encrypted_request.as_ref(),
            &mut 0,
        )
        .unwrap();
        let _device_request: DeviceRequest = crate::cbor::from_slice(&plaintext).unwrap();
    }
}
