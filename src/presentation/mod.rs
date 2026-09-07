//! This module responsible on handling the interaction between the device and reader.
//!
//! You can see examples on how to use this module in `examples`
//! directory and read about in the dedicated `README.md`.
//!
//! # **Device** and **Reader** interaction
//!
//! This flow demonstrates a simulated device and reader interaction.
//! The reader requests the `age_over_21` element, and the device responds with that value.
//! The flow is something like this:
//!
//! ```ignore
#![doc = include_str!("../../docs/simulated_device_and_reader.txt")]
//! ```
//!
//! ## The flow of the interaction
//!
//! 1. **Device initialization and engagement:**
//!     - The device creates a `QR code` containing `DeviceEngagement` data, which includes its public key.
//!     - Internally:
//!         - The device initializes with the `mDL` data, private key, and public key.
//! 2. **Reader processing `QR code` and requesting needed fields:**
//!     - The reader processes the QR code and creates a request for the `age_over_21` element.
//!     - Internally:
//!         - Generates its private and public keys.
//!         - Initiates a key exchange, and generates the session keys.
//!         - The request is encrypted with the reader's session key.
//! 3. **Device accepting request and responding:**
//!     - The device receives the request and creates a response with the `age_over_21` element.
//!     - Internally:
//!         - Initiates the key exchange, and generates the session keys.
//!         - Decrypts the request with the reader's session key.
//!         - Parse and validate it creating error response if needed.
//!         - The response is encrypted with the device's session key.
//! 4. **Reader Processing mDL data:**
//!     - The reader processes the response and prints the value of the `age_over_21` element.
//!
//! ### Examples
//!
//! You can see the example in `simulated_device_and_reader.rs` from `examples` directory or a version that
//! uses **State pattern**, `Arc` and `Mutex` `simulated_device_and_reader_state.rs`.
pub mod authentication;
#[cfg(feature = "session-key-agreement")]
pub mod device;
#[cfg(feature = "session-key-agreement")]
pub mod reader;
pub mod reader_utils;

#[cfg(feature = "session-key-agreement")]
use anyhow::Result;
#[cfg(feature = "session-key-agreement")]
use base64::{decode, encode};
#[cfg(feature = "session-key-agreement")]
use serde::{Deserialize, Serialize};

/// Trait that handles serialization of [CBOR](https://cbor.io) objects to/from [String].
/// It is an auto trait.
#[cfg(feature = "session-key-agreement")]
pub trait Stringify: Serialize + for<'a> Deserialize<'a> {
    /// Serialize to [CBOR](https://cbor.io) representation.
    ///
    /// Operation may fail, so it returns a [Result].
    ///
    /// # Example
    ///
    /// ```
    /// use base64::decode;
    /// use serde::Serialize;
    /// use isomdl::cbor::from_slice;
    /// use isomdl::presentation::{device, Stringify};
    /// use isomdl::presentation::device::Document;
    ///
    /// let doc_str = include_str!("../../test/stringified-mdl.txt").to_string();
    /// let doc : Document = from_slice(&decode(doc_str).unwrap()).unwrap();
    /// let serialized = doc.stringify().unwrap();
    /// assert_eq!(serialized, Document::parse(serialized.clone()).unwrap().stringify().unwrap());
    /// ```
    fn stringify(&self) -> Result<String> {
        let data = crate::cbor::to_vec(self)?;
        let encoded = encode(data);
        Ok(encoded)
    }

    /// Deserialize the object from the [CBOR](https://cbor.io) representation.
    ///
    /// You can call this on something returned by [Stringify::stringify].
    /// Operation may fail, so it returns a [Result].
    ///
    /// # Example
    ///
    /// ```
    /// use base64::decode;
    /// use serde::Serialize;
    /// use isomdl::cbor::from_slice;
    /// use isomdl::presentation::{device, Stringify};
    /// use isomdl::presentation::device::Document;
    ///
    /// let doc_str = include_str!("../../test/stringified-mdl.txt").to_string();
    /// let doc : Document = from_slice(&decode(doc_str).unwrap()).unwrap();
    /// let serialized = doc.stringify().unwrap();
    /// assert_eq!(serialized, Document::parse(serialized.clone()).unwrap().stringify().unwrap());
    /// ```
    fn parse(encoded: String) -> Result<Self> {
        let data = decode(encoded)?;
        let this = crate::cbor::from_slice(&data)?;
        Ok(this)
    }
}

#[cfg(feature = "session-key-agreement")]
impl Stringify for device::Document {}
#[cfg(feature = "session-key-agreement")]
use crate::definitions::{device_key::cose_key::CoseKey, helpers::Tag24};
#[cfg(feature = "session-key-agreement")]
use hkdf::Hkdf;
#[cfg(feature = "session-key-agreement")]
use sha2::Sha256;

#[cfg(feature = "session-key-agreement")]
fn calculate_ble_ident(e_device_key: &Tag24<CoseKey>) -> Result<[u8; 16]> {
    let e_device_key_bytes = crate::cbor::to_vec(e_device_key)?;
    let mut ble_ident = [0u8; 16];

    Hkdf::<Sha256>::new(None, &e_device_key_bytes)
        .expand("BLEIdent".as_bytes(), &mut ble_ident)
        .map_err(|e| anyhow::anyhow!("unable to perform HKDF: {}", e))?;

    Ok(ble_ident)
}

/// Marker used to document the ephemeral session capability boundary.
///
/// Passive verification remains available with `presentation-verifier`, while
/// reader/device state machines that generate or retain ephemeral secrets
/// require `session-key-agreement`.
///
/// ```compile_fail
/// use isomdl::presentation::reader::SessionManager;
///
/// fn session_api_is_not_available() {
///     let _ = core::mem::size_of::<SessionManager>();
/// }
/// ```
///
/// ```compile_fail
/// use isomdl::definitions::session::create_p256_ephemeral_keys;
///
/// fn ephemeral_key_generation_is_not_available() {
///     let _ = create_p256_ephemeral_keys();
/// }
/// ```
#[cfg(not(feature = "session-key-agreement"))]
pub struct SessionKeyAgreementDisabled;
