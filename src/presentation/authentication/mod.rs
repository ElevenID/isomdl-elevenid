use std::collections::BTreeMap;

use crate::cbor::CborError;
use crate::definitions::device_key::cose_key::Error as CoseKeyError;
use crate::definitions::device_request::ItemsRequest;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Module containing functions to perform mdoc authentication.
pub mod mdoc;

/// The outcome of the holder device authenticating the device request.
#[derive(Debug, Serialize, Deserialize, Default, Clone, PartialEq)]
pub struct RequestAuthenticationOutcome {
    /// The requested items from the mDL namespace.
    pub items_request: Vec<ItemsRequest>,
    /// The common name from the certificate that signed this request, if available.
    /// This value can be used to display to the user who the reader is, however
    /// caution should be exercised if reader authentication was not successful.
    pub common_name: Option<String>,
    /// Outcome of reader authentication.
    pub reader_authentication: AuthenticationStatus,
    /// Errors that occurred during request processing.
    pub errors: Errors,
}

/// The outcome of the reader device authenticating the device response.
#[derive(Debug, Serialize, Deserialize, Default, Clone, PartialEq, Eq)]
pub struct ResponseAuthenticationOutcome {
    /// The values sent back from the holder device, serialized as JSON.
    pub response: BTreeMap<String, Value>,
    /// Outcome of issuer authentication.
    pub issuer_authentication: AuthenticationStatus,
    /// Outcome of device authentication.
    pub device_authentication: AuthenticationStatus,
    /// Errors that occurred during response processing.
    pub errors: Errors,
}

/// The outcome of authenticity checks.
#[derive(Debug, Serialize, Deserialize, Default, Clone, Copy, PartialEq, Eq)]
pub enum AuthenticationStatus {
    #[default]
    Unchecked,
    Invalid,
    Valid,
}

/// Errors that occur during request/response processing.
pub type Errors = BTreeMap<String, serde_json::Value>;

/// Errors produced by passive mdoc authentication.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Received IssuerAuth had a detached payload.")]
    DetachedIssuerAuth,
    #[error("Could not parse MSO.")]
    MSOParsing,
    #[error("Unexpected CBOR type for offered value")]
    CborDecodingError,
    #[error("Failed mdoc authentication: {0}")]
    MdocAuth(String),
    #[error("Currently unsupported format")]
    Unsupported,
    #[error("issuer authentication failed: {0}")]
    IssuerAuthentication(String),
    #[error("Unable to parse issuer public key")]
    IssuerPublicKey(anyhow::Error),
}

impl From<CborError> for Error {
    fn from(_: CborError) -> Self {
        Self::CborDecodingError
    }
}

impl From<x509_cert::der::Error> for Error {
    fn from(value: x509_cert::der::Error) -> Self {
        Self::MdocAuth(value.to_string())
    }
}

impl From<p256::ecdsa::Error> for Error {
    fn from(value: p256::ecdsa::Error) -> Self {
        Self::MdocAuth(value.to_string())
    }
}

impl From<x509_cert::spki::Error> for Error {
    fn from(value: x509_cert::spki::Error) -> Self {
        Self::MdocAuth(value.to_string())
    }
}

impl From<CoseKeyError> for Error {
    fn from(value: CoseKeyError) -> Self {
        Self::MdocAuth(value.to_string())
    }
}
