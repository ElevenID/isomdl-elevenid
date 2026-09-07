//! This module contains the implementation of the `issuance` module.
//!
//! The `issuance` module provides functionality for handling issuance related operations.
pub mod mdoc;

pub use mdoc::{Mdoc, MdocBatchItem, Namespaces, PreparedMdocBatchItem};

/// Marker used to document the local-signing capability boundary.
///
/// Direct signing entry points are deliberately absent from production builds.
/// KMS-backed issuers use `Mdoc::prepare`,
/// `PreparedMdoc::signature_payload`, and `PreparedMdoc::complete` instead.
///
/// ```compile_fail
/// use isomdl::issuance::Mdoc;
///
/// fn direct_signing_is_not_available() {
///     let _ = Mdoc::issue;
/// }
/// ```
pub struct LocalSigningDisabled;
