//! This module contains the definition of the [IssuerSigned] struct and related types.
//!
//! The [IssuerSigned] struct represents a signed issuer object, which includes information about `namespaces`, `authentication`, and `signed items`.  
//!
//! # Notes
//!
//! - [IssuerSigned] struct is serialized and deserialized using the [Serialize] and [Deserialize] traits from the [serde] crate.
//! - [IssuerNamespaces] type is an alias for [`NonEmptyMap<String, NonEmptyVec<IssuerSignedItemBytes>>`].
//! - [IssuerSignedItemBytes] type is an alias for [`Tag24<IssuerSignedItem>`].
//! - [IssuerSignedItem] struct represents a signed item within the [IssuerSigned] object, including information such as digest ID, random bytes, element identifier, and element value.
//! - [IssuerSigned] struct also includes a test module with a unit test for serialization and deserialization.

use crate::cose::MaybeTagged;
use crate::definitions::{
    helpers::{ByteStr, NonEmptyMap, NonEmptyVec, Tag24},
    DigestId,
};
use coset::CoseSign1;
use serde::{de::Error as _, Deserialize, Deserializer, Serialize};
use std::collections::BTreeMap;

/// Represents an issuer-signed object.
///
/// This struct is used to store information about an issuer-signed object, which includes namespaces and issuer authentication.  
/// [IssuerSigned::namespaces] field is an optional [IssuerNamespaces] object that contains namespaces associated with the issuer.  
/// [IssuerSigned::issuer_auth] field is a [CoseSign1] object that represents the issuer authentication.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuerSigned {
    #[serde(
        default,
        deserialize_with = "deserialize_optional_issuer_namespaces",
        skip_serializing_if = "Option::is_none",
        rename = "nameSpaces"
    )]
    pub namespaces: Option<IssuerNamespaces>,
    pub issuer_auth: MaybeTagged<CoseSign1>,
}

pub type IssuerNamespaces = NonEmptyMap<String, NonEmptyVec<IssuerSignedItemBytes>>;
pub type IssuerSignedItemBytes = Tag24<IssuerSignedItem>;

/// Decode the optional disclosure map used in an `IssuerSigned` response.
///
/// ISO 18013-5 models `nameSpaces` as optional. Some interoperable wallets,
/// including the OpenID Foundation conformance wallet, encode a presentation
/// with no disclosed issuer-signed items as an empty map instead of omitting
/// the field. Treat those two encodings as the same semantic value. Non-empty
/// namespace maps remain strict: every included namespace must still contain
/// at least one signed item.
fn deserialize_optional_issuer_namespaces<'de, D>(
    deserializer: D,
) -> Result<Option<IssuerNamespaces>, D::Error>
where
    D: Deserializer<'de>,
{
    let Some(namespaces) =
        Option::<BTreeMap<String, Vec<IssuerSignedItemBytes>>>::deserialize(deserializer)?
    else {
        return Ok(None);
    };
    if namespaces.is_empty() {
        return Ok(None);
    }

    let namespaces = namespaces
        .into_iter()
        .map(|(name, items)| {
            NonEmptyVec::try_from(items)
                .map(|items| (name, items))
                .map_err(D::Error::custom)
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    NonEmptyMap::try_from(namespaces)
        .map(Some)
        .map_err(D::Error::custom)
}

/// Represents an item signed by the issuer.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuerSignedItem {
    /// The ID of the digest used for signing.
    #[serde(rename = "digestID")]
    pub digest_id: DigestId,

    /// Random bytes associated with the signed item.
    pub random: ByteStr,

    /// The identifier of the element.
    pub element_identifier: String,

    /// The value of the element.
    pub element_value: ciborium::Value,
}

#[cfg(test)]
mod test {
    use super::IssuerSigned;
    use crate::cbor;
    use ciborium::Value;
    use hex::FromHex;

    static ISSUER_SIGNED_CBOR: &str = include_str!("../../test/definitions/issuer_signed.cbor");

    #[test]
    fn serde_issuer_signed() {
        let cbor_bytes =
            <Vec<u8>>::from_hex(ISSUER_SIGNED_CBOR).expect("unable to convert cbor hex to bytes");
        let signed: IssuerSigned =
            cbor::from_slice(&cbor_bytes).expect("unable to decode cbor as an IssuerSigned");
        let roundtripped_bytes =
            cbor::to_vec(&signed).expect("unable to encode IssuerSigned as cbor bytes");
        assert_eq!(
            cbor_bytes, roundtripped_bytes,
            "original cbor and re-serialized IssuerSigned do not match"
        );
    }

    #[test]
    fn empty_issuer_namespaces_are_treated_as_not_disclosed() {
        let cbor_bytes =
            <Vec<u8>>::from_hex(ISSUER_SIGNED_CBOR).expect("unable to convert cbor hex to bytes");
        let mut value: Value =
            cbor::from_slice(&cbor_bytes).expect("unable to decode issuer signed fixture");
        let Value::Map(entries) = &mut value else {
            panic!("issuer signed fixture must be a CBOR map");
        };
        let namespaces = entries
            .iter_mut()
            .find(|(key, _)| key == &Value::Text("nameSpaces".to_string()))
            .expect("issuer signed fixture must contain nameSpaces");
        namespaces.1 = Value::Map(Vec::new());
        let cbor_bytes = cbor::to_vec(&value).expect("unable to encode empty disclosure map");

        let signed: IssuerSigned =
            cbor::from_slice(&cbor_bytes).expect("empty disclosure map must be accepted");

        assert!(signed.namespaces.is_none());
    }

    #[test]
    fn non_empty_namespace_with_no_items_remains_invalid() {
        let cbor_bytes =
            <Vec<u8>>::from_hex(ISSUER_SIGNED_CBOR).expect("unable to convert cbor hex to bytes");
        let mut value: Value =
            cbor::from_slice(&cbor_bytes).expect("unable to decode issuer signed fixture");
        let Value::Map(entries) = &mut value else {
            panic!("issuer signed fixture must be a CBOR map");
        };
        let namespaces = entries
            .iter_mut()
            .find(|(key, _)| key == &Value::Text("nameSpaces".to_string()))
            .expect("issuer signed fixture must contain nameSpaces");
        namespaces.1 = Value::Map(vec![(
            Value::Text("org.iso.18013.5.1".to_string()),
            Value::Array(Vec::new()),
        )]);
        let cbor_bytes = cbor::to_vec(&value).expect("unable to encode invalid disclosure map");

        assert!(cbor::from_slice::<IssuerSigned>(&cbor_bytes).is_err());
    }
}
