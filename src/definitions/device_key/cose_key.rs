//! An implementation of `RFC-8152` `COSE_Key` restricted to the requirements of `ISO/IEC 18013-5:2021`.
//!
//! This module provides the [CoseKey] enum, which represents a `COSE_Key` object as defined in `RFC-8152`.  
//! It supports two key types: `EC2 (Elliptic Curve)` and `OKP (Octet Key Pair).
//!
//! # Examples
//!
//! ```ignore
//! use std::convert::TryInto;
//! use crate::CoseKey;
//!
//! let cbor_value: ciborium::Value = /* ... */;
//! let cose_key: Result<CoseKey, _> = cbor_value.try_into();
//!
//! match cose_key {
//!     Ok(key) => {
//!         // Perform operations with the COSE_Key
//!     }
//!     Err(err) => {
//!         // Handle the error
//!     }
//! }
//! ```
use std::collections::BTreeMap;

use coset::iana::Algorithm;
use p256::EncodedPoint;
use serde::{Deserialize, Serialize};

/// An implementation of RFC-8152 [COSE_Key](https://datatracker.ietf.org/doc/html/rfc8152#section-13)
/// restricted to the requirements of ISO/IEC 18013-5:2021.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(try_from = "ciborium::Value", into = "ciborium::Value")]
pub enum CoseKey {
    EC2 { crv: EC2Curve, x: Vec<u8>, y: EC2Y },
    OKP { crv: OKPCurve, x: Vec<u8> },
}

/// The sign bit or value of the y-coordinate for the EC point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EC2Y {
    Value(Vec<u8>),
    SignBit(bool),
}

/// The RFC-8152 identifier of the curve, for EC2 key type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EC2Curve {
    P256,
    P384,
    P521,
    P256K,
}

/// The RFC-8152 identifier of the curve, for OKP key type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OKPCurve {
    X25519,
    X448,
    Ed25519,
    Ed448,
}

/// Errors that can occur when deserializing a COSE_Key.
#[derive(Debug, Clone, thiserror::Error)]
pub enum Error {
    #[error("COSE_Key of kty 'EC2' missing x coordinate")]
    EC2MissingX,
    #[error("COSE_Key of kty 'EC2' missing y coordinate")]
    EC2MissingY,
    #[error("Expected to parse a CBOR bool or bstr for y-coordinate, received: '{0:?}'")]
    InvalidTypeY(ciborium::Value),
    #[error("Expected to parse a CBOR map, received: '{0:?}'")]
    NotAMap(ciborium::Value),
    #[error("Unable to discern the elliptic curve")]
    UnknownCurve,
    #[error("This implementation of COSE_Key only supports P-256, P-384, P-521, Ed25519 and Ed448 elliptic curves"
    )]
    UnsupportedCurve,
    #[error("This implementation of COSE_Key only supports EC2 and OKP keys")]
    UnsupportedKeyType,
    #[error("Could not reconstruct coordinates from the provided COSE_Key")]
    InvalidCoseKey,
    #[error("Constructing a JWK from CoseKey with point-compression is not supported.")]
    UnsupportedFormat,
    #[error("could not serialize from to cbor")]
    CborError,
}

impl CoseKey {
    /// Returns the signature algorithm associated with the key.
    pub fn signature_algorithm(&self) -> Option<Algorithm> {
        match self {
            CoseKey::EC2 {
                crv: EC2Curve::P256,
                ..
            } => Some(Algorithm::ES256),
            CoseKey::EC2 {
                crv: EC2Curve::P384,
                ..
            } => Some(Algorithm::ES384),
            CoseKey::EC2 {
                crv: EC2Curve::P521,
                ..
            } => Some(Algorithm::ES512),
            CoseKey::OKP {
                crv: OKPCurve::Ed448,
                ..
            } => Some(Algorithm::EdDSA),
            CoseKey::OKP {
                crv: OKPCurve::Ed25519,
                ..
            } => Some(Algorithm::EdDSA),
            _ => None,
        }
    }
}

impl From<CoseKey> for ciborium::Value {
    fn from(key: CoseKey) -> ciborium::Value {
        let mut map = vec![];
        match key {
            CoseKey::EC2 { crv, x, y } => {
                // kty: 1, EC2: 2
                map.push((
                    ciborium::Value::Integer(1.into()),
                    ciborium::Value::Integer(2.into()),
                ));
                // crv: -1
                map.push((ciborium::Value::Integer((-1).into()), {
                    let cbor: ciborium::Value = crv.into();
                    cbor
                }));
                // x: -2
                map.push((
                    ciborium::Value::Integer((-2).into()),
                    ciborium::Value::Bytes(x),
                ));
                // y: -3
                map.push((ciborium::Value::Integer((-3).into()), {
                    let cbor: ciborium::Value = y.into();
                    cbor
                }));
            }
            CoseKey::OKP { crv, x } => {
                // kty: 1, OKP: 1
                map.push((
                    ciborium::Value::Integer(1.into()),
                    ciborium::Value::Integer(1.into()),
                ));
                // crv: -1
                map.push((ciborium::Value::Integer((-1).into()), {
                    let cbor: ciborium::Value = crv.into();
                    cbor
                }));
                // x: -2
                map.push((
                    ciborium::Value::Integer((-2).into()),
                    ciborium::Value::Bytes(x),
                ));
            }
        }
        ciborium::Value::Map(map)
    }
}

impl TryFrom<ciborium::Value> for CoseKey {
    type Error = Error;

    fn try_from(v: ciborium::Value) -> Result<Self, Error> {
        if let ciborium::Value::Map(map) = v.clone() {
            let mut map: BTreeMap<i128, ciborium::Value> = map
                .into_iter()
                .map(|(k, v)| {
                    let k = k.into_integer().map_err(|_| Error::CborError)?.into();
                    Ok((k, v))
                })
                .collect::<Result<BTreeMap<_, _>, Error>>()?;
            match (map.remove(&1), map.remove(&-1), map.remove(&-2)) {
                (
                    Some(ciborium::Value::Integer(i2)),
                    Some(ciborium::Value::Integer(crv_id)),
                    Some(ciborium::Value::Bytes(x)),
                ) if <ciborium::value::Integer as Into<i128>>::into(i2) == 2 => {
                    let crv_id: i128 = crv_id.into();
                    let crv = crv_id.try_into()?;
                    let y = map.remove(&-3).ok_or(Error::EC2MissingY)?.try_into()?;
                    Ok(Self::EC2 { crv, x, y })
                }
                (
                    Some(ciborium::Value::Integer(i1)),
                    Some(ciborium::Value::Integer(crv_id)),
                    Some(ciborium::Value::Bytes(x)),
                ) if <ciborium::value::Integer as Into<i128>>::into(i1) == 1 => {
                    let crv_id: i128 = crv_id.into();
                    let crv = crv_id.try_into()?;
                    Ok(Self::OKP { crv, x })
                }
                _ => Err(Error::UnsupportedKeyType),
            }
        } else {
            Err(Error::NotAMap(v))
        }
    }
}

impl TryFrom<CoseKey> for EncodedPoint {
    type Error = Error;
    fn try_from(value: CoseKey) -> Result<EncodedPoint, Self::Error> {
        match value {
            CoseKey::EC2 {
                crv: EC2Curve::P256,
                x,
                y,
            } => match y {
                EC2Y::Value(y) => {
                    if x.len() != 32 || y.len() != 32 {
                        return Err(Error::InvalidCoseKey);
                    }
                    let mut bytes = Vec::with_capacity(65);
                    bytes.push(4);
                    bytes.extend_from_slice(&x);
                    bytes.extend_from_slice(&y);
                    EncodedPoint::from_bytes(bytes).map_err(|_| Error::InvalidCoseKey)
                }
                EC2Y::SignBit(y) => {
                    if x.len() != 32 {
                        return Err(Error::InvalidCoseKey);
                    }
                    let mut bytes = Vec::with_capacity(33);
                    if y {
                        bytes.push(3)
                    } else {
                        bytes.push(2)
                    }
                    bytes.extend_from_slice(&x);

                    EncodedPoint::from_bytes(bytes).map_err(|_| Error::InvalidCoseKey)
                }
            },
            _ => Err(Error::InvalidCoseKey),
        }
    }
}

impl From<EC2Y> for ciborium::Value {
    fn from(y: EC2Y) -> ciborium::Value {
        match y {
            EC2Y::Value(s) => ciborium::Value::Bytes(s),
            EC2Y::SignBit(b) => ciborium::Value::Bool(b),
        }
    }
}

impl TryFrom<ciborium::Value> for EC2Y {
    type Error = Error;

    fn try_from(v: ciborium::Value) -> Result<Self, Error> {
        match v {
            ciborium::Value::Bytes(s) => Ok(EC2Y::Value(s)),
            ciborium::Value::Bool(b) => Ok(EC2Y::SignBit(b)),
            _ => Err(Error::InvalidTypeY(v)),
        }
    }
}

impl From<EC2Curve> for ciborium::Value {
    fn from(crv: EC2Curve) -> ciborium::Value {
        match crv {
            EC2Curve::P256 => ciborium::Value::Integer(1.into()),
            EC2Curve::P384 => ciborium::Value::Integer(2.into()),
            EC2Curve::P521 => ciborium::Value::Integer(3.into()),
            EC2Curve::P256K => ciborium::Value::Integer(8.into()),
        }
    }
}

impl TryFrom<i128> for EC2Curve {
    type Error = Error;

    fn try_from(crv_id: i128) -> Result<Self, Error> {
        match crv_id {
            1 => Ok(EC2Curve::P256),
            2 => Ok(EC2Curve::P384),
            3 => Ok(EC2Curve::P521),
            8 => Ok(EC2Curve::P256K),
            _ => Err(Error::UnsupportedCurve),
        }
    }
}

impl From<OKPCurve> for ciborium::Value {
    fn from(crv: OKPCurve) -> ciborium::Value {
        match crv {
            OKPCurve::X25519 => ciborium::Value::Integer(4.into()),
            OKPCurve::X448 => ciborium::Value::Integer(5.into()),
            OKPCurve::Ed25519 => ciborium::Value::Integer(6.into()),
            OKPCurve::Ed448 => ciborium::Value::Integer(7.into()),
        }
    }
}

impl TryFrom<i128> for OKPCurve {
    type Error = Error;

    fn try_from(crv_id: i128) -> Result<Self, Error> {
        match crv_id {
            4 => Ok(OKPCurve::X25519),
            5 => Ok(OKPCurve::X448),
            6 => Ok(OKPCurve::Ed25519),
            7 => Ok(OKPCurve::Ed448),
            _ => Err(Error::UnsupportedCurve),
        }
    }
}

#[cfg(test)]
mod test {
    use hex::FromHex;

    use crate::cbor;

    use super::*;

    static EC_P256: &str = include_str!("../../../test/definitions/cose_key/ec_p256.cbor");

    #[test]
    fn ec_p256() {
        let key_bytes = <Vec<u8>>::from_hex(EC_P256).expect("unable to convert cbor hex to bytes");
        let key = crate::cbor::from_slice(&key_bytes).unwrap();
        match &key {
            CoseKey::EC2 { crv, .. } => assert_eq!(crv, &EC2Curve::P256),
            _ => panic!("expected an EC2 cose key"),
        };
        assert_eq!(
            cbor::to_vec(&key).unwrap(),
            key_bytes,
            "cbor encoding roundtrip failed"
        );
    }

    #[test]
    fn malformed_p256_coordinates_return_error_without_panicking() {
        let malformed = CoseKey::EC2 {
            crv: EC2Curve::P256,
            x: vec![1; 31],
            y: EC2Y::Value(vec![2; 32]),
        };

        assert_eq!(
            EncodedPoint::try_from(malformed).unwrap_err().to_string(),
            Error::InvalidCoseKey.to_string()
        );
    }

    #[test]
    fn okp_key_is_not_reinterpreted_as_a_p256_point() {
        let okp = CoseKey::OKP {
            crv: OKPCurve::Ed25519,
            x: vec![7; 32],
        };

        assert!(matches!(
            EncodedPoint::try_from(okp),
            Err(Error::InvalidCoseKey)
        ));
    }
}
