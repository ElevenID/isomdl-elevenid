use anyhow::{bail, Context, Error};
use const_oid::{
    db::{rfc4519::COMMON_NAME, rfc5912::ID_EC_PUBLIC_KEY},
    AssociatedOid, ObjectIdentifier,
};
use der::{
    asn1::{Ia5StringRef, PrintableStringRef, TeletexStringRef, Utf8StringRef},
    Tag, Tagged,
};
use ecdsa::{PrimeCurve, VerifyingKey};
use elliptic_curve::{
    sec1::{FromEncodedPoint, ToEncodedPoint},
    AffinePoint, CurveArithmetic, FieldBytesSize, PublicKey,
};
use sec1::point::ModulusSize;
use x509_cert::{attr::AttributeValue, Certificate};

/// Get the public key from a certificate for verification.
pub fn public_key<C>(certificate: &Certificate) -> Result<VerifyingKey<C>, Error>
where
    C: AssociatedOid + CurveArithmetic + PrimeCurve,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: ModulusSize,
{
    public_key_with_oid(certificate, <C as AssociatedOid>::OID)
}

pub(crate) fn public_key_with_oid<C>(
    certificate: &Certificate,
    expected_curve_oid: ObjectIdentifier,
) -> Result<VerifyingKey<C>, Error>
where
    C: CurveArithmetic + PrimeCurve,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: ModulusSize,
{
    let spki = &certificate.tbs_certificate.subject_public_key_info;
    if spki.algorithm.oid != ID_EC_PUBLIC_KEY {
        bail!("certificate public key algorithm is not id-ecPublicKey");
    }

    let curve_oid = spki
        .algorithm
        .parameters
        .as_ref()
        .context("certificate EC public key is missing named-curve parameters")?
        .decode_as::<ObjectIdentifier>()
        .context("certificate EC public key parameters are not a named-curve OID")?;
    if curve_oid != expected_curve_oid {
        bail!("certificate EC public key uses an unexpected named curve");
    }

    PublicKey::<C>::from_sec1_bytes(spki.subject_public_key.raw_bytes())
        .map(Into::into)
        .context("could not parse certificate SEC1 public key")
}

/// Get the first CommonName of the X.509 certificate, or return "Unknown".
pub fn common_name_or_unknown(certificate: &Certificate) -> &str {
    common_name(certificate).unwrap_or("Unknown")
}

fn common_name(certificate: &Certificate) -> Option<&str> {
    certificate
        .tbs_certificate
        .subject
        .0
        .iter()
        .flat_map(|rdn| rdn.0.iter())
        .filter_map(|attribute| {
            if attribute.oid == COMMON_NAME {
                attribute_value_to_str(&attribute.value)
            } else {
                None
            }
        })
        .next()
}

pub fn attribute_value_to_str(av: &AttributeValue) -> Option<&str> {
    match av.tag() {
        Tag::PrintableString => PrintableStringRef::try_from(av).ok().map(|s| s.as_str()),
        Tag::Utf8String => Utf8StringRef::try_from(av).ok().map(|s| s.as_str()),
        Tag::Ia5String => Ia5StringRef::try_from(av).ok().map(|s| s.as_str()),
        Tag::TeletexString => TeletexStringRef::try_from(av).ok().map(|s| s.as_str()),
        _ => None,
    }
}
