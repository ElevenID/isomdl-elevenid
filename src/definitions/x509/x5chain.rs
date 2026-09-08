use std::io::Read;

use crate::definitions::helpers::NonEmptyVec;

use anyhow::{anyhow, bail, Context, Error, Result};

use const_oid::{AssociatedOid, ObjectIdentifier};

use ciborium::Value as CborValue;
use ecdsa::{PrimeCurve, VerifyingKey};
use elliptic_curve::{
    sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint},
    AffinePoint, CurveArithmetic, FieldBytesSize,
};
use x509_cert::der::Encode;
use x509_cert::{certificate::Certificate, der::Decode};

use super::util::{common_name_or_unknown, public_key};

/// See: <https://www.iana.org/assignments/cose/cose.xhtml#header-parameters>
pub const X5CHAIN_COSE_HEADER_LABEL: i64 = 0x21;

/// X.509 certificate with the DER representation held in memory for ease of serialization.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CertificateWithDer {
    pub inner: Certificate,
    der: Vec<u8>,
}

impl CertificateWithDer {
    pub fn from_pem(bytes: &[u8]) -> Result<Self> {
        let bytes = pem_rfc7468::decode_vec(bytes)
            .map_err(|e| anyhow!("unable to parse certificate from PEM encoding: {e}"))?
            .1;
        CertificateWithDer::from_der(&bytes)
    }

    pub fn from_der(bytes: &[u8]) -> Result<Self> {
        let inner = Certificate::from_der(bytes)
            .context("unable to parse certificate from DER encoding")?;
        Ok(Self {
            inner,
            der: bytes.to_vec(),
        })
    }

    pub fn from_cert(certificate: Certificate) -> Result<Self> {
        let der = certificate.to_der()?;
        Ok(Self {
            inner: certificate,
            der,
        })
    }
}

#[derive(Debug, Clone)]
pub struct X5Chain(NonEmptyVec<CertificateWithDer>);

impl From<NonEmptyVec<CertificateWithDer>> for X5Chain {
    fn from(v: NonEmptyVec<CertificateWithDer>) -> Self {
        Self(v)
    }
}

impl X5Chain {
    pub fn builder() -> Builder {
        Builder::default()
    }

    pub fn into_cbor(&self) -> CborValue {
        match &self.0.as_ref() {
            &[cert] => CborValue::Bytes(cert.der.clone()),
            certs => CborValue::Array(
                certs
                    .iter()
                    .map(|x509| x509.der.clone())
                    .map(CborValue::Bytes)
                    .collect::<Vec<CborValue>>(),
            ),
        }
    }

    pub fn from_cbor(cbor: CborValue) -> Result<Self, Error> {
        match cbor {
            CborValue::Bytes(bytes) => {
                Self::builder().with_der_certificate(&bytes)?.build()
            },
            CborValue::Array(x509s) => {
                x509s.iter()
                    .try_fold(Self::builder(), |mut builder, x509| match x509 {
                        CborValue::Bytes(bytes) => {
                            builder = builder.with_der_certificate(bytes)?;
                            Ok(builder)
                        },
                        _ => bail!("expected x509 certificate in the x5chain to be a cbor encoded bytestring, but received: {x509:?}")
                    })?
                    .build()
            },
            _ => bail!("expected x5chain to be a cbor encoded bytestring or array, but received: {cbor:?}")
        }
    }

    /// Retrieve the end-entity certificate.
    pub fn end_entity_certificate(&self) -> &Certificate {
        &self.0[0].inner
    }

    /// Retrieve the public key of the end-entity certificate.
    pub fn end_entity_public_key<C>(&self) -> Result<VerifyingKey<C>, Error>
    where
        C: AssociatedOid + CurveArithmetic + PrimeCurve,
        AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
        FieldBytesSize<C>: ModulusSize,
    {
        public_key(self.end_entity_certificate())
    }

    pub(crate) fn end_entity_public_key_with_oid<C>(
        &self,
        expected_curve_oid: ObjectIdentifier,
    ) -> Result<VerifyingKey<C>, Error>
    where
        C: CurveArithmetic + PrimeCurve,
        AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
        FieldBytesSize<C>: ModulusSize,
    {
        super::util::public_key_with_oid(self.end_entity_certificate(), expected_curve_oid)
    }

    /// Retrieve the public key of the end-entity certificate.
    pub fn end_entity_common_name(&self) -> &str {
        common_name_or_unknown(self.end_entity_certificate())
    }
}

#[derive(Default, Debug, Clone)]
pub struct Builder {
    certs: Vec<CertificateWithDer>,
}

impl Builder {
    pub fn with_certificate(mut self, cert: Certificate) -> Result<Builder> {
        let x509 = CertificateWithDer::from_cert(cert)?;
        self.certs.push(x509);
        Ok(self)
    }
    pub fn with_certificate_and_der(mut self, x509: CertificateWithDer) -> Builder {
        self.certs.push(x509);
        self
    }
    pub fn with_pem_certificate(mut self, data: &[u8]) -> Result<Builder> {
        let x509 = CertificateWithDer::from_pem(data)?;
        self.certs.push(x509);
        Ok(self)
    }
    pub fn with_der_certificate(mut self, data: &[u8]) -> Result<Builder> {
        let x509 = CertificateWithDer::from_der(data)?;
        self.certs.push(x509);
        Ok(self)
    }
    pub fn with_pem_certificate_from_io<R: Read>(self, mut io: R) -> Result<Builder> {
        let mut data: Vec<u8> = vec![];
        io.read_to_end(&mut data)?;
        self.with_pem_certificate(&data)
    }
    pub fn with_der_certificate_from_io<R: Read>(self, mut io: R) -> Result<Builder> {
        let mut data: Vec<u8> = vec![];
        io.read_to_end(&mut data)?;
        self.with_der_certificate(&data)
    }
    pub fn build(self) -> Result<X5Chain> {
        Ok(X5Chain(self.certs.try_into().context(
            "at least one certificate must be given to the builder",
        )?))
    }
}

#[cfg(test)]
pub mod test {
    use super::*;

    static CERT_256: &[u8] = include_bytes!("../../../test/issuance/256-cert.pem");
    static CERT_384: &[u8] = include_bytes!("../../../test/issuance/384-cert.pem");
    #[cfg(feature = "issuer-planning")]
    static CERT_521: &[u8] = include_bytes!("../../../test/issuance/521-cert.pem");

    #[test]
    pub fn self_signed_es256() {
        let x5chain = X5Chain::builder()
            .with_pem_certificate(CERT_256)
            .expect("unable to add cert")
            .build()
            .expect("unable to build x5chain");
        x5chain
            .end_entity_public_key::<p256::NistP256>()
            .expect("unable to decode P-256 public point");
    }

    #[test]
    fn preserves_the_existing_associated_oid_generic_bound() {
        fn decode_with_existing_bound<C>(x5chain: &X5Chain) -> Result<VerifyingKey<C>, Error>
        where
            C: const_oid::AssociatedOid + CurveArithmetic + PrimeCurve,
            AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
            FieldBytesSize<C>: ModulusSize,
        {
            x5chain.end_entity_public_key::<C>()
        }

        let x5chain = X5Chain::builder()
            .with_pem_certificate(CERT_256)
            .expect("unable to add cert")
            .build()
            .expect("unable to build x5chain");
        decode_with_existing_bound::<p256::NistP256>(&x5chain)
            .expect("the established AssociatedOid wrapper remains compatible");
    }

    #[test]
    pub fn self_signed_es384() {
        let x5chain = X5Chain::builder()
            .with_pem_certificate(CERT_384)
            .expect("unable to add cert")
            .build()
            .expect("unable to build x5chain");
        x5chain
            .end_entity_public_key::<p384::NistP384>()
            .expect("unable to decode P-384 public point");
    }

    #[cfg(feature = "issuer-planning")]
    #[test]
    pub fn self_signed_es512() {
        let x5chain = X5Chain::builder()
            .with_pem_certificate(CERT_521)
            .expect("unable to add cert")
            .build()
            .expect("unable to build x5chain");
        x5chain
            .end_entity_public_key::<p521::NistP521>()
            .expect("unable to decode P-521 public point");
    }

    #[test]
    fn rejects_public_point_when_named_curve_does_not_match() {
        let x5chain = X5Chain::builder()
            .with_pem_certificate(CERT_256)
            .expect("unable to add cert")
            .build()
            .expect("unable to build x5chain");
        let error = x5chain
            .end_entity_public_key::<p384::NistP384>()
            .expect_err("P-256 certificate must not decode as P-384");
        assert_eq!(
            error.to_string(),
            "certificate EC public key uses an unexpected named curve"
        );
    }

    #[test]
    fn rejects_certificate_public_point_with_unused_bits() {
        use der::asn1::BitString;

        let x5chain = X5Chain::builder()
            .with_pem_certificate(CERT_256)
            .expect("unable to add cert")
            .build()
            .expect("unable to build x5chain");
        let mut certificate = x5chain.end_entity_certificate().clone();
        let mut point = certificate
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes()
            .to_vec();
        *point.last_mut().expect("non-empty SEC1 point") &= 0xfe;
        certificate
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key = BitString::new(1, point).expect("one-unused-bit public point");
        let malformed = X5Chain::builder()
            .with_certificate(certificate)
            .expect("encode malformed test certificate")
            .build()
            .expect("build malformed test chain");

        let error = malformed
            .end_entity_public_key_with_oid::<p256::NistP256>(const_oid::db::rfc5912::SECP_256_R_1)
            .expect_err("non-canonical BIT STRING must fail before point decoding");
        assert_eq!(
            error.to_string(),
            "certificate EC public key BIT STRING has unused bits"
        );
    }
}
