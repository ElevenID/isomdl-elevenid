pub mod trust_anchor;
mod util;
pub mod validation;
pub mod x5chain;

pub use util::NamedCurve;
pub use x5chain::{Builder, X5Chain};

#[cfg(test)]
mod test {
    use std::time::Duration;

    use const_oid::ObjectIdentifier;
    use der::asn1::OctetString;
    use elliptic_curve::Generate;
    use p256::NistP256;
    use rand::random;
    use sha1::{Digest, Sha1};
    use signature::Signer;
    use signature_legacy::Keypair;
    use x509_cert::spki::EncodePublicKey;
    use x509_cert::{
        builder::{Builder, CertificateBuilder},
        ext::pkix::{
            crl::dp::DistributionPoint,
            name::{DistributionPointName, GeneralName},
            AuthorityKeyIdentifier, BasicConstraints, CrlDistributionPoints, ExtendedKeyUsage,
            IssuerAltName, KeyUsage, KeyUsages, SubjectKeyIdentifier,
        },
        name::Name,
        spki::{DynSignatureAlgorithmIdentifier, SubjectPublicKeyInfoOwned},
        time::Validity,
        Certificate,
    };

    use super::validation;

    // Test-only bridge between the existing X.509 builder's SPKI/signature
    // generation and the modern curve backend. DER bytes are unchanged.
    struct CertificateTestKey(p256::ecdsa::SigningKey);
    #[derive(Clone)]
    struct CertificateTestPublic(ecdsa::VerifyingKey<NistP256>);

    impl Keypair for CertificateTestKey {
        type VerifyingKey = CertificateTestPublic;
        fn verifying_key(&self) -> Self::VerifyingKey {
            CertificateTestPublic(*self.0.verifying_key())
        }
    }
    impl EncodePublicKey for CertificateTestPublic {
        fn to_public_key_der(&self) -> x509_cert::spki::Result<der::Document> {
            use p256::pkcs8::EncodePublicKey as _;
            let document = self
                .0
                .to_public_key_der()
                .map_err(|_| x509_cert::spki::Error::KeyMalformed)?;
            Ok(der::Document::try_from(document.as_bytes())?)
        }
    }
    impl DynSignatureAlgorithmIdentifier for CertificateTestKey {
        fn signature_algorithm_identifier(
            &self,
        ) -> x509_cert::spki::Result<x509_cert::spki::AlgorithmIdentifierOwned> {
            Ok(x509_cert::spki::AlgorithmIdentifierOwned {
                oid: ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2"),
                parameters: None,
            })
        }
    }
    impl CertificateTestKey {
        fn generate() -> Self {
            Self(p256::ecdsa::SigningKey::generate())
        }
        fn sign(&self, message: &[u8]) -> ecdsa::Signature<NistP256> {
            self.0.sign(message)
        }
    }

    fn prepare_root_certificate<S>(root_key: &S, issuer: Name) -> CertificateBuilder<'_, S>
    where
        S: Keypair + DynSignatureAlgorithmIdentifier,
        S::VerifyingKey: EncodePublicKey,
    {
        let spki = SubjectPublicKeyInfoOwned::from_key(root_key.verifying_key()).unwrap();
        let ski_digest = Sha1::digest(spki.subject_public_key.raw_bytes());
        let ski_digest_octet = OctetString::new(ski_digest.to_vec()).unwrap();

        let mut builder = CertificateBuilder::new(
            x509_cert::builder::Profile::Manual { issuer: None },
            random::<u64>().into(),
            Validity::from_now(Duration::from_secs(600)).unwrap(),
            issuer,
            spki,
            root_key,
        )
        .unwrap();

        builder
            .add_extension(&SubjectKeyIdentifier(ski_digest_octet))
            .unwrap();

        builder
            .add_extension(&KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign))
            .unwrap();

        builder
            .add_extension(&BasicConstraints {
                ca: true,
                path_len_constraint: Some(0),
            })
            .unwrap();

        builder
            .add_extension(&IssuerAltName(vec![GeneralName::Rfc822Name(
                "test@example.com".to_string().try_into().unwrap(),
            )]))
            .unwrap();

        builder
            .add_extension(&CrlDistributionPoints(vec![DistributionPoint {
                distribution_point: Some(DistributionPointName::FullName(vec![
                    GeneralName::UniformResourceIdentifier(
                        "http://example.com".to_string().try_into().unwrap(),
                    ),
                ])),
                reasons: None,
                crl_issuer: None,
            }]))
            .unwrap();

        builder
    }

    fn prepare_signer_certificate<'s, S>(
        signer_key: &'s S,
        root_key: &'s S,
        issuer: Name,
    ) -> CertificateBuilder<'s, S>
    where
        S: Keypair + DynSignatureAlgorithmIdentifier,
        S::VerifyingKey: EncodePublicKey,
    {
        let spki = SubjectPublicKeyInfoOwned::from_key(signer_key.verifying_key()).unwrap();
        let ski_digest = Sha1::digest(spki.subject_public_key.raw_bytes());
        let ski_digest_octet = OctetString::new(ski_digest.to_vec()).unwrap();

        let apki = SubjectPublicKeyInfoOwned::from_key(root_key.verifying_key()).unwrap();
        let aki_digest = Sha1::digest(apki.subject_public_key.raw_bytes());
        let aki_digest_octet = OctetString::new(aki_digest.to_vec()).unwrap();

        let mut builder = CertificateBuilder::new(
            x509_cert::builder::Profile::Manual {
                issuer: Some(issuer),
            },
            random::<u64>().into(),
            Validity::from_now(Duration::from_secs(600)).unwrap(),
            "CN=subject,C=US".parse().unwrap(),
            spki,
            root_key,
        )
        .unwrap();

        builder
            .add_extension(&SubjectKeyIdentifier(ski_digest_octet))
            .unwrap();

        builder
            .add_extension(&AuthorityKeyIdentifier {
                key_identifier: Some(aki_digest_octet),
                ..Default::default()
            })
            .unwrap();

        builder
            .add_extension(&KeyUsage(KeyUsages::DigitalSignature.into()))
            .unwrap();

        builder
            .add_extension(&IssuerAltName(vec![GeneralName::Rfc822Name(
                "test@example.com".to_string().try_into().unwrap(),
            )]))
            .unwrap();

        builder
            .add_extension(&CrlDistributionPoints(vec![DistributionPoint {
                distribution_point: Some(DistributionPointName::FullName(vec![
                    GeneralName::UniformResourceIdentifier(
                        "http://example.com".to_string().try_into().unwrap(),
                    ),
                ])),
                reasons: None,
                crl_issuer: None,
            }]))
            .unwrap();

        builder
            .add_extension(&ExtendedKeyUsage(vec![ObjectIdentifier::new_unwrap(
                "1.0.18013.5.1.2",
            )]))
            .unwrap();

        builder
    }

    fn setup() -> (Certificate, Certificate) {
        let root_key = CertificateTestKey::generate();
        let signer_key = CertificateTestKey::generate();

        let issuer: Name = "CN=issuer,C=US".parse().unwrap();

        let mut prepared_root_certificate = prepare_root_certificate(&root_key, issuer.clone());
        let signature: ecdsa::Signature<NistP256> =
            root_key.sign(&prepared_root_certificate.finalize().unwrap());
        let root_certificate: Certificate = prepared_root_certificate
            .assemble(der::asn1::BitString::from_bytes(signature.to_der().as_bytes()).unwrap())
            .unwrap();

        let mut prepared_signer_certificate =
            prepare_signer_certificate(&signer_key, &root_key, issuer.clone());
        let signature: ecdsa::Signature<NistP256> =
            root_key.sign(&prepared_signer_certificate.finalize().unwrap());
        let signer_certificate: Certificate = prepared_signer_certificate
            .assemble(der::asn1::BitString::from_bytes(signature.to_der().as_bytes()).unwrap())
            .unwrap();

        assert!(validation::signature::issuer_signed_subject(
            &signer_certificate,
            &root_certificate
        ));

        (root_certificate, signer_certificate)
    }

    mod iaca {
        use der::EncodePem;

        use crate::definitions::x509::{
            trust_anchor::{TrustAnchor, TrustAnchorRegistry, TrustPurpose},
            validation::ValidationRuleset,
            X5Chain,
        };

        #[test_log::test]
        fn valid_mdoc_issuer_certificate_chain_is_validated() {
            let (root, signer) = super::setup();

            tracing::debug!(
                "issuer certificate:\n{}",
                root.to_pem(Default::default()).unwrap()
            );
            tracing::debug!(
                "signer certificate:\n{}",
                signer.to_pem(Default::default()).unwrap()
            );

            let trust_anchor_registry = TrustAnchorRegistry {
                anchors: vec![TrustAnchor {
                    certificate: root,
                    purpose: TrustPurpose::Iaca,
                }],
            };
            let x5chain = X5Chain::builder()
                .with_certificate(signer)
                .unwrap()
                .build()
                .unwrap();
            let outcome = ValidationRuleset::Mdl.validate(&x5chain, &trust_anchor_registry);
            assert!(outcome.success(), "{outcome:?}");
        }
    }
}
