use der::Encode;
use ecdsa::{Signature, VerifyingKey};
use p256::NistP256;
use sha2::Digest;
use x509_cert::Certificate;

use crate::definitions::x509::util::public_key_with_oid;

/// Check that the issuer certificate signed the subject certificate.
pub fn issuer_signed_subject(subject: &Certificate, issuer: &Certificate) -> bool {
    // TODO: Support curves other than P-256.
    let issuer_public_key: VerifyingKey<NistP256> =
        match public_key_with_oid(issuer, const_oid::db::rfc5912::SECP_256_R_1) {
            Ok(pk) => pk,
            Err(e) => {
                tracing::error!("failed to decode issuer public key: {e:?}");
                return false;
            }
        };

    let sig: Signature<NistP256> = match Signature::from_der(subject.signature.raw_bytes()) {
        Ok(sig) => sig,
        Err(e) => {
            tracing::error!("failed to parse subject signature: {e:?}");
            return false;
        }
    };

    let tbs = match subject.tbs_certificate.to_der() {
        Ok(tbs) => tbs,
        Err(e) => {
            tracing::error!("failed to parse subject tbs: {e:?}");
            return false;
        }
    };

    let digest = sha2::Sha256::digest(&tbs);
    let z = match ecdsa::hazmat::bits2field::<NistP256>(&digest) {
        Ok(z) => z,
        Err(e) => {
            tracing::error!("failed to prepare certificate signature digest: {e:?}");
            return false;
        }
    };
    let public_point = p256::ProjectivePoint::from(*issuer_public_key.as_affine());
    match ecdsa::hazmat::verify_prehashed::<NistP256>(&public_point, &z, &sig) {
        Ok(()) => true,
        Err(e) => {
            tracing::info!("subject certificate signature could not be validated: {e:?}");
            false
        }
    }
}

#[cfg(test)]
mod test {
    use crate::definitions::x509::x5chain::CertificateWithDer;

    use super::issuer_signed_subject;

    #[test]
    pub fn correct_signature() {
        let target = include_bytes!("../../../../test/presentation/isomdl_iaca_signer.pem");
        let issuer = include_bytes!("../../../../test/presentation/isomdl_iaca_root_cert.pem");
        assert!(issuer_signed_subject(
            &CertificateWithDer::from_pem(target).unwrap().inner,
            &CertificateWithDer::from_pem(issuer).unwrap().inner,
        ))
    }

    #[test]
    pub fn incorrect_signature() {
        let issuer = include_bytes!("../../../../test/presentation/isomdl_iaca_signer.pem");
        let target = include_bytes!("../../../../test/presentation/isomdl_iaca_root_cert.pem");
        assert!(!issuer_signed_subject(
            &CertificateWithDer::from_pem(target).unwrap().inner,
            &CertificateWithDer::from_pem(issuer).unwrap().inner,
        ))
    }
}
