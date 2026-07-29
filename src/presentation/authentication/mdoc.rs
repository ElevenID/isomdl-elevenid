use crate::cbor;
use crate::cose;
use crate::cose::sign1::VerificationResult;
use crate::definitions::device_response::Document;
use crate::definitions::issuer_signed;
use crate::definitions::session::SessionTranscript;
use crate::definitions::x509::X5Chain;
use crate::definitions::DeviceAuth;
use crate::definitions::Mso;
use crate::definitions::{device_signed::DeviceAuthentication, helpers::Tag24};
use crate::presentation::reader::Error;
use anyhow::Result;
use elliptic_curve::generic_array::GenericArray;
use issuer_signed::IssuerSigned;
use p256::ecdsa::Signature;
use p256::ecdsa::VerifyingKey;
use ssi_jwk::Params;
use ssi_jwk::JWK as SsiJwk;

pub fn issuer_authentication(x5chain: X5Chain, issuer_signed: &IssuerSigned) -> Result<(), Error> {
    let signer_key = x5chain
        .end_entity_public_key()
        .map_err(Error::IssuerPublicKey)?;
    let verification_result: cose::sign1::VerificationResult =
        issuer_signed
            .issuer_auth
            .verify::<VerifyingKey, Signature>(&signer_key, None, None);
    verification_result
        .into_result()
        .map_err(Error::IssuerAuthentication)
}

pub fn device_authentication<S>(document: &Document, session_transcript: S) -> Result<(), Error>
where
    S: SessionTranscript + Clone,
{
    let detached_payload = Tag24::new(DeviceAuthentication::new(
        session_transcript,
        document.doc_type.clone(),
        document.device_signed.namespaces.clone(),
    ))
    .map_err(|_| Error::CborDecodingError)?;
    let cbor_payload = cbor::to_vec(&detached_payload)?;
    verify_device_authentication_payload(document, &cbor_payload)
}

/// Verify device authentication while preserving the exact verifier transcript bytes.
///
/// ISO/IEC 18013-5 device authentication signs a detached CBOR payload. A
/// verifier must therefore embed the original session transcript encoding,
/// rather than decode and re-encode an equivalent CBOR value.
pub fn device_authentication_with_raw_session_transcript(
    document: &Document,
    session_transcript_cbor: &[u8],
) -> Result<(), Error> {
    let _: ciborium::Value =
        cbor::from_slice(session_transcript_cbor).map_err(|_| Error::CborDecodingError)?;
    let cbor_payload = raw_device_authentication_payload(
        session_transcript_cbor,
        &document.doc_type,
        &document.device_signed.namespaces,
    )?;
    verify_device_authentication_payload(document, &cbor_payload)
}

fn verify_device_authentication_payload(
    document: &Document,
    cbor_payload: &[u8],
) -> Result<(), Error> {
    let mso_bytes = document
        .issuer_signed
        .issuer_auth
        .payload
        .as_ref()
        .ok_or(Error::DetachedIssuerAuth)?;
    let mso: Tag24<Mso> = cbor::from_slice(mso_bytes).map_err(|_| Error::MSOParsing)?;
    let device_key = mso.into_inner().device_key_info.device_key;
    let jwk = SsiJwk::try_from(device_key)?;
    match jwk.params {
        Params::EC(p) => {
            let x_coordinate = p.x_coordinate.clone();
            let y_coordinate = p.y_coordinate.clone();
            let (Some(x), Some(y)) = (x_coordinate, y_coordinate) else {
                return Err(Error::MdocAuth(
                    "device key jwk is missing coordinates".to_string(),
                ));
            };
            let encoded_point = p256::EncodedPoint::from_affine_coordinates(
                GenericArray::from_slice(x.0.as_slice()),
                GenericArray::from_slice(y.0.as_slice()),
                false,
            );
            let verifying_key = VerifyingKey::from_encoded_point(&encoded_point)?;
            let device_auth: &DeviceAuth = &document.device_signed.device_auth;

            match device_auth {
                DeviceAuth::DeviceSignature(device_signature) => {
                    let external_aad = None;
                    let result = device_signature.verify::<VerifyingKey, Signature>(
                        &verifying_key,
                        Some(cbor_payload),
                        external_aad,
                    );
                    match result {
                        VerificationResult::Success => Ok(()),
                        VerificationResult::Failure(e) => Err(Error::MdocAuth(format!(
                            "failed verifying device signature: {e}"
                        ))),
                        VerificationResult::Error(e) => Err(Error::MdocAuth(format!(
                            "error verifying device signature: {e}"
                        ))),
                    }
                }
                DeviceAuth::DeviceMac(_) => {
                    Err(Error::Unsupported)
                    // send not yet supported error
                }
            }
        }
        _ => Err(Error::MdocAuth("Unsupported device_key type".to_string())),
    }
}

fn raw_device_authentication_payload(
    session_transcript_cbor: &[u8],
    doc_type: &str,
    namespaces: &crate::definitions::device_signed::DeviceNamespacesBytes,
) -> Result<Vec<u8>, Error> {
    let mut device_authentication = vec![0x84];
    device_authentication.extend(cbor::to_vec(&"DeviceAuthentication")?);
    device_authentication.extend_from_slice(session_transcript_cbor);
    device_authentication.extend(cbor::to_vec(&doc_type)?);
    device_authentication.extend(cbor::to_vec(namespaces)?);

    let mut tagged = vec![0xd8, 0x18];
    append_byte_string_header(&mut tagged, device_authentication.len());
    tagged.extend(device_authentication);
    Ok(tagged)
}

fn append_byte_string_header(output: &mut Vec<u8>, length: usize) {
    match length {
        0..=23 => output.push(0x40 | length as u8),
        24..=0xff => output.extend([0x58, length as u8]),
        0x100..=0xffff => {
            output.push(0x59);
            output.extend((length as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            output.push(0x5a);
            output.extend((length as u32).to_be_bytes());
        }
        _ => {
            output.push(0x5b);
            output.extend((length as u64).to_be_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn raw_payload_preserves_non_preferred_transcript_encoding() {
        // [null], with null encoded using the valid but non-preferred f8 16 form.
        let transcript = [0x81, 0xf8, 0x16];
        let namespaces = Tag24::new(BTreeMap::new()).unwrap();

        let payload =
            raw_device_authentication_payload(&transcript, "org.example.mdoc", &namespaces)
                .unwrap();

        assert!(payload
            .windows(transcript.len())
            .any(|window| window == transcript));
        assert_ne!(
            cbor::to_vec(
                &cbor::from_slice::<ciborium::Value>(&transcript)
                    .expect("non-preferred CBOR must decode")
            )
            .unwrap(),
            transcript
        );
    }

    #[test]
    fn raw_payload_matches_multipaz_device_authentication_encoding() {
        // Interoperability vector captured from the unmodified OIDF verifier
        // suite's Multipaz wallet at commit dee9a25160e789f0f80517674693ef7989ab9fa1.
        // Keeping the expected bytes here tests this crate without patching or
        // weakening the external compliance suite that exposed the defect.
        let transcript = hex::decode(
            "83f6f682714f70656e494434565048616e646f76657258208de8445cdf79e416\
             aa68efad62b314f1d837dc31d12518d3027a3684fd72ad0c",
        )
        .unwrap();
        let namespaces = Tag24::new(BTreeMap::new()).unwrap();

        let payload =
            raw_device_authentication_payload(&transcript, "org.iso.18013.5.1.mDL", &namespaces)
                .unwrap();

        assert_eq!(
            hex::encode(payload),
            concat!(
                "d8185868847444657669636541757468656e7469636174696f6e",
                "83f6f682714f70656e494434565048616e646f76657258208de8445cdf79e416",
                "aa68efad62b314f1d837dc31d12518d3027a3684fd72ad0c",
                "756f72672e69736f2e31383031332e352e312e6d444c",
                "d81841a0"
            )
        );
    }

    #[test]
    fn rustcrypto_accepts_multipaz_device_signature() {
        use p256::ecdsa::signature::Verifier as _;

        let x = hex::decode("83c9cec471e04ee83e23fd7bfa3bc287a439803c8f57c9798c4cce6bd4d129c5")
            .unwrap();
        let y = hex::decode("3399f39ebc77152e320108045355521527d183873b7fb6658b2ab6bd5a7f60af")
            .unwrap();
        let point = p256::EncodedPoint::from_affine_coordinates(
            GenericArray::from_slice(&x),
            GenericArray::from_slice(&y),
            false,
        );
        let key = VerifyingKey::from_encoded_point(&point).unwrap();
        let signature = Signature::from_slice(
            &hex::decode(
                "8e66dedf4886cdddd75698e30bceeaeb677d7a18a2049d374032264e87f3bb7a\
                 bfc6d67a732c69c5210667e8da4477a2805f1fcb40167e14f4502860b151c018",
            )
            .unwrap(),
        )
        .unwrap();
        let sig_structure = hex::decode(
            "846a5369676e61747572653143a1012640586cd818586884744465766963654175\
             7468656e7469636174696f6e83f6f682714f70656e494434565048616e646f7665\
             7258208de8445cdf79e416aa68efad62b314f1d837dc31d12518d3027a3684fd72\
             ad0c756f72672e69736f2e31383031332e352e312e6d444cd81841a0",
        )
        .unwrap();

        key.verify(&sig_structure, &signature).unwrap();
    }

    #[test]
    fn cose_verifier_accepts_multipaz_device_signature() {
        let x = hex::decode("83c9cec471e04ee83e23fd7bfa3bc287a439803c8f57c9798c4cce6bd4d129c5")
            .unwrap();
        let y = hex::decode("3399f39ebc77152e320108045355521527d183873b7fb6658b2ab6bd5a7f60af")
            .unwrap();
        let point = p256::EncodedPoint::from_affine_coordinates(
            GenericArray::from_slice(&x),
            GenericArray::from_slice(&y),
            false,
        );
        let key = VerifyingKey::from_encoded_point(&point).unwrap();
        let cose: crate::cose::MaybeTagged<coset::CoseSign1> = cbor::from_slice(
            &hex::decode(
                "8443a10126a0f658408e66dedf4886cdddd75698e30bceeaeb677d7a18a2049d37\
                 4032264e87f3bb7abfc6d67a732c69c5210667e8da4477a2805f1fcb40167e14\
                 f4502860b151c018",
            )
            .unwrap(),
        )
        .unwrap();
        let payload = hex::decode(
            "d8185868847444657669636541757468656e7469636174696f6e83f6f682714f70\
             656e494434565048616e646f76657258208de8445cdf79e416aa68efad62b314f\
             1d837dc31d12518d3027a3684fd72ad0c756f72672e69736f2e31383031332e35\
             2e312e6d444cd81841a0",
        )
        .unwrap();

        cose.verify::<VerifyingKey, Signature>(&key, Some(&payload), None)
            .into_result()
            .unwrap();
    }
}
