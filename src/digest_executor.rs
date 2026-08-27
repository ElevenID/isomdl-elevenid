//! Execution boundary for independent credential digest jobs.
//!
//! Digest executors receive routing metadata and bytes to hash. Those bytes can
//! contain sensitive credential claims, but executors never receive signing
//! keys or signer handles. Callers must restore results by identity rather than
//! relying on the order in which results are returned.

use std::fmt;

use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::definitions::DigestAlgorithm;

/// One independently executable digest operation.
#[derive(Clone, Eq, PartialEq)]
pub struct DigestJob {
    pub credential_id: u64,
    pub job_id: u64,
    pub ordinal: usize,
    pub algorithm: DigestAlgorithm,
    pub input: Vec<u8>,
}

impl fmt::Debug for DigestJob {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DigestJob")
            .field("metadata", &"[redacted]")
            .field("input", &"[redacted]")
            .finish()
    }
}

/// The identified output of a [`DigestJob`].
#[derive(Clone, Eq, PartialEq)]
pub struct DigestResult {
    pub credential_id: u64,
    pub job_id: u64,
    pub ordinal: usize,
    pub digest: Vec<u8>,
}

impl fmt::Debug for DigestResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DigestResult")
            .field("metadata", &"[redacted]")
            .field("digest", &"[redacted]")
            .finish()
    }
}

/// A fail-closed digest execution failure.
///
/// The error intentionally contains no job metadata or credential contents so
/// it is safe to propagate without exposing per-item information.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("digest execution failed")]
pub struct DigestExecutionError;

/// Executes a collection of independent digest jobs.
///
/// Implementations may return results in any order. A successful execution
/// must return exactly one correct result for every input job while preserving
/// `credential_id`, `job_id`, and `ordinal`. Implementations must not log job
/// inputs, digests, identities, worker assignments, or per-item timings.
///
/// Job identities are scoped to one `execute` call. An executor shared by
/// concurrent callers must isolate those calls and must not merge their jobs
/// solely by `(credential_id, job_id)`. A future batch API can assign distinct
/// credential IDs before submitting several credentials in one call. Callers
/// can validate result identities and lengths, but validating same-length
/// digest contents would repeat the work; executors therefore remain inside
/// the issuer's trusted computing boundary.
pub trait DigestExecutor: Send + Sync {
    fn execute(&self, jobs: &[DigestJob]) -> Result<Vec<DigestResult>, DigestExecutionError>;
}

/// Normative scalar digest executor and oracle for optimized implementations.
#[derive(Clone, Copy, Debug, Default)]
pub struct SerialDigestExecutor;

impl DigestExecutor for SerialDigestExecutor {
    fn execute(&self, jobs: &[DigestJob]) -> Result<Vec<DigestResult>, DigestExecutionError> {
        Ok(jobs
            .iter()
            .map(|job| {
                let digest = digest(job.algorithm, &job.input);
                debug_assert_eq!(digest.len(), digest_length(job.algorithm));
                DigestResult {
                    credential_id: job.credential_id,
                    job_id: job.job_id,
                    ordinal: job.ordinal,
                    digest,
                }
            })
            .collect())
    }
}

pub(crate) fn digest_length(algorithm: DigestAlgorithm) -> usize {
    match algorithm {
        DigestAlgorithm::SHA256 => 32,
        DigestAlgorithm::SHA384 => 48,
        DigestAlgorithm::SHA512 => 64,
    }
}

fn digest(algorithm: DigestAlgorithm, input: &[u8]) -> Vec<u8> {
    match algorithm {
        DigestAlgorithm::SHA256 => Sha256::digest(input).to_vec(),
        DigestAlgorithm::SHA384 => Sha384::digest(input).to_vec(),
        DigestAlgorithm::SHA512 => Sha512::digest(input).to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serial_executor_hashes_all_supported_algorithms_and_preserves_identity() {
        let jobs = [
            DigestJob {
                credential_id: 7,
                job_id: 11,
                ordinal: 2,
                algorithm: DigestAlgorithm::SHA256,
                input: b"abc".to_vec(),
            },
            DigestJob {
                credential_id: 7,
                job_id: 12,
                ordinal: 1,
                algorithm: DigestAlgorithm::SHA384,
                input: b"abc".to_vec(),
            },
            DigestJob {
                credential_id: 7,
                job_id: 13,
                ordinal: 0,
                algorithm: DigestAlgorithm::SHA512,
                input: b"abc".to_vec(),
            },
        ];

        let results = SerialDigestExecutor.execute(&jobs).unwrap();

        assert_eq!(results.len(), jobs.len());
        for (job, result) in jobs.iter().zip(&results) {
            assert_eq!(result.credential_id, job.credential_id);
            assert_eq!(result.job_id, job.job_id);
            assert_eq!(result.ordinal, job.ordinal);
            assert_eq!(result.digest.len(), digest_length(job.algorithm));
        }
        assert_eq!(
            hex::encode(&results[0].digest),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex::encode(&results[1].digest),
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
        );
        assert_eq!(
            hex::encode(&results[2].digest),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
    }

    #[test]
    fn serial_executor_accepts_an_empty_batch() {
        assert!(SerialDigestExecutor.execute(&[]).unwrap().is_empty());
    }

    #[test]
    fn debug_output_redacts_job_and_result_contents() {
        let job = DigestJob {
            credential_id: 4_294_967_291,
            job_id: 4_294_967_279,
            ordinal: 97,
            algorithm: DigestAlgorithm::SHA256,
            input: b"private-claim-value".to_vec(),
        };
        let result = SerialDigestExecutor
            .execute(std::slice::from_ref(&job))
            .unwrap()
            .pop()
            .unwrap();

        let job_debug = format!("{job:?}");
        let result_debug = format!("{result:?}");
        let digest_hex = hex::encode(&result.digest);
        for sensitive in [
            "private-claim-value",
            "4294967291",
            "4294967279",
            "97",
            digest_hex.as_str(),
        ] {
            assert!(!job_debug.contains(sensitive));
            assert!(!result_debug.contains(sensitive));
        }
    }
}
