//! Execution boundary for independent credential digest jobs.
//!
//! Digest executors receive routing metadata and bytes to hash. Those bytes can
//! contain sensitive credential claims, but executors never receive signing
//! keys or signer handles. Callers must restore results by identity rather than
//! relying on the order in which results are returned.

#[cfg(all(feature = "simd", any(target_arch = "x86_64", target_arch = "aarch64")))]
use std::collections::BTreeMap;
use std::fmt;
#[cfg(feature = "parallel")]
use std::num::NonZeroUsize;
#[cfg(all(feature = "parallel", not(target_family = "wasm")))]
use std::panic::{catch_unwind, AssertUnwindSafe};
#[cfg(all(feature = "parallel", not(target_family = "wasm")))]
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex, OnceLock,
};

#[cfg(all(feature = "parallel", not(target_family = "wasm")))]
use rayon::prelude::*;
#[cfg(all(feature = "parallel", not(target_family = "wasm")))]
use rayon::{ThreadPool, ThreadPoolBuilder};
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
/// solely by `(credential_id, job_id)`. The mdoc batch API accepts distinct,
/// caller-assigned credential IDs before submitting several credentials in one
/// call. Callers can validate result identities and lengths, but validating
/// same-length digest contents would repeat the work; executors therefore
/// remain inside the issuer's trusted computing boundary.
pub trait DigestExecutor: Send + Sync {
    fn execute(&self, jobs: &[DigestJob]) -> Result<Vec<DigestResult>, DigestExecutionError>;
}

/// Normative scalar digest executor and oracle for optimized implementations.
#[derive(Clone, Copy, Debug, Default)]
pub struct SerialDigestExecutor;

impl DigestExecutor for SerialDigestExecutor {
    fn execute(&self, jobs: &[DigestJob]) -> Result<Vec<DigestResult>, DigestExecutionError> {
        Ok(jobs.iter().map(execute_digest_job).collect())
    }
}

/// Opt-in safe-SIMD executor for compatible SHA-256 digest groups.
///
/// On x86-64 and AArch64, complete groups of eight SHA-256 jobs with the same
/// padded block count use the owned SIMD lane implementation. Group remainders,
/// SHA-384, and SHA-512 use the exact scalar oracle. Unsupported targets,
/// including WebAssembly, use the scalar oracle for the complete call.
///
/// The default credential preparation APIs do not select this executor. A
/// caller must opt in through `prepare_with_digest_executor` after measuring
/// its own target and workload.
#[cfg(feature = "simd")]
#[derive(Clone, Copy, Debug, Default)]
pub struct SimdDigestExecutor;

#[cfg(feature = "simd")]
impl SimdDigestExecutor {
    /// Number of SHA-256 jobs in one SIMD group on a supported target.
    ///
    /// A value of one reports that this build uses only the scalar fallback.
    #[must_use]
    pub const fn sha256_lane_width() -> usize {
        if cfg!(any(target_arch = "x86_64", target_arch = "aarch64")) {
            8
        } else {
            1
        }
    }
}

#[cfg(feature = "simd")]
impl DigestExecutor for SimdDigestExecutor {
    fn execute(&self, jobs: &[DigestJob]) -> Result<Vec<DigestResult>, DigestExecutionError> {
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        {
            execute_simd_digest_jobs(jobs)
        }

        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            SerialDigestExecutor.execute(jobs)
        }
    }
}

#[cfg(all(feature = "simd", any(target_arch = "x86_64", target_arch = "aarch64")))]
fn execute_simd_digest_jobs(jobs: &[DigestJob]) -> Result<Vec<DigestResult>, DigestExecutionError> {
    let mut results = vec![None; jobs.len()];
    let mut sha256_groups = BTreeMap::<usize, Vec<usize>>::new();

    for (index, job) in jobs.iter().enumerate() {
        if job.algorithm == DigestAlgorithm::SHA256 {
            sha256_groups
                .entry(crate::simd_sha256::sha256_block_count(job.input.len()))
                .or_default()
                .push(index);
        } else {
            results[index] = Some(execute_digest_job(job));
        }
    }

    for indices in sha256_groups.values() {
        let simd_job_count = indices.len() / crate::simd_sha256::LANES * crate::simd_sha256::LANES;
        if simd_job_count != 0 {
            let inputs: Vec<&[u8]> = indices[..simd_job_count]
                .iter()
                .map(|&index| jobs[index].input.as_slice())
                .collect();
            let mut digests = vec![[0_u8; 32]; simd_job_count];
            if !crate::simd_sha256::hash_many_same_block_count(&inputs, &mut digests) {
                return Err(DigestExecutionError);
            }
            for (&index, digest) in indices[..simd_job_count].iter().zip(digests) {
                results[index] = Some(digest_result(&jobs[index], digest.to_vec()));
            }
        }

        for &index in &indices[simd_job_count..] {
            results[index] = Some(execute_digest_job(&jobs[index]));
        }
    }

    results
        .into_iter()
        .collect::<Option<Vec<_>>>()
        .ok_or(DigestExecutionError)
}

/// Maximum process-wide native pool size and per-call requested worker bound.
///
/// This is a resource-safety bound, not a performance threshold. Callers must
/// benchmark their target and workload before selecting parallel execution.
#[cfg(feature = "parallel")]
pub const MAX_PARALLEL_DIGEST_WORKERS: usize = 8;

/// Process-wide native-worker budget shared by every executor instance.
///
/// Contention falls back to the exact serial oracle instead of waiting or
/// admitting more pool work across concurrent credential preparations.
#[cfg(all(feature = "parallel", not(target_family = "wasm")))]
struct ParallelDigestWorkerBudget {
    available: AtomicUsize,
    capacity: usize,
}

#[cfg(all(feature = "parallel", not(target_family = "wasm")))]
impl ParallelDigestWorkerBudget {
    const fn new(capacity: usize) -> Self {
        Self {
            available: AtomicUsize::new(capacity),
            capacity,
        }
    }

    fn try_acquire(&self, worker_count: usize) -> Option<ParallelDigestWorkerLease<'_>> {
        if worker_count < 2 || worker_count > self.capacity {
            return None;
        }

        let mut available = self.available.load(Ordering::Acquire);
        loop {
            if available < worker_count {
                return None;
            }
            match self.available.compare_exchange_weak(
                available,
                available - worker_count,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Some(ParallelDigestWorkerLease {
                        budget: self,
                        worker_count,
                    });
                }
                Err(observed) => available = observed,
            }
        }
    }

    #[cfg(test)]
    fn available(&self) -> usize {
        self.available.load(Ordering::Acquire)
    }
}

#[cfg(all(feature = "parallel", not(target_family = "wasm")))]
struct ParallelDigestWorkerLease<'a> {
    budget: &'a ParallelDigestWorkerBudget,
    worker_count: usize,
}

#[cfg(all(feature = "parallel", not(target_family = "wasm")))]
impl Drop for ParallelDigestWorkerLease<'_> {
    fn drop(&mut self) {
        let previously_available = self
            .budget
            .available
            .fetch_add(self.worker_count, Ordering::Release);
        debug_assert!(
            previously_available <= self.budget.capacity - self.worker_count,
            "parallel digest worker budget over-release"
        );
    }
}

#[cfg(all(feature = "parallel", not(target_family = "wasm")))]
struct NativeDigestPool {
    threads: ThreadPool,
    budget: ParallelDigestWorkerBudget,
}

#[cfg(all(feature = "parallel", not(target_family = "wasm")))]
impl NativeDigestPool {
    fn new(worker_count: usize) -> Option<Self> {
        if worker_count == 0 || worker_count > MAX_PARALLEL_DIGEST_WORKERS {
            return None;
        }
        ThreadPoolBuilder::new()
            .num_threads(worker_count)
            .build()
            .ok()
            .map(|threads| Self {
                threads,
                budget: ParallelDigestWorkerBudget::new(worker_count),
            })
    }

    fn worker_count(&self) -> usize {
        self.threads.current_num_threads()
    }
}

#[cfg(all(feature = "parallel", not(target_family = "wasm")))]
fn get_or_initialize_native_digest_pool<'a>(
    pool_slot: &'a OnceLock<NativeDigestPool>,
    initialization_lock: &Mutex<()>,
    initialize: impl FnOnce() -> Option<NativeDigestPool>,
) -> Option<&'a NativeDigestPool> {
    if let Some(pool) = pool_slot.get() {
        return Some(pool);
    }

    let _initialization_guard = initialization_lock
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(pool) = pool_slot.get() {
        return Some(pool);
    }

    let pool = initialize()?;
    let _ = pool_slot.set(pool);
    pool_slot.get()
}

#[cfg(all(feature = "parallel", not(target_family = "wasm")))]
fn native_digest_pool() -> Option<&'static NativeDigestPool> {
    static POOL: OnceLock<NativeDigestPool> = OnceLock::new();
    static INITIALIZATION_LOCK: Mutex<()> = Mutex::new(());
    get_or_initialize_native_digest_pool(&POOL, &INITIALIZATION_LOCK, || {
        let worker_count = std::thread::available_parallelism()
            .map(NonZeroUsize::get)
            .unwrap_or(1)
            .min(MAX_PARALLEL_DIGEST_WORKERS);
        NativeDigestPool::new(worker_count)
    })
}

/// Opt-in bounded native executor for independent digest jobs.
///
/// The executor reuses one process-wide native worker pool, never retains input
/// or output buffers, and waits for each submitted operation to quiesce before
/// returning. A pool initialization failure leaves later calls free to retry. Under an
/// unwind panic profile, a worker panic discards all completed sibling results
/// and returns the same redacted [`DigestExecutionError`]; an abort profile
/// retains its process-abort semantics. On WebAssembly it uses the exact
/// serial oracle because native threads are not assumed to be available.
///
/// This executor is deliberately not used by `Mdoc::prepare` or
/// `Builder::prepare`. Callers must opt in through the existing
/// `prepare_with_digest_executor` boundary and keep the executor inside the
/// issuer's trusted process.
#[cfg(feature = "parallel")]
#[derive(Clone, Copy)]
pub struct NativeParallelDigestExecutor {
    worker_count: usize,
    #[cfg(test)]
    worker: DigestWorker,
}

#[cfg(feature = "parallel")]
type DigestWorker = fn(&DigestJob) -> DigestResult;

#[cfg(feature = "parallel")]
impl NativeParallelDigestExecutor {
    /// Create an executor with an explicit, bounded worker count.
    ///
    /// Values above [`MAX_PARALLEL_DIGEST_WORKERS`] are capped. A non-zero
    /// input keeps invalid zero-worker configurations out of the executor.
    #[must_use]
    pub fn new(worker_count: NonZeroUsize) -> Self {
        Self {
            worker_count: worker_count.get().min(MAX_PARALLEL_DIGEST_WORKERS),
            #[cfg(test)]
            worker: execute_digest_job,
        }
    }

    /// Create an executor bounded by the host's reported parallelism.
    #[must_use]
    pub fn available_parallelism() -> Self {
        #[cfg(target_family = "wasm")]
        let worker_count = NonZeroUsize::MIN;
        #[cfg(not(target_family = "wasm"))]
        let worker_count = std::thread::available_parallelism().unwrap_or(NonZeroUsize::MIN);

        Self::new(worker_count)
    }

    /// Return the configured worker bound after applying the safety cap.
    #[must_use]
    pub const fn worker_count(&self) -> usize {
        self.worker_count
    }

    #[cfg(test)]
    fn with_worker(worker_count: NonZeroUsize, worker: DigestWorker) -> Self {
        Self {
            worker_count: worker_count.get().min(MAX_PARALLEL_DIGEST_WORKERS),
            worker,
        }
    }

    fn worker(&self) -> DigestWorker {
        #[cfg(test)]
        {
            self.worker
        }
        #[cfg(not(test))]
        {
            execute_digest_job
        }
    }
}

#[cfg(feature = "parallel")]
impl Default for NativeParallelDigestExecutor {
    fn default() -> Self {
        Self::available_parallelism()
    }
}

#[cfg(feature = "parallel")]
impl fmt::Debug for NativeParallelDigestExecutor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeParallelDigestExecutor")
            .field("worker_count", &self.worker_count)
            .finish()
    }
}

#[cfg(feature = "parallel")]
impl DigestExecutor for NativeParallelDigestExecutor {
    fn execute(&self, jobs: &[DigestJob]) -> Result<Vec<DigestResult>, DigestExecutionError> {
        if jobs.len() < 2 || self.worker_count < 2 {
            return Ok(jobs.iter().map(self.worker()).collect());
        }

        #[cfg(target_family = "wasm")]
        {
            SerialDigestExecutor.execute(jobs)
        }

        #[cfg(not(target_family = "wasm"))]
        {
            let pool = native_digest_pool().ok_or(DigestExecutionError)?;
            self.execute_with_pool(jobs, pool)
        }
    }
}

#[cfg(all(feature = "parallel", not(target_family = "wasm")))]
impl NativeParallelDigestExecutor {
    fn execute_with_pool(
        &self,
        jobs: &[DigestJob],
        pool: &NativeDigestPool,
    ) -> Result<Vec<DigestResult>, DigestExecutionError> {
        let worker_count = self.worker_count.min(pool.worker_count()).min(jobs.len());
        let Some(lease) = pool.budget.try_acquire(worker_count) else {
            return Ok(jobs.iter().map(self.worker()).collect());
        };

        let chunk_size = static_chunk_size(jobs.len(), worker_count);
        let worker = self.worker();
        let result = catch_unwind(AssertUnwindSafe(|| {
            pool.threads.install(|| {
                jobs.par_chunks(chunk_size)
                    .flat_map_iter(|chunk| chunk.iter().map(worker))
                    .collect::<Vec<_>>()
            })
        }))
        .map_err(|_| DigestExecutionError)
        .and_then(|results| {
            if results.len() == jobs.len() {
                Ok(results)
            } else {
                Err(DigestExecutionError)
            }
        });
        drop(lease);
        result
    }
}

#[cfg(all(feature = "parallel", not(target_family = "wasm")))]
fn static_chunk_size(job_count: usize, worker_count: usize) -> usize {
    debug_assert_ne!(job_count, 0);
    debug_assert_ne!(worker_count, 0);
    job_count / worker_count + usize::from(!job_count.is_multiple_of(worker_count))
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

fn execute_digest_job(job: &DigestJob) -> DigestResult {
    digest_result(job, digest(job.algorithm, &job.input))
}

fn digest_result(job: &DigestJob, digest: Vec<u8>) -> DigestResult {
    debug_assert_eq!(digest.len(), digest_length(job.algorithm));
    DigestResult {
        credential_id: job.credential_id,
        job_id: job.job_id,
        ordinal: job.ordinal,
        digest,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "parallel")]
    use rand::seq::SliceRandom;
    #[cfg(feature = "parallel")]
    use rand::{rngs::StdRng, SeedableRng};
    #[cfg(all(feature = "parallel", not(target_family = "wasm")))]
    use std::{
        sync::{Arc, Barrier},
        thread,
    };

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

    #[cfg(any(feature = "parallel", feature = "simd"))]
    fn mixed_digest_jobs(job_count: usize) -> Vec<DigestJob> {
        const INPUT_LENGTHS: [usize; 15] = [
            0, 1, 55, 56, 63, 64, 65, 111, 112, 127, 128, 129, 255, 1_024, 4_096,
        ];
        const ALGORITHMS: [DigestAlgorithm; 3] = [
            DigestAlgorithm::SHA256,
            DigestAlgorithm::SHA384,
            DigestAlgorithm::SHA512,
        ];

        (0..job_count)
            .map(|ordinal| DigestJob {
                credential_id: 17 + (ordinal % 3) as u64,
                job_id: 10_000 + ordinal as u64,
                ordinal: job_count.saturating_sub(ordinal),
                algorithm: ALGORITHMS[ordinal % ALGORITHMS.len()],
                input: vec![(ordinal % 251) as u8; INPUT_LENGTHS[ordinal % INPUT_LENGTHS.len()]],
            })
            .collect()
    }

    #[cfg(feature = "parallel")]
    fn sorted_results(mut results: Vec<DigestResult>) -> Vec<DigestResult> {
        results.sort_by_key(|result| (result.credential_id, result.job_id, result.ordinal));
        results
    }

    #[cfg(feature = "simd")]
    #[test]
    fn simd_executor_matches_scalar_for_mixed_algorithms_and_block_boundaries() {
        for job_count in [0, 1, 2, 7, 8, 9, 31, 32, 33, 128, 512] {
            let mut jobs = mixed_digest_jobs(job_count);
            // Guarantee several full SHA-256 groups while retaining varied
            // lengths within one padded-block class.
            jobs.extend((0..24).map(|offset| DigestJob {
                credential_id: 91 + (offset % 3) as u64,
                job_id: 20_000 + offset as u64,
                ordinal: job_count + 24 - offset,
                algorithm: DigestAlgorithm::SHA256,
                input: vec![offset as u8; 256 + offset],
            }));
            let original_jobs = jobs.clone();

            let expected = SerialDigestExecutor.execute(&jobs).unwrap();
            let actual = SimdDigestExecutor.execute(&jobs).unwrap();

            assert_eq!(actual, expected);
            assert_eq!(jobs, original_jobs, "executor mutated its input jobs");
        }
    }

    #[cfg(feature = "simd")]
    #[test]
    fn simd_executor_preserves_caller_order_and_uses_scalar_fallbacks() {
        let mut jobs = Vec::new();
        for ordinal in 0..9 {
            jobs.push(DigestJob {
                credential_id: 3,
                job_id: 100 - ordinal as u64,
                ordinal,
                algorithm: DigestAlgorithm::SHA256,
                input: vec![ordinal as u8; 64 + ordinal],
            });
        }
        jobs.push(DigestJob {
            credential_id: 2,
            job_id: 7,
            ordinal: 99,
            algorithm: DigestAlgorithm::SHA384,
            input: b"sha-384 stays scalar".to_vec(),
        });
        jobs.push(DigestJob {
            credential_id: 1,
            job_id: 8,
            ordinal: 98,
            algorithm: DigestAlgorithm::SHA512,
            input: b"sha-512 stays scalar".to_vec(),
        });

        assert_eq!(
            SimdDigestExecutor.execute(&jobs).unwrap(),
            SerialDigestExecutor.execute(&jobs).unwrap()
        );
        assert_eq!(format!("{SimdDigestExecutor:?}"), "SimdDigestExecutor");
        assert_eq!(
            SimdDigestExecutor::sha256_lane_width(),
            if cfg!(any(target_arch = "x86_64", target_arch = "aarch64")) {
                8
            } else {
                1
            }
        );
    }

    #[cfg(feature = "parallel")]
    #[test]
    fn native_executor_matches_serial_for_mixed_algorithms_and_block_boundaries() {
        for job_count in [0, 1, 2, 3, 7, 8, 9, 32, 128, 512] {
            let jobs = mixed_digest_jobs(job_count);
            let original_jobs = jobs.clone();
            let serial = sorted_results(SerialDigestExecutor.execute(&jobs).unwrap());

            for workers in 1..=MAX_PARALLEL_DIGEST_WORKERS {
                let executor = NativeParallelDigestExecutor::new(
                    NonZeroUsize::new(workers).expect("worker count is non-zero"),
                );
                let parallel = sorted_results(executor.execute(&jobs).unwrap());
                assert_eq!(parallel, serial);
                assert_eq!(jobs, original_jobs, "executor mutated its input jobs");
            }
        }
    }

    #[cfg(feature = "parallel")]
    #[test]
    fn native_executor_is_independent_of_repeated_shuffled_schedules() {
        let mut jobs = mixed_digest_jobs(128);
        let expected = sorted_results(SerialDigestExecutor.execute(&jobs).unwrap());
        let mut rng = StdRng::seed_from_u64(0x4344_4c41_5343_4845);

        for round in 0..64 {
            jobs.shuffle(&mut rng);
            let workers = 2 + round % (MAX_PARALLEL_DIGEST_WORKERS - 1);
            let executor = NativeParallelDigestExecutor::new(NonZeroUsize::new(workers).unwrap());
            assert_eq!(
                sorted_results(executor.execute(&jobs).unwrap()),
                expected,
                "digest results changed in schedule round {round}"
            );
        }
    }

    #[cfg(feature = "parallel")]
    #[test]
    fn native_executor_caps_workers_and_redacts_debug_output() {
        let executor = NativeParallelDigestExecutor::new(NonZeroUsize::MAX);
        assert_eq!(executor.worker_count(), MAX_PARALLEL_DIGEST_WORKERS);
        assert_eq!(
            format!("{executor:?}"),
            format!(
                "NativeParallelDigestExecutor {{ worker_count: {MAX_PARALLEL_DIGEST_WORKERS} }}"
            )
        );
    }

    #[cfg(all(feature = "parallel", not(target_family = "wasm")))]
    #[test]
    fn concurrent_executor_calls_keep_overlapping_identities_isolated() {
        let executor = Arc::new(NativeParallelDigestExecutor::new(
            NonZeroUsize::new(4).unwrap(),
        ));
        let first_jobs = mixed_digest_jobs(128);
        let mut second_jobs = first_jobs.clone();
        for job in &mut second_jobs {
            job.input.push(0xa5);
        }
        let expected_first = sorted_results(SerialDigestExecutor.execute(&first_jobs).unwrap());
        let expected_second = sorted_results(SerialDigestExecutor.execute(&second_jobs).unwrap());

        let (first, second) = thread::scope(|scope| {
            let first_executor = Arc::clone(&executor);
            let first = scope.spawn(move || first_executor.execute(&first_jobs).unwrap());
            let second_executor = Arc::clone(&executor);
            let second = scope.spawn(move || second_executor.execute(&second_jobs).unwrap());
            (first.join().unwrap(), second.join().unwrap())
        });

        assert_eq!(sorted_results(first), expected_first);
        assert_eq!(sorted_results(second), expected_second);
    }

    #[cfg(all(feature = "parallel", not(target_family = "wasm")))]
    #[test]
    fn worker_panic_returns_the_redacted_error_and_leaves_the_pool_usable() {
        fn panic_worker(_job: &DigestJob) -> DigestResult {
            panic!("injected worker failure")
        }

        let jobs = mixed_digest_jobs(16);
        let worker_count = NonZeroUsize::new(4).unwrap();
        let pool = NativeDigestPool::new(worker_count.get()).expect("test pool must initialize");
        let panic_executor = NativeParallelDigestExecutor::with_worker(worker_count, panic_worker);
        let error = panic_executor
            .execute_with_pool(&jobs, &pool)
            .expect_err("native worker failures must fail closed");
        assert_eq!(error, DigestExecutionError);
        assert_eq!(error.to_string(), "digest execution failed");
        assert_eq!(pool.budget.available(), worker_count.get());

        let recovered = NativeParallelDigestExecutor::new(worker_count)
            .execute_with_pool(&jobs, &pool)
            .expect("the pool must remain usable after an unwind");
        assert_eq!(
            sorted_results(recovered),
            sorted_results(SerialDigestExecutor.execute(&jobs).unwrap())
        );
        assert_eq!(pool.budget.available(), worker_count.get());
    }

    #[cfg(all(feature = "parallel", not(target_family = "wasm")))]
    #[test]
    fn process_pool_is_reused_and_respects_the_worker_cap() {
        let first = native_digest_pool().expect("native pool must initialize");
        let second = native_digest_pool().expect("native pool must be reusable");
        assert!(std::ptr::eq(first, second));
        assert!((1..=MAX_PARALLEL_DIGEST_WORKERS).contains(&first.worker_count()));
        assert_eq!(first.budget.capacity, first.worker_count());
    }

    #[cfg(all(feature = "parallel", not(target_family = "wasm")))]
    #[test]
    fn failed_pool_initialization_is_retried() {
        let pool_slot = OnceLock::new();
        let initialization_lock = Mutex::new(());

        assert!(
            get_or_initialize_native_digest_pool(&pool_slot, &initialization_lock, || None,)
                .is_none()
        );

        let pool = get_or_initialize_native_digest_pool(&pool_slot, &initialization_lock, || {
            NativeDigestPool::new(2)
        })
        .expect("a later initialization attempt must be allowed to succeed");
        assert_eq!(pool.worker_count(), 2);
    }

    #[cfg(all(feature = "parallel", not(target_family = "wasm")))]
    static ACTIVE_ROUTE_WORKERS: AtomicUsize = AtomicUsize::new(0);
    #[cfg(all(feature = "parallel", not(target_family = "wasm")))]
    static MAX_ACTIVE_ROUTE_WORKERS: AtomicUsize = AtomicUsize::new(0);
    #[cfg(all(feature = "parallel", not(target_family = "wasm")))]
    static ACTIVE_ROUTE_BARRIER: OnceLock<Barrier> = OnceLock::new();

    #[cfg(all(feature = "parallel", not(target_family = "wasm")))]
    fn active_route_worker(job: &DigestJob) -> DigestResult {
        let active = ACTIVE_ROUTE_WORKERS.fetch_add(1, Ordering::AcqRel) + 1;
        MAX_ACTIVE_ROUTE_WORKERS.fetch_max(active, Ordering::AcqRel);
        ACTIVE_ROUTE_BARRIER
            .get()
            .expect("route barrier must be initialized")
            .wait();
        ACTIVE_ROUTE_WORKERS.fetch_sub(1, Ordering::AcqRel);
        execute_digest_job(job)
    }

    #[cfg(all(feature = "parallel", not(target_family = "wasm")))]
    #[test]
    fn local_pool_executes_with_exactly_the_requested_active_worker_bound() {
        const WORKERS: usize = 4;
        ACTIVE_ROUTE_WORKERS.store(0, Ordering::Release);
        MAX_ACTIVE_ROUTE_WORKERS.store(0, Ordering::Release);
        ACTIVE_ROUTE_BARRIER
            .set(Barrier::new(WORKERS))
            .expect("the route barrier is initialized once");

        let jobs = mixed_digest_jobs(WORKERS * 2);
        let pool = NativeDigestPool::new(WORKERS).expect("test pool must initialize");
        let executor = NativeParallelDigestExecutor::with_worker(
            NonZeroUsize::new(WORKERS).unwrap(),
            active_route_worker,
        );
        let actual = executor.execute_with_pool(&jobs, &pool).unwrap();

        assert_eq!(ACTIVE_ROUTE_WORKERS.load(Ordering::Acquire), 0);
        assert_eq!(MAX_ACTIVE_ROUTE_WORKERS.load(Ordering::Acquire), WORKERS);
        assert_eq!(
            sorted_results(actual),
            sorted_results(SerialDigestExecutor.execute(&jobs).unwrap())
        );
    }

    #[cfg(all(feature = "parallel", not(target_family = "wasm")))]
    static CALLER_ROUTE_JOBS: AtomicUsize = AtomicUsize::new(0);
    #[cfg(all(feature = "parallel", not(target_family = "wasm")))]
    static POOL_ROUTE_JOBS: AtomicUsize = AtomicUsize::new(0);

    #[cfg(all(feature = "parallel", not(target_family = "wasm")))]
    fn route_observing_worker(job: &DigestJob) -> DigestResult {
        if rayon::current_thread_index().is_some() {
            POOL_ROUTE_JOBS.fetch_add(1, Ordering::Relaxed);
        } else {
            CALLER_ROUTE_JOBS.fetch_add(1, Ordering::Relaxed);
        }
        execute_digest_job(job)
    }

    #[cfg(all(feature = "parallel", not(target_family = "wasm")))]
    #[test]
    fn exhausted_pool_budget_uses_caller_thread_fallback_then_recovers() {
        let worker_count = NonZeroUsize::new(2).unwrap();
        let pool = NativeDigestPool::new(worker_count.get()).expect("test pool must initialize");
        let executor =
            NativeParallelDigestExecutor::with_worker(worker_count, route_observing_worker);
        let jobs = mixed_digest_jobs(8);
        let expected = sorted_results(SerialDigestExecutor.execute(&jobs).unwrap());

        CALLER_ROUTE_JOBS.store(0, Ordering::Release);
        POOL_ROUTE_JOBS.store(0, Ordering::Release);
        let lease = pool
            .budget
            .try_acquire(worker_count.get())
            .expect("the test must exhaust the real pool budget");
        let contended = executor.execute_with_pool(&jobs, &pool).unwrap();
        assert_eq!(CALLER_ROUTE_JOBS.load(Ordering::Acquire), jobs.len());
        assert_eq!(POOL_ROUTE_JOBS.load(Ordering::Acquire), 0);
        assert_eq!(sorted_results(contended), expected);

        drop(lease);
        CALLER_ROUTE_JOBS.store(0, Ordering::Release);
        let admitted = executor.execute_with_pool(&jobs, &pool).unwrap();
        assert_eq!(CALLER_ROUTE_JOBS.load(Ordering::Acquire), 0);
        assert_eq!(POOL_ROUTE_JOBS.load(Ordering::Acquire), jobs.len());
        assert_eq!(sorted_results(admitted), expected);
    }

    #[cfg(all(feature = "parallel", not(target_family = "wasm")))]
    #[test]
    fn worker_budget_is_nonblocking_bounded_and_released() {
        let budget = ParallelDigestWorkerBudget::new(3);
        let first = budget.try_acquire(2).expect("two workers fit");
        assert_eq!(budget.available(), 1);
        assert!(budget.try_acquire(2).is_none());
        assert!(budget.try_acquire(1).is_none());

        drop(first);
        assert_eq!(budget.available(), 3);
        let all = budget.try_acquire(3).expect("the full budget was released");
        assert_eq!(budget.available(), 0);
        drop(all);
        assert_eq!(budget.available(), 3);
    }

    #[cfg(feature = "parallel")]
    #[test]
    fn one_worker_uses_the_exact_serial_fallback() {
        let jobs = mixed_digest_jobs(32);
        let serial = SerialDigestExecutor.execute(&jobs).unwrap();
        let executor = NativeParallelDigestExecutor::new(NonZeroUsize::MIN);
        assert_eq!(executor.execute(&jobs).unwrap(), serial);
    }
}
