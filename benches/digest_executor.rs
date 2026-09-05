#[cfg(feature = "simd")]
use std::collections::BTreeMap;
use std::hint::black_box;
#[cfg(feature = "parallel")]
use std::num::NonZeroUsize;
use std::time::Duration;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use isomdl::definitions::DigestAlgorithm;
#[cfg(feature = "simd")]
use isomdl::digest_executor::SimdDigestExecutor;
#[cfg(feature = "parallel")]
use isomdl::digest_executor::{AdaptiveDigestExecutor, NativeParallelDigestExecutor};
use isomdl::digest_executor::{DigestExecutor, DigestJob, DigestResult, SerialDigestExecutor};

const JOB_COUNTS: [usize; 5] = [1, 8, 32, 128, 512];

#[derive(Clone, Copy)]
enum InputProfile {
    Mixed,
    Uniform256,
    Uniform1024,
    Uniform4096,
}

fn digest_jobs(
    job_count: usize,
    algorithm: DigestAlgorithm,
    profile: InputProfile,
) -> Vec<DigestJob> {
    const INPUT_LENGTHS: [usize; 5] = [16, 64, 256, 1024, 4096];

    (0..job_count)
        .map(|ordinal| {
            let input_length = match profile {
                InputProfile::Mixed => INPUT_LENGTHS[ordinal % INPUT_LENGTHS.len()],
                InputProfile::Uniform256 => 256,
                InputProfile::Uniform1024 => 1_024,
                InputProfile::Uniform4096 => 4_096,
            };
            DigestJob {
                credential_id: 0,
                job_id: ordinal as u64,
                ordinal,
                algorithm,
                input: vec![(ordinal % 251) as u8; input_length],
            }
        })
        .collect()
}

fn canonical_results(mut results: Vec<DigestResult>) -> Vec<DigestResult> {
    results.sort_by_key(|result| (result.credential_id, result.job_id, result.ordinal));
    results
}

fn assert_serial_equivalence<E>(executor: &E, jobs: &[DigestJob])
where
    E: DigestExecutor,
{
    let expected = canonical_results(
        SerialDigestExecutor
            .execute(jobs)
            .expect("scalar digest preflight must succeed"),
    );
    let actual = canonical_results(
        executor
            .execute(jobs)
            .expect("candidate digest preflight must succeed"),
    );
    assert_eq!(actual, expected, "candidate digest output changed");
}

fn benchmark_executor<E>(criterion: &mut Criterion, group_name: &str, executor: &E)
where
    E: DigestExecutor,
{
    let mut group = criterion.benchmark_group(group_name);
    for (name, algorithm, profile) in [
        ("sha256", DigestAlgorithm::SHA256, InputProfile::Mixed),
        (
            "sha256-uniform-256",
            DigestAlgorithm::SHA256,
            InputProfile::Uniform256,
        ),
        (
            "sha256-uniform-1024",
            DigestAlgorithm::SHA256,
            InputProfile::Uniform1024,
        ),
        (
            "sha256-uniform-4096",
            DigestAlgorithm::SHA256,
            InputProfile::Uniform4096,
        ),
        ("sha384", DigestAlgorithm::SHA384, InputProfile::Mixed),
        (
            "sha384-uniform-4096",
            DigestAlgorithm::SHA384,
            InputProfile::Uniform4096,
        ),
        ("sha512", DigestAlgorithm::SHA512, InputProfile::Mixed),
        (
            "sha512-uniform-4096",
            DigestAlgorithm::SHA512,
            InputProfile::Uniform4096,
        ),
    ] {
        for job_count in JOB_COUNTS {
            let jobs = digest_jobs(job_count, algorithm, profile);
            assert_serial_equivalence(executor, &jobs);
            let total_bytes = jobs.iter().map(|job| job.input.len() as u64).sum();
            group.throughput(Throughput::Bytes(total_bytes));
            group.bench_with_input(BenchmarkId::new(name, job_count), &jobs, |bencher, jobs| {
                bencher.iter(|| {
                    black_box(
                        executor
                            .execute(black_box(jobs))
                            .expect("digest execution must succeed"),
                    );
                });
            });
        }
    }
    group.finish();
}

#[cfg(feature = "simd")]
fn report_simd_coverage() {
    let lane_width = SimdDigestExecutor::sha256_lane_width();
    eprintln!("digest executor benchmark: SIMD SHA-256 logical lane width is {lane_width}");
    if lane_width == 1 {
        eprintln!("digest executor benchmark: this target uses the complete scalar fallback");
        return;
    }

    for (profile_name, profile) in [
        ("sha256", InputProfile::Mixed),
        ("sha256-uniform-256", InputProfile::Uniform256),
    ] {
        for job_count in JOB_COUNTS {
            let jobs = digest_jobs(job_count, DigestAlgorithm::SHA256, profile);
            let mut jobs_by_block_count = BTreeMap::<usize, usize>::new();
            for job in &jobs {
                let input_len = job.input.len();
                let block_count = input_len / 64 + usize::from(input_len % 64 >= 56) + 1;
                *jobs_by_block_count.entry(block_count).or_default() += 1;
            }
            let simd_jobs: usize = jobs_by_block_count
                .values()
                .map(|count| count / lane_width * lane_width)
                .sum();
            let simd_groups = simd_jobs / lane_width;
            let coverage = simd_jobs as f64 / job_count as f64 * 100.0;
            let lane_utilization = if simd_groups == 0 { "n/a" } else { "100%" };
            eprintln!(
                "digest executor benchmark: profile={profile_name} jobs={job_count} \
                 simd_groups={simd_groups} simd_job_coverage={coverage:.1}% \
                 dispatched_lane_utilization={lane_utilization}"
            );
        }
    }
}

fn benchmark_digest_executor(criterion: &mut Criterion) {
    benchmark_executor(criterion, "digest_executor/scalar", &SerialDigestExecutor);

    #[cfg(feature = "parallel")]
    {
        let requested_workers = NonZeroUsize::new(4).unwrap();
        let host_worker_bound = std::thread::available_parallelism()
            .map(NonZeroUsize::get)
            .unwrap_or(1)
            .min(requested_workers.get());
        eprintln!(
            "digest executor benchmark: requested up to 4 workers; host bound is {host_worker_bound}"
        );
        benchmark_executor(
            criterion,
            "digest_executor/native-up-to-4-workers",
            &NativeParallelDigestExecutor::new(requested_workers),
        );
        benchmark_executor(
            criterion,
            "digest_executor/adaptive",
            &AdaptiveDigestExecutor,
        );
    }

    #[cfg(feature = "simd")]
    {
        report_simd_coverage();
        benchmark_executor(criterion, "digest_executor/simd", &SimdDigestExecutor);
    }
}

fn criterion_config() -> Criterion {
    Criterion::default()
        .sample_size(50)
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(3))
        .significance_level(0.05)
        .noise_threshold(0.03)
}

criterion_group! {
    name = benches;
    config = criterion_config();
    targets = benchmark_digest_executor
}
criterion_main!(benches);
