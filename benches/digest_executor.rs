use std::hint::black_box;
#[cfg(feature = "parallel")]
use std::num::NonZeroUsize;
use std::time::Duration;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use isomdl::definitions::DigestAlgorithm;
#[cfg(feature = "parallel")]
use isomdl::digest_executor::NativeParallelDigestExecutor;
use isomdl::digest_executor::{DigestExecutor, DigestJob, DigestResult, SerialDigestExecutor};

const JOB_COUNTS: [usize; 5] = [1, 8, 32, 128, 512];

fn digest_jobs(job_count: usize, algorithm: DigestAlgorithm) -> Vec<DigestJob> {
    const INPUT_LENGTHS: [usize; 5] = [16, 64, 256, 1024, 4096];

    (0..job_count)
        .map(|ordinal| {
            let input_length = INPUT_LENGTHS[ordinal % INPUT_LENGTHS.len()];
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
    for (name, algorithm) in [
        ("sha256", DigestAlgorithm::SHA256),
        ("sha384", DigestAlgorithm::SHA384),
        ("sha512", DigestAlgorithm::SHA512),
    ] {
        for job_count in JOB_COUNTS {
            let jobs = digest_jobs(job_count, algorithm);
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
