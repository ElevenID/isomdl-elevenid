use std::hint::black_box;
use std::time::Duration;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use isomdl::definitions::DigestAlgorithm;
use isomdl::digest_executor::{DigestExecutor, DigestJob, SerialDigestExecutor};

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

fn benchmark_digest_executor(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("digest_executor/scalar");
    for (name, algorithm) in [
        ("sha256", DigestAlgorithm::SHA256),
        ("sha384", DigestAlgorithm::SHA384),
        ("sha512", DigestAlgorithm::SHA512),
    ] {
        for job_count in JOB_COUNTS {
            let jobs = digest_jobs(job_count, algorithm);
            let total_bytes = jobs.iter().map(|job| job.input.len() as u64).sum();
            group.throughput(Throughput::Bytes(total_bytes));
            group.bench_with_input(BenchmarkId::new(name, job_count), &jobs, |bencher, jobs| {
                bencher.iter(|| {
                    black_box(
                        SerialDigestExecutor
                            .execute(black_box(jobs))
                            .expect("scalar digest execution must succeed"),
                    );
                });
            });
        }
    }
    group.finish();
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
