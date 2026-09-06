use std::collections::BTreeMap;
use std::hint::black_box;
use std::time::Duration;

use ciborium::Value;
use coset::iana::Algorithm;
use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput};
use isomdl::definitions::device_key::cose_key::{CoseKey, EC2Curve, EC2Y};
use isomdl::definitions::{DeviceKeyInfo, DigestAlgorithm, ValidityInfo};
#[cfg(feature = "parallel")]
use isomdl::digest_executor::NativeParallelDigestExecutor;
use isomdl::digest_executor::{DigestExecutor, SerialDigestExecutor};
use isomdl::issuance::mdoc::{Mdoc, Namespaces};
use time::OffsetDateTime;

const ITEM_COUNTS: [usize; 5] = [1, 8, 32, 128, 512];

#[derive(Clone, Copy)]
enum PayloadClass {
    Small,
    Medium,
    Portrait,
    Mixed,
    Uniform256,
    Uniform4096,
    DigestHeavy,
}

#[derive(Clone)]
struct PrepareInput {
    doc_type: String,
    namespaces: Namespaces,
    validity_info: ValidityInfo,
    digest_algorithm: DigestAlgorithm,
    device_key_info: DeviceKeyInfo,
    enable_decoy_digests: bool,
}

impl PrepareInput {
    fn prepare(self) {
        black_box(
            Mdoc::prepare(
                self.doc_type,
                self.namespaces,
                self.validity_info,
                self.digest_algorithm,
                self.device_key_info,
                Algorithm::ES256,
                self.enable_decoy_digests,
            )
            .expect("benchmark fixture must prepare a valid mdoc"),
        );
    }

    fn prepare_with_digest_executor<E>(self, digest_executor: &E)
    where
        E: DigestExecutor,
    {
        black_box(
            Mdoc::prepare_with_digest_executor(
                self.doc_type,
                self.namespaces,
                self.validity_info,
                self.digest_algorithm,
                self.device_key_info,
                Algorithm::ES256,
                self.enable_decoy_digests,
                digest_executor,
            )
            .expect("benchmark fixture must prepare a valid mdoc"),
        );
    }
}

fn prepare_input(
    item_count: usize,
    payload_class: PayloadClass,
    digest_algorithm: DigestAlgorithm,
    enable_decoy_digests: bool,
) -> PrepareInput {
    let mut namespaces: Namespaces = BTreeMap::new();
    for ordinal in 0..item_count {
        let namespace = format!("org.example.bench.{:02}", ordinal % 4);
        namespaces.entry(namespace).or_default().insert(
            format!("element_{ordinal:04}"),
            payload(payload_class, ordinal),
        );
    }

    let signed = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
    let valid_from = OffsetDateTime::from_unix_timestamp(1_700_000_060).unwrap();
    let valid_until = OffsetDateTime::from_unix_timestamp(1_731_536_000).unwrap();
    let validity_info = ValidityInfo {
        signed,
        valid_from,
        valid_until,
        expected_update: None,
    };
    let device_key_info = DeviceKeyInfo {
        device_key: CoseKey::EC2 {
            crv: EC2Curve::P256,
            x: vec![0x11; 32],
            y: EC2Y::Value(vec![0x22; 32]),
        },
        key_authorizations: None,
        key_info: None,
    };

    PrepareInput {
        doc_type: "org.example.benchmark".to_owned(),
        namespaces,
        validity_info,
        digest_algorithm,
        device_key_info,
        enable_decoy_digests,
    }
}

fn payload(class: PayloadClass, ordinal: usize) -> Value {
    match class {
        PayloadClass::Small => Value::Text(format!("value-{ordinal:04}")),
        PayloadClass::Medium => Value::Map(vec![
            (
                Value::Text("label".to_owned()),
                Value::Text("m".repeat(256)),
            ),
            (
                Value::Text("active".to_owned()),
                Value::Bool(ordinal & 1 == 0),
            ),
            (
                Value::Text("ordinal".to_owned()),
                Value::Integer((ordinal as u64).into()),
            ),
        ]),
        PayloadClass::Portrait => Value::Bytes(vec![(ordinal % 251) as u8; 64 * 1024]),
        PayloadClass::Mixed => match ordinal % 4 {
            0 => Value::Text(format!("value-{ordinal:04}")),
            1 => Value::Bytes(vec![(ordinal % 251) as u8; 1024]),
            2 => Value::Array(vec![
                Value::Bool(true),
                Value::Integer((ordinal as u64).into()),
                Value::Text("mixed".repeat(16)),
            ]),
            _ => Value::Map(vec![
                (
                    Value::Text("nested".to_owned()),
                    Value::Text("payload".repeat(32)),
                ),
                (
                    Value::Text("ordinal".to_owned()),
                    Value::Integer((ordinal as u64).into()),
                ),
            ]),
        },
        PayloadClass::Uniform256 => Value::Bytes(vec![(ordinal % 251) as u8; 256]),
        PayloadClass::Uniform4096 => Value::Bytes(vec![(ordinal % 251) as u8; 4_096]),
        PayloadClass::DigestHeavy => {
            const INPUT_LENGTHS: [usize; 5] = [16, 64, 256, 1_024, 4_096];
            Value::Bytes(vec![
                (ordinal % 251) as u8;
                INPUT_LENGTHS[ordinal % INPUT_LENGTHS.len()]
            ])
        }
    }
}

fn benchmark_mdoc_prepare(criterion: &mut Criterion) {
    let mut scaling = criterion.benchmark_group("mdoc_prepare/items");
    scaling.throughput(Throughput::Elements(1));
    for enable_decoy_digests in [false, true] {
        let mode = if enable_decoy_digests {
            "decoys-on"
        } else {
            "decoys-off"
        };
        for item_count in ITEM_COUNTS {
            let input = prepare_input(
                item_count,
                PayloadClass::Mixed,
                DigestAlgorithm::SHA256,
                enable_decoy_digests,
            );
            scaling.bench_with_input(
                BenchmarkId::new(mode, item_count),
                &input,
                |bencher, input| {
                    bencher.iter_batched(
                        || input.clone(),
                        PrepareInput::prepare,
                        BatchSize::SmallInput,
                    );
                },
            );
        }
    }
    scaling.finish();

    let mut algorithms = criterion.benchmark_group("mdoc_prepare/algorithm");
    algorithms.throughput(Throughput::Elements(1));
    for (name, algorithm) in [
        ("sha256", DigestAlgorithm::SHA256),
        ("sha384", DigestAlgorithm::SHA384),
        ("sha512", DigestAlgorithm::SHA512),
    ] {
        let input = prepare_input(32, PayloadClass::Mixed, algorithm, false);
        algorithms.bench_with_input(BenchmarkId::new(name, 32), &input, |bencher, input| {
            bencher.iter_batched(
                || input.clone(),
                PrepareInput::prepare,
                BatchSize::SmallInput,
            );
        });
    }
    algorithms.finish();

    let mut payloads = criterion.benchmark_group("mdoc_prepare/payload");
    payloads.throughput(Throughput::Elements(1));
    for (name, payload_class) in [
        ("small", PayloadClass::Small),
        ("medium", PayloadClass::Medium),
        ("portrait-64k", PayloadClass::Portrait),
        ("mixed", PayloadClass::Mixed),
    ] {
        let input = prepare_input(32, payload_class, DigestAlgorithm::SHA256, false);
        payloads.bench_with_input(BenchmarkId::new(name, 32), &input, |bencher, input| {
            bencher.iter_batched(
                || input.clone(),
                PrepareInput::prepare,
                BatchSize::SmallInput,
            );
        });
    }
    payloads.finish();

    let mut adaptive = criterion.benchmark_group("mdoc_prepare/adaptive");
    adaptive.throughput(Throughput::Elements(1));
    for (name, payload_class, algorithm) in [
        (
            "uniform-256",
            PayloadClass::Uniform256,
            DigestAlgorithm::SHA256,
        ),
        (
            "uniform-4096",
            PayloadClass::Uniform4096,
            DigestAlgorithm::SHA256,
        ),
        (
            "uniform-4096-sha384",
            PayloadClass::Uniform4096,
            DigestAlgorithm::SHA384,
        ),
        (
            "uniform-4096-sha512",
            PayloadClass::Uniform4096,
            DigestAlgorithm::SHA512,
        ),
        (
            "digest-heavy",
            PayloadClass::DigestHeavy,
            DigestAlgorithm::SHA256,
        ),
    ] {
        let input = prepare_input(512, payload_class, algorithm, false);
        adaptive.bench_with_input(
            BenchmarkId::new(format!("serial-oracle-{name}"), 512),
            &input,
            |bencher, input| {
                bencher.iter_batched(
                    || input.clone(),
                    |input| input.prepare_with_digest_executor(&SerialDigestExecutor),
                    BatchSize::SmallInput,
                );
            },
        );
        adaptive.bench_with_input(
            BenchmarkId::new(format!("default-candidate-{name}"), 512),
            &input,
            |bencher, input| {
                bencher.iter_batched(
                    || input.clone(),
                    PrepareInput::prepare,
                    BatchSize::SmallInput,
                );
            },
        );
        #[cfg(feature = "parallel")]
        adaptive.bench_with_input(
            BenchmarkId::new(format!("native-4-{name}"), 512),
            &input,
            |bencher, input| {
                let executor =
                    NativeParallelDigestExecutor::new(std::num::NonZeroUsize::new(4).unwrap());
                bencher.iter_batched(
                    || input.clone(),
                    |input| input.prepare_with_digest_executor(&executor),
                    BatchSize::SmallInput,
                );
            },
        );
    }
    adaptive.finish();
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
    targets = benchmark_mdoc_prepare
}
criterion_main!(benches);
