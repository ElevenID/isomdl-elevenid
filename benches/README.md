# Digest-lane benchmarks

`mdoc_prepare` measures the public `Mdoc::prepare` boundary. It covers 1, 8,
32, 128, and 512 items; decoys off/on; SHA-256/384/512; and small, medium,
64 KiB portrait, and mixed payloads. It also includes 512-item uniform-256,
digest-heavy, and uniform-4096 cells around the adaptive byte gate. Fixture
cloning is outside the timed region, and benchmark identifiers contain only
aggregate labels.

Hosted CI runs `cargo test --benches --all-features` as a compile and smoke
gate. Do not use wall-clock thresholds on shared CI runners.

For a revision comparison, use the same idle machine. Keep Cargo build
targets separate so equal package names and versions cannot reuse another
worktree's library artifact. Share only Criterion's measurement directory. If
the comparison base predates `mdoc_prepare`, create a detached worktree at the
base and cherry-pick only the commit that introduced that harness:

```powershell
$baselineWorktree = "C:\tmp\isomdl-cdla-baseline"
$baseCommit = "origin/main"
$harnessCommit = git log --diff-filter=A --format="%H" -- benches/mdoc_prepare.rs |
    Select-Object -First 1
git worktree add --detach $baselineWorktree $baseCommit
git -C $baselineWorktree cherry-pick $harnessCommit

$env:CRITERION_HOME = "C:\tmp\isomdl-cdla-criterion"

# Run from the baseline worktree first.
$env:CARGO_TARGET_DIR = "C:\tmp\isomdl-cdla-baseline-target"
cargo bench --manifest-path "$baselineWorktree\Cargo.toml" --bench mdoc_prepare -- --save-baseline main --verbose

# Run from the feature worktree second.
$env:CARGO_TARGET_DIR = "C:\tmp\isomdl-cdla-feature-target"
cargo bench --bench mdoc_prepare -- --baseline main --verbose

git worktree remove --force $baselineWorktree
```

Skip the worktree bootstrap when the comparison base already contains
`mdoc_prepare`. The harness-only baseline commit must not contain production
changes.

That historical workflow compares only fixture IDs whose construction is
identical on both revisions. It does not qualify the new adaptive cells unless
the same current harness is applied unchanged to both trees. The adaptive mdoc
group instead compares an explicit serial oracle, the default candidate, and
forced native execution in the same feature-enabled binary. Repeat its serial
and default filters in reverse order.

The equivalent POSIX-shell procedure is:

```sh
baseline_worktree=/tmp/isomdl-cdla-baseline
base_commit=origin/main
harness_commit=$(git log --diff-filter=A --format=%H -- benches/mdoc_prepare.rs | head -n 1)
git worktree add --detach "$baseline_worktree" "$base_commit"
git -C "$baseline_worktree" cherry-pick "$harness_commit"

export CRITERION_HOME=/tmp/isomdl-cdla-criterion
CARGO_TARGET_DIR=/tmp/isomdl-cdla-baseline-target \
  cargo bench --manifest-path "$baseline_worktree/Cargo.toml" \
  --bench mdoc_prepare -- --save-baseline main --verbose
CARGO_TARGET_DIR=/tmp/isomdl-cdla-feature-target \
  cargo bench --bench mdoc_prepare -- --baseline main --verbose

git worktree remove --force "$baseline_worktree"
```

Record the median, 95% confidence interval, and relevant throughput in the
review record: credentials per second for mdoc and bytes per second for the
digest executor. Treat a result as a regression when the entire 95% change
interval is more than 5% slower, then repeat once before accepting or repairing
it. Do not commit machine-specific Criterion output or claim a speedup when a
reverse-order repeat contradicts the first run.

These crate-level targets are proof-boundary regression gates; they do not by
themselves complete the CDLA performance report. Criterion's timed estimates
report total elapsed time and throughput here, not separate planning, encoding,
assembly, signing, or allocation measurements. The digest harness additionally
prints deterministic SIMD coverage and lane occupancy for its synthetic input
matrix. The 512-item and 64 KiB portrait cases expose scaling, while stage and
allocation metrics must be captured by the later service/batch harness before
expanding the adaptive thresholds or enabling `parallel` in a deployment.

`digest_executor` isolates hashing from mdoc planning and assembly. It measures
1, 8, 32, 128, and 512 mixed-size inputs for SHA-256/384/512 and reports byte
throughput. Uniform 256-byte and 1024-byte SHA-256 profiles remain below the
adaptive byte gate; uniform 4096-byte SHA-256/384/512 profiles reach its 2 MiB
floor at 512 jobs. These profiles also provide complete SIMD groups. Default
builds contain only the scalar oracle. With `parallel`, the same process also
measures the explicit native executor and the production adaptive selector.
The benchmark prints the host-derived bound; a one-job cell
deliberately takes the scalar branch, and a constrained host can use fewer
workers or only the scalar fallback. The process-wide pool is initialized
during benchmark preflight and reused across samples, so measured work includes
dispatch and synchronization without repeatedly measuring thread creation.
Every fixture is checked against the scalar oracle before timing.

With the `simd` feature, the process additionally measures the caller-selected
`SimdDigestExecutor`. On x86-64 and AArch64 it groups SHA-256 jobs by padded
message-block count and dispatches only complete groups of eight logical lanes;
group remainders, SHA-384, and SHA-512 remain scalar. Unsupported targets report
a lane width of one and use the scalar executor for the complete call. The
benchmark prints aggregate group count, the percentage of jobs dispatched to
SIMD, and dispatched-lane utilization for each SHA-256 fixture. Because partial
groups stay scalar, every dispatched group is 100% occupied. These labels and
metrics describe synthetic fixtures only and contain no credential data.

The generic x86-64 build uses the dependency's SSE2 representation; AVX2 is a
compile-time choice rather than runtime dispatch. Do not distribute a binary
compiled with `+avx2` to CPUs that might lack AVX2. The AArch64 code path must
pass the native ARM64 CI differential suite before it is considered qualified
on that architecture. SIMD remains caller-selected and is never chosen by the
adaptive policy.

Run the complete matrix once, then repeat in reverse implementation order by
using Criterion's filters:

```powershell
$env:CRITERION_HOME = "C:\tmp\isomdl-cdla-digest-order-run-1"
cargo bench --features parallel --bench digest_executor -- --save-baseline forward --noplot
cargo bench --features parallel --bench digest_executor -- --baseline forward --noplot adaptive
cargo bench --features parallel --bench digest_executor -- --baseline forward --noplot native-up-to-4-workers
cargo bench --features parallel --bench digest_executor -- --baseline forward --noplot scalar
```

```sh
export CRITERION_HOME=/tmp/isomdl-cdla-digest-order-run-1
cargo bench --features parallel --bench digest_executor -- --save-baseline forward --noplot
cargo bench --features parallel --bench digest_executor -- --baseline forward --noplot adaptive
cargo bench --features parallel --bench digest_executor -- --baseline forward --noplot native-up-to-4-workers
cargo bench --features parallel --bench digest_executor -- --baseline forward --noplot scalar
```

For the SIMD qualification, use the same forward/reverse discipline and keep a
fresh Criterion directory. The full pass runs scalar before SIMD; the two
filtered passes reverse that order:

```powershell
$env:CRITERION_HOME = "C:\tmp\isomdl-cdla-simd-order-run-1"
cargo bench --features simd --bench digest_executor -- --save-baseline forward --noplot
cargo bench --features simd --bench digest_executor -- --baseline forward --noplot simd
cargo bench --features simd --bench digest_executor -- --baseline forward --noplot scalar
```

```sh
export CRITERION_HOME=/tmp/isomdl-cdla-simd-order-run-1
cargo bench --features simd --bench digest_executor -- --save-baseline forward --noplot
cargo bench --features simd --bench digest_executor -- --baseline forward --noplot simd
cargo bench --features simd --bench digest_executor -- --baseline forward --noplot scalar
```

Choose an empty `CRITERION_HOME` for every two-pass experiment. The named
`forward` baseline preserves the complete first pass while the two filtered
runs write the reverse-order samples without replacing it.

The scalar and native implementations have different Criterion IDs. A printed
`change` interval therefore compares that ID with its own previous run, not
native execution with the scalar group. Compare the corresponding
`median.point_estimate` values and 95% confidence intervals from each ID's
`estimates.json`; do not describe Criterion's slope estimate as a median. A
revision baseline is valid only for like-for-like IDs present in both
revisions. Treat an apparent crossover as workload-specific and unqualified if
the confidence intervals overlap or the reverse-order repeat contradicts it.

The explicit native and SIMD executors remain caller-selected. With `parallel`,
ordinary mdoc preparation selects native execution only for at least 512 jobs,
2 MiB of balanced aggregate digest input, and two available threads, capped at
four workers. Other builds retain the scalar oracle. A measured mixed-size
workload around 560 KiB regressed end-to-end under forced native execution and
therefore stays below the adaptive byte floor. Isolated digest numbers do not
establish an end-to-end credential speedup, so compare the matching
`mdoc_prepare/adaptive` cells against their same-binary serial oracle. Record
regressions as well as improvements and retain the scalar result as the
behavioral oracle.
