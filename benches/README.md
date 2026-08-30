# Digest-lane benchmarks

`mdoc_prepare` measures the unchanged public `Mdoc::prepare` boundary. It
covers 1, 8, 32, 128, and 512 items; decoys off/on; SHA-256/384/512; and small,
medium, 64 KiB portrait, and mixed payloads. Fixture cloning is outside the
timed region, and benchmark identifiers contain only aggregate fixture labels.

Hosted CI runs `cargo test --benches --all-features` as a compile and smoke
gate. Do not use wall-clock thresholds on shared CI runners.

For a pull request comparison, use the same idle machine. Keep Cargo build
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

Record the median, 95% confidence interval, and relevant throughput in the pull
request: credentials per second for mdoc and bytes per second for the digest
executor. Treat a result as a regression when the entire 95% change
interval is more than 5% slower, then repeat once before accepting or repairing
it. Do not commit machine-specific Criterion output or claim a speedup when a
reverse-order repeat contradicts the first run.

These crate-level targets are proof-boundary regression gates; they do not by
themselves complete the CDLA performance report. Criterion's timed estimates
report total elapsed time and throughput here, not separate planning, encoding,
assembly, signing, or allocation measurements. The digest harness additionally
prints deterministic SIMD coverage and lane occupancy for its synthetic input
matrix. The 512-item and 64 KiB portrait cases expose scaling, while the stage
and allocation metrics must be captured by the later service/batch harness
before enabling an accelerated executor by default.

`digest_executor` isolates hashing from mdoc planning and assembly. It measures
1, 8, 32, 128, and 512 mixed-size inputs for SHA-256/384/512 and reports byte
throughput. It also includes a uniform 256-byte SHA-256 profile so every group
of eight compatible jobs can fill a complete SIMD group. Default builds contain
only the scalar oracle. With the `parallel` feature, the same process also
measures the opt-in native executor with a requested bound of up to four
workers. The benchmark prints the host-derived bound; a one-job cell
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
on that architecture. The scalar executor remains the default on every target.

Run the complete matrix once, then repeat in reverse implementation order by
using Criterion's filters:

```powershell
$env:CRITERION_HOME = "C:\tmp\isomdl-cdla-digest-order-run-1"
cargo bench --features parallel --bench digest_executor -- --save-baseline forward --noplot
cargo bench --features parallel --bench digest_executor -- --baseline forward --noplot native-up-to-4-workers
cargo bench --features parallel --bench digest_executor -- --baseline forward --noplot scalar
```

```sh
export CRITERION_HOME=/tmp/isomdl-cdla-digest-order-run-1
cargo bench --features parallel --bench digest_executor -- --save-baseline forward --noplot
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

The native and SIMD executors remain caller-selected and are not the
`Mdoc::prepare` default. These isolated digest numbers do not establish an
end-to-end credential speedup or justify adaptive routing. Record regressions
as well as improvements, and retain the scalar result as the behavioral oracle.
