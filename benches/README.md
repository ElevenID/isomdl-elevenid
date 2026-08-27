# Digest-lane benchmarks

`mdoc_prepare` measures the unchanged public `Mdoc::prepare` boundary. It
covers 1, 8, 32, 128, and 512 items; decoys off/on; SHA-256/384/512; and small,
medium, 64 KiB portrait, and mixed payloads. Fixture cloning is outside the
timed region, and benchmark identifiers contain only aggregate fixture labels.

Hosted CI runs `cargo test --benches` as a compile and smoke gate. Do not use
wall-clock thresholds on shared CI runners.

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

Record the median, 95% confidence interval, and credentials per second in the
pull request. Treat a result as a regression when the entire 95% change
interval is more than 5% slower, then repeat once before accepting or repairing
it. Do not commit machine-specific Criterion output or claim a speedup when a
reverse-order repeat contradicts the first run.

These crate-level targets are proof-boundary regression gates; they do not by
themselves complete the CDLA performance report. Criterion reports total
elapsed time and throughput here, not separate planning, encoding, assembly,
signing, allocation, or lane-utilization measurements. The 512-item and 64 KiB
portrait cases expose scaling, while those stage and allocation metrics must be
captured by the later service/batch harness before enabling a parallel executor
by default.

`digest_executor` isolates scalar hashing from mdoc planning and assembly. It
measures 1, 8, 32, 128, and 512 mixed-size inputs for SHA-256/384/512 and reports
byte throughput. Its introduction establishes the scalar baseline; it cannot
be compared to a revision without the executor API. For a later optimized
executor, check out the commit that introduced this benchmark as the baseline
and again isolate Cargo build targets:

```powershell
$digestBaselineWorktree = "C:\tmp\isomdl-digest-baseline"
$digestBaselineCommit = git log --diff-filter=A --format="%H" -- benches/digest_executor.rs |
    Select-Object -First 1
git worktree add --detach $digestBaselineWorktree $digestBaselineCommit

$env:CRITERION_HOME = "C:\tmp\isomdl-digest-criterion"
$env:CARGO_TARGET_DIR = "C:\tmp\isomdl-digest-baseline-target"
cargo bench --manifest-path "$digestBaselineWorktree\Cargo.toml" --bench digest_executor -- --save-baseline scalar --verbose

$env:CARGO_TARGET_DIR = "C:\tmp\isomdl-digest-feature-target"
cargo bench --bench digest_executor -- --baseline scalar --verbose

git worktree remove --force $digestBaselineWorktree
```

```sh
digest_baseline_worktree=/tmp/isomdl-digest-baseline
digest_baseline_commit=$(git log --diff-filter=A --format=%H -- benches/digest_executor.rs | head -n 1)
git worktree add --detach "$digest_baseline_worktree" "$digest_baseline_commit"

export CRITERION_HOME=/tmp/isomdl-digest-criterion
CARGO_TARGET_DIR=/tmp/isomdl-digest-baseline-target \
  cargo bench --manifest-path "$digest_baseline_worktree/Cargo.toml" \
  --bench digest_executor -- --save-baseline scalar --verbose
CARGO_TARGET_DIR=/tmp/isomdl-digest-feature-target \
  cargo bench --bench digest_executor -- --baseline scalar --verbose

git worktree remove --force "$digest_baseline_worktree"
```
