# Digest-lane benchmarks

`mdoc_prepare` measures the unchanged public `Mdoc::prepare` boundary. It
covers 1, 8, 32, 128, and 512 items; decoys off/on; SHA-256/384/512; and small,
medium, 64 KiB portrait, and mixed payloads. Fixture cloning is outside the
timed region, and benchmark identifiers contain only aggregate fixture labels.

Hosted CI runs `cargo test --benches` as a compile and smoke gate. Do not use
wall-clock thresholds on shared CI runners.

For a pull request comparison, use the same idle machine and a shared Cargo
target directory for both worktrees:

```powershell
$env:CDLA_CARGO_TARGET = "C:\tmp\isomdl-cdla-target"
$env:CARGO_TARGET_DIR = $env:CDLA_CARGO_TARGET

# Run from the main worktree first.
cargo bench --bench mdoc_prepare -- --save-baseline main

# Run from the feature worktree second.
cargo bench --bench mdoc_prepare -- --baseline main
```

Record the median, 95% confidence interval, and credentials per second in the
ElevenID pull request. Treat a result as a regression when the entire 95%
change interval is more than 5% slower, then repeat once before accepting or
repairing it. Do not commit machine-specific Criterion output.

Criterion reports elapsed time, not total allocated bytes. The 512-item and
64 KiB portrait cases are included to expose scaling, but peak-live allocation
must also be measured in the later service/batch harness before enabling a
parallel executor by default.
