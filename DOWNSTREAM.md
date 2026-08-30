# ElevenID downstream status

This repository is the maintained ElevenID fork of
[`spruceid/isomdl`](https://github.com/spruceid/isomdl). It preserves the
upstream Git history and Apache-2.0/MIT licensing. It is not represented as an
official SpruceID release.

## Downstream delta

ElevenID keeps local changes small and reviewable:

1. Replace `ssi-jwk 0.2.1` and its `rsa 0.6.1` graph with the current,
   narrowly featured `ssi-jwk` release.
2. Normalize an explicitly empty optional `issuerSigned.nameSpaces` map to no
   disclosed issuer-signed items. Non-empty namespace maps remain strict. This
   is required for the representation emitted by the official OIDF wallet
   when no claims are requested.
3. Verify `DeviceAuthentication` against the verifier-owned, exact CBOR
   `SessionTranscript` bytes. Re-encoding the transcript can produce
   semantically equivalent CBOR with different bytes and therefore invalidate
   a correct device signature.
4. Separate mdoc digest planning, execution, and assembly behind a fail-closed
   scalar executor. Issuance allocates randomness before executor dispatch and
   restores results by stable, per-call identity; scalar execution remains the
   default and signing is unchanged.
5. Offer an opt-in `parallel` digest executor that uses a reusable native
   worker pool, a fixed process-wide worker budget, and serial fallback on
   contention or WebAssembly. Public preparation remains serial unless a
   caller explicitly selects the executor inside the issuer trust boundary.

The third correction is covered by an ElevenID-owned regression harness using
the observed OIDF Multipaz interoperability vector. The harness is not
represented as an official OIDF test, and no imported compliance-suite source,
selection, assertion, fixture, or expected result is modified to make it pass.

The fourth change is a proof boundary, not a parallel-performance claim.
Fixed-randomness differential tests cover real items, decoys, all supported
SHA-2 algorithms, multiple namespaces, reordered results, and exact MSO and
signature-payload bytes. Malformed and incomplete executor results fail before
a prepared credential is returned. Executor inputs can contain sensitive
claims and therefore remain inside the issuer's trusted process; signing keys
and signer handles never cross the executor boundary. Criterion fixtures track
end-to-end preparation plus scalar and opt-in native digest throughput without
logging per-item metadata.

The internal mdoc digest plan can assign distinct credential identities so one
trusted executor call can carry jobs from more than one future credential plan.
Assembly restores results by `(credential_id, job_id)`, validates each job and
planned digest against its owning plan, and preserves input plan order. This is
structural validation of metadata that the trusted executor promises to
preserve, not cryptographic authentication of result metadata; assembly does
not repeat the digest operation. Existing public single-credential entry points
continue to assign credential identity zero, and no public batch API or default
parallel route is introduced by this change.

The fifth change adds an execution candidate, not default routing or a general
mdoc speedup claim. The reusable pool owns at most eight native threads across
the process, and a permit budget bounds work admitted to those threads.
Contending calls run through the exact scalar oracle on their caller threads
without waiting, so the pool bound is not a hard cap on total concurrent
caller-thread computation. Initialization failure aborts the current call with
the redacted digest-execution error but can be retried by a later call. Under
an unwind panic profile, a worker panic discards sibling outputs and surfaces
the same error; abort profiles retain their process-abort semantics.
Differential tests cover SHA-256/384/512, SHA block boundaries, repeated
shuffled schedules, overlapping identities in concurrent calls, actual pool
admission and contention fallback, post-panic reuse, decoys, fixed-random MSO
bytes, namespaces, and signature payloads. The benchmark reuses the pool while
retaining dispatch and synchronization costs. Stage and batch measurements
remain required before any adaptive or default activation.

## Upstream maintenance

The `Sync upstream` GitHub workflow runs on the first day of every month and
can also be dispatched manually. It merges the current upstream `main` into a
dedicated synchronization branch and creates or refreshes one
`upstream-sync` pull request.

Synchronization never auto-merges. The exact upstream SHA and ElevenID base
SHA are recorded in the pull request, normal CI is dispatched against the
resulting head commit, and conflicts create or update a visible issue. A
maintainer reviews the downstream delta and test results before merging.
Synchronization pull requests must use a merge commit rather than squash or
rebase so the upstream SHA remains an ancestor of `main`; this prevents the
same upstream history from being proposed again. This exception applies only
to upstream synchronization pull requests.

Compatibility baseline is the published upstream tag `isomdl/v0.2.0`.
Unreleased upstream API changes are adopted only through the reviewed
synchronization pull request. Marty consumers pin an exact fork commit.

Equivalent upstream behavior may replace a downstream patch after the
official interoperability and security suites pass against a released
upstream version; ElevenID does not depend on upstream acceptance to maintain
this fork.
