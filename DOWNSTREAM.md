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
end-to-end preparation and scalar digest throughput without logging per-item
metadata.

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
