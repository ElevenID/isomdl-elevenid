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

The third correction is covered by an ElevenID-owned regression harness using
the observed OIDF Multipaz interoperability vector. The harness is not
represented as an official OIDF test, and no imported compliance-suite source,
selection, assertion, fixture, or expected result is modified to make it pass.

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
