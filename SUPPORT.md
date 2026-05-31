# Support and lifecycle policy

This document tells you what to expect from the project as a long-term
dependency: what gets fixed, how fast, on which versions, and what
constitutes a breaking change.

If you need a vendor-style support contract, the library is open
source and does not currently offer one. The discussion below describes
the **community** support policy.

## Versioning

The library follows [Semantic Versioning 2.0](https://semver.org).

| Change | Version bump |
| --- | --- |
| Bug fix that does not change any public API or hash format | Patch (e.g. `0.3.0 → 0.3.1`) |
| New API, no removal or signature change | Minor (e.g. `0.3.0 → 0.4.0`) |
| Removal, renamed type, changed signature, changed default that affects security posture | Major (e.g. `0.4.0 → 1.0.0`) |
| Security fix | Patch on every supported line, plus an advisory |
| Change to the emitted PHC hash format that breaks verification of prior hashes | Major + migration guide |

The public API surface is locked by
`Microsoft.CodeAnalysis.PublicApiAnalyzers` and tracked in
[`PublicAPI.Shipped.txt`](src/Argon2id.PasswordHasher/PublicAPI.Shipped.txt) /
[`PublicAPI.Unshipped.txt`](src/Argon2id.PasswordHasher/PublicAPI.Unshipped.txt)
for each package. Anything not in those files is not part of the
contract.

## Supported versions

While the library is in preview (`0.x`):

- The latest preview is the only supported version.
- Security fixes are issued only to the latest preview line.

After `1.0.0` ships:

- The two most recent **minor** versions receive bug + security fixes.
- The current minor version receives feature additions.
- Earlier minor versions are supported on a best-effort basis for
  security issues for **six months** after the next minor releases.

See [`SECURITY.md`](SECURITY.md) for the current supported-versions
table.

## What we commit to keep stable across minor versions

Even before `1.0`, the following are **format-stable**:

- The emitted PHC hash string format. A hash produced by `0.3.0`
  verifies against `0.3.x`, `0.4.x`, and (planned) `1.x` without
  data migration.
- The PHC parser remains a superset over time. We add support for new
  variants, never remove support for old ones, except in a major
  release with a documented migration path.

What may change in any minor before 1.0:

- Default `Argon2idOptions` parameter values, if industry guidance shifts.
- The exact list of which Argon2-variant family the parser accepts (we
  may add support for `keyid` extensions from libsodium etc.).
- Internal implementation details and dependency versions.

## What we commit to keep stable across patch versions

- Public API surface (mechanically enforced).
- All defaults.
- Wire format and PHC string layout.
- Dependency major versions.

## Breaking changes during preview

The library is `0.x` — by SemVer convention, anything can change in
a minor bump. In practice we use that latitude conservatively:

- Each preview-to-preview break is documented in
  [`CHANGELOG.md`](CHANGELOG.md) under a `### Breaking changes`
  header.
- We try to provide a one-step migration for every break.
- Hash format changes are avoided. The PHC string format is treated
  as already-stable.

## Release cadence

There is no fixed cadence. Releases happen when:

- A security fix lands.
- A material new feature merges.
- An enterprise consumer requests a stabilising release.

Expect one to four releases per quarter on average. Tags are pushed
with the version prefix `v` (e.g. `v0.4.0-preview.3`); the
[Release workflow](.github/workflows/release.yml) handles the matrix
test, pack, SBOM generation, provenance attestation, and creation of
the GitHub Release with all artifacts attached. **NuGet publication is
a separate, deliberately-manual CLI step** performed from a
maintainer's workstation after artifact review — see
[`PUBLISHING.md`](PUBLISHING.md) for the procedure.

## How to ask for help

Pick the channel matching your need:

| Question | Channel | Expected first response |
| --- | --- | --- |
| Usage / how-do-I | [GitHub Discussions](https://github.com/systemslibrarian/argon2id-passwordhasher/discussions) | A few days |
| Suspected bug | [GitHub Issues](https://github.com/systemslibrarian/argon2id-passwordhasher/issues) (Bug report template) | A few days; quicker for clearly-reproducible repros |
| Suspected vulnerability | [Private Security Advisory](https://github.com/systemslibrarian/argon2id-passwordhasher/security/advisories/new) (described in [`SECURITY.md`](SECURITY.md)) | A few days |
| Vendor questionnaire / compliance | Comment in [`COMPLIANCE.md`](COMPLIANCE.md) or open a discussion | A few days |
| Operational guidance | [`OPERATIONS.md`](OPERATIONS.md) covers most things; open a discussion otherwise | A few days |

We aim to triage every issue within a week and respond to security
reports within 72 hours. These are best-effort targets, not SLA
commitments.

## Backports

For preview lines, no backports — fixes go to the latest preview only.

Post-`1.0`:

- Security fixes are backported to every supported minor version.
- Bug fixes are backported to the latest supported minor only.
- New features land only on the current minor.

## Issue triage labels

If you open an issue, expect one or more of these labels to be applied
within a few days:

- `bug` — confirmed defect.
- `enhancement` — proposed feature; will be evaluated against
  [`KNOWN-GAPS.md`](KNOWN-GAPS.md) and the project scope.
- `documentation` — doc fix or improvement.
- `security` — escalated to private security advisory channel; the
  public issue stays open as a tracker only after disclosure.
- `needs-triage` — awaiting maintainer attention.
- `needs-info` — waiting on a reproducer or clarification.
- `wontfix` — out of scope; the label comment explains why.
- `good-first-issue` — small, well-bounded, suitable for new
  contributors.

## Roadmap

Current open priorities, in rough order:

1. First `1.0.0` release once the API has had a preview cycle of
   real-world use.
2. Independent third-party cryptographic audit. See
   [`KNOWN-GAPS.md`](KNOWN-GAPS.md) §11.
3. Authenticode / NuGet code-signing certificate. See
   [`KNOWN-GAPS.md`](KNOWN-GAPS.md) §10.
4. Optional HSM-backed peppering path.

Items on this list are aspirational, not commitments.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). All pull requests should:

- Pass `dotnet format --verify-no-changes`.
- Compile with no warnings under `-warnaserror`.
- Include or update tests.
- Update `PublicAPI.Unshipped.txt` for any public surface change.
- Have a `CHANGELOG.md` entry under `## [Unreleased]` for any
  user-visible change.

---

*To God be the glory — 1 Corinthians 10:31.*
