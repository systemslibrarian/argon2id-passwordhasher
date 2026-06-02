# Security Policy

## Supported versions

This project is in early preview. Security fixes are applied to the latest
`0.x` preview only until a `1.0.0` release is published.

| Version | Supported |
| --- | --- |
| `0.4.x-preview` | ✅ |
| `0.3.x-preview` | ❌ |
| `0.2.x-preview` | ❌ |
| `0.1.x-preview` | ❌ |

## Reporting a vulnerability

**Please do not open public GitHub issues for security vulnerabilities.**

Instead, report privately using GitHub's
[**Security Advisories**](https://github.com/systemslibrarian/argon2id-passwordhasher/security/advisories/new)
("Report a vulnerability"). If you cannot use that channel, contact the maintainer
through the email on the GitHub profile.

When reporting, please include:

- A clear description of the issue and its impact.
- Steps to reproduce or a proof of concept.
- Affected version(s) and environment details (OS, .NET SDK).

You can expect an acknowledgement within a few days. We will work with you on a
fix and coordinate disclosure. Credit is given to reporters unless you prefer to
remain anonymous.

## Scope

This library hashes and verifies passwords. The following are **in scope**:

- Incorrect Argon2id usage that weakens the resulting hash.
- Hash encoding/parsing flaws (PHC string handling).
- Timing side channels in verification.
- Parameter-validation gaps that allow insecure configurations.
- Memory-hygiene regressions in the buffers the library owns (password, salt,
  candidate hash).

The following are **out of scope** (see [`KNOWN-GAPS.md`](KNOWN-GAPS.md) for detail):

- The lifetime of a plaintext `string` password in managed memory (a .NET runtime
  constraint, not something a library can fully control).
- Vulnerabilities in the underlying
  [Konscious.Security.Cryptography.Argon2](https://github.com/kmaragon/Konscious.Security.Cryptography)
  package — report those upstream (we will help coordinate).
- Misuse such as logging plaintext passwords, transmitting them insecurely, or
  storing the resulting hashes without access control.

## Supply chain controls

The library is shipped with several measures designed to make tampering visible:

- **Deterministic builds** + **SourceLink** for reproducible binaries that
  resolve back to the exact source commit.
- **`NuGetAudit`** at build time flags known CVEs in direct and transitive
  dependencies.
- **CodeQL** weekly scans for security-and-quality issues.
- **Build-provenance attestations** (`actions/attest-build-provenance`) for
  every published `.nupkg`/`.snupkg` AND every SBOM. Consumers can verify with
  `gh attestation verify <file> --repo systemslibrarian/argon2id-passwordhasher`.
- **CycloneDX SBOMs** generated per package on every release, attached to the
  GitHub Release as `Argon2id.PasswordHasher.cyclonedx.json` and
  `Argon2id.PasswordHasher.AspNetCore.cyclonedx.json`. Pull them into your
  allowlisting/vulnerability-tracking pipeline.
- **OpenSSF Scorecard** weekly + per-push grading of supply-chain hygiene.
- **Locked public API surface** via `Microsoft.CodeAnalysis.PublicApiAnalyzers`,
  so unintended surface changes break the build.

## Cryptographic guidance

This library follows:

- [RFC 9106 — Argon2 Memory-Hard Function](https://www.rfc-editor.org/rfc/rfc9106)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

Default parameters (`m = 64 MiB`, `t = 3`, `p = 1`) exceed the current OWASP minimum.
Operators should still benchmark on their own hardware and tune to their latency budget.

## Implementation choice & dependency posture

This library does not implement Argon2id itself. The actual memory-hard
computation is delegated to
[**Konscious.Security.Cryptography.Argon2**](https://github.com/kmaragon/Konscious.Security.Cryptography),
an MIT-licensed managed C# implementation. That choice is deliberate and has
trade-offs worth naming:

- **Why a managed implementation rather than the reference C / libsodium.**
  A pure-.NET Argon2 ships without a P/Invoke dependency, runs unchanged on
  every platform .NET runs on (Windows, Linux, macOS, Blazor WebAssembly, and
  Native AOT), and keeps the package trimmable. A `libsodium`-backed wrapper
  would be faster on raw throughput but would re-introduce a native dependency
  per RID and would not work in the WASM demo.
- **What we give up.** Managed Argon2 ports have historically had subtle
  issues in older versions (off-by-one allocations, wrong index in the
  reference-block path, etc.). We accept this trade-off but it is the most
  load-bearing third-party dependency in the package and we treat it as such.
- **What we do about it.**
  - Konscious is **pinned at `>= 1.3.1`** (an exact version reference in the
    csproj). Bumping it is a deliberate maintainer action, gated by a
    code review of the upstream diff.
  - Every build runs **`NuGetAudit` at `low` severity over all transitive
    dependencies** — see `Directory.Build.props`. A future advisory on
    Konscious (or its `Konscious.Security.Cryptography.Blake2` dependency)
    surfaces as a build warning on the first build after the advisory lands.
  - **Dependabot** opens grouped PRs for the `nuget` ecosystem weekly. A
    Konscious release shows up there with the upstream changelog attached
    for review.
  - A **pinned known-answer-vector (KAT) test** in
    `tests/Argon2id.PasswordHasher.Tests/PhcInteropTests.cs` locks the
    Argon2id output of fixed inputs at known parameters. The expected tag
    was computed against the reference C implementation (via `argon2-cffi`)
    and cross-checked against Konscious 1.3.1; a future Konscious regression
    that still self-round-trips but diverges from the standard output fails
    the build.
- **Vulnerabilities in Konscious itself remain out of scope for this repo's
  Security Advisories** — report those upstream. We will help coordinate
  disclosure where it affects users of this package.

### Side-channel posture

The final tag comparison is constant-time
(`CryptographicOperations.FixedTimeEquals`). The **Argon2id round itself may
have data-dependent timing** on the second half of each pass (Argon2id is
intentionally data-dependent in that region — that is what makes it Argon2
**id** rather than Argon2i). This is the accepted RFC 9106 posture for
password hashing on a server you control; the password isn't recovered by
timing the round even if a local adversary could observe it precisely,
because the round is memory-hard and the time signal is dominated by memory
access patterns of values the attacker would already need to know the
password to predict.

One additional timing observable, documented for honesty: if the stored hash
references a `keyid` the live `PepperRing` does not hold, verify fails fast
(it returns before doing the full Argon2id round). The keyid is already part
of the public PHC string, so this timing signal does not disclose any value
an attacker who reads the stored hash does not already have. See
[`KNOWN-GAPS.md`](KNOWN-GAPS.md) §12 for the long form.
