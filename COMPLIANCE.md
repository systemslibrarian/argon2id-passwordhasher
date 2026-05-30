# Compliance posture

This document is for security reviewers, compliance teams, and engineers
filling out vendor-onboarding questionnaires. It tells you, plainly,
what `Argon2id.PasswordHasher` is and is not under common compliance
regimes — so you can answer the questionnaire correctly the first time
and not get blocked at procurement.

If something here is unclear or inadequate for your audit, please open
an issue or contact us through the security channel in
[`SECURITY.md`](SECURITY.md).

## FIPS 140-3 position

**Argon2id is not currently a FIPS-approved password-hashing
primitive.** This is the most-asked question, so it's first.

If you operate in a FIPS-enforced environment (US Federal, certain DoD
deployments, some regulated healthcare and financial workloads), the
library should not be used to hash passwords in a way that has to pass
a FIPS validator. **Use the stock ASP.NET Core Identity
`PasswordHasher<TUser>` (PBKDF2 with HMAC-SHA-512) instead.** PBKDF2 *is*
FIPS-approved; it ships with the .NET runtime and Microsoft maintains its
FIPS posture.

If you operate in a FIPS-*aware* environment where Argon2id is
acceptable when alternatives also exist (most commercial SaaS, most
healthcare unless under specific federal contract, most financial
services outside of US Federal scope), Argon2id is the modern-best
choice: memory-hard, peer-reviewed, RFC-standardised, and the OWASP
top recommendation for password storage since 2021.

**Hybrid deployments** can use the
[`MigratingPasswordHasher<TUser>`](src/Argon2id.PasswordHasher.AspNetCore/MigratingPasswordHasher.cs)
pattern in reverse: keep PBKDF2 as the primary hasher in the
FIPS-enforced tenant, use Argon2id in non-FIPS tenants, route by
tenant. The library never *prevents* you from using PBKDF2 — it just
gives you Argon2id when you want it.

## What this library is and is not

| The library is… | The library is NOT… |
| --- | --- |
| A password-hashing primitive | An identity store |
| A managed wrapper around a peer-reviewed Argon2id implementation | A vendor with a SOC 2 attestation of its own |
| Open source under MIT | Commercially supported |
| Built with reproducible, attested supply chain | Cryptographically validated by NIST / FIPS |
| Versioned with a public CHANGELOG and locked public API | A platform component with a published EOL schedule yet |

Treat it like you treat any other open-source NuGet dependency — pull
into your SBOM, scan it for CVEs, govern its updates the same way you
govern System.* and Microsoft.AspNetCore.* packages.

## Common compliance regimes

### SOC 2

The library itself does not provide SOC 2 controls — those live at the
application layer (access control, audit logging, monitoring, change
management). What the library *does* provide that is relevant to a SOC 2
audit:

- **CC6.1 (Logical access — authentication)**: cryptographically strong
  password hashing using a memory-hard primitive aligned with industry
  best practice (OWASP, RFC 9106). Verification is constant-time.
- **CC7.1 / CC7.2 (Monitoring)**: native
  `System.Diagnostics.Metrics` instruments under
  `Argon2idDiagnostics.MeterName` for hash/verify counts, durations,
  rehash rates, parse-failure rates.
- **CC8.1 (Change management)**: deterministic builds, SourceLink, and
  per-release SLSA-style build-provenance attestations via
  `actions/attest-build-provenance`. Public API surface locked by
  `Microsoft.CodeAnalysis.PublicApiAnalyzers` so changes are
  intentional and visible.

### PCI DSS v4

Argon2id is acceptable under PCI DSS v4 requirement 8.3.2 ("strong
cryptography") — the standard defers to industry practice and Argon2id
is the OWASP-recommended primitive for password storage. Pair it with
unique per-user salt (the library does this automatically) and a
strong work factor.

### HIPAA / HITECH

The Security Rule does not name specific algorithms; the standard is
"addressable" technical safeguards. Argon2id is broadly considered
acceptable. If your covered entity contractually requires FIPS-only
cryptography, see the FIPS section above.

### GDPR (Article 32)

Article 32 requires "appropriate technical and organisational measures."
Argon2id with the library's default parameters (64 MiB memory, 3
iterations, 1 lane, 128-bit salt, 256-bit tag) is on the high end of
what regulators consider appropriate for password storage. The library
helps you demonstrate this by storing parameters inside the hash, so
your audit log can show the exact configuration used per row.

### ISO 27001 (Annex A.10.1.1)

"Policy on the use of cryptographic controls." The library's defaults
align with the OWASP Password Storage Cheat Sheet and RFC 9106 — both
acceptable references in your statement of applicability.

### NIST SP 800-63B

Argon2id is not currently on the NIST-approved list for memorised
secret verification (SP 800-63B §5.1.1.2 still names PBKDF2 and
bcrypt). This is the FIPS gap restated — see the FIPS section.

## Vendor questionnaire FAQ

Copy-paste-ready answers for common security-questionnaire questions.

> **"What cryptographic algorithm does the library use?"**

Argon2id (RFC 9106), the recommended variant of the Argon2 password
hashing function. The implementation delegates to
`Konscious.Security.Cryptography.Argon2` — a managed .NET port that
uses only BCL primitives (no native dependencies).

> **"Are the algorithm and parameters configurable?"**

Yes, via `Argon2idOptions`. The library enforces minimums at
construction time (no silent acceptance of below-OWASP parameters).
Defaults are 64 MiB memory, 3 iterations, 1 lane, 128-bit salt, 256-bit
tag — above the current OWASP minimum.

> **"Is the library FIPS-validated?"**

No. Argon2id is not currently FIPS-approved. See the FIPS section above.

> **"How are secrets (passwords) handled in memory?"**

Password byte buffers are zeroed with
`CryptographicOperations.ZeroMemory` in `finally` blocks. Salt and
candidate-hash buffers are also zeroed. The library cannot fully zero
an immutable `string` (a .NET runtime constraint); the
`ReadOnlySpan<char>` and `ReadOnlySpan<byte>` overloads let you avoid
materialising a `string` at all.

> **"Does the library support keyed hashing (pepper)?"**

Yes, via `Pepper` and `PepperRing`. Pepper key bytes are never persisted
by the library; rotation is first-class. The pepper id (not the key) is
embedded in the hash via the PHC `keyid` extension. See
[`docs/pepper-key-management.md`](docs/pepper-key-management.md) for the
loading patterns against Azure Key Vault, AWS Secrets Manager, GCP
Secret Manager, HashiCorp Vault, and environment variables.

> **"How is the library built, signed, and distributed?"**

Deterministic builds with SourceLink. Symbol packages (`.snupkg`)
published with every release. Build-provenance attestations via
`actions/attest-build-provenance` are attached to every NuGet artifact;
consumers can verify with
`gh attestation verify --repo systemslibrarian/argon2id-passwordhasher`.
The library is not currently Authenticode-signed; see
[`KNOWN-GAPS.md`](KNOWN-GAPS.md) §10.

> **"What is the disclosure policy for vulnerabilities?"**

Coordinated disclosure via GitHub Security Advisories. Maintainers
acknowledge within a few days. See [`SECURITY.md`](SECURITY.md).

> **"What is the support lifecycle?"**

The library is currently in preview (`0.x`). Security fixes apply to
the latest `0.x` preview. A formal long-term support policy will
publish with `1.0.0`.

> **"What is your supply-chain security posture?"**

- Public API surface locked by `Microsoft.CodeAnalysis.PublicApiAnalyzers`.
- `NuGetAudit` enabled at build time (transitive CVE scanning).
- CodeQL `security-and-quality` queries on every PR + weekly schedule.
- OpenSSF Scorecard run weekly, score published as a README badge.
- Dependabot covers `nuget` and `github-actions` ecosystems.
- Deterministic builds + SourceLink + build-provenance attestations.
- SBOM generation is on the roadmap (see [`KNOWN-GAPS.md`](KNOWN-GAPS.md)).

> **"Has the library been independently audited?"**

Not currently. The Konscious upstream implementation has been
reviewed by the broader cryptographic community; this wrapper has
been reviewed by the maintainer and the public via GitHub issues +
the CodeQL pipeline. A formal third-party audit is on the roadmap;
see [`KNOWN-GAPS.md`](KNOWN-GAPS.md).

## How to engage

For compliance-specific questions that this document does not answer,
open a public discussion or contact us via the security channel in
[`SECURITY.md`](SECURITY.md). We will not knowingly let a compliance
question block a customer adoption — if the answer is "no" we will
tell you, and if the answer is "yes with caveats" we will write the
caveats down.

---

*To God be the glory — 1 Corinthians 10:31.*
