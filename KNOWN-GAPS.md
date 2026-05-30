# Known Gaps & Honest Limitations

This document is a deliberately frank account of what `Argon2id.PasswordHasher`
does **not** do (yet), and the trade-offs behind its design. Security tools earn
trust by being honest about their edges. If something here surprises you, that is
the document doing its job.

Nothing below is a secret defect — these are conscious scope decisions as of
the `0.4.0-preview.1` release.

## 1. Plaintext `string` password lifetime

The public API takes `string password`. .NET strings are immutable and
garbage-collected, so the plaintext can linger in managed memory until the GC
reclaims (and possibly relocates) it. We **cannot reliably zero a `string`**.

- **What we do:** we zero every `byte[]` we own — the password copy, the salt,
  and the candidate-hash buffer used during verification — via
  `CryptographicOperations.ZeroMemory` as soon as the operation finishes.
  `ReadOnlySpan<char>` and `ReadOnlySpan<byte>` overloads let you avoid
  creating a `string` at all.
- **What we don't do:** control a `string` you pass in. .NET cannot reliably
  zero it. Prefer the span overloads when the password never needs to be a
  `string`.
- **Your part:** avoid logging passwords, keep them in scope briefly, and prefer
  HTTPS + short-lived request handling.

## 2. Pepper / secret-key (keyed hashing) — supported, with caveats

Peppering is supported via `Pepper` and `PepperRing`. The pepper id is stored
in the hash (PHC `keyid`); the key bytes never are. Rotation is first-class:
keep retired peppers in the ring and `NeedsRehash` upgrades old hashes on login.

Remaining caveats you own:

- **Key storage is yours.** The library never persists pepper keys; keep them in
  a vault / KMS / env var, not in source or the database.
- **Lose the active key and you lose the ability to verify** hashes made with it
  — treat retirement and backups deliberately.
- The pepper is applied via the underlying library's `KnownSecret`; we do not
  yet expose Argon2's separate *associated data* field (see §3).

## 3. No "associated data" support

Argon2's optional associated-data field (e.g. binding a hash to a user ID) is
not exposed. It is a niche feature and out of scope for the opinionated default
API.

## 4. Argon2id only — by design

We intentionally support **only** Argon2id (RFC 9106's recommended variant).
Argon2i and Argon2d are not offered, and the verifier rejects them. This removes
an algorithm-confusion footgun rather than being a limitation to fix.

## 5. Single embedded version (v=19)

The PHC parser accepts only Argon2 version `0x13` (19), the current version.
There is no migration path for hypothetical future Argon2 versions yet; that
would be added if and when a new version ships.

## 6. Defaults are general-purpose, not tuned to *your* hardware

The defaults (`m = 64 MiB`, `t = 3`, `p = 1`) are a strong, safe baseline — not
a benchmark-optimized value for your specific servers and latency budget.
**Measure on your own hardware** and adjust. The library makes this easy: raise
the work factor and `NeedsRehash` will transparently upgrade users on their next
login.

## 7. No built-in rate limiting or lockout

Password hashing is one layer. This library does **not** provide login
throttling, account lockout, breached-password checks (e.g. Have I Been Pwned),
or MFA. Those belong at the application / identity layer and are out of scope.

## 8. Memory-cost denial-of-service

By design, each hash allocates a large block of memory (64 MiB by default). An
attacker who can trigger many concurrent hash operations could pressure server
memory. Mitigate with request rate limiting and by sizing parameters against
your expected concurrency. This is inherent to memory-hard hashing, not a bug.

## 9. Preview API stability

This is `0.4.0-preview.1`. The API, defaults, and PHC handling may change before
`1.0.0`. Hashes produced now use the standard PHC format and are expected to
remain verifiable, but treat the surface as not-yet-frozen. The
`PublicApiAnalyzers`-tracked surface (`PublicAPI.Shipped.txt`,
`PublicAPI.Unshipped.txt`) is the authoritative source for "what counts as
public" at any given commit.

## 10. No NuGet code-signing certificate (yet)

Packages are deterministic, published with SourceLink, accompanied by
CycloneDX SBOMs, and carry build-provenance attestations on both the
`.nupkg` and the SBOM. They are **not** yet signed with an Authenticode
/ NuGet author-key certificate. Verify integrity with
`gh attestation verify <file> --repo systemslibrarian/argon2id-passwordhasher`
in the interim.

## 11. No independent third-party audit (yet)

The library has a published [threat model](THREAT-MODEL.md), a public
[compliance posture](COMPLIANCE.md), and is continuously scanned by
CodeQL + OpenSSF Scorecard. It has **not** yet been audited by an
independent cryptographic-review firm. This is on the roadmap and is
the most-asked-about gap during enterprise procurement; pre-audit, the
library should be treated as a high-quality open-source dependency
rather than a vendor-attested platform component.

---

If you find a gap not listed here, please tell us — see [`SECURITY.md`](SECURITY.md).

*To God be the glory — 1 Corinthians 10:31.*
