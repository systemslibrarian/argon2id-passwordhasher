# Known Gaps & Honest Limitations

This document is a deliberately frank account of what `Argon2id.PasswordHasher`
does **not** do (yet), and the trade-offs behind its design. Security tools earn
trust by being honest about their edges. If something here surprises you, that is
the document doing its job.

Nothing below is a secret defect — these are conscious scope decisions as of
the `0.4.0-preview.5` release.

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

- **⚠️ Lose your pepper ring, lose your users.** This is the single biggest
  operational risk of opting into peppering, so it gets its own bullet:

  - Hashes made with a pepper **cannot be verified** without the key bytes that
    produced them. The library has no recovery path; it fails closed by design.
  - If the **active** pepper key is lost (vault wipe, single-region key store
    with no backup, an `unset` on the env var the secret was bound to), every
    user whose password hash was produced under that key must go through a
    full password-reset flow. There is no offline reconstruction.
  - If a **retired** pepper key is lost while any stored hash still references
    its id, the same is true for the slice of users still on that key. A
    `SELECT COUNT(*) WHERE PasswordHash LIKE '%keyid=<old-id-b64>%'`
    interrogation of your user table tells you the blast radius before you
    drop a retired key.
  - **Back up active and retired pepper material to a separate trust domain**
    (different cloud account, different KMS key envelope, offline ciphertext)
    so a single-system breach does not lose both your DB and the pepper at
    once. See [`docs/pepper-key-management.md`](docs/pepper-key-management.md)
    for the full rotation playbook.

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

What is **not** inherent — and is now closed — is the *stored-hash* variant:
verification recomputes Argon2id with the parameters embedded in the stored
string, so a crafted row (e.g. `m=2147483647`) could previously drive a
multi-terabyte allocation attempt. The parser now rejects stored hashes whose
parameters exceed hard caps (`m` ≤ 4 GiB, `t` ≤ 1024, `p` ≤ 128, salt 8–64
bytes, tag 16–512 bytes, `keyid` ≤ 64 bytes), and `VerifyPassword` returns
`false` for them. The honest flip side: a hash legitimately produced elsewhere
with parameters above those caps will not verify here. The caps sit far above
any sane production configuration, and `Argon2idOptions.Validate()` enforces
the same bounds, so the library can never emit a hash its own parser rejects.

Two honest residuals within the caps:

- A crafted stored row at the caps (`m` = 4 GiB, `t` = 1024, `p` = 128) still
  drives a ~4 GiB allocation and minutes of compute per verification. On a
  memory-constrained host that allocation can fail, and because the
  underlying Konscious implementation runs the computation via
  `Task.Run(...).Result`, the failure surfaces as an `AggregateException`
  wrapping `OutOfMemoryException` — a narrow exception to the "verify never
  throws on bad stored data" rule that only occurs when the host cannot
  physically satisfy a within-cap allocation. If your hash column is
  attacker-writable and your hosts are small, add an application-side cap
  check before verifying.
- The same `Task.Run(...).Result` design means each hash/verify blocks one
  thread-pool thread while its work runs on another. Under a login burst
  this doubles thread-pool pressure (latency, not corruption). Rate-limit
  login endpoints — which you should do anyway (§7).

## 9. Preview API stability — and what `1.0.0` will (and won't) mean

This is `0.4.0-preview.5`. The API, defaults, and PHC handling may change before
`1.0.0`. Hashes produced now use the standard PHC format and are expected to
remain verifiable, but treat the surface as not-yet-frozen. The
`PublicApiAnalyzers`-tracked surface (`PublicAPI.Shipped.txt`,
`PublicAPI.Unshipped.txt`) is the authoritative source for "what counts as
public" at any given commit.

So that nobody projects more onto the version number than it carries,
here is the commitment `1.0.0` **will** make when it ships:

- The public API surface is frozen under SemVer — breaking changes only
  in a major version, with a migration guide.
- The PHC hash format and parser behavior are stable: every hash ever
  emitted by a `1.x` release verifies against every later `1.x` release.
- Defaults change only in a minor version, only to *strengthen*, and
  are always logged in `CHANGELOG.md`; `NeedsRehash` upgrades users
  transparently.
- Security fixes per the supported-versions policy in
  [`SUPPORT.md`](SUPPORT.md).

And what `1.0.0` will **not** mean:

- It is **not** an independent-audit claim (§11 — unchanged by any
  version number).
- It is **not** a FIPS or formal-validation claim (see
  [`COMPLIANCE.md`](COMPLIANCE.md)).
- It does **not** upgrade the support model beyond what
  [`SUPPORT.md`](SUPPORT.md) states — this remains a community-supported
  open-source project.

`1.0.0` is a *stability* milestone, not an *assurance* milestone.

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

## 12. Managed Argon2 implementation, not the reference C / libsodium

The Argon2id round itself is delegated to
[**Konscious.Security.Cryptography.Argon2**](https://github.com/kmaragon/Konscious.Security.Cryptography),
a managed C# port — not the
[official Argon2 reference C implementation](https://github.com/P-H-C/phc-winner-argon2)
and not a `libsodium` P/Invoke wrapper. This is a deliberate trade-off and
worth naming explicitly.

- **Why the managed port.** A pure-.NET Argon2 ships without a P/Invoke
  surface and runs unchanged on every platform .NET runs on, including the
  Blazor WebAssembly demo and Native AOT publishes where a native dependency
  would be painful or impossible. Trimming and AOT correctness are properties
  the package advertises and they depend on this choice.
- **What we give up.** Managed Argon2 ports have historically had subtle
  issues in older versions (off-by-one allocations, wrong index in the
  reference-block path). Konscious 1.3.1 is, to the best of our review, a
  faithful implementation — we pin to it as a floor and continuously check it
  from several independent directions: a known-answer-vector corpus
  (including the RFC 9106 §5.3 Argon2id vector with secret + associated
  data), differential testing against a second independent managed
  implementation (Isopoh) with a randomized parameter matrix re-seeded
  nightly, and property-based round-trip tests. Any version bump is gated on
  a maintainer review of the upstream diff plus a `NuGetAudit` clean pass
  plus all of the above staying green.
- **What you can do about it on your side.** If you need a `libsodium`- or
  reference-C-backed implementation for a compliance reason, this is not the
  library for you yet — open an issue describing the requirement.

### Argon2 round timing — the honest version

The library's final tag comparison uses
`CryptographicOperations.FixedTimeEquals`, which is constant-time over the
tag bytes. The **Argon2id round itself is not constant-time** — Argon2id is
intentionally data-dependent on the second half of each pass (that is what
distinguishes it from Argon2i). RFC 9106 considers this acceptable for
password hashing on a server you control; the time signal is dominated by
memory-access patterns of values an attacker would need to know the password
to predict, and the memory-hard cost is the primary defense regardless.

One additional timing observable, documented so we don't over-claim: when a
stored hash carries a `keyid=…` PHC parameter the live `PepperRing` does not
hold, `Verify` returns **before** running the full Argon2id round. That is
faster than a normal wrong-password verify, which runs the full round and
then loses the `FixedTimeEquals` comparison. The keyid is part of the public
PHC string the attacker can already read, so this fast-fail does not disclose
any value they don't already have — but it would be wrong to call the verify
path globally constant-time, and we don't.

## 13. Parser accepts non-canonical encodings of the same hash

`TryParse` is deliberately permissive-fail-safe, and that permissiveness
means several *distinct strings* decode to the *same logical hash*: base64
segments with restored `=` padding, base64 whose final character carries
non-canonical trailing bits, and integer parameters with leading zeros
(`m=0065536`) are all accepted, though `Encode` only ever emits the
canonical form. Verification is completely unaffected — the decoded bytes
are identical — but if you deduplicate, audit, or search stored hashes by
**exact string** comparison (including the `keyid=` `LIKE` query in §2),
be aware that non-canonical variants of the same hash would evade it. We
keep the parser permissive because rejecting padded base64 could break
verification of hashes imported from producers that pad; canonicality was
never a PHC security guarantee.

## 14. Single maintainer (bus factor of one)

One person holds commit and publish rights. This is the honest
structural risk of most open-source libraries and this one is no
exception. The mitigations — standard hash format (your data is never
hostage to this project), fully reproducible builds, MIT license, an
independently-validating test suite that travels with any fork, and a
no-silent-abandonment commitment — are laid out in
[`SUPPORT.md`](SUPPORT.md) § "Governance, bus factor, and continuity".

---

If you find a gap not listed here, please tell us — see [`SECURITY.md`](SECURITY.md).

*To God be the glory — 1 Corinthians 10:31.*
