# Threat model

A deliberately concrete STRIDE-style threat model for
`Argon2id.PasswordHasher`. Written for security reviewers, platform
architects, and developers integrating the library.

This document is **versioned with the library** and updates with each
release that materially changes a trust boundary or control. It is the
authoritative source for what the library does and does not defend against;
[`KNOWN-GAPS.md`](KNOWN-GAPS.md) summarises the gaps in plain language.

## Scope and non-goals

### In scope

| Concern | Coverage |
| --- | --- |
| Producing an Argon2id PHC hash from a password | ✅ |
| Verifying a PHC hash against a password in constant time | ✅ |
| Detecting weakened parameters / retired peppers | ✅ (`NeedsRehash`) |
| Refusing insecure configuration at construction | ✅ |
| Safe handling of unparseable / unsupported stored values | ✅ (fail-safe, never throws) |
| Memory hygiene for password, salt, and candidate-hash byte buffers | ✅ (zeroed via `CryptographicOperations.ZeroMemory`) |
| Optional keyed pepper with first-class rotation | ✅ |
| Algorithm-confusion attacks | ✅ (only `argon2id`, only `v=19`) |
| Migration from a legacy hasher with zero broken logins | ✅ (`MigratingPasswordHasher<TUser>`) |
| Observability of hash/verify operations | ✅ (`System.Diagnostics.Metrics`) |

### Out of scope

| Concern | Where it should live |
| --- | --- |
| Plaintext password lifetime in managed memory | .NET runtime constraint — use the span overloads |
| Storing the hash securely (access control, encryption-at-rest) | Application data layer |
| Rate limiting, account lockout, brute-force throttling | Authentication / identity layer |
| Breached-password checks (e.g., HIBP) | Authentication / identity layer |
| Multi-factor authentication | Authentication / identity layer |
| Memory-cost denial-of-service mitigation | Application + infrastructure layer |
| Key Management Service / HSM integration | Application infrastructure |
| FIPS 140-3 compliance | See [`COMPLIANCE.md`](COMPLIANCE.md) — Argon2id is intentionally *not* FIPS-approved |
| Defending against malicious code running in the same process | Out of scope for any password hasher |

If you need any of the right-column items, you must add them at a higher
layer. The library does not pretend to do them.

## Trust boundaries

```
┌───────────────────────────────────────────────────────────────────────────┐
│                          Application process                              │
│                                                                           │
│   ┌─────────────┐    plaintext     ┌──────────────────────────────────┐   │
│   │  Identity   │ ────password───▶ │  Argon2idPasswordHasher          │   │
│   │  / web      │ ◀──PHC string─── │  • zeroes password buffer        │   │
│   │  handler    │                  │  • zeroes salt + tag             │   │
│   └─────────────┘                  │  • constant-time tag compare     │   │
│         ▲                          │  • optional PepperRing           │   │
│         │                          └──────────────┬───────────────────┘   │
│         │                                         │ pepper key (RAM)      │
│         │                          ┌──────────────▼───────────────────┐   │
│         │                          │  PepperRing (in-process secret)  │   │
│         │                          └──────────────────────────────────┘   │
└─────────┼───────────────────────────────────────────────────────────────────┘
          │ PHC string                                  ▲
          ▼                                             │
   ┌──────────────┐                              ┌──────────────────┐
   │  Database    │                              │  Secret store    │
   │  (untrusted  │ ◀── PHC strings ──           │  (KMS / vault)   │
   │   from a     │                              │  ← pepper bytes  │
   │   crypto     │                              └──────────────────┘
   │   POV)       │                                      ▲
   └──────────────┘                                      │
                                              [admin / operator]
```

The library treats two boundaries as untrusted:

1. **The stored PHC string** read from the database may have been
   tampered with. Verification parses it defensively and any deviation
   from the expected shape yields a fail-safe `false` / `Failed` result.
2. **The supplied password** is treated as an opaque byte sequence. No
   structure is inferred; nothing is logged.

The library treats two boundaries as trusted:

1. **Pepper bytes in process memory.** The `PepperRing` holds them for
   the lifetime of the hasher; secure delivery into the process is the
   caller's responsibility.
2. **The Konscious managed-Argon2 implementation.** We delegate the
   actual round to it, on the assumption that the upstream
   implementation is correct. Konscious's security posture is monitored
   separately; vulnerabilities there are reported upstream and tracked
   in our [`SECURITY.md`](SECURITY.md).

## STRIDE walkthrough

### Spoofing

| Threat | Mitigation |
| --- | --- |
| Attacker submits a forged PHC string they crafted offline | Parser rejects any non-`argon2id` / non-`v=19` input. Tag comparison uses `FixedTimeEquals`. |
| Attacker tries to bypass the pepper by stripping the `keyid=` segment | Verifier hands a peppered hash to the Argon2id round with `KnownSecret = null` — the tag will not match. |
| Attacker passes a hash that was produced with a now-retired pepper they recovered | The pepper id is stored in the hash; if the ring no longer holds that pepper, verify fails closed. |

### Tampering

| Threat | Mitigation |
| --- | --- |
| Last-character flip of the base64 tag | Tag comparison is byte-wise; tampered bytes won't match the recomputed tag. |
| Parameter downgrade (rewrite `m=65536` to `m=8192` in the stored string) | Verify uses the *stored* parameters, then computes against the same password. Stored params cannot be lowered without invalidating the tag. |
| In-flight tampering of the password bytes | Out of scope — this is the caller's transport layer. |

### Repudiation

Not applicable — the library produces no auditable events of its own.
Observability hooks via `Argon2idDiagnostics` give the application
operator the data to build an audit trail; the library does not assert
non-repudiation.

### Information disclosure

| Threat | Mitigation |
| --- | --- |
| Password leaks via stack traces / log dumps | Library never logs the password. Application must avoid the same. |
| Password leaks via heap residue | Password byte buffers are zeroed in `finally` blocks via `CryptographicOperations.ZeroMemory`. The `string` overload's GC-managed copy is unavoidable; see [`KNOWN-GAPS.md`](KNOWN-GAPS.md) §1. |
| Pepper leaks via logging | Pepper bytes are never exposed beyond `internal` boundaries; `Pepper.Key` is `internal ReadOnlySpan<byte>`. |
| Salt leakage | The salt is *not secret* (it is part of the PHC string by design). No mitigation needed. |
| Timing oracle for username enumeration | Per-call timing of a verify against a real vs missing user is up to the caller. The Server demo's `LoginCanary` shows the standard pattern (run a dummy verify on missing-user paths). |
| Timing oracle for password-prefix discrimination | `FixedTimeEquals` on the final tag comparison eliminates a per-byte oracle. |

### Denial of service

| Threat | Mitigation |
| --- | --- |
| Attacker triggers many concurrent hashes to OOM the server | Each hash holds ~64 MiB by default. The library does not bound concurrency itself — the application must (the Server demo's `HashingGate` shows the pattern). |
| Attacker submits a 100 MB password | The library does not cap password length. Callers should validate input (the demos use a 256-character cap). |
| Maliciously crafted PHC string with huge stored memory cost | The library passes the stored `m` value to Konscious without validation. A `m=4_000_000_000` stored value could be a DoS vector. **Caller mitigation:** trust the stored hash only if you produced it (i.e., your DB row hasn't been tampered with by an attacker who already owns the box). The `Verify` path does cap nothing; this is documented residual risk. |
| Slow verification of a malformed string | The PHC parser rejects bad input in O(length); no quadratic behavior. |

### Elevation of privilege

| Threat | Mitigation |
| --- | --- |
| Library bug that returns `true` for any password | Covered by tests including round-trip, wrong-password, tampered-hash, malformed-input, peppered, Unicode, and large-input cases. Public API surface is locked by `Microsoft.CodeAnalysis.PublicApiAnalyzers` to prevent silent regression. |
| Upstream vulnerability in Konscious | Tracked via `NuGetAudit` at build time; coordinated disclosure via our `SECURITY.md`. |
| Algorithm confusion (argon2i / argon2d swap) | Verifier hard-rejects anything other than `argon2id`. |

## Controls

| Control | Where it lives | Verified by |
| --- | --- | --- |
| Constant-time tag comparison | `CryptographicOperations.FixedTimeEquals` in `VerifyAndZero` | `Verify_TamperedHash_ReturnsFalse` + others |
| Memory zeroing | `finally` blocks in `HashAndZero`, `VerifyAndZero` | Code review |
| Parameter validation | `Argon2idOptions.Validate()` called by constructor | `Constructor_InvalidOptions_Throws` |
| PHC parser strictness | `PhcString.TryParse` rejects unknown algorithm / version / malformed | `Verify_MalformedHash_ReturnsFalseNeverThrows` |
| Pepper fail-closed | `VerifyAndZero` returns `Failed` if `keyid` is present but not in ring | `PepperTests.Verify_WithoutTheRequiredPepper_ReturnsFalse` |
| Public API surface lock | `PublicAPI.{Shipped,Unshipped}.txt` + `Microsoft.CodeAnalysis.PublicApiAnalyzers` | Build error on accidental change |
| Build-time vulnerability audit | `NuGetAudit=true` + `NuGetAuditMode=all` in `Directory.Build.props` | CI fails on known CVE in any transitive dep |
| Supply-chain provenance | `actions/attest-build-provenance` on every published `.nupkg` | `gh attestation verify` |
| Deterministic builds + SourceLink | `Deterministic=true`, `EmbedUntrackedSources=true` | Reproducible-build comparison |
| Static analysis | CodeQL `security-and-quality` queries on every PR + weekly | GitHub Security tab |
| Supply-chain grading | OpenSSF Scorecard workflow + public badge | securityscorecards.dev |

## Residual risks

These are accepted, documented gaps. Each is either inherent to the
problem domain or out of scope for a password-hashing library:

1. **Plaintext `string` lifetime.** Garbage-collected immutable strings
   cannot be reliably zeroed. Use the span overloads.
2. **Memory-cost DoS amplification.** Per-call cost is intentional; the
   *concurrency* is the application's to bound.
3. **Stored-PHC parameter DoS.** A maliciously rewritten stored
   `m=4_000_000_000` would be honored on verify. Mitigate with
   defense-in-depth at the data layer.
4. **No FIPS approval.** Argon2id is not currently on the FIPS-approved
   list. See [`COMPLIANCE.md`](COMPLIANCE.md) for the regulatory
   trade-off.
5. **No code-signing certificate yet.** Packages carry build-provenance
   attestations but are not signed with an Authenticode certificate.

Each residual risk is referenced from [`KNOWN-GAPS.md`](KNOWN-GAPS.md)
with the same numbering and language.

## Disclosure policy

Vulnerabilities go through GitHub Security Advisories — see
[`SECURITY.md`](SECURITY.md). Coordinated disclosure with credit by
default.

---

*To God be the glory — 1 Corinthians 10:31.*
