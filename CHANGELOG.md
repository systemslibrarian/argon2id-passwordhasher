# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
(with `-preview.N` suffixes for previews).

## [1.0.0] — 2026-07-02

**First stable release.** The public API surface of both packages is now
frozen under SemVer (`PublicAPI.Shipped.txt` is the contract — 68 core +
16 adapter API lines), the PHC hash format is stable (every hash emitted
by any `1.x` verifies against every later `1.x`), and the
[`SUPPORT.md`](SUPPORT.md) supported-versions policy takes effect. As
stated before release in `KNOWN-GAPS.md` §9: **1.0 is a stability
milestone, not an assurance milestone** — it is not an audit claim
(§11) and not a FIPS claim ([`COMPLIANCE.md`](COMPLIANCE.md)).

This release also contains everything below, produced by a comprehensive
adversarial review (five independent review passes plus source
verification of every finding) conducted for the 1.0 freeze.

### Security

- **`Pepper` ids are now validated at construction.** Previously any non-empty
  string was accepted, but the PHC parser caps `keyid` at 64 UTF-8 bytes and
  UTF-8 encoding silently rewrites unpaired surrogates to U+FFFD — so an id
  over the byte cap (including "short-looking" multibyte ids: 22 CJK chars =
  66 bytes) or containing ill-formed UTF-16 produced hashes **the library
  could never verify**: `HashPassword` succeeded, every subsequent
  `VerifyPassword` returned false forever. A silent lockout of every user
  registered under that pepper. The constructor now throws `ArgumentException`
  for ids that exceed 64 UTF-8 bytes or contain unpaired surrogates,
  restoring the invariant that the library can never emit a hash its own
  parser rejects.
- **`NeedsRehash` now flags two previously-missed upgrade cases:** a stored
  salt shorter than the configured `SaltSizeBytes` (the parser accepts
  8-byte salts for interop, below the library's 16-byte floor, but such
  hashes were never reported as needing an upgrade), and a hash carrying a
  pepper `keyid` under a hasher with **no** pepper ring (verification
  correctly fails closed, but `NeedsRehash` said `false` — masking an
  accidental de-peppering outage from any dashboard or migration job built
  on it).
- **Invalid Argon2id options now fail at host startup, not on the first
  login.** The DI extensions call `ValidateOnStart()`, so a bad
  `appsettings.json` value (e.g. `MemorySizeKib` below the floor) refuses
  deployment instead of producing HTTP 500s on the login endpoint at
  runtime.
- **The explicit-options DI overload snapshots the options at registration.**
  Previously the `IOptions` pipeline captured the caller's live instance and
  copied it lazily at first resolution, so a post-registration mutation could
  weaken the hasher — defeating the snapshot guarantee the core constructor
  makes.
- **A plain `AddArgon2idPasswordHasher` call no longer silently replaces a
  migrating registration.** Previously, calling it after
  `AddArgon2idPasswordHasherWithMigration` (two setup modules, a refactor)
  displaced the migrating hasher and every user still on a legacy PBKDF2
  hash got `Failed` on correct credentials — order-dependent and invisible.
  The migrating registration is now detected and preserved.
- **Options are snapshotted at hasher construction.** `Argon2idOptions`
  properties are settable (for the Options pattern), which previously left
  two footguns open: mutating an options instance *after* passing it to a
  hasher (or mutating the instance returned by `hasher.Options`) silently
  changed that hasher's parameters — bypassing constructor validation and
  potentially weakening every future hash — and
  `Argon2idOptions.Recommended` was a shared mutable singleton, so one
  mutation poisoned the process-wide defaults (including the no-arg
  hasher constructor, which uses it). The hasher now validates and stores
  a private snapshot, `Options` returns a defensive copy, and
  `Recommended` returns a fresh instance per access. No public API
  signature changes; behavior now matches what the XML docs already
  promised.

### Fixed

- **Legacy empty-password accounts no longer throw mid-login during
  migration.** The stock Identity hasher can hold a hash of `""`; on
  successful legacy verification the migrating hasher signalled
  `SuccessRehashNeeded`, making Identity call `HashPassword(user, "")` —
  which Argon2id (correctly) refuses, turning a successful login into an
  unhandled exception. Such logins now return plain `Success`; the account
  upgrades when the password actually changes.
- **Verify metrics are now accurate.** An empty-password attempt against a
  perfectly valid stored hash no longer increments
  `argon2id.parse.failure.count` (the corrupted-data alarm), and
  `argon2id.verify.count` now counts early-rejected attempts (empty
  password, unparseable hash) as documented ("regardless of outcome") —
  previously `parse.failure.count` could exceed `verify.count`.

### Added

- **Identity migration sample**
  (`samples/Argon2id.PasswordHasher.IdentityMigrationSample`) — a runnable
  console walkthrough of the primary adoption path: a stock Identity PBKDF2
  hash transparently upgraded to peppered Argon2id on first login through
  the real `UserManager<TUser>` pipeline, with the pepper key sourced from
  an environment variable. The samples previously demonstrated only the
  core hasher; this is the first to exercise the `.AspNetCore` package.
- **Producer-direction fuzz phase.** The SharpFuzz harness now also
  interprets fuzz bytes as *producer* inputs — options clamped to the valid
  domain and a candidate pepper id gated through the real `Pepper`
  constructor — and asserts everything `Encode` emits parses back
  losslessly. The original harness only fuzzed the consumer direction
  (parse → re-encode), which was structurally blind to the pepper-id
  encode/parse asymmetry fixed above. A matching CsCheck property
  (`AnyPepperAcceptedId_RoundTripsThroughEncodeAndParse`) runs the same
  invariant with arbitrary UTF-16 on every CI run.
- **Seven new fuzz corpus seeds** covering the boundaries today's review
  proved interesting: padded-base64 keyid, leading-zero integers, the
  64-byte keyid cap (at and over), the 8-byte salt minimum (at and below),
  and an `m < 8p` violation. All replay as unit tests on every CI run.
- **Fuzz corpus persistence.** The nightly fuzz workflow now restores the
  grown corpus from previous runs via `actions/cache` and saves it after
  every run (including crashing ones), so libFuzzer's coverage discoveries
  compound instead of restarting from the committed seeds each night.
- **NuGet Trusted Publishing.** The release workflow now publishes to
  nuget.org via OIDC — a short-lived, workflow-scoped token minted at
  publish time replaces the long-lived API key entirely. The
  deliberate-publish policy is preserved by a manual-approval gate (the
  `nuget` GitHub environment): tagging prepares and attests the release,
  a maintainer inspects the artifacts and approves the publish. The
  manual CLI flow remains documented in `PUBLISHING.md` as an emergency
  fallback only.
- **`SECURITY-INSIGHTS.yml`** — machine-readable security posture per the
  OpenSSF Security Insights specification.
- **Governance & continuity statement** in `SUPPORT.md`: single-maintainer
  disclosure, why stored hashes are never hostage to this project
  (standard PHC format), reproducible-build fork-ability, and a concrete
  fork/vendor contingency for the Konscious dependency. Registered as
  `KNOWN-GAPS.md` §14.
- **OpenSSF Best Practices badge evidence map**
  (`.github/OPENSSF-BEST-PRACTICES.md`) so the maintainer can complete
  the bestpractices.dev self-attestation quickly.
- Draft materials for soliciting external review at zero cost
  (`.github/DRAFT-request-for-cryptographic-review.md`,
  `.github/DRAFT-ostif-application.md`).

### Changed

- **README** gains a "What we claim — and what we don't" section stating
  the claim boundary (verified-correctness machinery vs. no independent
  audit / no FIPS validation / no support contract) in one place, and the
  versioning section now states what `1.0.0` will and will not mean.
- **`KNOWN-GAPS.md` §9** now spells out the exact `1.0.0` commitment
  (API/format freeze under SemVer) and its explicit non-claims — a
  stability milestone, not an assurance milestone.
- **`SECURITY.md`** supported-versions section now states the concrete
  post-1.0 support policy (aligned with `SUPPORT.md`).
- **`KNOWN-GAPS.md` §8** now documents two within-cap residuals honestly: a
  stored row at the parser caps can still OOM a small host (surfacing as
  `AggregateException` wrapping `OutOfMemoryException` due to the underlying
  implementation's `Task.Run(...).Result`), and the same design blocks one
  thread-pool thread per hash under load. **New §13** documents that the
  parser accepts non-canonical encodings (padded base64, slack trailing
  bits, leading-zero integers) of the same logical hash — verification is
  unaffected, exact-string dedupe/audits should know.
- Removed stray AI-brainstorm notes (`chatgpt.md`,
  `geminisuggestions.md`) from the repo root; everything actionable in
  them was already implemented or documented.
- Fixed mojibake em-dashes (`â€"` → `—`) in comments across six workflow
  files.

## [0.4.0-preview.5] — 2026-06-11

### Security

- **Verification-side resource caps in the PHC parser.** `TryParse` now
  rejects stored hashes whose declared parameters exceed hard caps
  (`m` > 4 GiB, `t` > 1024, `p` > 128, `m` < 8·`p`, salt outside 8–64 bytes,
  tag outside 16–512 bytes, `keyid` > 64 bytes). Previously a crafted stored
  hash (e.g. `m=2147483647`) could drive a multi-terabyte allocation attempt
  during verification. `VerifyPassword` still returns `false` (never throws)
  for such inputs; `Argon2idOptions.Validate()` now enforces the same upper
  bounds so the library can never emit a hash its own parser rejects. The
  parser also rejects `keyid` payloads that are not valid UTF-8, since a
  pepper id is a string and invalid bytes cannot round-trip losslessly.

### Added

- **Coverage-guided fuzzing** of the PHC parser: SharpFuzz/libFuzzer harness
  (`fuzz/`), a committed seed corpus, a nightly fuzz workflow, and
  `FuzzCorpusReplayTests` which replays every corpus input as a plain unit
  test on every CI run.
- **Property-based tests** (CsCheck): parser totality on arbitrary and
  adversarial inputs, encode→parse identity, hash→verify round-trips for
  arbitrary Unicode passwords.
- **Differential testing** against Isopoh.Cryptography.Argon2 (an
  independent managed Argon2 implementation): fixed matrix in regular CI,
  randomized matrix re-seeded nightly (`differential.yml`).
- **Cross-ecosystem KAT corpus** (`tests/.../TestData/argon2id-vectors.json`)
  with provenance per vector, including the RFC 9106 §5.3 Argon2id test
  vector exercised with secret + associated data, plus verbatim PHC strings
  emitted by the reference-C `libargon2` (via argon2-cffi) — covering a
  64-byte tag, `p=2` lanes, and a Unicode (astral-codepoint) password — each
  verified through the public API.
- **Mutation testing** (Stryker.NET): weekly workflow with a
  mutation-score break threshold (`mutation.yml`, `stryker-config.json`).
- **Reproducible-build verification**: CI now builds + packs twice from a
  clean tree and fails if assemblies differ byte-for-byte; documented SLSA
  position in `COMPLIANCE.md`.
- **Line-coverage threshold gate** (coverlet, 80% line) in CI.
- **Native AOT smoke test** (`samples/Argon2id.PasswordHasher.AotSmokeTest`):
  CI publishes a trimmed Native AOT binary and runs it, proving the
  `IsAotCompatible` claim end to end.
- **Hardware calibration tool** (`tools/Argon2id.PasswordHasher.Calibration`):
  measures Argon2id latency on the host and recommends the strongest
  `Argon2idOptions` that fit a target latency budget.
- **Docs**: migration guides (ASP.NET Core Identity/PBKDF2 and BCrypt) on
  the docs site; pepper & key-management article added to the site TOC.
- **`EnablePackageValidation`** on both shipped packages, with
  `PackageValidationBaselineVersion` pinned to `0.4.0-preview.4` so every
  pack verifies binary compatibility against the last published release.

### Changed

- **All GitHub Actions are pinned to full commit SHAs** (with the
  human-readable tag retained as a trailing comment) across every workflow,
  removing the mutable-tag supply-chain risk flagged by OpenSSF Scorecard.

### Fixed

- **`release.yml` now passes GitHub workflow validation.** Its
  release-notes preamble was a column-0 heredoc body inside a `run: |`
  block scalar; the dedent terminated the scalar early and made the whole
  file invalid YAML, so the workflow was silently rejected before any job
  ran (every tag push since 0.4.0-preview.1 produced no GitHub Release).
  The preamble is now a single ANSI-C-quoted string prepended to the
  API-generated notes — no heredoc, no dedent.

## [0.4.0-preview.4] — 2026-06-01

### Changed

- **`SECURITY.md`** now carries an explicit "Implementation choice & dependency
  posture" section naming the managed-Argon2 trade-off (pure-.NET vs reference
  C / libsodium), the Konscious version-pin policy (`>= 1.3.1`, exact-version
  reference), and the build-time mitigations (`NuGetAudit` over all transitive
  dependencies, weekly Dependabot, a pinned KAT). A short "Side-channel
  posture" sub-section makes clear that the final tag comparison is
  constant-time but the Argon2id round itself is not, and that an
  unknown-`keyid` verify fast-fails — both expected, neither over-claimed.
- **`KNOWN-GAPS.md` §12 (new)** captures the same managed-Argon2 trade-off in
  the gaps register, including the honest Argon2id-round-timing posture and
  the pepper-keyid early-return note.
- **`KNOWN-GAPS.md` §2 (pepper)** restructured so the "lose your pepper ring,
  lose your users" warning is a standalone bolded sub-bullet rather than a
  single line of prose, with a `keyid=` `LIKE`-query pattern operators can use
  to size the blast radius of a retired-key loss.
- **`README.md`** pepper section: the `[!WARNING]` callout moved up to precede
  the pepper code example (instead of following the rotation example), with
  stronger framing about backups. "License & acknowledgements" now links to
  `SECURITY.md` / `KNOWN-GAPS.md §12` next to the Konscious credit so the
  trade-off is one click away from the front door.
- **`docs/pepper-key-management.md`** now opens with a "Before you start: back
  up your pepper ring" callout enumerating the four prerequisites (canonical
  store, backup to a separate trust domain, written recovery runbook, never
  reuse a pepper id) before the first code example.

### Tests

- New **`PhcInteropTests.Verify_KnownAnswerVector_MatchesExpectedTag`** —
  Argon2id Known-Answer-Vector test with a pinned expected tag for fixed
  password / salt / parameters. The expected hex
  (`bf9fa3eb…5d35a2fa`) was computed against the official Argon2 reference
  C implementation via `argon2-cffi` 25.1.0 and cross-checked against
  Konscious 1.3.1 before being committed. Guards against a future Konscious
  regression that still self-round-trips but diverges from the standard
  Argon2id output.

### Notes

- This is documentation + a test. **No production code changes; no version
  bump.** `Argon2idPasswordHasher` (`FixedTimeEquals`, stored-parameter
  verification, the `finally` zeroing pattern) is untouched; the default
  `Argon2idOptions` are untouched; the public `Pepper` / `PepperRing` surface
  is untouched. The Konscious version pin in
  `src/Argon2id.PasswordHasher/Argon2id.PasswordHasher.csproj` is unchanged
  — it was already at the intended `>= 1.3.1` floor. The doc work above
  records *why* that pin is the floor.

## [0.4.0-preview.3] — 2026-05-30

### Added

- **`Argon2idPasswordHasher.IsArgon2idHash(string?)`** static method
  + **`Argon2idPasswordHasher.PhcPrefix`** const (`"$argon2id$"`).
  Allocation-free, null-safe sniff test for callers writing their own
  routing logic over a heterogeneous password column. Use alongside
  `MigratingPasswordHasher<TUser>` (which now uses this internally) or
  standalone in admin / data-audit tooling.
- **NuGet package icon.** Both packages now ship `icon.png` and render
  with a proper visual identity on nuget.org listings and search
  results. Source-of-truth is `assets/Generate-Icon.ps1` — Windows
  PowerShell + `System.Drawing.Common`, deterministic output, no
  extra tooling required to regenerate.

### Changed

- `MigratingPasswordHasher<TUser>` consolidated to use the new
  public `Argon2idPasswordHasher.IsArgon2idHash`; the duplicated
  internal helper + constant are removed. Behavior unchanged.

### Tests

- New **`IsArgon2idHashTests`** (14 cases) covering null/empty,
  wrong-variant, case-sensitivity, peppered hashes, the library's
  own emitted output round-tripping the sniff test, and a constant
  lock between `PhcPrefix` and the emitted prefix.
- New **`UserManagerIntegrationTests`** (6 cases) driving the real
  ASP.NET Core Identity `UserManager<TUser>` pipeline end-to-end —
  proving `CreateAsync` → `CheckPasswordAsync` works, that rehash-on-
  login transparently upgrades a weaker stored hash through the
  Identity layer, and that `AddArgon2idPasswordHasherWithMigration`
  upgrades a pre-loaded PBKDF2 hash on first successful login.
  Full suite: **441 tests** across net8 + net9 + net10 (was 381).

## [0.4.0-preview.2] — 2026-05-30

### Removed

- **`Pepper.FromHex(string, string)`** and **`Pepper.FromBase64(string, string)`**
  static factories. They shipped in `0.4.0-preview.1` and have been pulled
  here because the maintainer intends to host that "decode-from-text-then-
  construct" pattern in a separate library; shipping it from two packages
  would create a naming-collision problem when both are referenced together.
  - **Migration:** use the plain `Pepper(string id, byte[] key)` constructor
    and decode the hex/base64 yourself:
    `new Pepper("2026-11", Convert.FromHexString(hex))` or
    `new Pepper("2026-11", Convert.FromBase64String(b64))`.

### Notes

- The release-tag workflow has been split: tag pushes now only **prepare**
  the release (test, pack, SBOM, attestations, GitHub Release with all
  artifacts attached). **NuGet publication is a separate manual CLI step**
  — see [`PUBLISHING.md`](PUBLISHING.md). The `NUGET_API_KEY` repository
  secret is no longer read by any workflow.

## [0.4.0-preview.1] — 2026-05-30

### Breaking changes

- `Argon2idOptions` properties are now `set` instead of `init`. This
  unlocks the standard .NET Options pattern (`IOptions<Argon2idOptions>`
  + `services.Configure<Argon2idOptions>(...)` binding from
  `IConfiguration`). Source-compatible for the common
  object-initializer construction; binary-breaking for callers that
  reflected over the property setters as `init`-only. Hashers continue
  to treat their options as effectively immutable post-construction.

### Added

- **`Argon2idDiagnostics`** static class exposing the
  `System.Diagnostics.Metrics.Meter` name (`"Argon2id.PasswordHasher"`)
  and the names of every instrument the library emits. Subscribing your
  observability stack (OpenTelemetry, Prometheus, etc.) with
  `AddMeter(Argon2idDiagnostics.MeterName)` is now sufficient to get
  hash count + duration, verify count + duration, verify-success count,
  rehash-needed count, and parse-failure count out of the box. Zero
  per-call overhead when nothing is listening.
- **`MigratingPasswordHasher<TUser>`** in the AspNetCore package — an
  `IPasswordHasher<TUser>` that routes verification by format: any stored
  value beginning with `$argon2id$` goes to the Argon2id path, everything
  else (PBKDF2, null, garbage) to a configurable legacy hasher. Successful
  legacy verifications return `SuccessRehashNeeded` so ASP.NET Core
  Identity transparently upgrades the stored hash on the next sign-in.
  Fail-safe on garbage input.
- **`IdentityBuilder.AddArgon2idPasswordHasherWithMigration<TUser>()`** —
  one-line DI registration that wires the migrating adapter on top of the
  stock Identity PBKDF2 hasher. Optional `Action<Argon2idOptions>` overload.
- **`MIGRATION.md`** end-to-end guide for switching an existing user store
  from the default `PasswordHasher<TUser>` (or bcrypt, scrypt, or any
  custom scheme) to Argon2id with zero downtime, zero forced resets, and
  zero broken logins.
- **`IdentityBuilder.AddArgon2idPasswordHasher<TUser>()`** chaining
  extension — `builder.Services.AddIdentityCore<TUser>().AddArgon2idPasswordHasher<TUser>()`
  reads more naturally than breaking out to `.Services`.
- **`Pepper.FromHex(string, string)`** and **`Pepper.FromBase64(string, string)`**
  static factories so vault/KMS-sourced secrets don't need
  `Convert.FromHexString` boilerplate.
- **`AddArgon2idPasswordHasher<TUser>(Action<Argon2idOptions>)`** overload
  in the AspNetCore package — the standard .NET Options pattern, with
  `IValidateOptions<Argon2idOptions>` for startup validation.
- **`Argon2idPasswordHasher.Verify(...)`** overloads returning a new
  **`VerifyResult`** readonly record struct (`Success`, `NeedsRehash`). Fuses
  verify + needs-rehash into one call and parses the PHC string once instead of
  twice. The existing `VerifyPassword(...)` and `NeedsRehash(...)` continue to
  work and remain the right choice when you only need one piece of information.
- The ASP.NET Core Identity adapter now uses `Verify(...)` internally, so
  Identity's `PasswordVerificationResult.SuccessRehashNeeded` path runs with
  half the PHC parsing work.

### Changed

- Hardened the GitHub Pages deploy step: the `<base href>` rewrite now
  pre- and post-asserts the substitution actually happened, so any future
  drift in `index.html` fails the workflow loudly instead of silently
  publishing 404s.

### Added (docs)

- **DocFx-generated API documentation site** lives under
  `https://systemslibrarian.github.io/argon2id-passwordhasher/docs/`,
  co-published with the WASM demo via the same Pages workflow. Every
  public type + member, generated from the source XML doc comments,
  filtered to match `PublicAPI.Shipped.txt`.

### Added (CI / supply chain)

- **OpenSSF Scorecard** workflow (`.github/workflows/scorecard.yml`) runs
  weekly + on push, uploads SARIF to GitHub Security, and publishes the
  numeric score to the README badge. Grades maintained status, branch
  protection, dangerous workflow patterns, pinned dependencies, signed
  releases, and more.
- **README badges** for Pages deploy status and OpenSSF Scorecard score
  alongside the existing CI / CodeQL ones.

### Added (samples)

- **Parameter playground** page (`/playground`) in the WASM demo: tweak
  memory cost, iterations, parallelism in the browser and watch the
  elapsed-time column. History table includes a slow-down ratio vs. the
  library defaults, and below-minimum runs are flagged in red.
- **Verify any hash** page (`/verify`) in the WASM demo: paste a PHC
  string + password, see verify outcome and the decomposed parameters.
  Calls the new `Verify(...)` API. Useful for sanity-checking hashes
  produced by another backend (libsodium, the reference impl, etc.).
- The WebAssembly demo now enables multi-threaded WASM
  (`WasmEnableThreads=true`) and offloads hashing via `Task.Run`, so the UI
  stays responsive during Argon2. A minimal in-tree
  `wwwroot/coi-serviceworker.js` provides the cross-origin isolation that
  multi-threaded WASM requires on GitHub Pages.

## [0.3.0-preview.1] — 2026-05-30

### Breaking changes

- Renamed the core type `PasswordHasher` to **`Argon2idPasswordHasher`**. The old
  name shadowed the root namespace (`Argon2id.PasswordHasher`), forcing callers
  to use a `global::`-qualified alias when referencing the type from child
  namespaces. The new name is unambiguous, mirrors the ASP.NET Core adapter
  (`Argon2idPasswordHasher<TUser>`), and removes the alias workaround.
  - Migration: replace `new PasswordHasher(...)` with
    `new Argon2idPasswordHasher(...)`. The PHC hash format, parameters, and
    semantics are unchanged — existing stored hashes verify without migration.

### Added

- **Multi-targeting:** the library now ships for `net8.0`, `net9.0`, and
  `net10.0`, widening compatibility to every supported .NET LTS and STS.
- **Public API surface lock** via `Microsoft.CodeAnalysis.PublicApiAnalyzers`
  with shipped/unshipped tracking files (`PublicAPI.Shipped.txt`,
  `PublicAPI.Unshipped.txt`). Any accidental change to the public surface
  becomes a build error.
- **Trim and Native AOT support:** assemblies are marked `IsTrimmable=true` and
  `IsAotCompatible=true`.
- **`NuGetAudit`** is enabled at build time to surface known CVEs in transitive
  dependencies.
- **CodeQL** weekly scan + **Dependabot** updates for `nuget` and
  `github-actions` ecosystems.
- **CI matrix** across Ubuntu, Windows, and macOS; format verification with
  `dotnet format --verify-no-changes`; test result artifacts on every run.
- **Release workflow** now creates a GitHub Release with auto-generated notes
  and pushes both `.nupkg` and `.snupkg` packages.
- Repo hygiene: `.editorconfig`, `global.json`, `CHANGELOG.md`,
  `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `THIRD-PARTY-NOTICES.md`, issue and
  PR templates.
- New tests: concurrency stress over a shared singleton hasher and a PHC
  golden-string fixture that guards against accidental hash-format regressions.

### Changed

- **Memory hygiene:** salt and candidate-hash buffers are now zeroed after use
  via `CryptographicOperations.ZeroMemory`, complementing the existing password
  zeroing.
- **Pepper allocation:** verification no longer allocates a fresh `byte[]` copy
  of the pepper key per call; the cached key is reused.

## [0.2.0-preview.1]

### Added

- **Pepper / keyed hashing** via `Pepper` and `PepperRing` with first-class
  rotation. The pepper id is recorded in the PHC string as `keyid=…`; key bytes
  are never persisted by the library.
- **Span overloads** for `HashPassword` and `VerifyPassword`
  (`ReadOnlySpan<char>` and `ReadOnlySpan<byte>`), letting callers avoid
  materializing the password as an immutable `string`.
- **ASP.NET Core Identity adapter** package
  (`Argon2id.PasswordHasher.AspNetCore`) with `IPasswordHasher<TUser>`
  implementation and a one-line `AddArgon2idPasswordHasher<TUser>` DI extension.
- **BenchmarkDotNet** harness for measuring per-hash cost across parameter
  sets.

### Changed

- `NeedsRehash` also returns `true` when a hash uses a non-active pepper.

## [0.1.0-preview.1]

### Added

- Initial release: `PasswordHasher`, `Argon2idOptions`, secure defaults
  (64 MiB / t=3 / p=1, 128-bit salt, 256-bit tag), PHC string encoding /
  decoding, constant-time verification, `NeedsRehash` for transparent
  work-factor upgrades.

[Unreleased]: https://github.com/systemslibrarian/argon2id-passwordhasher/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/systemslibrarian/argon2id-passwordhasher/compare/v0.4.0-preview.5...v1.0.0
[0.4.0-preview.5]: https://github.com/systemslibrarian/argon2id-passwordhasher/compare/v0.4.0-preview.4...v0.4.0-preview.5
[0.4.0-preview.4]: https://github.com/systemslibrarian/argon2id-passwordhasher/compare/v0.4.0-preview.3...v0.4.0-preview.4
[0.4.0-preview.3]: https://github.com/systemslibrarian/argon2id-passwordhasher/compare/v0.4.0-preview.2...v0.4.0-preview.3
[0.4.0-preview.2]: https://github.com/systemslibrarian/argon2id-passwordhasher/compare/v0.4.0-preview.1...v0.4.0-preview.2
[0.4.0-preview.1]: https://github.com/systemslibrarian/argon2id-passwordhasher/compare/v0.3.0-preview.1...v0.4.0-preview.1
[0.3.0-preview.1]: https://github.com/systemslibrarian/argon2id-passwordhasher/compare/v0.2.0-preview.1...v0.3.0-preview.1
[0.2.0-preview.1]: https://github.com/systemslibrarian/argon2id-passwordhasher/compare/v0.1.0-preview.1...v0.2.0-preview.1
[0.1.0-preview.1]: https://github.com/systemslibrarian/argon2id-passwordhasher/releases/tag/v0.1.0-preview.1
