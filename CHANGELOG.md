# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
(with `-preview.N` suffixes for previews).

## [Unreleased]

### Added

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

### Added (samples)

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

[Unreleased]: https://github.com/systemslibrarian/argon2id-passwordhasher/compare/v0.3.0-preview.1...HEAD
[0.3.0-preview.1]: https://github.com/systemslibrarian/argon2id-passwordhasher/compare/v0.2.0-preview.1...v0.3.0-preview.1
[0.2.0-preview.1]: https://github.com/systemslibrarian/argon2id-passwordhasher/compare/v0.1.0-preview.1...v0.2.0-preview.1
[0.1.0-preview.1]: https://github.com/systemslibrarian/argon2id-passwordhasher/releases/tag/v0.1.0-preview.1
