# CLAUDE.md — Project Conventions

Guidance for Claude Code (and humans) working in this repository.

## What this project is

`Argon2id.PasswordHasher` is an opinionated, secure-by-default Argon2id password
hashing library targeting **.NET 8, 9, and 10**. It wraps
`Konscious.Security.Cryptography.Argon2` with strong defaults, a standard PHC
hash format, and a small, hard-to-misuse API.

The bar is "professional-grade cryptographic library": correctness, transparency,
and honesty over feature count.

## Layout

```
src/Argon2id.PasswordHasher/              # core library (no ASP.NET dependency)
src/Argon2id.PasswordHasher.AspNetCore/   # IPasswordHasher<TUser> adapter + DI extension
tests/Argon2id.PasswordHasher.Tests/      # core xUnit tests
tests/Argon2id.PasswordHasher.AspNetCore.Tests/  # adapter xUnit tests
benchmarks/Argon2id.PasswordHasher.Benchmarks/   # BenchmarkDotNet harness
samples/Argon2id.PasswordHasher.Demo/     # runnable Blazor Server demo
docs/                                     # tuning & design notes
.github/workflows/                        # CI + CodeQL + Release pipelines
.github/ISSUE_TEMPLATE/                   # bug + feature issue forms
Directory.Build.props                     # shared build/packaging settings
global.json                               # SDK pin for reproducible CI
.editorconfig                             # repo-wide style + analyzer severities
```

The core package must stay free of ASP.NET / DI dependencies — all framework
integration lives in the `.AspNetCore` package. Inside the adapter file, alias
the core type as `using CoreHasher = Argon2id.PasswordHasher.Argon2idPasswordHasher;`
because the adapter (`Argon2idPasswordHasher<TUser>`) shares its simple name
with the core type (different arity, different namespace).

## Core design principles

1. **Secure by default.** A developer using the no-arg constructor must get a
   safe configuration. Never weaken the defaults without a strong, documented reason.
2. **Self-describing hashes.** Always emit and parse the standard PHC string
   (`$argon2id$v=19$m=...,t=...,p=...$salt$hash`). Parameters live *in* the hash.
3. **Fail safe, not loud.** `VerifyPassword` returns `false` on any malformed or
   unsupported input; it never throws on bad stored data. Constructors *do* throw
   on insecure configuration (fail fast at setup time).
4. **Constant-time comparisons.** Use `CryptographicOperations.FixedTimeEquals`.
5. **Argon2id only.** Reject argon2i/argon2d and any version other than 19.
6. **Memory hygiene.** Every password-, salt-, and candidate-hash byte buffer
   the library owns is zeroed via `CryptographicOperations.ZeroMemory` in
   `finally` blocks.
7. **Be honest.** Every real limitation goes in `KNOWN-GAPS.md`.

## Coding conventions

- Target `net8.0`, `net9.0`, `net10.0` (multi-targeted from
  `Directory.Build.props`). `Nullable` and `ImplicitUsings` are enabled.
- **Warnings are errors** (`TreatWarningsAsErrors`); analyzers run at
  `latest-recommended`. Keep the build clean — no suppressions without a comment
  explaining why.
- **Public API is locked** via `Microsoft.CodeAnalysis.PublicApiAnalyzers`. Any
  new or changed public API must be reflected in `PublicAPI.Unshipped.txt`
  beside the project's csproj. The analyzer offers a code fix.
- Public APIs require XML doc comments (`GenerateDocumentationFile` is on).
- Prefer `record`/`sealed` types; keep the public surface minimal and intentional.
- No new dependencies without justification. The runtime dependency set is
  intentionally tiny (Konscious + per-TFM Identity.Core for the adapter).
- Assemblies are marked `IsTrimmable` + `IsAotCompatible`; don't introduce
  reflection-heavy or dynamic-code paths.

## Testing

- xUnit. Run `dotnet test` from the repo root.
- Tests use deliberately light Argon2 parameters (8 MiB / 1 iteration) for speed —
  never copy those into production code or docs as recommendations.
- Cover round-trip, wrong-password, malformed-input, tamper, rehash, Unicode,
  concurrency, and PHC golden-format cases at minimum. Add a test with every
  behavior change.

## Packaging

- Versioning is SemVer with preview suffixes (e.g. `0.4.0-preview.1`).
- Single `<Version>` source of truth in `Directory.Build.props`.
- Full NuGet metadata + SourceLink + deterministic builds + `NuGetAudit` are
  set in the `.csproj` and `Directory.Build.props`. Keep them in sync when
  bumping versions.
- Update `CHANGELOG.md` under `## [Unreleased]` for every user-visible change.

## CI / supply chain

- **CI** (`.github/workflows/ci.yml`): `dotnet format --verify-no-changes`,
  then build + test matrix across Ubuntu/Windows/macOS for all three TFMs.
- **CodeQL** (`codeql.yml`): weekly + per-PR scan with `security-and-quality`.
- **Release** (`release.yml`): on `v*` tag — full test matrix, then pack +
  build-provenance attestation + NuGet push + GitHub Release with
  auto-generated notes.
- **Dependabot** (`.github/dependabot.yml`): weekly grouped updates for
  `nuget` and `github-actions` ecosystems.

## Commit / PR discipline

- Small, focused commits. Don't commit `bin/`, `obj/`, or other build output.
- Don't commit or push unless explicitly asked.
- Security-relevant changes must update `SECURITY.md` and/or `KNOWN-GAPS.md`.
- PR template: `.github/PULL_REQUEST_TEMPLATE.md`.

---

*To God be the glory — 1 Corinthians 10:31.*
