# Contributing

Thank you for considering a contribution to **Argon2id.PasswordHasher** — a
small, security-sensitive library where every line is intentional. Issues, bug
reports, and well-scoped pull requests are all welcome.

## Code of conduct

Participation in this project is governed by the
[Code of Conduct](CODE_OF_CONDUCT.md). By participating you agree to uphold it.

## Reporting a security vulnerability

**Do not open a public issue.** Use GitHub's
[private security advisories](https://github.com/systemslibrarian/argon2id-passwordhasher/security/advisories/new)
to report a vulnerability. See [`SECURITY.md`](SECURITY.md) for full details.

## Getting set up

You need the **.NET 10 SDK** (pinned in [`global.json`](global.json)) to build.
CI also exercises the library against `net8.0` and `net9.0`; locally you can
restrict yourself to a single TFM via `--framework net10.0` while iterating.

```bash
dotnet restore
dotnet build  -c Release
dotnet test   -c Release
```

For a one-shot end-to-end check matching what CI runs:

```bash
dotnet format --verify-no-changes
dotnet build  -c Release --no-restore -warnaserror
dotnet test   -c Release --no-build
```

## Repository layout

```
src/Argon2id.PasswordHasher/              core library
src/Argon2id.PasswordHasher.AspNetCore/   IPasswordHasher<TUser> adapter + DI
tests/                                     xUnit test projects
benchmarks/                                BenchmarkDotNet harness
docs/                                      tuning + design notes
.github/                                   CI, CodeQL, Dependabot, templates
```

See [`CLAUDE.md`](CLAUDE.md) for the design principles that govern the codebase
(secure-by-default, self-describing hashes, fail-safe verification, etc.).

## Style and conventions

- `dotnet format` is enforced in CI — run it before committing.
- Warnings are errors (`TreatWarningsAsErrors=true`). Do not silence analyzer
  rules without a comment explaining why.
- Public API surface is locked by `Microsoft.CodeAnalysis.PublicApiAnalyzers`.
  When you add or change a public API, the analyzer offers a one-click fix that
  appends the new signature to `PublicAPI.Unshipped.txt`. Take that fix.
- Every public API needs an XML doc comment.
- Tests use deliberately light Argon2 parameters (8 MiB / t=1) for speed. Never
  copy those into production code or docs as recommendations.

## Pull request checklist

- [ ] `dotnet format --verify-no-changes` passes locally.
- [ ] `dotnet build -c Release` produces no warnings.
- [ ] `dotnet test -c Release` passes (all TFMs you can run).
- [ ] Public-API additions appear in `PublicAPI.Unshipped.txt`.
- [ ] User-visible changes have a `CHANGELOG.md` entry under `## [Unreleased]`.
- [ ] Security-relevant changes update `SECURITY.md` and/or `KNOWN-GAPS.md`.

## Scope guidance

This library is intentionally small. Before proposing a feature, ask whether it
belongs at the *hashing* layer or at a higher layer (your identity stack, your
web framework, your rate limiter). See [`KNOWN-GAPS.md`](KNOWN-GAPS.md) for a
list of things this library deliberately does **not** do.

---

*To God be the glory — 1 Corinthians 10:31.*
