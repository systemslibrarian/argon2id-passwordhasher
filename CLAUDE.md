# CLAUDE.md — Project Conventions

Guidance for Claude Code (and humans) working in this repository.

## What this project is

`Argon2id.PasswordHasher` is an opinionated, secure-by-default Argon2id password
hashing library for .NET 10. It wraps `Konscious.Security.Cryptography.Argon2` with
strong defaults, a standard PHC hash format, and a small, hard-to-misuse API.

The bar is "professional-grade cryptographic library": correctness, transparency,
and honesty over feature count.

## Layout

```
src/Argon2id.PasswordHasher/              # core library (no ASP.NET dependency)
src/Argon2id.PasswordHasher.AspNetCore/   # IPasswordHasher<TUser> adapter + DI extension
tests/Argon2id.PasswordHasher.Tests/      # core xUnit tests
tests/Argon2id.PasswordHasher.AspNetCore.Tests/  # adapter xUnit tests
benchmarks/Argon2id.PasswordHasher.Benchmarks/   # BenchmarkDotNet harness
docs/                                     # tuning & design notes
.github/workflows/                        # CI (build/test) + Release (pack/publish)
Directory.Build.props                     # shared build/packaging settings
```

The core package must stay free of ASP.NET / DI dependencies — all framework
integration lives in the `.AspNetCore` package. Because the root namespace
(`Argon2id.PasswordHasher`) ends with the same segment as the `PasswordHasher` type,
reference the core class from child namespaces via a `global::`-qualified alias
(`using CoreHasher = global::Argon2id.PasswordHasher.PasswordHasher;`).

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
6. **Be honest.** Every real limitation goes in `KNOWN-GAPS.md`.

## Coding conventions

- Target `net10.0` only. `Nullable` and `ImplicitUsings` are enabled.
- **Warnings are errors** (`TreatWarningsAsErrors`); analyzers run at
  `latest-recommended`. Keep the build clean — no suppressions without a comment
  explaining why.
- Public APIs require XML doc comments (`GenerateDocumentationFile` is on).
- Prefer `record`/`sealed` types; keep the public surface minimal and intentional.
- No new dependencies without justification. The runtime dependency set is
  intentionally tiny (Konscious + SourceLink for packaging).

## Testing

- xUnit. Run `dotnet test` from the repo root.
- Tests use deliberately light Argon2 parameters (8 MiB / 1 iteration) for speed —
  never copy those into production code or docs as recommendations.
- Cover round-trip, wrong-password, malformed-input, tamper, rehash, and Unicode
  cases at minimum. Add a test with every behavior change.

## Packaging

- Versioning is SemVer with preview suffixes (`0.1.0-preview.1`).
- Full NuGet metadata + SourceLink + deterministic builds live in the `.csproj`
  and `Directory.Build.props`. Keep them in sync when bumping versions.

## Commit / PR discipline

- Small, focused commits. Don't commit `bin/`, `obj/`, or other build output.
- Don't commit or push unless explicitly asked.
- Security-relevant changes must update `SECURITY.md` and/or `KNOWN-GAPS.md`.

---

*To God be the glory — 1 Corinthians 10:31.*
