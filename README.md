<div align="center">

# 🔐 Argon2id.PasswordHasher

**The opinionated, secure-by-default Argon2id password hasher for .NET 8, 9, and 10.**

[![CI](https://github.com/systemslibrarian/argon2id-passwordhasher/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/systemslibrarian/argon2id-passwordhasher/actions/workflows/ci.yml)
[![CodeQL](https://github.com/systemslibrarian/argon2id-passwordhasher/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/systemslibrarian/argon2id-passwordhasher/actions/workflows/codeql.yml)
[![Pages](https://github.com/systemslibrarian/argon2id-passwordhasher/actions/workflows/pages.yml/badge.svg?branch=main)](https://systemslibrarian.github.io/argon2id-passwordhasher/)
[![NuGet](https://img.shields.io/nuget/vpre/Argon2id.PasswordHasher.svg?logo=nuget&label=Argon2id.PasswordHasher)](https://www.nuget.org/packages/Argon2id.PasswordHasher)
[![NuGet (AspNetCore)](https://img.shields.io/nuget/vpre/Argon2id.PasswordHasher.AspNetCore.svg?logo=nuget&label=.AspNetCore)](https://www.nuget.org/packages/Argon2id.PasswordHasher.AspNetCore)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![.NET](https://img.shields.io/badge/.NET-8%20%7C%209%20%7C%2010-512BD4.svg)](https://dotnet.microsoft.com/)
[![AOT](https://img.shields.io/badge/AOT-compatible-success.svg)](#)

*Memory-hard password hashing that's hard to get wrong.*

</div>

---

Argon2id.PasswordHasher wraps a vetted Argon2id implementation in a tiny, hard-to-misuse API
with **strong defaults out of the box**. You get memory-hard resistance to GPU/ASIC cracking
(RFC 9106 / OWASP-aligned), self-describing hashes that carry their own parameters, constant-time
verification, an optional keyed **pepper** with rotation, and a one-line ASP.NET Core Identity
integration — without having to become a cryptographer first.

```csharp
using Argon2id.PasswordHasher;

var hasher = new Argon2idPasswordHasher();

string stored = hasher.HashPassword("correct horse battery staple");
//   $argon2id$v=19$m=65536,t=3,p=1$<salt>$<hash>

bool ok = hasher.VerifyPassword("correct horse battery staple", stored); // true
```

## Try the demo

There are two runnable samples, sharing the same UX so you can pick whichever
fits what you want to show:

| Sample | Where it runs | When to use it |
| --- | --- | --- |
| [**Live WASM demo**](https://systemslibrarian.github.io/argon2id-passwordhasher/) | In your browser, no install | Quickest way to try the library. Hashing runs on your CPU via WebAssembly. Auto-deployed to GitHub Pages on every push. |
| [`samples/Argon2id.PasswordHasher.Demo`](samples/Argon2id.PasswordHasher.Demo) | Blazor Server (local) | Shows production-shape integration: DI, antiforgery, rate limiting, HSTS, CSP, constant-time login, memory-cost DoS gate. |
| [`samples/Argon2id.PasswordHasher.WasmDemo`](samples/Argon2id.PasswordHasher.WasmDemo) | Blazor WebAssembly (local) | Same UX as the live demo, but running against the in-tree library. Edit and refresh. |

Run either locally:

```bash
git clone https://github.com/systemslibrarian/argon2id-passwordhasher.git
cd argon2id-passwordhasher

# Server flavor (production-shape, hardened):
dotnet run --project samples/Argon2id.PasswordHasher.Demo

# WASM flavor (same UX as the live demo):
dotnet run --project samples/Argon2id.PasswordHasher.WasmDemo
```

Both samples use a `ProjectReference` to the in-tree library, so they always
exercise the version you're working on. **They are demos, not starter
templates** — users live in memory and hash internals are shown on screen for
educational clarity (see each sample's own README).

## Table of contents

- [Why this library](#why-this-library)
- [Packages](#packages)
- [Install](#install)
- [Quick start](#quick-start)
- [The hash format](#the-hash-format)
- [Configuration](#configuration)
- [Upgrading work factor (rehash on login)](#upgrading-work-factor-rehash-on-login)
- [Avoiding `string` passwords (span overloads)](#avoiding-string-passwords-span-overloads)
- [Pepper (secret key) with rotation](#pepper-secret-key-with-rotation)
- [ASP.NET Core Identity](#aspnet-core-identity)
- [Trimming & Native AOT](#trimming--native-aot)
- [Security posture](#security-posture)
- [API reference](#api-reference)
- [FAQ](#faq)
- [Building, testing & benchmarks](#building-testing--benchmarks)
- [Versioning & status](#versioning--status)
- [Contributing & security](#contributing--security)
- [License & acknowledgements](#license--acknowledgements)

## Why this library

| | |
| --- | --- |
| 🛡️ **Secure by default** | The no-arg constructor gives you 64 MiB / t=3 / p=1 — comfortably above the OWASP minimum. No footguns to configure. |
| 📦 **Self-describing hashes** | Every hash is a standard **PHC string** containing its own parameters, so verification never breaks when you raise the work factor. |
| ♻️ **Built-in upgrade path** | `NeedsRehash` tells you when a stored hash is weaker than your current settings (or uses an old pepper) so you can upgrade users transparently. |
| ⏱️ **Constant-time** | Final comparison uses `CryptographicOperations.FixedTimeEquals`. |
| 🌶️ **Pepper with rotation** | Optional keyed secret kept outside your database, with first-class key rotation. |
| 🧩 **ASP.NET Core ready** | Drop-in `IPasswordHasher<TUser>` + a one-line DI extension. |
| 🚀 **Trim + AOT compatible** | Marked `IsTrimmable` and `IsAotCompatible` so Native AOT consumers just work. |
| 🧼 **Tiny & honest** | One runtime dependency. Every real limitation is documented in [`KNOWN-GAPS.md`](KNOWN-GAPS.md). |

## Packages

| Package | Purpose | Depends on |
| --- | --- | --- |
| [`Argon2id.PasswordHasher`](https://www.nuget.org/packages/Argon2id.PasswordHasher) | Core hasher — no web/framework dependency | Konscious.Security.Cryptography.Argon2 |
| [`Argon2id.PasswordHasher.AspNetCore`](https://www.nuget.org/packages/Argon2id.PasswordHasher.AspNetCore) | `IPasswordHasher<TUser>` adapter + DI extension | the core package + Microsoft.Extensions.Identity.Core |

Both packages target **`net8.0`, `net9.0`, and `net10.0`**.

## Install

```bash
# Core
dotnet add package Argon2id.PasswordHasher --prerelease

# Optional: ASP.NET Core Identity integration
dotnet add package Argon2id.PasswordHasher.AspNetCore --prerelease
```

## Quick start

**Registration** — hash the password and store the returned string:

```csharp
var hasher = new Argon2idPasswordHasher();
user.PasswordHash = hasher.HashPassword(password);
await db.SaveChangesAsync();
```

**Login** — verify against the stored string:

```csharp
if (!hasher.VerifyPassword(password, user.PasswordHash))
    return Unauthorized();

// Optionally strengthen the stored hash if your settings have grown:
if (hasher.NeedsRehash(user.PasswordHash))
{
    user.PasswordHash = hasher.HashPassword(password);
    await db.SaveChangesAsync();
}
```

`VerifyPassword` **never throws** on bad input: a `null`, empty, malformed, or non-Argon2id
stored value simply returns `false`.

> [!TIP]
> `Argon2idPasswordHasher` is stateless and thread-safe. Create one and reuse it (e.g. register
> it as a singleton) rather than constructing one per request.

## The hash format

Hashes are emitted in the standard **PHC string format** used by libsodium and the Argon2
reference implementation:

```
$argon2id$v=19$m=65536,t=3,p=1$<base64 salt>$<base64 hash>
└── alg ──┘└ ver ┘└── cost params ──┘└── salt ──┘└── hash ──┘
```

Because the parameters live *inside* the string, the hash is **portable** and **self-verifying**:
you can change your defaults whenever you like and old hashes keep validating with the parameters
they were created with. When a pepper is used, an extra `keyid=<id>` parameter is added so
verification can select the right secret.

## Configuration

Pass an `Argon2idOptions` to tune the work factor. Invalid values (below the safe minimums) throw
`ArgumentOutOfRangeException` at construction — fail fast, not silently weak.

```csharp
var hasher = new Argon2idPasswordHasher(new Argon2idOptions
{
    MemorySizeKib       = 131072, // 128 MiB
    Iterations          = 4,
    DegreeOfParallelism = 1,
});
```

| Option | Default | Minimum | Notes |
| --- | --- | --- | --- |
| `MemorySizeKib` | `65536` (64 MiB) | `8192` | Primary GPU/ASIC defense. Raise this first. |
| `Iterations` | `3` | `1` | Passes over memory (linear CPU cost). |
| `DegreeOfParallelism` | `1` | `1` | Lanes/threads per hash. Keep low on shared servers. |
| `SaltSizeBytes` | `16` (128-bit) | `16` | RFC 9106 recommendation. |
| `HashSizeBytes` | `32` (256-bit) | `16` | Output (tag) length. |

**Why these defaults?** They're a strong, general-purpose baseline for 2026 server hardware that
exceeds the current OWASP minimum (Argon2id, 19 MiB, t=2, p=1) while keeping `p=1` so per-hash CPU
stays predictable under concurrent logins. They are **not** tuned to *your* machine — measure and
adjust. See [`docs/parameter-tuning.md`](docs/parameter-tuning.md) and the
[benchmark project](benchmarks/Argon2id.PasswordHasher.Benchmarks).

`Argon2idOptions.Recommended` exposes the defaults explicitly.

## Upgrading work factor (rehash on login)

Security guidance gets stronger over time. When you raise your parameters, existing users upgrade
themselves the next time they sign in — no mass migration, no broken logins:

```csharp
if (hasher.VerifyPassword(password, user.PasswordHash))
{
    if (hasher.NeedsRehash(user.PasswordHash))
        user.PasswordHash = hasher.HashPassword(password); // re-hashed with current settings
    // sign the user in...
}
```

`NeedsRehash` returns `true` when the stored hash is unparseable, any stored parameter is below
your current configuration, or (with a pepper ring) the hash doesn't use your active pepper.

## Avoiding `string` passwords (span overloads)

`HashPassword` / `VerifyPassword` also accept `ReadOnlySpan<char>` and `ReadOnlySpan<byte>`, so you
can hash a credential without ever materializing it as a `string`. The hasher zeroes every
password-derived buffer it owns.

```csharp
ReadOnlySpan<char> pw = GetPasswordChars();
string hash = hasher.HashPassword(pw);
bool ok    = hasher.VerifyPassword(pw, hash);
```

> [!NOTE]
> .NET cannot reliably wipe an immutable `string` from memory. Prefer the span overloads when the
> password doesn't otherwise need to be a `string`. See [`KNOWN-GAPS.md`](KNOWN-GAPS.md) §1.

## Pepper (secret key) with rotation

A **pepper** is an application secret mixed into every hash and kept **outside** the database (in a
key vault, KMS, or environment variable). If your password table leaks but the pepper doesn't, the
stolen hashes can't be cracked offline. Peppers here are **keyed and rotatable** — each hash records
*which* pepper produced it (via the PHC `keyid`), and the key bytes are never stored.

```csharp
byte[] key = GetPepperFromVault();             // ≥ 16 bytes, kept secret
var ring   = new PepperRing(new Pepper("2026-05", key));
var hasher = new Argon2idPasswordHasher(Argon2idOptions.Recommended, ring);

string hash = hasher.HashPassword(password);
//   $argon2id$v=19$m=65536,t=3,p=1,keyid=<id>$<salt>$<hash>
```

**Rotation** — promote a new active key and keep the old one as *retired* so existing hashes still
verify; `NeedsRehash` then upgrades them on the next login:

```csharp
var rotated = new PepperRing(
    active:  new Pepper("2026-11", newKey),
    retired: new Pepper("2026-05", oldKey));
```

> [!WARNING]
> The library never persists pepper keys — that's your responsibility. **Lose the active key and
> you lose the ability to verify hashes made with it.** Back up and retire keys deliberately.

## ASP.NET Core Identity

Install `Argon2id.PasswordHasher.AspNetCore` and register the hasher in one line:

```csharp
builder.Services
    .AddIdentityCore<IdentityUser>()
    .Services
    .AddArgon2idPasswordHasher<IdentityUser>(); // optional: pass Argon2idOptions and/or a PepperRing
```

This registers an `IPasswordHasher<TUser>` backed by Argon2id and shares a single core hasher as a
singleton. Verification maps cleanly onto Identity's contract:

| Result | When |
| --- | --- |
| `Success` | Password matches and the hash is up to date. |
| `SuccessRehashNeeded` | Password matches but the hash is weaker than current settings / uses an old pepper. Identity rehashes it automatically. |
| `Failed` | Password doesn't match, or the stored value is malformed. |

## Trimming & Native AOT

Both packages are marked `IsTrimmable=true` and `IsAotCompatible=true`. No reflection, no dynamic
codegen, no `System.Reflection.Emit` — the library uses only BCL crypto primitives plus the
Konscious managed Argon2 implementation. Native AOT consumers can publish trimmed binaries without
warnings.

## Security posture

| Concern | How this library handles it |
| --- | --- |
| GPU / ASIC cracking | Argon2id, memory-hard (64 MiB default) |
| Rainbow tables | 128-bit cryptographically random salt per hash (`RandomNumberGenerator`) |
| Parameter drift | Parameters embedded in the PHC string + `NeedsRehash` |
| Timing side channels | `FixedTimeEquals` on the final comparison |
| Sensitive memory | Password, salt, and candidate hash buffers zeroed with `CryptographicOperations.ZeroMemory`; `Span` overloads avoid `string` |
| Database-only leak | Optional keyed **pepper** (secret kept outside the DB), with rotation |
| Algorithm confusion | Verifier accepts only `argon2id`, version 19 |
| Insecure config | Below-minimum parameters throw at construction |
| Supply chain | SourceLink, deterministic builds, `NuGetAudit` at build time, CodeQL, build-provenance attestations on every release |

**This library is one layer.** It does not provide rate limiting, account lockout, breached-password
checks, or MFA — those belong at your application/identity layer. For a frank account of everything
it does *not* do (plaintext `string` lifetime, memory-cost DoS, and more), read
[`KNOWN-GAPS.md`](KNOWN-GAPS.md). Transparency is a feature.

## API reference

**`Argon2idPasswordHasher`**

```csharp
Argon2idPasswordHasher()                                          // recommended defaults, no pepper
Argon2idPasswordHasher(Argon2idOptions options)                   // custom parameters
Argon2idPasswordHasher(Argon2idOptions options, PepperRing? pepper)

string HashPassword(string password)
string HashPassword(ReadOnlySpan<char> password)
string HashPassword(ReadOnlySpan<byte> password)

bool   VerifyPassword(string password, string encodedHash)
bool   VerifyPassword(ReadOnlySpan<char> password, string encodedHash)
bool   VerifyPassword(ReadOnlySpan<byte> password, string encodedHash)

VerifyResult Verify(string password, string encodedHash)           // single-parse: returns Success + NeedsRehash
VerifyResult Verify(ReadOnlySpan<char> password, string encodedHash)
VerifyResult Verify(ReadOnlySpan<byte> password, string encodedHash)

bool   NeedsRehash(string encodedHash)

Argon2idOptions Options { get; }
```

**`VerifyResult`** (readonly record struct) — `Success`, `NeedsRehash`,
`static Failed`. Returned by `Verify(...)`.

**`Argon2idOptions`** (record) — `MemorySizeKib`, `Iterations`, `DegreeOfParallelism`,
`SaltSizeBytes`, `HashSizeBytes`, `Validate()`, `static Recommended`.

**`Pepper`** — `Pepper(string id, byte[] key)`, `string Id`.
**`PepperRing`** — `PepperRing(Pepper active, params Pepper[] retired)`, `Pepper Active`.

**`Argon2id.PasswordHasher.AspNetCore`** — `Argon2idPasswordHasher<TUser> : IPasswordHasher<TUser>`
and `IServiceCollection.AddArgon2idPasswordHasher<TUser>(options?, pepper?)`.

The full public surface is locked by [`Microsoft.CodeAnalysis.PublicApiAnalyzers`](https://github.com/dotnet/roslyn-analyzers/blob/main/src/PublicApiAnalyzers/PublicApiAnalyzers.Help.md);
see `PublicAPI.Shipped.txt` / `PublicAPI.Unshipped.txt` next to each csproj.

## FAQ

**Which Argon2 variant?** Argon2id only — RFC 9106's recommended variant. Argon2i/Argon2d are
intentionally not offered, and the verifier rejects them.

**Are hashes interoperable with other Argon2 libraries?** Yes for the standard form — it's the same
PHC string libsodium and the reference implementation use. The optional `keyid` parameter is a PHC
extension some parsers may not expect.

**Do I need to store the salt separately?** No. The salt (and all parameters) are part of the
returned string. Store that single value.

**How slow should hashing be?** Aim for roughly 100–500 ms per hash on your production hardware for
interactive logins. Benchmark and tune — see [`docs/parameter-tuning.md`](docs/parameter-tuning.md).

**Can I hash API keys / tokens with this?** It's designed for *human* passwords. High-entropy
secrets don't need memory-hard hashing; a fast keyed hash (HMAC/SHA-256) is usually the right tool.

## Building, testing & benchmarks

```bash
dotnet build -c Release
dotnet test  -c Release

# Run the benchmarks (Release only)
dotnet run -c Release --project benchmarks/Argon2id.PasswordHasher.Benchmarks

# Run the Blazor demo
dotnet run --project samples/Argon2id.PasswordHasher.Demo
```

Repository layout:

```
src/Argon2id.PasswordHasher/              core library
src/Argon2id.PasswordHasher.AspNetCore/   IPasswordHasher<TUser> adapter + DI
tests/                                     xUnit test projects
benchmarks/                                BenchmarkDotNet harness
samples/Argon2id.PasswordHasher.Demo/      runnable Blazor Server demo (hardened)
samples/Argon2id.PasswordHasher.WasmDemo/  Blazor WebAssembly demo (deployed to GH Pages)
docs/                                      tuning & design notes
.github/                                   CI, CodeQL, Dependabot, templates
```

CI builds and tests on every push/PR across Ubuntu, Windows, and macOS for all three TFMs.
CodeQL scans run weekly. Tagged releases (`v*`) pack and publish both packages with build-provenance
attestations.

## Versioning & status

`0.3.0-preview.1` — **preview**. Follows SemVer with preview suffixes. The API and defaults may
still change before `1.0.0`; hashes use the standard PHC format and are expected to stay verifiable.

See [`CHANGELOG.md`](CHANGELOG.md) for the full version history.

## Contributing & security

Issues and PRs are welcome — see [`CONTRIBUTING.md`](CONTRIBUTING.md) and
[`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md). Security-relevant changes should update
[`SECURITY.md`](SECURITY.md) and/or [`KNOWN-GAPS.md`](KNOWN-GAPS.md).

**Found a vulnerability?** Please report it privately — see [`SECURITY.md`](SECURITY.md). Do not
open public issues for security reports.

## License & acknowledgements

[MIT](LICENSE) © Paul Clark. See [`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md) for upstream
attributions.

Built on [Konscious.Security.Cryptography.Argon2](https://github.com/kmaragon/Konscious.Security.Cryptography),
an MIT-licensed managed Argon2 implementation. Parameter guidance follows
[RFC 9106](https://www.rfc-editor.org/rfc/rfc9106) and the
[OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).

---

<div align="center">

*To God be the glory — 1 Corinthians 10:31.*

</div>
