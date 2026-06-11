# Argon2id.PasswordHasher

An opinionated, secure-by-default Argon2id password hashing library for
.NET 8, 9, and 10. Memory-hard resistance to GPU/ASIC cracking
(RFC 9106 / OWASP-aligned), self-describing PHC hash strings, constant-time
verification, optional keyed pepper with rotation, and a one-line ASP.NET
Core Identity integration.

```csharp
using Argon2id.PasswordHasher;

var hasher = new Argon2idPasswordHasher();

string stored = hasher.HashPassword("correct horse battery staple");
// $argon2id$v=19$m=65536,t=3,p=1$<salt>$<hash>

bool ok = hasher.VerifyPassword("correct horse battery staple", stored); // true
```

## Where to start

- **[Parameter tuning](parameter-tuning.md)** — how to pick `m`, `t`, `p` for
  *your* hardware and your latency budget.
- **[Pepper & key management](pepper-key-management.md)** — keyed hashing,
  rotation, and loading the pepper from a vault/KMS.
- **Migrating an existing user store** — from
  [ASP.NET Core Identity (PBKDF2)](migrate-from-identity.md) or
  [BCrypt](migrate-from-bcrypt.md), with zero downtime and no forced resets.
- **[API reference](api/index.md)** — every public type, generated from the source
  XML doc comments. Mirrors `PublicAPI.Shipped.txt` in the repo.
- **[Live demo](https://systemslibrarian.github.io/argon2id-passwordhasher/)** —
  the Blazor WebAssembly sample running in your browser. Try register / login
  / see-the-PHC-string without installing anything.
- **[README](https://github.com/systemslibrarian/argon2id-passwordhasher#readme)** —
  full project overview, security posture, install, and FAQ.

## Packages

| Package | Purpose | TFMs |
| --- | --- | --- |
| [`Argon2id.PasswordHasher`](https://www.nuget.org/packages/Argon2id.PasswordHasher) | Core hasher — no web/framework dependency | net8.0, net9.0, net10.0 |
| [`Argon2id.PasswordHasher.AspNetCore`](https://www.nuget.org/packages/Argon2id.PasswordHasher.AspNetCore) | `IPasswordHasher<TUser>` adapter + DI extension | net8.0, net9.0, net10.0 |

## Status

Preview (`0.4.0-preview.5`). Public API is locked by
`Microsoft.CodeAnalysis.PublicApiAnalyzers`. Hashes use the standard PHC
format and are expected to remain verifiable through 1.0.

See [`SECURITY.md`](https://github.com/systemslibrarian/argon2id-passwordhasher/blob/main/SECURITY.md)
for the supported-versions matrix and the private vulnerability-reporting
channel.

---

*To God be the glory — 1 Corinthians 10:31.*
