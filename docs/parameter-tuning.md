# Parameter Tuning Guide

Argon2id has three work-factor knobs. This guide explains them and how to pick
values for *your* hardware. The library's defaults are a strong baseline, not a
substitute for measuring.

## The three parameters

| Parameter | `Argon2idOptions` property | Default | What it controls |
| --- | --- | --- | --- |
| Memory cost (`m`) | `MemorySizeKib` | `65536` (64 MiB) | RAM per hash — the main GPU/ASIC defense |
| Time cost (`t`) | `Iterations` | `3` | Passes over memory — linear CPU cost |
| Parallelism (`p`) | `DegreeOfParallelism` | `1` | Lanes/threads used per hash |

Plus two output sizes: `SaltSizeBytes` (default 16) and `HashSizeBytes` (default 32).
Leave these at the defaults unless you have a specific reason.

## How to choose

1. **Start from the defaults.** They exceed the OWASP minimum
   (Argon2id, 19 MiB, t=2, p=1).
2. **Pick a latency target.** A common rule of thumb for interactive login is
   ~100–500 ms per hash on your production hardware.
3. **Prefer memory over iterations.** Memory hardness is what defeats GPUs. Raise
   `MemorySizeKib` first; only add `Iterations` once memory is as high as your
   concurrency budget allows.
4. **Mind concurrency.** Each in-flight hash holds `m` KiB of RAM. At 64 MiB,
   100 simultaneous logins ≈ 6.4 GiB. Size `m` against peak concurrent logins,
   not just single-hash cost.
5. **Keep `p` low on shared servers.** `p = 1` keeps per-hash CPU predictable and
   leaves cores free to serve concurrent requests.

## Measuring

A quick local benchmark sketch:

```csharp
using System.Diagnostics;
using Argon2id.PasswordHasher;

var hasher = new PasswordHasher(new Argon2idOptions { MemorySizeKib = 65536, Iterations = 3 });
var sw = Stopwatch.StartNew();
hasher.HashPassword("benchmark password");
sw.Stop();
Console.WriteLine($"{sw.ElapsedMilliseconds} ms");
```

Run it several times on the target hardware and adjust `MemorySizeKib` /
`Iterations` until you hit your latency target.

## Raising the work factor later

Because every hash stores its own parameters, you can raise the defaults at any
time without breaking existing users:

```csharp
if (hasher.VerifyPassword(password, user.PasswordHash) && hasher.NeedsRehash(user.PasswordHash))
{
    user.PasswordHash = hasher.HashPassword(password); // upgraded in place
}
```

Old hashes keep verifying with their stored (weaker) parameters; each user is
transparently upgraded on their next successful login.

## References

- [RFC 9106 — Argon2](https://www.rfc-editor.org/rfc/rfc9106)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

---

*To God be the glory — 1 Corinthians 10:31.*
