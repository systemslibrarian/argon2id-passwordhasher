# Migration guide

This guide is for teams **already shipping** a user store with passwords
hashed by something other than Argon2id — most commonly the default ASP.NET
Core Identity `PasswordHasher<TUser>` (PBKDF2 with HMAC-SHA-512, 100 000
iterations as of Identity v3 / .NET 8+).

The goal: switch to Argon2id with **zero downtime, zero forced password
resets, and zero broken logins**.

## TL;DR

If you're on ASP.NET Core Identity and want the safest, shortest path:

```csharp
// Program.cs — was:
builder.Services
    .AddIdentityCore<IdentityUser>()
    .AddEntityFrameworkStores<AppDbContext>();

// Now:
builder.Services
    .AddIdentityCore<IdentityUser>()
    .AddArgon2idPasswordHasherWithMigration<IdentityUser>() // <— one line
    .AddEntityFrameworkStores<AppDbContext>();
```

That's it. Existing users keep logging in with their PBKDF2 hashes; each
successful login transparently upgrades the stored value to Argon2id.

## How it works

`AddArgon2idPasswordHasherWithMigration<TUser>()` registers a
[`MigratingPasswordHasher<TUser>`](src/Argon2id.PasswordHasher.AspNetCore/MigratingPasswordHasher.cs)
as ASP.NET Core Identity's `IPasswordHasher<TUser>`. It wraps two hashers:

1. **`Argon2idPasswordHasher<TUser>`** — used to **produce** every new
   hash and to **verify** any stored value that begins with `$argon2id$`
   (the standard PHC prefix).
2. **`PasswordHasher<TUser>`** (the stock ASP.NET Core Identity PBKDF2
   implementation) — used to **verify** any other stored value, including
   the v2 and v3 PBKDF2 formats the default hasher has ever produced.

Routing is purely format-based. Pseudocode:

```text
verify(stored, password):
    if stored starts with "$argon2id$":
        return argon2id.verify(stored, password)
    legacy_result = legacy.verify(stored, password)            ← PBKDF2
    if legacy_result == Success:
        return SuccessRehashNeeded                              ← !
    return legacy_result
```

`SuccessRehashNeeded` is the standard Identity signal that tells
`SignInManager` / `UserManager` to call `HashPassword(user, plaintext)`
again and persist the new hash. `HashPassword` always emits Argon2id, so
the database transparently migrates one user at a time, at their next
successful sign-in.

## What "garbage in the column" does

The migrating adapter is **fail-safe**: a `null`, empty, or unparseable
stored value returns `PasswordVerificationResult.Failed`, never throws.
This matters because the stock `PasswordHasher<TUser>` does throw on
malformed input.

## What about users who never log in?

They keep the old hash forever. There is no background re-hashing because
**we don't have the plaintext** — `HashPassword` requires the password,
and the password only flows through your handler on a real sign-in.

Three options for the long tail:

1. **Let it ride.** The old PBKDF2 hash is still strong; the only cost of
   not migrating it is that you remain dependent on the stock hasher for
   verification. This is the recommended default.
2. **Decommission the legacy hasher** at a future flag day. Force a
   password reset for anyone whose stored hash still doesn't begin with
   `$argon2id$`. Operationally: a `Users.PasswordHash NOT LIKE '$argon2id$%'`
   query → password-reset email blast → eventual hard cutoff.
3. **Pre-migrate at the next opportunity.** If your auth flow has a
   "confirm password" or "change password" prompt for any reason
   (security event, billing change, MFA enrollment), use that as a
   rehash trigger. Even though those flows ultimately call
   `ChangePasswordAsync` / `CreateAsync`, the new hash will be Argon2id.

## Migrating from other algorithms

If your existing store uses **bcrypt**, **scrypt**, or an older custom
scheme that isn't compatible with the stock `PasswordHasher<TUser>`,
write a small adapter that implements `IPasswordHasher<TUser>` against
your existing scheme and pass it to `MigratingPasswordHasher`:

```csharp
public sealed class BCryptIPasswordHasher<TUser> : IPasswordHasher<TUser>
    where TUser : class
{
    public string HashPassword(TUser user, string password)
        => throw new InvalidOperationException(
            "BCryptIPasswordHasher only verifies — Argon2id handles new hashes.");

    public PasswordVerificationResult VerifyHashedPassword(
        TUser user, string hashedPassword, string providedPassword)
    {
        return BCrypt.Net.BCrypt.Verify(providedPassword, hashedPassword)
            ? PasswordVerificationResult.Success
            : PasswordVerificationResult.Failed;
    }
}

// Wire it up:
builder.Services.AddIdentityCore<IdentityUser>();
builder.Services.AddArgon2idPasswordHasher<IdentityUser>();
builder.Services.Replace(ServiceDescriptor.Singleton<IPasswordHasher<IdentityUser>>(sp =>
    new MigratingPasswordHasher<IdentityUser>(
        new Argon2idPasswordHasher<IdentityUser>(
            sp.GetRequiredService<Argon2idPasswordHasher>()),
        new BCryptIPasswordHasher<IdentityUser>())));
```

Same pattern works for any verify-only legacy implementation.

## Verifying the migration

Two things to watch in production:

1. **`PasswordVerificationResult.SuccessRehashNeeded` rate.** Right after
   you deploy, every legacy user's sign-in returns `SuccessRehashNeeded`.
   The rate should fall toward zero over your active-user window
   (typically 30–90 days). Flat-line means no one's logging in; that's a
   different problem.

2. **Stored-hash format mix.** A scheduled query like
   `SELECT COUNT(*) FILTER (WHERE PasswordHash LIKE '$argon2id$%') AS argon2id,
   COUNT(*) FILTER (WHERE PasswordHash NOT LIKE '$argon2id$%') AS legacy FROM AspNetUsers`
   gives you a single number you can chart. The Argon2id share should
   only ever go up.

## What NOT to do

- **Don't** mass-rehash on import. You don't have the plaintext, and
  rehashing a stored hash doesn't strengthen anything.
- **Don't** lower the Argon2id parameters to match PBKDF2 verification
  speed. Argon2id is intentionally slower — that's the point.
- **Don't** disable the legacy hasher until you've verified the long
  tail is acceptable. A premature cutoff locks legitimate users out.

## A note on parameters

The migrating adapter uses whatever Argon2id parameters you configure (or
the library defaults — 64 MiB memory, 3 iterations, 1 lane). That's a
single-hash latency of ~100–500 ms on production server hardware. If your
PBKDF2 latency was significantly lower, your average login latency will
visibly climb for the migration window. This is expected and is the cost
of switching to a memory-hard hasher; it normalizes after the cutover.

See [`docs/parameter-tuning.md`](docs/parameter-tuning.md) for how to
pick parameters that hit your latency budget.

---

*To God be the glory — 1 Corinthians 10:31.*
