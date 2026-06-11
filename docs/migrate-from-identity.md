# Migrating from ASP.NET Core Identity (PBKDF2)

This guide is for teams **already shipping** a user store with passwords
hashed by the default ASP.NET Core Identity `PasswordHasher<TUser>`
(PBKDF2 with HMAC-SHA-512, 100 000 iterations as of Identity v3 / .NET 8+).

The goal: switch to Argon2id with **zero downtime, zero forced password
resets, and zero broken logins**.

## TL;DR

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
`MigratingPasswordHasher<TUser>` as ASP.NET Core Identity's
`IPasswordHasher<TUser>`. It wraps two hashers:

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
   rehash trigger.

## Verifying the migration

Two things to watch in production:

1. **`PasswordVerificationResult.SuccessRehashNeeded` rate.** Right after
   you deploy, every legacy user's sign-in returns `SuccessRehashNeeded`.
   The rate should fall toward zero over your active-user window
   (typically 30–90 days).

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
the library defaults). If your PBKDF2 latency was significantly lower,
your average login latency will visibly climb for the migration window —
expected, and the cost of switching to a memory-hard hasher.

See [Parameter tuning](parameter-tuning.md) for picking parameters that
hit your latency budget, and the repository's `MIGRATION.md` for the
canonical, always-current version of this guide.

If you're coming from **bcrypt** (or scrypt / a custom scheme), see
[Migrating from BCrypt](migrate-from-bcrypt.md).
