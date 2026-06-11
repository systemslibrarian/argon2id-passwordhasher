# Migrating from BCrypt

This guide is for stores whose password column holds **bcrypt** hashes —
typically `$2a$`, `$2b$`, or `$2y$` prefixed strings produced by
[BCrypt.Net-Next](https://www.nuget.org/packages/BCrypt.Net-Next),
a previous non-.NET stack (PHP `password_hash`, Rails `has_secure_password`,
Spring Security), or an imported user base.

The strategy is identical to the
[Identity/PBKDF2 migration](migrate-from-identity.md): verify legacy
hashes with the legacy algorithm, emit only Argon2id for new hashes, and
let each successful login upgrade the stored value. The only difference
is that you supply the legacy verifier yourself.

## Step 1 — a verify-only bcrypt adapter

```csharp
using Microsoft.AspNetCore.Identity;

public sealed class BCryptVerifyOnlyHasher<TUser> : IPasswordHasher<TUser>
    where TUser : class
{
    public string HashPassword(TUser user, string password)
        => throw new InvalidOperationException(
            "BCryptVerifyOnlyHasher only verifies — Argon2id handles new hashes.");

    public PasswordVerificationResult VerifyHashedPassword(
        TUser user, string hashedPassword, string providedPassword)
    {
        // Route on format: bcrypt hashes start with $2a$ / $2b$ / $2y$.
        if (hashedPassword is null
            || !(hashedPassword.StartsWith("$2a$", StringComparison.Ordinal)
                 || hashedPassword.StartsWith("$2b$", StringComparison.Ordinal)
                 || hashedPassword.StartsWith("$2y$", StringComparison.Ordinal)))
        {
            return PasswordVerificationResult.Failed;
        }

        try
        {
            return BCrypt.Net.BCrypt.Verify(providedPassword, hashedPassword)
                ? PasswordVerificationResult.Success
                : PasswordVerificationResult.Failed;
        }
        catch (BCrypt.Net.SaltParseException)
        {
            // Fail safe on malformed stored data — never throw from verify.
            return PasswordVerificationResult.Failed;
        }
    }
}
```

Notes:

- **Verify-only is deliberate.** `HashPassword` throws so a wiring
  mistake (bcrypt accidentally producing new hashes) fails loudly in
  development instead of silently extending the legacy era.
- **Fail safe.** Malformed stored values return `Failed` rather than
  throwing, matching this library's verification contract.

## Step 2 — wire it into the migrating hasher

```csharp
using Microsoft.Extensions.DependencyInjection.Extensions;

builder.Services.AddIdentityCore<IdentityUser>()
    .AddEntityFrameworkStores<AppDbContext>();

builder.Services.AddArgon2idPasswordHasher<IdentityUser>();
builder.Services.Replace(ServiceDescriptor.Singleton<IPasswordHasher<IdentityUser>>(sp =>
    new MigratingPasswordHasher<IdentityUser>(
        new Argon2idPasswordHasher<IdentityUser>(
            sp.GetRequiredService<Argon2idPasswordHasher>()),
        new BCryptVerifyOnlyHasher<IdentityUser>())));
```

From this point:

- Stored values beginning with `$argon2id$` verify through Argon2id.
- Everything else falls through to the bcrypt adapter; a successful
  bcrypt verification returns `SuccessRehashNeeded`, which makes
  Identity re-hash with Argon2id and persist the upgrade.

## Not using ASP.NET Core Identity?

The same pattern works with the core package alone — route on the
prefix yourself:

```csharp
public bool VerifyAndMaybeUpgrade(string password, ref string stored)
{
    if (Argon2idPasswordHasher.IsArgon2idHash(stored))
    {
        var (success, needsRehash) = _argon2id.Verify(password, stored);
        if (success && needsRehash)
        {
            stored = _argon2id.HashPassword(password); // params were raised
        }

        return success;
    }

    if (BCrypt.Net.BCrypt.Verify(password, stored))
    {
        stored = _argon2id.HashPassword(password);     // upgrade to Argon2id
        return true;
    }

    return false;
}
```

Persist `stored` when it changes.

## Operational notes

- **Work-factor mismatch.** bcrypt cost 10–12 typically runs 50–250 ms.
  Tune your Argon2id parameters to a similar latency budget
  ([Parameter tuning](parameter-tuning.md)) so login latency doesn't
  jump during the migration window.
- **The long tail never logs in.** Users who don't sign in keep bcrypt
  hashes forever. Track the format mix
  (`WHERE PasswordHash NOT LIKE '$argon2id$%'`) and decide on a flag-day
  reset policy once the active population has migrated.
- **The 72-byte quirk disappears.** bcrypt silently truncates passwords
  at 72 bytes; Argon2id doesn't. A user whose password exceeds 72 bytes
  will verify via bcrypt with the truncated secret, then be re-hashed
  by Argon2id with the *full* secret — which is correct, but means the
  truncated variant stops working after migration. This is a security
  improvement; just be aware of it if support tickets mention very long
  passwords or password-manager-generated passphrases.
- **scrypt / PBKDF2 / custom schemes** migrate the same way: swap the
  bcrypt calls in the adapter for your legacy verifier and keep the
  verify-only, fail-safe shape.
