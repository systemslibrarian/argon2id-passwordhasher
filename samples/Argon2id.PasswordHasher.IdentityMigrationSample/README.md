# Identity migration sample

Runnable, self-contained walkthrough of the library's **primary adoption
path**: an existing ASP.NET Core Identity user store full of stock PBKDF2
hashes, migrated to **peppered Argon2id** with zero downtime, zero forced
resets, and zero broken logins.

```bash
dotnet run --project samples/Argon2id.PasswordHasher.IdentityMigrationSample
```

What it demonstrates, end to end, through the **real** `UserManager<TUser>`
pipeline (not a mock):

1. A user whose stored hash is the stock Identity PBKDF2 format.
2. The one-line migration wiring —
   `AddIdentityCore<TUser>().AddArgon2idPasswordHasherWithMigration<TUser>()` —
   plus a `PepperRing` registered from an environment-variable key
   (`ARGON2ID_PEPPER`, base64; a throwaway key is generated if unset).
3. The first login after the switch: verified against PBKDF2, then
   transparently rewritten as a peppered `$argon2id$…keyid=…` hash by
   Identity's rehash-on-login mechanism.
4. Steady state: subsequent logins verify directly against Argon2id, the
   hash stops changing, wrong passwords still fail.

The sample runs with the **library defaults** (64 MiB, t=3) — the same
parameters a production app gets — so each hash deliberately takes a few
hundred milliseconds. That cost is the security feature.

Production notes: read [`MIGRATION.md`](../../MIGRATION.md) for the full
migration guide (bulk stores, bcrypt/scrypt legacies, rollback), and
[`docs/pepper-key-management.md`](../../docs/pepper-key-management.md) —
especially the backup warnings — before adopting peppering.
