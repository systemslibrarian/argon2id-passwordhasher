# API reference

The complete public surface of `Argon2id.PasswordHasher` and
`Argon2id.PasswordHasher.AspNetCore`, generated from the source XML doc
comments. Mirrors `PublicAPI.Shipped.txt` and `PublicAPI.Unshipped.txt`
in the repo.

## Core (`Argon2id.PasswordHasher`)

- <xref:Argon2id.PasswordHasher.Argon2idPasswordHasher> — main entry point. Hash, verify, needs-rehash.
- <xref:Argon2id.PasswordHasher.Argon2idOptions> — work-factor parameters.
- <xref:Argon2id.PasswordHasher.VerifyResult> — single-call verify outcome (`Success` + `NeedsRehash`).
- <xref:Argon2id.PasswordHasher.Pepper> — named secret key mixed into hashes.
- <xref:Argon2id.PasswordHasher.PepperRing> — pepper rotation surface.

## ASP.NET Core (`Argon2id.PasswordHasher.AspNetCore`)

- <xref:Argon2id.PasswordHasher.AspNetCore.Argon2idPasswordHasher`1> — `IPasswordHasher<TUser>` implementation.
- <xref:Argon2id.PasswordHasher.AspNetCore.ServiceCollectionExtensions> — `AddArgon2idPasswordHasher<TUser>(...)` DI extension.
