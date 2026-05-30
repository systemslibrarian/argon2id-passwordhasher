# Pepper key management

This guide is for teams that want to use a pepper with
`Argon2id.PasswordHasher` and need the key material to come from a
real secret store — Azure Key Vault, AWS KMS / Secrets Manager,
Google Cloud Secret Manager, HashiCorp Vault, or just a Kubernetes
Secret / environment variable in simpler setups.

The library deliberately ships **no KMS-specific code**. The
`PepperRing` API is the integration boundary: build a `PepperRing`
from whatever bytes your secret store hands you, register it as a
singleton in DI, and the library picks it up.

This document shows the right way to do that for each common
provider, plus the rotation playbook that pairs with the
[`Argon2idPasswordHasher.NeedsRehash`](../src/Argon2id.PasswordHasher/Argon2idPasswordHasher.cs)
upgrade flow.

## The shape every integration follows

Regardless of where the bytes come from, the pattern is the same:

```csharp
// 1. Acquire the key bytes (or a hex/base64 string) from your secret store.
byte[] activeKey   = await secretStore.GetBytesAsync("argon2id-pepper-active");
byte[] retiredKey  = await secretStore.GetBytesAsync("argon2id-pepper-2026-05");

// 2. Build a PepperRing. The Pepper id is your stable rotation marker;
//    pick something like a date or a monotonic counter and never reuse it.
var ring = new PepperRing(
    active: new Pepper("2026-11", activeKey),
    retired: new Pepper("2026-05", retiredKey));

// 3. Register as a singleton. Both the core hasher and the AspNetCore
//    adapter resolve PepperRing from DI when present.
builder.Services.AddSingleton(ring);
builder.Services.AddArgon2idPasswordHasher<IdentityUser>();
```

Once `PepperRing` is in DI, every new hash is produced with the active
pepper and every verify can use either the active or any retired
pepper (selected by the `keyid` embedded in the stored hash).

The `Pepper.FromHex(string, string)` and `Pepper.FromBase64(string, string)`
factories save a `Convert.FromHexString` / `Convert.FromBase64String`
line when your secret store returns text rather than bytes.

## Environment variables (dev / minimal prod)

The simplest setup. Suitable for local dev, small private deployments,
or anywhere your platform already encrypts environment variables at
rest (Kubernetes Secrets, Azure App Service Configuration, AWS Fargate
secret injection).

```csharp
string activeHex = builder.Configuration["Argon2id:Pepper:ActiveHex"]
    ?? throw new InvalidOperationException("Missing Argon2id pepper.");

var ring = new PepperRing(Pepper.FromHex("2026-11", activeHex));
builder.Services.AddSingleton(ring);
```

**Generating the key once:**

```bash
# 32 random bytes, hex-encoded:
openssl rand -hex 32
# Drop into your secret store as Argon2id__Pepper__ActiveHex.
```

**What to watch out for**

- Never commit `.env` files containing pepper bytes.
- Environment variables are visible to anything that can read
  `/proc/<pid>/environ` on the host. Use a real secret manager when
  you can.

## Azure Key Vault

```csharp
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;

var vaultUri = new Uri(builder.Configuration["KeyVault:Uri"]!);
var client = new SecretClient(vaultUri, new DefaultAzureCredential());

KeyVaultSecret active = await client.GetSecretAsync("argon2id-pepper-active");
KeyVaultSecret retired = await client.GetSecretAsync("argon2id-pepper-2026-05");

var ring = new PepperRing(
    active: Pepper.FromBase64("2026-11", active.Value),
    retired: Pepper.FromBase64("2026-05", retired.Value));

builder.Services.AddSingleton(ring);
```

**Recommended secret format:** store the pepper as a base64-encoded
string in Key Vault. The name of the secret is *not* the pepper id —
the pepper id is what you embed in the hash, so it must outlive the
KV secret name and not change when you rotate the KV secret value.
Use Key Vault's secret-version mechanism for the actual rotation
operation; map the version-id in your audit trail to the pepper id
in the hash.

**Permissions:** the principal needs `secrets/get` and `secrets/list`
on the vault, nothing else.

## AWS Secrets Manager

```csharp
using Amazon.SecretsManager;
using Amazon.SecretsManager.Model;

using var client = new AmazonSecretsManagerClient();

GetSecretValueResponse active = await client.GetSecretValueAsync(
    new GetSecretValueRequest { SecretId = "argon2id/pepper/active" });
GetSecretValueResponse retired = await client.GetSecretValueAsync(
    new GetSecretValueRequest { SecretId = "argon2id/pepper/2026-05" });

var ring = new PepperRing(
    active: Pepper.FromBase64("2026-11", active.SecretString),
    retired: Pepper.FromBase64("2026-05", retired.SecretString));

builder.Services.AddSingleton(ring);
```

**Recommended secret format:** plain base64 string in `SecretString`
(do not wrap in JSON unless you also rotate the JSON shape).

**Permissions:** the principal needs
`secretsmanager:GetSecretValue` for the specific secret ARNs,
nothing else. Use a resource-scoped IAM policy, not `*`.

## Google Cloud Secret Manager

```csharp
using Google.Cloud.SecretManager.V1;

SecretManagerServiceClient client = SecretManagerServiceClient.Create();

SecretVersionName activeName = new("PROJECT_ID", "argon2id-pepper-active", "latest");
AccessSecretVersionResponse active = client.AccessSecretVersion(activeName);

var ring = new PepperRing(
    active: Pepper.FromBase64("2026-11", active.Payload.Data.ToStringUtf8()));

builder.Services.AddSingleton(ring);
```

**Permissions:** `roles/secretmanager.secretAccessor` on the specific
secret resource.

## HashiCorp Vault

```csharp
using VaultSharp;
using VaultSharp.V1.AuthMethods.Token;

var settings = new VaultClientSettings(
    builder.Configuration["Vault:Address"]!,
    new TokenAuthMethodInfo(builder.Configuration["Vault:Token"]!));
var vault = new VaultClient(settings);

var active = await vault.V1.Secrets.KeyValue.V2
    .ReadSecretAsync("argon2id/pepper/active", mountPoint: "secret");

var ring = new PepperRing(
    Pepper.FromBase64("2026-11", (string)active.Data.Data["value"]));

builder.Services.AddSingleton(ring);
```

## Rotation playbook

The point of pepper rotation is to limit the blast radius if a pepper
ever leaks. There is no urgency in normal operation — rotate on a
schedule (annual is common) or in response to a specific incident.

```
                     ┌──────────────────────────────────────────┐
  Day 0              │ ring.Active = "2026-11"  (just rotated)  │
                     │ ring.Retired = ["2026-05", ...]          │
                     └──────────────────────────────────────────┘
                                       │
                                       │  Every successful login:
                                       │  - if hash used "2026-05",
                                       │    NeedsRehash returns true
                                       │  - HashPassword writes a fresh
                                       │    hash tagged "2026-11"
                                       ▼
                     ┌──────────────────────────────────────────┐
  T + active-user    │ The vast majority of rows now use the    │
  window (~30–90d)   │ active pepper. Long-tail of inactive     │
                     │ users still on "2026-05".                │
                     └──────────────────────────────────────────┘
                                       │
                                       │  Operator decision:
                                       │  - Accept the long tail and keep
                                       │    "2026-05" in `retired` forever,
                                       │    OR
                                       │  - Force-reset the long tail and
                                       │    remove "2026-05" from the ring.
                                       ▼
                     ┌──────────────────────────────────────────┐
                     │ ring.Active = "2026-11"                  │
                     │ ring.Retired = []                        │
                     └──────────────────────────────────────────┘
```

### The five rules of safe rotation

1. **Never reuse a pepper id.** The id is embedded in the hash. If you
   reuse a retired id with new bytes, every old hash tagged with that
   id silently fails to verify.
2. **Never delete a pepper from the ring while it is still referenced
   by any stored hash.** A `SELECT COUNT(*) WHERE PasswordHash LIKE
   '%keyid=<old-id-b64>%'` query tells you when it's safe.
3. **Promote the new active pepper FIRST**, *then* trigger the rehash
   pressure (via natural login activity). Do not flip the ring atomically
   and then immediately delete the old key — you'll lose any in-flight
   verifies.
4. **Treat the active key like a TLS private key.** Store in a real
   secret manager. Limit access. Audit reads. Restrict IAM.
5. **Have a recovery path documented** for the case where the active
   key is lost. Without the key, hashes tagged with its id cannot be
   verified — the only remediation is a password reset for every
   affected user. Back up active key material to a separate trust
   domain so a single-system breach doesn't compromise both.

## HSM-backed peppering

The library does not currently support delegating the `KnownSecret`
application to an HSM (the underlying Argon2 implementation requires
the key bytes in process memory). HSM-backed peppering is a roadmap
item; for now, the closest you can get is:

- Keep the master pepper material in the HSM.
- Use the HSM to wrap/unwrap a per-process pepper at startup.
- Hold the unwrapped pepper in process memory for the lifetime of the
  hasher (which is what the library already does).

This narrows the window where the key bytes are exposed to "while the
process is running" rather than "at rest in your secret store."

## Where this lives in DI

When a `PepperRing` is registered as a singleton, the AspNetCore
adapter resolves it automatically:

```csharp
// Both of these pick up the registered PepperRing:
services.AddArgon2idPasswordHasher<IdentityUser>();
services.AddArgon2idPasswordHasher<IdentityUser>(opts => { /* ... */ });
```

If you do not register a `PepperRing`, no pepper is applied — exactly
the same as constructing the core hasher with `pepper: null`.

---

*To God be the glory — 1 Corinthians 10:31.*
