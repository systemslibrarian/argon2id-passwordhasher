// Runnable end-to-end walkthrough of the library's primary adoption path:
// an existing ASP.NET Core Identity user store full of PBKDF2 hashes,
// migrated to peppered Argon2id with zero downtime, zero forced resets,
// and zero broken logins.
//
//   dotnet run --project samples/Argon2id.PasswordHasher.IdentityMigrationSample
//
// Optionally set ARGON2ID_PEPPER to a base64-encoded key (>= 16 bytes) to see
// vault-sourced peppering; otherwise a throwaway key is generated for the run.
//
// This sample uses the LIBRARY DEFAULTS (64 MiB, t=3) — the same parameters a
// production app gets from the no-arg path. Expect each hash to take a few
// hundred milliseconds; that cost is the security feature.

using System.Security.Cryptography;
using Argon2id.PasswordHasher;
using Argon2id.PasswordHasher.AspNetCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;

const string UserName = "alice";
const string Password = "Sunny-Meadow-42!";

Console.WriteLine("=== Argon2id.PasswordHasher — Identity migration walkthrough ===");
Console.WriteLine();

// ---------------------------------------------------------------------------
// STEP 1 — The "existing app": a user whose stored hash is the stock
// ASP.NET Core Identity PBKDF2 format, exactly as found in a real database.
// ---------------------------------------------------------------------------
var alice = new DemoUser { UserName = UserName, NormalizedUserName = UserName.ToUpperInvariant() };
alice.PasswordHash = new PasswordHasher<DemoUser>().HashPassword(alice, Password);

Console.WriteLine("[1] Existing user with a stock Identity PBKDF2 hash:");
Console.WriteLine($"    {Preview(alice.PasswordHash)}");
Console.WriteLine();

// ---------------------------------------------------------------------------
// STEP 2 — The migration wiring. This is the part you copy into Program.cs of
// a real app: one extension call on the IdentityBuilder. The optional pepper
// is registered first so the hasher picks it up; in production the key comes
// from a vault / KMS / environment — never from source or the database.
// ---------------------------------------------------------------------------
byte[] pepperKey;
string pepperSource;
if (Environment.GetEnvironmentVariable("ARGON2ID_PEPPER") is { Length: > 0 } fromEnv)
{
    pepperKey = Convert.FromBase64String(fromEnv);
    pepperSource = "ARGON2ID_PEPPER environment variable";
}
else
{
    pepperKey = RandomNumberGenerator.GetBytes(32);
    pepperSource = "generated for this run (set ARGON2ID_PEPPER to supply your own)";
}

var services = new ServiceCollection();
services.AddLogging();
services.AddSingleton<IUserStore<DemoUser>, InMemoryUserStore>();
services.AddSingleton(new PepperRing(new Pepper("sample-2026", pepperKey)));

services.AddIdentityCore<DemoUser>()
    .AddArgon2idPasswordHasherWithMigration<DemoUser>();

CryptographicOperations.ZeroMemory(pepperKey); // Pepper made its own copy

Console.WriteLine("[2] Identity wired with AddArgon2idPasswordHasherWithMigration:");
Console.WriteLine($"    pepper id 'sample-2026', key from: {pepperSource}");
Console.WriteLine();

using ServiceProvider provider = services.BuildServiceProvider();
var userManager = provider.GetRequiredService<UserManager<DemoUser>>();
await provider.GetRequiredService<IUserStore<DemoUser>>().CreateAsync(alice, CancellationToken.None);

// ---------------------------------------------------------------------------
// STEP 3 — Alice logs in with her usual password. The migrating hasher
// verifies against the legacy PBKDF2 hash, reports success-needs-rehash, and
// Identity transparently rewrites the stored hash as peppered Argon2id.
// ---------------------------------------------------------------------------
bool firstLogin = await userManager.CheckPasswordAsync(alice, Password);

Console.WriteLine("[3] First login after the switch (verified against PBKDF2, rehashed):");
Console.WriteLine($"    login succeeded: {firstLogin}");
Console.WriteLine($"    stored hash is now: {Preview(alice.PasswordHash)}");
Console.WriteLine($"    upgraded to Argon2id: {Argon2idPasswordHasher.IsArgon2idHash(alice.PasswordHash)}");
Console.WriteLine($"    carries the pepper id: {alice.PasswordHash!.Contains("keyid=", StringComparison.Ordinal)}");
Console.WriteLine();

// ---------------------------------------------------------------------------
// STEP 4 — Subsequent logins verify directly against Argon2id. No further
// rehash happens; wrong passwords still fail.
// ---------------------------------------------------------------------------
string hashAfterUpgrade = alice.PasswordHash!;
bool secondLogin = await userManager.CheckPasswordAsync(alice, Password);
bool wrongPassword = await userManager.CheckPasswordAsync(alice, "not-her-password");

Console.WriteLine("[4] Steady state:");
Console.WriteLine($"    second login (pure Argon2id): {secondLogin}");
Console.WriteLine($"    hash unchanged by second login: {ReferenceEquals(hashAfterUpgrade, alice.PasswordHash) || hashAfterUpgrade == alice.PasswordHash}");
Console.WriteLine($"    wrong password rejected: {!wrongPassword}");
Console.WriteLine();

Console.WriteLine("Done. Every user migrates the same way — on their next successful login,");
Console.WriteLine("with no reset emails and no flag-day. See MIGRATION.md for the full guide,");
Console.WriteLine("and docs/pepper-key-management.md before adopting peppering in production.");

static string Preview(string? hash) =>
    hash is null ? "<null>" : hash.Length <= 56 ? hash : hash[..56] + "…";

/// <summary>Minimal user shape; UserManager only needs Id + name + hash fields.</summary>
internal sealed class DemoUser
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public string UserName { get; set; } = "";
    public string NormalizedUserName { get; set; } = "";
    public string? PasswordHash { get; set; }
    public string? SecurityStamp { get; set; }
}

/// <summary>
/// Smallest in-memory IUserStore + IUserPasswordStore that satisfies
/// UserManager. A real app uses EF Core / Dapper / etc. — the hasher neither
/// knows nor cares where the hash column lives.
/// </summary>
internal sealed class InMemoryUserStore : IUserStore<DemoUser>, IUserPasswordStore<DemoUser>
{
    private readonly Dictionary<string, DemoUser> _byId = new(StringComparer.Ordinal);

    public Task<IdentityResult> CreateAsync(DemoUser user, CancellationToken cancellationToken)
    {
        _byId[user.Id] = user;
        return Task.FromResult(IdentityResult.Success);
    }

    public Task<IdentityResult> UpdateAsync(DemoUser user, CancellationToken cancellationToken)
    {
        _byId[user.Id] = user;
        return Task.FromResult(IdentityResult.Success);
    }

    public Task<IdentityResult> DeleteAsync(DemoUser user, CancellationToken cancellationToken)
    {
        _byId.Remove(user.Id);
        return Task.FromResult(IdentityResult.Success);
    }

    public Task<DemoUser?> FindByIdAsync(string userId, CancellationToken cancellationToken) =>
        Task.FromResult(_byId.GetValueOrDefault(userId));

    public Task<DemoUser?> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken) =>
        Task.FromResult(_byId.Values.FirstOrDefault(u =>
            string.Equals(u.NormalizedUserName, normalizedUserName, StringComparison.Ordinal)));

    public Task<string> GetUserIdAsync(DemoUser user, CancellationToken cancellationToken) => Task.FromResult(user.Id);
    public Task<string?> GetUserNameAsync(DemoUser user, CancellationToken cancellationToken) => Task.FromResult<string?>(user.UserName);
    public Task SetUserNameAsync(DemoUser user, string? userName, CancellationToken cancellationToken) { user.UserName = userName ?? ""; return Task.CompletedTask; }
    public Task<string?> GetNormalizedUserNameAsync(DemoUser user, CancellationToken cancellationToken) => Task.FromResult<string?>(user.NormalizedUserName);
    public Task SetNormalizedUserNameAsync(DemoUser user, string? normalizedName, CancellationToken cancellationToken) { user.NormalizedUserName = normalizedName ?? ""; return Task.CompletedTask; }

    public Task SetPasswordHashAsync(DemoUser user, string? passwordHash, CancellationToken cancellationToken) { user.PasswordHash = passwordHash; return Task.CompletedTask; }
    public Task<string?> GetPasswordHashAsync(DemoUser user, CancellationToken cancellationToken) => Task.FromResult(user.PasswordHash);
    public Task<bool> HasPasswordAsync(DemoUser user, CancellationToken cancellationToken) => Task.FromResult(user.PasswordHash is { Length: > 0 });

    public void Dispose() { }
}
