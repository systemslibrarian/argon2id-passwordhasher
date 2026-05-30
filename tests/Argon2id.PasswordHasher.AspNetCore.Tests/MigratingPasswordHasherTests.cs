using Argon2id.PasswordHasher;
using Argon2id.PasswordHasher.AspNetCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Argon2id.PasswordHasher.AspNetCore.Tests;

public class MigratingPasswordHasherTests
{
    private sealed class TestUser { public string Id { get; set; } = ""; }

    private static readonly Argon2idOptions FastOptions = new()
    {
        MemorySizeKib = 8192,
        Iterations = 1,
        DegreeOfParallelism = 1,
    };

    private static MigratingPasswordHasher<TestUser> Build(
        Argon2idPasswordHasher<TestUser>? primary = null,
        IPasswordHasher<TestUser>? legacy = null)
    {
        primary ??= new Argon2idPasswordHasher<TestUser>(new Argon2idPasswordHasher(FastOptions));
        legacy ??= new PasswordHasher<TestUser>();
        return new MigratingPasswordHasher<TestUser>(primary, legacy);
    }

    [Fact]
    public void HashPassword_AlwaysEmitsArgon2id()
    {
        var hasher = Build();
        string hash = hasher.HashPassword(new TestUser(), "pw");
        Assert.StartsWith("$argon2id$", hash, StringComparison.Ordinal);
    }

    [Fact]
    public void VerifyHashedPassword_Argon2idStored_DelegatesToArgon2id_Success()
    {
        var argon2idCore = new Argon2idPasswordHasher(FastOptions);
        var hasher = Build(new Argon2idPasswordHasher<TestUser>(argon2idCore));

        string stored = argon2idCore.HashPassword("pw");

        Assert.Equal(
            PasswordVerificationResult.Success,
            hasher.VerifyHashedPassword(new TestUser(), stored, "pw"));
    }

    [Fact]
    public void VerifyHashedPassword_Argon2idStored_WrongPassword_ReturnsFailed()
    {
        var argon2idCore = new Argon2idPasswordHasher(FastOptions);
        var hasher = Build(new Argon2idPasswordHasher<TestUser>(argon2idCore));

        string stored = argon2idCore.HashPassword("right");

        Assert.Equal(
            PasswordVerificationResult.Failed,
            hasher.VerifyHashedPassword(new TestUser(), stored, "wrong"));
    }

    [Fact]
    public void VerifyHashedPassword_LegacyStored_RightPassword_ReturnsSuccessRehashNeeded()
    {
        // Pre-existing PBKDF2 hash produced by the stock Identity hasher.
        var legacy = new PasswordHasher<TestUser>();
        string legacyHash = legacy.HashPassword(new TestUser(), "pw");
        Assert.DoesNotContain("$argon2id$", legacyHash, StringComparison.Ordinal);

        var migrating = Build(legacy: legacy);

        // The legacy verify succeeds, but the adapter MUST report SuccessRehashNeeded
        // so Identity rewrites the stored hash with the Argon2id one on next sign-in.
        Assert.Equal(
            PasswordVerificationResult.SuccessRehashNeeded,
            migrating.VerifyHashedPassword(new TestUser(), legacyHash, "pw"));
    }

    [Fact]
    public void VerifyHashedPassword_LegacyStored_WrongPassword_ReturnsFailed()
    {
        var legacy = new PasswordHasher<TestUser>();
        string legacyHash = legacy.HashPassword(new TestUser(), "right");

        var migrating = Build(legacy: legacy);

        Assert.Equal(
            PasswordVerificationResult.Failed,
            migrating.VerifyHashedPassword(new TestUser(), legacyHash, "wrong"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not-a-hash-at-all")]
    [InlineData("AQAAAAEAACcQ...truncated junk")] // looks PBKDF2-ish but isn't valid
    public void VerifyHashedPassword_GarbageStored_ReturnsFailed_NeverThrows(string? stored)
    {
        var hasher = Build();
        Assert.Equal(
            PasswordVerificationResult.Failed,
            hasher.VerifyHashedPassword(new TestUser(), stored!, "anything"));
    }

    [Fact]
    public void Constructor_Nulls_Throw()
    {
        var argon2id = new Argon2idPasswordHasher<TestUser>(new Argon2idPasswordHasher(FastOptions));
        var legacy = new PasswordHasher<TestUser>();

        Assert.Throws<ArgumentNullException>(
            () => new MigratingPasswordHasher<TestUser>(null!, legacy));
        Assert.Throws<ArgumentNullException>(
            () => new MigratingPasswordHasher<TestUser>(argon2id, null!));
    }

    [Fact]
    public void AddArgon2idPasswordHasherWithMigration_WiresMigratingHasher()
    {
        var services = new ServiceCollection();
        services.AddIdentityCore<TestUser>()
            .AddArgon2idPasswordHasherWithMigration<TestUser>(opts =>
            {
                opts.MemorySizeKib = FastOptions.MemorySizeKib;
                opts.Iterations = FastOptions.Iterations;
            });

        using ServiceProvider sp = services.BuildServiceProvider();

        var resolved = sp.GetRequiredService<IPasswordHasher<TestUser>>();
        Assert.IsType<MigratingPasswordHasher<TestUser>>(resolved);

        // End-to-end: hash a legacy PBKDF2 password manually, then verify through
        // the migrating hasher and confirm SuccessRehashNeeded.
        string legacyHash = new PasswordHasher<TestUser>().HashPassword(new TestUser(), "end-to-end");
        Assert.Equal(
            PasswordVerificationResult.SuccessRehashNeeded,
            resolved.VerifyHashedPassword(new TestUser(), legacyHash, "end-to-end"));
    }
}
