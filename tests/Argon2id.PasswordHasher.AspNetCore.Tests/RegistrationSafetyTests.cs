using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

using CoreHasher = Argon2id.PasswordHasher.Argon2idPasswordHasher;

namespace Argon2id.PasswordHasher.AspNetCore.Tests;

/// <summary>
/// Guards three registration-time safety contracts: invalid options must be
/// catchable at host startup rather than surfacing as a 500 on the first
/// login; an explicitly-passed options instance is snapshotted at
/// registration; and a plain <c>AddArgon2idPasswordHasher</c> call must not
/// silently replace a migrating registration (which would lock out every
/// user still on a legacy hash). Plus: a legacy empty-password account must
/// log in without triggering a throwing Argon2id rehash.
/// </summary>
public class RegistrationSafetyTests
{
    private sealed class TestUser;

    private static readonly Argon2idOptions FastOptions = new()
    {
        MemorySizeKib = 8192,
        Iterations = 1,
        DegreeOfParallelism = 1,
    };

    [Fact]
    public void InvalidOptions_AreRejectedByStartupValidator()
    {
        var services = new ServiceCollection();
        services.AddArgon2idPasswordHasher<TestUser>(o => o.MemorySizeKib = 1024); // below the 8192 floor

        using ServiceProvider provider = services.BuildServiceProvider();
        IStartupValidator? startupValidator = provider.GetService<IStartupValidator>();

        // ValidateOnStart must have wired a startup validator, and running it
        // (as Microsoft.Extensions.Hosting does on host start) must fail fast.
        Assert.NotNull(startupValidator);
        Assert.Throws<OptionsValidationException>(startupValidator.Validate);
    }

    [Fact]
    public void ExplicitOptionsInstance_IsSnapshottedAtRegistration()
    {
        var options = new Argon2idOptions
        {
            MemorySizeKib = 16384,
            Iterations = 2,
            DegreeOfParallelism = 1,
        };

        var services = new ServiceCollection();
        services.AddArgon2idPasswordHasher<TestUser>(options);

        // Mutating the caller's instance after registration must not reach the hasher.
        options.MemorySizeKib = 8192;
        options.Iterations = 1;

        using ServiceProvider provider = services.BuildServiceProvider();
        CoreHasher hasher = provider.GetRequiredService<CoreHasher>();

        Assert.Equal(16384, hasher.Options.MemorySizeKib);
        Assert.Equal(2, hasher.Options.Iterations);
    }

    [Fact]
    public void PlainRegistration_AfterMigration_PreservesMigratingHasher()
    {
        var services = new ServiceCollection();
        services.AddIdentityCore<TestUser>()
            .AddArgon2idPasswordHasherWithMigration<TestUser>(o => o.MemorySizeKib = 8192);

        // A second module (or a later refactor) wiring the plain hasher must
        // not silently displace migration — that would fail every user still
        // holding a legacy PBKDF2 hash.
        services.AddArgon2idPasswordHasher<TestUser>();

        using ServiceProvider provider = services.BuildServiceProvider();
        IPasswordHasher<TestUser> hasher = provider.GetRequiredService<IPasswordHasher<TestUser>>();

        Assert.IsType<MigratingPasswordHasher<TestUser>>(hasher);
    }

    [Fact]
    public void PlainRegistration_WithoutMigration_UsesPlainAdapter()
    {
        var services = new ServiceCollection();
        services.AddArgon2idPasswordHasher<TestUser>();

        using ServiceProvider provider = services.BuildServiceProvider();
        IPasswordHasher<TestUser> hasher = provider.GetRequiredService<IPasswordHasher<TestUser>>();

        Assert.IsType<Argon2idPasswordHasher<TestUser>>(hasher);
    }

    private sealed class EmptyPasswordLegacyHasher : IPasswordHasher<TestUser>
    {
        public string HashPassword(TestUser user, string password) => "legacy";

        public PasswordVerificationResult VerifyHashedPassword(
            TestUser user, string hashedPassword, string providedPassword) =>
            providedPassword.Length == 0
                ? PasswordVerificationResult.Success
                : PasswordVerificationResult.Failed;
    }

    [Fact]
    public void LegacyEmptyPasswordAccount_LogsInWithoutRehashSignal()
    {
        // A legacy store can hold a hash of "" (the stock hasher allows it).
        // Signalling SuccessRehashNeeded would make Identity call
        // HashPassword(user, "") mid-login, which Argon2id (correctly) refuses —
        // an unhandled exception on an otherwise-successful login. Plain
        // Success keeps the login working; the account upgrades when the
        // password actually changes.
        var migrating = new MigratingPasswordHasher<TestUser>(
            new Argon2idPasswordHasher<TestUser>(new CoreHasher(FastOptions)),
            new EmptyPasswordLegacyHasher());

        PasswordVerificationResult result =
            migrating.VerifyHashedPassword(new TestUser(), "legacy-stored", "");

        Assert.Equal(PasswordVerificationResult.Success, result);
    }

    [Fact]
    public void LegacyNonEmptyPasswordSuccess_StillSignalsRehash()
    {
        var migrating = new MigratingPasswordHasher<TestUser>(
            new Argon2idPasswordHasher<TestUser>(new CoreHasher(FastOptions)),
            new AlwaysSuccessLegacyHasher());

        PasswordVerificationResult result =
            migrating.VerifyHashedPassword(new TestUser(), "legacy-stored", "pw");

        Assert.Equal(PasswordVerificationResult.SuccessRehashNeeded, result);
    }

    private sealed class AlwaysSuccessLegacyHasher : IPasswordHasher<TestUser>
    {
        public string HashPassword(TestUser user, string password) => "legacy";

        public PasswordVerificationResult VerifyHashedPassword(
            TestUser user, string hashedPassword, string providedPassword) =>
            PasswordVerificationResult.Success;
    }
}
