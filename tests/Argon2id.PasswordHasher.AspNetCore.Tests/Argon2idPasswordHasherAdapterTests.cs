using Argon2id.PasswordHasher;
using Argon2id.PasswordHasher.AspNetCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Argon2id.PasswordHasher.AspNetCore.Tests;

public class Argon2idPasswordHasherAdapterTests
{
    private sealed class TestUser;

    private static readonly Argon2idOptions FastOptions = new()
    {
        MemorySizeKib = 8192,
        Iterations = 1,
        DegreeOfParallelism = 1,
    };

    private static readonly Argon2idOptions StrongerOptions = new()
    {
        MemorySizeKib = 16384,
        Iterations = 2,
        DegreeOfParallelism = 1,
    };

    private static Argon2idPasswordHasher<TestUser> Adapter(Argon2idOptions options) =>
        new(new PasswordHasher(options));

    private static readonly TestUser User = new();

    [Fact]
    public void HashThenVerify_ReturnsSuccess()
    {
        var hasher = Adapter(FastOptions);
        string hash = hasher.HashPassword(User, "pw");

        Assert.Equal(PasswordVerificationResult.Success, hasher.VerifyHashedPassword(User, hash, "pw"));
    }

    [Fact]
    public void WrongPassword_ReturnsFailed()
    {
        var hasher = Adapter(FastOptions);
        string hash = hasher.HashPassword(User, "pw");

        Assert.Equal(PasswordVerificationResult.Failed, hasher.VerifyHashedPassword(User, hash, "nope"));
    }

    [Fact]
    public void WeakerStoredHash_ReturnsSuccessRehashNeeded()
    {
        string oldHash = Adapter(FastOptions).HashPassword(User, "pw");
        var stronger = Adapter(StrongerOptions);

        Assert.Equal(
            PasswordVerificationResult.SuccessRehashNeeded,
            stronger.VerifyHashedPassword(User, oldHash, "pw"));
    }

    [Fact]
    public void MalformedStoredHash_ReturnsFailed()
    {
        var hasher = Adapter(FastOptions);

        Assert.Equal(PasswordVerificationResult.Failed, hasher.VerifyHashedPassword(User, "garbage", "pw"));
    }

    [Fact]
    public void AddArgon2idPasswordHasher_RegistersAdapterAndSharedHasher()
    {
        var services = new ServiceCollection();
        services.AddArgon2idPasswordHasher<TestUser>(FastOptions);

        using ServiceProvider provider = services.BuildServiceProvider();

        var resolved = provider.GetRequiredService<IPasswordHasher<TestUser>>();
        Assert.IsType<Argon2idPasswordHasher<TestUser>>(resolved);

        // The shared core hasher is registered as a singleton.
        var core1 = provider.GetRequiredService<PasswordHasher>();
        var core2 = provider.GetRequiredService<PasswordHasher>();
        Assert.Same(core1, core2);

        string hash = resolved.HashPassword(User, "pw");
        Assert.Equal(PasswordVerificationResult.Success, resolved.VerifyHashedPassword(User, hash, "pw"));
    }
}
