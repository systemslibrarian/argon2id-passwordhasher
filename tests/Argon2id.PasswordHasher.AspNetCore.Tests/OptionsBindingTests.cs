using Argon2id.PasswordHasher;
using Argon2id.PasswordHasher.AspNetCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace Argon2id.PasswordHasher.AspNetCore.Tests;

public class OptionsBindingTests
{
    private sealed class TestUser;

    private static Argon2idOptions FastOptions() => new()
    {
        MemorySizeKib = 8192,
        Iterations = 1,
        DegreeOfParallelism = 1,
    };

    [Fact]
    public void ActionOverload_AppliesConfigurationToHasher()
    {
        var services = new ServiceCollection();
        services.AddArgon2idPasswordHasher<TestUser>(opts =>
        {
            opts.MemorySizeKib = 16384;
            opts.Iterations = 2;
        });

        using ServiceProvider sp = services.BuildServiceProvider();

        Argon2idPasswordHasher hasher = sp.GetRequiredService<Argon2idPasswordHasher>();
        Assert.Equal(16384, hasher.Options.MemorySizeKib);
        Assert.Equal(2, hasher.Options.Iterations);
    }

    [Fact]
    public void ActionOverload_RegistersIPasswordHasher()
    {
        var services = new ServiceCollection();
        services.AddArgon2idPasswordHasher<TestUser>(opts =>
        {
            opts.MemorySizeKib = FastOptions().MemorySizeKib;
            opts.Iterations = FastOptions().Iterations;
        });

        using ServiceProvider sp = services.BuildServiceProvider();

        var resolved = sp.GetRequiredService<IPasswordHasher<TestUser>>();
        Assert.IsType<Argon2idPasswordHasher<TestUser>>(resolved);
    }

    [Fact]
    public void OptionsPattern_ConfigureViaIServiceCollection_IsPickedUp()
    {
        // The standard .NET pattern: configure options separately, then call AddArgon2idPasswordHasher().
        var services = new ServiceCollection();
        services.Configure<Argon2idOptions>(opts =>
        {
            opts.MemorySizeKib = 24576;
            opts.Iterations = 2;
        });
        services.AddArgon2idPasswordHasher<TestUser>();

        using ServiceProvider sp = services.BuildServiceProvider();

        Argon2idPasswordHasher hasher = sp.GetRequiredService<Argon2idPasswordHasher>();
        Assert.Equal(24576, hasher.Options.MemorySizeKib);
        Assert.Equal(2, hasher.Options.Iterations);
    }

    [Fact]
    public void PreviouslyRegisteredPepperRing_IsAppliedToHasher()
    {
        var ring = new PepperRing(new Pepper("k", Enumerable.Repeat((byte)0xAA, 16).ToArray()));
        var services = new ServiceCollection();
        services.AddSingleton(ring);
        services.AddArgon2idPasswordHasher<TestUser>(opts =>
        {
            opts.MemorySizeKib = FastOptions().MemorySizeKib;
            opts.Iterations = FastOptions().Iterations;
        });

        using ServiceProvider sp = services.BuildServiceProvider();

        Argon2idPasswordHasher hasher = sp.GetRequiredService<Argon2idPasswordHasher>();
        string hash = hasher.HashPassword("peppered-via-di");
        Assert.Contains("keyid=", hash, StringComparison.Ordinal);
        Assert.True(hasher.VerifyPassword("peppered-via-di", hash));
    }

    [Fact]
    public void InvalidOptions_AreReportedByTheValidator()
    {
        // Below-minimum memory: the validator should report failure on IOptions<T>.Value access.
        var services = new ServiceCollection();
        services.AddArgon2idPasswordHasher<TestUser>(opts =>
        {
            opts.MemorySizeKib = 1024; // way below the 8192 minimum
        });

        using ServiceProvider sp = services.BuildServiceProvider();

        var monitor = sp.GetRequiredService<IOptions<Argon2idOptions>>();
        // Accessing .Value runs the registered IValidateOptions<T> instances.
        Assert.Throws<OptionsValidationException>(() => monitor.Value);
    }

    [Fact]
    public void ParameterlessAddArgon2idPasswordHasher_UsesRecommendedDefaults()
    {
        var services = new ServiceCollection();
        services.AddArgon2idPasswordHasher<TestUser>();

        using ServiceProvider sp = services.BuildServiceProvider();

        Argon2idPasswordHasher hasher = sp.GetRequiredService<Argon2idPasswordHasher>();
        Assert.Equal(Argon2idOptions.Recommended.MemorySizeKib, hasher.Options.MemorySizeKib);
        Assert.Equal(Argon2idOptions.Recommended.Iterations, hasher.Options.Iterations);
        Assert.Equal(Argon2idOptions.Recommended.DegreeOfParallelism, hasher.Options.DegreeOfParallelism);
    }
}
