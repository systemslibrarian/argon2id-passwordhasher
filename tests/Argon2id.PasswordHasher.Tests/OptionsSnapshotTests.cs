using Xunit;

namespace Argon2id.PasswordHasher.Tests;

/// <summary>
/// Guards the options-snapshot contract: a hasher's parameters are fixed at
/// construction and cannot be weakened afterwards, even though
/// <see cref="Argon2idOptions"/> has settable properties for the Options
/// pattern. Without these guarantees, post-construction mutation could
/// silently bypass constructor validation and weaken every future hash.
/// </summary>
public class OptionsSnapshotTests
{
    private static Argon2idOptions FastOptions() => new()
    {
        MemorySizeKib = 8192,
        Iterations = 1,
        DegreeOfParallelism = 1,
    };

    [Fact]
    public void MutatingOptionsAfterConstruction_DoesNotAffectHasher()
    {
        var options = FastOptions();
        var hasher = new Argon2idPasswordHasher(options);

        // Attempt to weaken (and outright invalidate) the original instance
        // after the hasher has been built.
        options.MemorySizeKib = 1;
        options.Iterations = 0;

        string hash = hasher.HashPassword("p");
        Assert.Contains("m=8192,t=1,p=1", hash, StringComparison.Ordinal);
        Assert.True(hasher.VerifyPassword("p", hash));
    }

    [Fact]
    public void MutatingReturnedOptions_DoesNotAffectHasher()
    {
        var hasher = new Argon2idPasswordHasher(FastOptions());

        hasher.Options.MemorySizeKib = 1;

        Assert.Equal(8192, hasher.Options.MemorySizeKib);
        string hash = hasher.HashPassword("p");
        Assert.Contains("m=8192,t=1,p=1", hash, StringComparison.Ordinal);
    }

    [Fact]
    public void OptionsProperty_ReturnsValueEqualSnapshot()
    {
        var options = FastOptions();
        var hasher = new Argon2idPasswordHasher(options);

        // Value-equal to what was passed in, but not the same instance —
        // callers can inspect without being able to mutate hasher state.
        Assert.Equal(options, hasher.Options);
        Assert.NotSame(options, hasher.Options);
    }

    [Fact]
    public void Recommended_ReturnsFreshInstancePerAccess()
    {
        var first = Argon2idOptions.Recommended;
        first.MemorySizeKib = 1;

        // A mutation of one returned instance must never poison the
        // process-wide defaults.
        Assert.NotSame(first, Argon2idOptions.Recommended);
        Assert.Equal(new Argon2idOptions().MemorySizeKib, Argon2idOptions.Recommended.MemorySizeKib);
    }

    [Fact]
    public void DefaultConstructor_IsImmuneToRecommendedMutation()
    {
        var tampered = Argon2idOptions.Recommended;
        tampered.Iterations = 1;

        var hasher = new Argon2idPasswordHasher();
        Assert.Equal(new Argon2idOptions().Iterations, hasher.Options.Iterations);
    }
}
