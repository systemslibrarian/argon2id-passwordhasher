using System.Text;
using Xunit;

namespace Argon2id.PasswordHasher.Tests;

public class VerifyResultTests
{
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

    [Fact]
    public void Verify_CorrectPassword_AtCurrentParameters_ReturnsSuccessAndNoRehash()
    {
        var hasher = new Argon2idPasswordHasher(FastOptions);
        string hash = hasher.HashPassword("rich-result");

        VerifyResult result = hasher.Verify("rich-result", hash);

        Assert.True(result.Success);
        Assert.False(result.NeedsRehash);
    }

    [Fact]
    public void Verify_CorrectPassword_AtWeakerParameters_FlagsRehash()
    {
        // Hash with weak params, then verify under a stronger hasher.
        string oldHash = new Argon2idPasswordHasher(FastOptions).HashPassword("upgrade me");
        var stronger = new Argon2idPasswordHasher(StrongerOptions);

        VerifyResult result = stronger.Verify("upgrade me", oldHash);

        Assert.True(result.Success);
        Assert.True(result.NeedsRehash);
    }

    [Fact]
    public void Verify_WrongPassword_ReturnsFailed_AndRehashHintIsFalse()
    {
        var hasher = new Argon2idPasswordHasher(FastOptions);
        string hash = hasher.HashPassword("real");

        VerifyResult result = hasher.Verify("nope", hash);

        Assert.False(result.Success);
        Assert.False(result.NeedsRehash); // no rehash hint when verification failed
        Assert.Equal(VerifyResult.Failed, result);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not-a-phc-string")]
    [InlineData("$argon2i$v=19$m=8192,t=1,p=1$c2FsdHNhbHQ$aGFzaA")]
    public void Verify_MalformedHash_ReturnsFailed(string? encoded)
    {
        var hasher = new Argon2idPasswordHasher(FastOptions);

        VerifyResult result = hasher.Verify("anything", encoded!);

        Assert.Equal(VerifyResult.Failed, result);
    }

    [Fact]
    public void Verify_AcceptsSpanOverloads_Equivalently()
    {
        var hasher = new Argon2idPasswordHasher(FastOptions);
        string hash = hasher.HashPassword("span equivalence");

        VerifyResult fromString = hasher.Verify("span equivalence", hash);
        VerifyResult fromChars = hasher.Verify("span equivalence".AsSpan(), hash);
        VerifyResult fromBytes = hasher.Verify(
            (ReadOnlySpan<byte>)Encoding.UTF8.GetBytes("span equivalence"), hash);

        Assert.True(fromString.Success);
        Assert.Equal(fromString, fromChars);
        Assert.Equal(fromString, fromBytes);
    }

    [Fact]
    public void Verify_AgreesWith_LegacyVerifyPlusNeedsRehash()
    {
        // The new Verify is intended to be equivalent to VerifyPassword + NeedsRehash
        // when both return true. This locks that contract in.
        var weak = new Argon2idPasswordHasher(FastOptions);
        var strong = new Argon2idPasswordHasher(StrongerOptions);

        string old = weak.HashPassword("contract");

        VerifyResult one = strong.Verify("contract", old);
        bool legacySuccess = strong.VerifyPassword("contract", old);
        bool legacyNeedsRehash = strong.NeedsRehash(old);

        Assert.Equal(legacySuccess, one.Success);
        Assert.Equal(legacyNeedsRehash, one.NeedsRehash);
    }

    [Fact]
    public void Failed_IsSingleton_AndEqualsAnotherFailed()
    {
        Assert.Equal(VerifyResult.Failed, new VerifyResult(Success: false, NeedsRehash: false));
        Assert.False(VerifyResult.Failed.Success);
        Assert.False(VerifyResult.Failed.NeedsRehash);
    }
}
