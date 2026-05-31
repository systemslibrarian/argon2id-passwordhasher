using Xunit;

namespace Argon2id.PasswordHasher.Tests;

public class IsArgon2idHashTests
{
    [Fact]
    public void NullInput_ReturnsFalse()
    {
        Assert.False(Argon2idPasswordHasher.IsArgon2idHash(null));
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("garbage")]
    [InlineData("$argon2i$v=19$m=8192,t=1,p=1$c2FsdHNhbHQ$aGFzaA")]   // wrong variant
    [InlineData("$argon2d$v=19$m=8192,t=1,p=1$c2FsdHNhbHQ$aGFzaA")]   // wrong variant
    [InlineData("$ARGON2ID$v=19$m=8192,t=1,p=1$c2FsdHNhbHQ$aGFzaA")]  // case-sensitive
    [InlineData("argon2id$v=19$m=8192,t=1,p=1$c2FsdHNhbHQ$aGFzaA")]   // missing leading $
    [InlineData("AQAAAAEAACcQ...some-pbkdf2-base64")]                  // legacy Identity PBKDF2 shape
    public void NonArgon2id_ReturnsFalse(string input)
    {
        Assert.False(Argon2idPasswordHasher.IsArgon2idHash(input));
    }

    [Theory]
    [InlineData("$argon2id$v=19$m=8192,t=1,p=1$c2FsdHNhbHQ$aGFzaA")]
    [InlineData("$argon2id$v=19$m=65536,t=3,p=1,keyid=Y29sb3I$c2FsdA$dGFn")] // with pepper keyid
    [InlineData("$argon2id$")]   // prefix-only: structurally invalid but the sniff test
                                 // is intentionally a prefix check only — Verify rejects
                                 // the rest of the malformed structure on its own.
    public void Argon2idPrefixed_ReturnsTrue(string input)
    {
        Assert.True(Argon2idPasswordHasher.IsArgon2idHash(input));
    }

    [Fact]
    public void HasherEmittedHashes_AlwaysSniffAsArgon2id()
    {
        // Sanity-check the contract end-to-end: every hash the library
        // produces must pass its own sniff test.
        var hasher = new Argon2idPasswordHasher(new Argon2idOptions
        {
            MemorySizeKib = 8192,
            Iterations = 1,
            DegreeOfParallelism = 1,
        });

        Assert.True(Argon2idPasswordHasher.IsArgon2idHash(hasher.HashPassword("sanity")));
    }

    [Fact]
    public void PhcPrefix_Constant_MatchesEmittedPrefix()
    {
        // Lock the constant: any future drift of the emitted prefix would
        // break the sniff test silently. The const becomes the canary.
        var hasher = new Argon2idPasswordHasher(new Argon2idOptions
        {
            MemorySizeKib = 8192,
            Iterations = 1,
            DegreeOfParallelism = 1,
        });

        string hash = hasher.HashPassword("prefix-check");
        Assert.StartsWith(Argon2idPasswordHasher.PhcPrefix, hash, StringComparison.Ordinal);
        Assert.Equal("$argon2id$", Argon2idPasswordHasher.PhcPrefix);
    }
}
