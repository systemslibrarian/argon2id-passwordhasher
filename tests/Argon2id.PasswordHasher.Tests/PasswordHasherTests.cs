using Xunit;

namespace Argon2id.PasswordHasher.Tests;

public class PasswordHasherTests
{
    // Use deliberately light parameters so the test suite stays fast while still
    // exercising the real Argon2id code paths.
    private static readonly Argon2idOptions FastOptions = new()
    {
        MemorySizeKib = 8192,
        Iterations = 1,
        DegreeOfParallelism = 1,
    };

    private static Argon2idPasswordHasher CreateHasher() => new(FastOptions);

    [Fact]
    public void HashThenVerify_RoundTrips()
    {
        var hasher = CreateHasher();
        const string password = "correct horse battery staple";

        string hash = hasher.HashPassword(password);

        Assert.True(hasher.VerifyPassword(password, hash));
    }

    [Fact]
    public void Verify_WrongPassword_ReturnsFalse()
    {
        var hasher = CreateHasher();
        string hash = hasher.HashPassword("the right password");

        Assert.False(hasher.VerifyPassword("the wrong password", hash));
    }

    [Fact]
    public void HashPassword_ProducesPhcFormat()
    {
        var hasher = CreateHasher();

        string hash = hasher.HashPassword("hunter2");

        Assert.StartsWith("$argon2id$v=19$m=8192,t=1,p=1$", hash, StringComparison.Ordinal);
        Assert.Equal(6, hash.Split('$').Length);
    }

    [Fact]
    public void HashPassword_SameInput_ProducesDifferentHashes()
    {
        // A fresh random salt per call means identical passwords must not collide.
        var hasher = CreateHasher();
        const string password = "repeat me";

        string first = hasher.HashPassword(password);
        string second = hasher.HashPassword(password);

        Assert.NotEqual(first, second);
        Assert.True(hasher.VerifyPassword(password, first));
        Assert.True(hasher.VerifyPassword(password, second));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void HashPassword_NullOrEmpty_Throws(string? password)
    {
        var hasher = CreateHasher();

        Assert.Throws<ArgumentException>(() => hasher.HashPassword(password!));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not-a-phc-string")]
    [InlineData("$argon2i$v=19$m=8192,t=1,p=1$c2FsdHNhbHQ$aGFzaA")] // wrong variant (argon2i)
    [InlineData("$argon2id$v=16$m=8192,t=1,p=1$c2FsdHNhbHQ$aGFzaA")] // unsupported version
    [InlineData("$argon2id$v=19$m=8192,t=1$c2FsdHNhbHQ$aGFzaA")] // missing cost parameter
    public void Verify_MalformedHash_ReturnsFalseNeverThrows(string? encoded)
    {
        var hasher = CreateHasher();

        Assert.False(hasher.VerifyPassword("any password", encoded!));
    }

    [Fact]
    public void Verify_TamperedHash_ReturnsFalse()
    {
        var hasher = CreateHasher();
        const string password = "tamper test";
        string hash = hasher.HashPassword(password);

        // Flip a character near the *start* of the encoded tag. The last
        // base64 character of a 32-byte tag carries only 4 valid bits (2 are
        // padding), so flipping it can be a no-op decode; mid-tag bytes are
        // unambiguous. Pick a position deep in the tag and guarantee the
        // replacement decodes to different bits.
        int tagStart = hash.LastIndexOf('$') + 1;
        int idx = tagStart + 4;
        char original = hash[idx];
        // Flip the high nibble of the base64 character so the decoded byte
        // differs by at least 0x10 — well clear of any boundary-padding bit.
        char replacement = original is 'A' or 'a' or '0' or '+' or '/' ? 'Z' : 'A';
        string tampered = hash[..idx] + replacement + hash[(idx + 1)..];

        Assert.NotEqual(hash, tampered);
        Assert.False(hasher.VerifyPassword(password, tampered));
    }

    [Fact]
    public void Constructor_InvalidOptions_Throws()
    {
        var weak = new Argon2idOptions { MemorySizeKib = 1024 };

        Assert.Throws<ArgumentOutOfRangeException>(() => new Argon2idPasswordHasher(weak));
    }

    [Fact]
    public void NeedsRehash_StrongerCurrentParameters_ReturnsTrue()
    {
        // Hash with weak params, then check against a stronger hasher.
        var weakHasher = new Argon2idPasswordHasher(FastOptions);
        string oldHash = weakHasher.HashPassword("upgrade me");

        var strongHasher = new Argon2idPasswordHasher(new Argon2idOptions
        {
            MemorySizeKib = 65536,
            Iterations = 3,
            DegreeOfParallelism = 1,
        });

        Assert.True(strongHasher.NeedsRehash(oldHash));
        // Verification must still succeed using the hash's stored parameters.
        Assert.True(strongHasher.VerifyPassword("upgrade me", oldHash));
    }

    [Fact]
    public void NeedsRehash_MatchingParameters_ReturnsFalse()
    {
        var hasher = CreateHasher();
        string hash = hasher.HashPassword("current");

        Assert.False(hasher.NeedsRehash(hash));
    }

    [Fact]
    public void NeedsRehash_MalformedHash_ReturnsTrue()
    {
        var hasher = CreateHasher();

        Assert.True(hasher.NeedsRehash("garbage"));
    }

    [Fact]
    public void Verify_UnicodePassword_RoundTrips()
    {
        var hasher = CreateHasher();
        const string password = "пароль\U0001f510Pässwört";

        string hash = hasher.HashPassword(password);

        Assert.True(hasher.VerifyPassword(password, hash));
        Assert.False(hasher.VerifyPassword("пароль\U0001f510Passwort", hash));
    }
}
