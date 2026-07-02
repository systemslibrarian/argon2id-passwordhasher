using Xunit;

namespace Argon2id.PasswordHasher.Tests;

/// <summary>
/// Guards the Pepper-id round-trip contract: any id the constructor accepts
/// must survive the UTF-8 keyid round-trip through a stored hash, and any id
/// that could not round-trip must be rejected at construction. Without this,
/// a legal-looking pepper id produced hashes the library could never verify —
/// a silent lockout of every user registered under it.
/// </summary>
public class PepperIdValidationTests
{
    private static readonly Argon2idOptions FastOptions = new()
    {
        MemorySizeKib = 8192,
        Iterations = 1,
        DegreeOfParallelism = 1,
    };

    private static byte[] Key() => new byte[16];

    [Theory]
    [InlineData(64)]  // exactly at the PHC keyid cap
    [InlineData(1)]
    public void AsciiIdWithinCap_IsAccepted_AndRoundTrips(int length)
    {
        var pepper = new Pepper(new string('a', length), Key());
        var hasher = new Argon2idPasswordHasher(FastOptions, new PepperRing(pepper));

        string hash = hasher.HashPassword("pw");

        Assert.True(hasher.VerifyPassword("pw", hash));
        Assert.False(hasher.NeedsRehash(hash));
    }

    [Fact]
    public void AsciiIdOverCap_ThrowsAtConstruction()
    {
        var ex = Assert.Throws<ArgumentException>(() => new Pepper(new string('a', 65), Key()));
        Assert.Equal("id", ex.ParamName);
    }

    [Fact]
    public void MultibyteIdWithinCap_IsAccepted_AndRoundTrips()
    {
        // 21 × '中' (3 UTF-8 bytes each) + 'a' = 64 bytes exactly.
        var pepper = new Pepper(new string('中', 21) + "a", Key());
        var hasher = new Argon2idPasswordHasher(FastOptions, new PepperRing(pepper));

        string hash = hasher.HashPassword("pw");

        Assert.True(hasher.VerifyPassword("pw", hash));
    }

    [Fact]
    public void MultibyteIdOverCap_ThrowsAtConstruction_CapIsBytesNotChars()
    {
        // 22 chars but 66 UTF-8 bytes — a "short-looking" id must still be rejected.
        Assert.Throws<ArgumentException>(() => new Pepper(new string('中', 22), Key()));
    }

    [Fact]
    public void IllFormedUtf16Id_ThrowsAtConstruction()
    {
        // Built at runtime rather than via [InlineData]: xUnit's theory-argument
        // serialization itself replaces lone surrogates with U+FFFD, which would
        // hand the constructor an already-valid string and mask the behavior.
        string[] illFormed =
        [
            "\uD800",       // lone high surrogate
            "a\uD800b",     // embedded lone high surrogate
            "a\uDC00b",     // embedded lone low surrogate
            "ab" + '\uDFFF',// trailing lone low surrogate
        ];

        foreach (string id in illFormed)
        {
            // UTF-8 encoding would silently rewrite the surrogate to U+FFFD, so
            // the stored keyid could never match this pepper's id again.
            var ex = Assert.Throws<ArgumentException>(() => new Pepper(id, Key()));
            Assert.Equal("id", ex.ParamName);
        }
    }

    [Fact]
    public void WellFormedAstralId_IsAccepted_AndRoundTrips()
    {
        // A proper surrogate PAIR is fine — only unpaired surrogates are rejected.
        var pepper = new Pepper("\U0001F511-2026", Key());
        var hasher = new Argon2idPasswordHasher(FastOptions, new PepperRing(pepper));

        string hash = hasher.HashPassword("pw");

        Assert.True(hasher.VerifyPassword("pw", hash));
        Assert.False(hasher.NeedsRehash(hash));
    }
}
