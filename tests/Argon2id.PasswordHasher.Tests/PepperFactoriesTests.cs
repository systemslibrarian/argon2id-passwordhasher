using Xunit;

namespace Argon2id.PasswordHasher.Tests;

public class PepperFactoriesTests
{
    [Fact]
    public void FromHex_DecodesAndConstructsPepper()
    {
        // 32 hex chars = 16 bytes. Uses both upper and lowercase to prove case-insensitivity.
        const string hex = "0102030405060708090A0b0c0D0e0f10";
        Pepper pepper = Pepper.FromHex("2026", hex);

        Assert.Equal("2026", pepper.Id);
    }

    [Fact]
    public void FromHex_TooShort_Throws()
    {
        const string hex = "01020304"; // only 4 bytes — below the 16-byte minimum
        Assert.Throws<ArgumentOutOfRangeException>(() => Pepper.FromHex("k", hex));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void FromHex_NullOrEmpty_Throws(string? hex)
    {
        Assert.Throws<ArgumentException>(() => Pepper.FromHex("k", hex!));
    }

    [Fact]
    public void FromHex_InvalidHex_Throws()
    {
        Assert.Throws<ArgumentException>(() => Pepper.FromHex("k", "not-hex-at-all"));
    }

    [Fact]
    public void FromBase64_DecodesAndConstructsPepper()
    {
        // base64 of 32 zero bytes — well above the 16-byte minimum
        const string b64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        Pepper pepper = Pepper.FromBase64("k", b64);

        Assert.Equal("k", pepper.Id);
    }

    [Fact]
    public void FromBase64_TooShort_Throws()
    {
        // base64 of 8 zero bytes
        const string b64 = "AAAAAAAAAAA=";
        Assert.Throws<ArgumentOutOfRangeException>(() => Pepper.FromBase64("k", b64));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void FromBase64_NullOrEmpty_Throws(string? b64)
    {
        Assert.Throws<ArgumentException>(() => Pepper.FromBase64("k", b64!));
    }

    [Fact]
    public void FromBase64_InvalidBase64_Throws()
    {
        Assert.Throws<ArgumentException>(() => Pepper.FromBase64("k", "***not-base64***"));
    }

    [Fact]
    public void FromHex_ProducesEquivalentPepperToConstructor()
    {
        byte[] bytes = Enumerable.Range(1, 16).Select(i => (byte)i).ToArray();
        string hex = Convert.ToHexString(bytes);

        var direct = new Pepper("k", bytes);
        var viaHex = Pepper.FromHex("k", hex);

        // The two peppers should produce identical hashes of the same input
        // (their key bytes are equal and id is equal).
        var options = new Argon2idOptions { MemorySizeKib = 8192, Iterations = 1, DegreeOfParallelism = 1 };
        var h1 = new Argon2idPasswordHasher(options, new PepperRing(direct));
        var h2 = new Argon2idPasswordHasher(options, new PepperRing(viaHex));

        string fromDirect = h1.HashPassword("p");
        Assert.True(h2.VerifyPassword("p", fromDirect));
    }
}
