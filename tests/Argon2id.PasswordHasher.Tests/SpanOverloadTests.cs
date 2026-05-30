using System.Text;
using Xunit;

namespace Argon2id.PasswordHasher.Tests;

public class SpanOverloadTests
{
    private static readonly Argon2idOptions FastOptions = new()
    {
        MemorySizeKib = 8192,
        Iterations = 1,
        DegreeOfParallelism = 1,
    };

    private static Argon2idPasswordHasher CreateHasher() => new(FastOptions);

    [Fact]
    public void CharSpan_RoundTrips()
    {
        var hasher = CreateHasher();
        ReadOnlySpan<char> password = "span based password".AsSpan();

        string hash = hasher.HashPassword(password);

        Assert.True(hasher.VerifyPassword("span based password".AsSpan(), hash));
        Assert.False(hasher.VerifyPassword("different".AsSpan(), hash));
    }

    [Fact]
    public void ByteSpan_RoundTrips()
    {
        var hasher = CreateHasher();
        byte[] password = Encoding.UTF8.GetBytes("byte based password");

        string hash = hasher.HashPassword(password);

        Assert.True(hasher.VerifyPassword(Encoding.UTF8.GetBytes("byte based password"), hash));
        Assert.False(hasher.VerifyPassword(Encoding.UTF8.GetBytes("wrong"), hash));
    }

    [Fact]
    public void Overloads_ProduceInterchangeableHashes()
    {
        // A hash made via one overload must verify via every other overload.
        var hasher = CreateHasher();
        const string password = "interchangeable";

        string fromString = hasher.HashPassword(password);

        Assert.True(hasher.VerifyPassword(password, fromString));
        Assert.True(hasher.VerifyPassword(password.AsSpan(), fromString));
        Assert.True(hasher.VerifyPassword(Encoding.UTF8.GetBytes(password), fromString));
    }

    [Fact]
    public void HashPassword_EmptyCharSpan_Throws()
    {
        var hasher = CreateHasher();

        Assert.Throws<ArgumentException>(() => hasher.HashPassword(ReadOnlySpan<char>.Empty));
    }

    [Fact]
    public void HashPassword_EmptyByteSpan_Throws()
    {
        var hasher = CreateHasher();

        Assert.Throws<ArgumentException>(() => hasher.HashPassword(ReadOnlySpan<byte>.Empty));
    }

    [Fact]
    public void VerifyPassword_EmptySpans_ReturnFalse()
    {
        var hasher = CreateHasher();
        string hash = hasher.HashPassword("non empty");

        Assert.False(hasher.VerifyPassword(ReadOnlySpan<char>.Empty, hash));
        Assert.False(hasher.VerifyPassword(ReadOnlySpan<byte>.Empty, hash));
    }
}
