using System.Text;
using Xunit;

namespace Argon2id.PasswordHasher.Tests;

/// <summary>
/// Stress-tests the hasher against pathological-but-legal password content:
/// very large inputs, single bytes, all-null / all-0xFF byte arrays,
/// Unicode boundary characters, and control-character mixtures. The goal is
/// to demonstrate that no input shape causes the library to throw on the
/// happy path or to round-trip incorrectly.
/// </summary>
public class EdgeCaseTests
{
    private static readonly Argon2idOptions FastOptions = new()
    {
        MemorySizeKib = 8192,
        Iterations = 1,
        DegreeOfParallelism = 1,
    };

    private static Argon2idPasswordHasher Hasher() => new(FastOptions);

    [Fact]
    public void SingleByteCharPassword_RoundTrips()
    {
        var hasher = Hasher();
        string hash = hasher.HashPassword("a");
        Assert.True(hasher.VerifyPassword("a", hash));
        Assert.False(hasher.VerifyPassword("b", hash));
    }

    [Fact]
    public void OneMegabytePassword_RoundTrips()
    {
        // The library must be able to swallow a 1 MiB password as one big
        // span without throwing or corrupting state. Use the span overload
        // to avoid bouncing through a 1 MiB string.
        byte[] huge = new byte[1024 * 1024];
        Random.Shared.NextBytes(huge);

        var hasher = Hasher();
        string hash = hasher.HashPassword((ReadOnlySpan<byte>)huge);

        Assert.True(hasher.VerifyPassword((ReadOnlySpan<byte>)huge, hash));

        // Mutating one byte must invalidate verification.
        huge[42] ^= 0xFF;
        Assert.False(hasher.VerifyPassword((ReadOnlySpan<byte>)huge, hash));
    }

    [Fact]
    public void AllZeroBytesPassword_RoundTrips()
    {
        // All-null is technically a valid byte sequence and a real
        // implementation has to handle it without conflating "empty"
        // with "zero-valued".
        byte[] zeros = new byte[32];
        var hasher = Hasher();

        string hash = hasher.HashPassword((ReadOnlySpan<byte>)zeros);

        Assert.True(hasher.VerifyPassword((ReadOnlySpan<byte>)zeros, hash));
        Assert.False(hasher.VerifyPassword((ReadOnlySpan<byte>)new byte[31], hash)); // length matters
    }

    [Fact]
    public void AllOnesBytesPassword_RoundTrips()
    {
        byte[] ones = Enumerable.Repeat((byte)0xFF, 32).ToArray();
        var hasher = Hasher();

        string hash = hasher.HashPassword((ReadOnlySpan<byte>)ones);

        Assert.True(hasher.VerifyPassword((ReadOnlySpan<byte>)ones, hash));
    }

    [Fact]
    public void ControlCharsPassword_RoundTrips()
    {
        // Control characters are valid in a password — the library must
        // not "sanitise" anything.
        const string control = "\t\r\n\0\x01\x1bhello";
        var hasher = Hasher();

        string hash = hasher.HashPassword(control);

        Assert.True(hasher.VerifyPassword(control, hash));
        // Stripping the null byte changes the meaning; must NOT verify.
        Assert.False(hasher.VerifyPassword("\t\r\nhello", hash));
    }

    [Fact]
    public void HighUnicodePassword_RoundTrips()
    {
        // BMP + supplementary plane (surrogate pair).
        const string mixed = "Héllo世界\U0001f31f";
        var hasher = Hasher();

        string hash = hasher.HashPassword(mixed);

        Assert.True(hasher.VerifyPassword(mixed, hash));
    }

    [Fact]
    public void HashesAcrossOverloads_AreInterchangeable()
    {
        // A char-span hash must verify against the equivalent byte-span
        // password (UTF-8 encoded), and vice-versa.
        var hasher = Hasher();
        const string password = "interop-Üñîçødë";

        string viaChars = hasher.HashPassword(password.AsSpan());
        string viaString = hasher.HashPassword(password);
        string viaBytes = hasher.HashPassword((ReadOnlySpan<byte>)Encoding.UTF8.GetBytes(password));

        foreach (string stored in new[] { viaChars, viaString, viaBytes })
        {
            Assert.True(hasher.VerifyPassword(password, stored));
            Assert.True(hasher.VerifyPassword(password.AsSpan(), stored));
            Assert.True(hasher.VerifyPassword(
                (ReadOnlySpan<byte>)Encoding.UTF8.GetBytes(password), stored));
        }
    }

    [Fact]
    public void RepeatedHashing_DoesNotLeakStateBetweenCalls()
    {
        // Confirm that the hasher is stateless: a hash of password A
        // followed by a hash of password B must produce values that
        // each only verify against their respective input.
        var hasher = Hasher();
        string hashA = hasher.HashPassword("alpha");
        string hashB = hasher.HashPassword("beta");

        Assert.True(hasher.VerifyPassword("alpha", hashA));
        Assert.True(hasher.VerifyPassword("beta", hashB));

        Assert.False(hasher.VerifyPassword("alpha", hashB));
        Assert.False(hasher.VerifyPassword("beta", hashA));
    }
}
