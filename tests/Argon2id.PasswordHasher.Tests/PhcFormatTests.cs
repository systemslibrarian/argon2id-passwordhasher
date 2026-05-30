using System.Text.RegularExpressions;
using Xunit;

namespace Argon2id.PasswordHasher.Tests;

/// <summary>
/// Golden / structural tests for the emitted PHC string. These guard against
/// accidental format regressions that would silently break existing deployments.
/// </summary>
public class PhcFormatTests
{
    private static readonly Argon2idOptions FastOptions = new()
    {
        MemorySizeKib = 8192,
        Iterations = 1,
        DegreeOfParallelism = 1,
    };

    // Mirrors the de-facto Argon2 PHC layout used by libsodium and the reference
    // implementation: $argon2id$v=19$m=<int>,t=<int>,p=<int>[,keyid=<b64>]$<b64-salt>$<b64-hash>
    // Base64 here is the "b64-nopad" form (no '=' padding) per the PHC spec.
    private static readonly Regex PhcShape = new(
        @"^\$argon2id\$v=19\$m=\d+,t=\d+,p=\d+(?:,keyid=[A-Za-z0-9+/]+)?\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$",
        RegexOptions.Compiled);

    [Fact]
    public void EmittedHash_MatchesPhcRegex_NoPepper()
    {
        var hasher = new Argon2idPasswordHasher(FastOptions);
        string hash = hasher.HashPassword("phc shape");

        Assert.Matches(PhcShape, hash);
    }

    [Fact]
    public void EmittedHash_MatchesPhcRegex_WithPepper()
    {
        var hasher = new Argon2idPasswordHasher(
            FastOptions,
            new PepperRing(new Pepper("k1", Enumerable.Repeat((byte)0xAA, 16).ToArray())));
        string hash = hasher.HashPassword("phc shape peppered");

        Assert.Matches(PhcShape, hash);
        Assert.Contains(",keyid=", hash, StringComparison.Ordinal);
    }

    [Fact]
    public void EmittedHash_HasNoBase64Padding()
    {
        // The PHC spec uses base64-nopad. Trailing '=' in either the salt or
        // hash segments would be a regression that breaks parsers that expect
        // canonical PHC output.
        var hasher = new Argon2idPasswordHasher(FastOptions);
        string hash = hasher.HashPassword("nopad");

        string[] parts = hash.Split('$');
        Assert.Equal(6, parts.Length);
        Assert.DoesNotContain('=', parts[4]); // salt
        Assert.DoesNotContain('=', parts[5]); // hash tag
    }

    [Fact]
    public void EmittedHash_DefaultParameters_StableFormat()
    {
        // Lock the default emission against a fully literal prefix so that a future
        // accidental change to defaults or formatting is loud, not silent.
        var hasher = new Argon2idPasswordHasher();
        string hash = hasher.HashPassword("defaults");

        Assert.StartsWith("$argon2id$v=19$m=65536,t=3,p=1$", hash, StringComparison.Ordinal);
    }

    [Fact]
    public void EmittedHash_SaltAndTagLengths_MatchOptions()
    {
        // Default options: 16-byte salt, 32-byte tag. Base64-nopad encodes
        // 16 bytes -> 22 chars and 32 bytes -> 43 chars.
        var hasher = new Argon2idPasswordHasher();
        string hash = hasher.HashPassword("lengths");

        string[] parts = hash.Split('$');
        Assert.Equal(22, parts[4].Length);
        Assert.Equal(43, parts[5].Length);
    }
}
