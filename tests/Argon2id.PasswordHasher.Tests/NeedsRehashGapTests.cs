using Xunit;

namespace Argon2id.PasswordHasher.Tests;

/// <summary>
/// Guards two <c>NeedsRehash</c> contracts: a stored salt shorter than the
/// configured size must be flagged for upgrade (the parser deliberately
/// accepts 8-byte salts for interop, below the library's own 16-byte floor),
/// and a hash that carries a pepper id must be flagged under a hasher with no
/// pepper ring, since it can never verify there.
/// </summary>
public class NeedsRehashGapTests
{
    private static readonly Argon2idOptions FastOptions = new()
    {
        MemorySizeKib = 8192,
        Iterations = 1,
        DegreeOfParallelism = 1,
    };

    private static string B64(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=');

    private static string SyntheticHash(int saltBytes) =>
        $"$argon2id$v=19$m=8192,t=1,p=1${B64(new byte[saltBytes])}${B64(new byte[32])}";

    [Fact]
    public void StoredSaltShorterThanConfigured_NeedsRehash()
    {
        // 8-byte salt parses (RFC interop minimum) but is below the configured
        // 16-byte default, so it must be reported as needing an upgrade.
        var hasher = new Argon2idPasswordHasher(FastOptions);

        Assert.True(hasher.NeedsRehash(SyntheticHash(saltBytes: 8)));
    }

    [Fact]
    public void StoredSaltAtConfiguredSize_NoRehash()
    {
        var hasher = new Argon2idPasswordHasher(FastOptions);

        Assert.False(hasher.NeedsRehash(SyntheticHash(saltBytes: 16)));
    }

    [Fact]
    public void PepperedHash_UnderRinglessHasher_NeedsRehash()
    {
        var pepper = new Pepper("2026-07", new byte[16]);
        var peppered = new Argon2idPasswordHasher(FastOptions, new PepperRing(pepper));
        string hash = peppered.HashPassword("pw");

        var ringless = new Argon2idPasswordHasher(FastOptions);

        // Fail-closed verify and the rehash signal must agree: this hash can
        // never verify here, so it needs attention.
        Assert.False(ringless.VerifyPassword("pw", hash));
        Assert.True(ringless.NeedsRehash(hash));
    }

    [Fact]
    public void UnpepperedHash_UnderRinglessHasher_NoRehash()
    {
        var hasher = new Argon2idPasswordHasher(FastOptions);
        string hash = hasher.HashPassword("pw");

        Assert.False(hasher.NeedsRehash(hash));
    }
}
