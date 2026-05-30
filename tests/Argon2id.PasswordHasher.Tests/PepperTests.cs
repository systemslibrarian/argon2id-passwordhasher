using System.Text;
using Argon2id.PasswordHasher;
using Xunit;

namespace Argon2id.PasswordHasher.Tests;

public class PepperTests
{
    private static readonly Argon2idOptions FastOptions = new()
    {
        MemorySizeKib = 8192,
        Iterations = 1,
        DegreeOfParallelism = 1,
    };

    private static byte[] Key(byte fill) => Enumerable.Repeat(fill, 32).ToArray();

    private static PasswordHasher Hasher(PepperRing? ring) => new(FastOptions, ring);

    [Fact]
    public void PepperedHash_EmbedsKeyId_AndVerifies()
    {
        var ring = new PepperRing(new Pepper("2026-05", Key(0x01)));
        var hasher = Hasher(ring);

        string hash = hasher.HashPassword("peppered");

        Assert.Contains("keyid=", hash, StringComparison.Ordinal);
        Assert.True(hasher.VerifyPassword("peppered", hash));
        Assert.False(hasher.NeedsRehash(hash));
    }

    [Fact]
    public void Verify_WithoutTheRequiredPepper_ReturnsFalse()
    {
        var ring = new PepperRing(new Pepper("2026-05", Key(0x01)));
        string hash = Hasher(ring).HashPassword("secret");

        // A hasher with no pepper cannot supply the secret, so it must fail closed.
        Assert.False(Hasher(null).VerifyPassword("secret", hash));

        // A hasher with a *different* pepper id also cannot verify.
        var otherRing = new PepperRing(new Pepper("other", Key(0x02)));
        Assert.False(Hasher(otherRing).VerifyPassword("secret", hash));
    }

    [Fact]
    public void Verify_WithWrongPepperBytesSameId_ReturnsFalse()
    {
        string hash = Hasher(new PepperRing(new Pepper("k", Key(0x01)))).HashPassword("secret");

        // Same id, different key bytes -> recomputed hash differs.
        var wrong = Hasher(new PepperRing(new Pepper("k", Key(0x99))));
        Assert.False(wrong.VerifyPassword("secret", hash));
    }

    [Fact]
    public void RetiredPepper_StillVerifies_ButNeedsRehash()
    {
        var oldPepper = new Pepper("2025", Key(0x01));
        string oldHash = Hasher(new PepperRing(oldPepper)).HashPassword("rotate me");

        // New ring: active key rotated, old key retained as retired.
        var rotated = new PepperRing(new Pepper("2026", Key(0x02)), oldPepper);
        var hasher = Hasher(rotated);

        Assert.True(hasher.VerifyPassword("rotate me", oldHash));
        Assert.True(hasher.NeedsRehash(oldHash));

        // Re-hashing adopts the active pepper and no longer needs a rehash.
        string upgraded = hasher.HashPassword("rotate me");
        Assert.True(hasher.VerifyPassword("rotate me", upgraded));
        Assert.False(hasher.NeedsRehash(upgraded));
    }

    [Fact]
    public void UnpepperedHash_VerifiesUnderPepperedHasher_AndNeedsRehash()
    {
        // Hash produced before peppering was introduced.
        string legacy = Hasher(null).HashPassword("legacy");

        var hasher = Hasher(new PepperRing(new Pepper("2026", Key(0x01))));

        Assert.DoesNotContain("keyid=", legacy, StringComparison.Ordinal);
        Assert.True(hasher.VerifyPassword("legacy", legacy));
        Assert.True(hasher.NeedsRehash(legacy));
    }

    [Fact]
    public void Pepper_InvalidArguments_Throw()
    {
        Assert.Throws<ArgumentException>(() => new Pepper("", Key(0x01)));
        Assert.Throws<ArgumentNullException>(() => new Pepper("id", null!));
        Assert.Throws<ArgumentOutOfRangeException>(() => new Pepper("id", new byte[8]));
    }

    [Fact]
    public void PepperRing_DuplicateIds_Throw()
    {
        var active = new Pepper("same", Key(0x01));
        var dup = new Pepper("same", Key(0x02));

        Assert.Throws<ArgumentException>(() => new PepperRing(active, dup));
    }

    [Fact]
    public void Pepper_DefensivelyCopiesKey()
    {
        byte[] key = Key(0x01);
        var pepper = new Pepper("k", key);
        string hash = Hasher(new PepperRing(pepper)).HashPassword("data");

        // Mutating the caller's array after construction must not affect verification.
        Array.Clear(key);
        Assert.True(Hasher(new PepperRing(new Pepper("k", Key(0x01)))).VerifyPassword("data", hash));
    }
}
