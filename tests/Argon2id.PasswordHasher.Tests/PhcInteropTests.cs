using Xunit;

namespace Argon2id.PasswordHasher.Tests;

/// <summary>
/// Proves the library's verify path accepts hashes produced by an
/// independent caller of the underlying Konscious Argon2id implementation
/// — i.e., we can verify any standard PHC-encoded Argon2id hash, not just
/// the ones we emitted ourselves.
/// </summary>
/// <remarks>
/// This is the closest we can get to a real libsodium-interop test
/// without taking a libsodium binary dependency in the test pack. We
/// construct an Argon2id instance directly (the same way libsodium and the
/// reference implementation produce hashes), hand-encode the PHC string,
/// and verify through the public library surface.
/// </remarks>
public class PhcInteropTests
{
    [Fact]
    public void Verify_AcceptsHashProducedByDirectKonsciousCall()
    {
        // Construct a hash the "external" way: with fixed salt and bytes,
        // using Konscious directly, then format as PHC. This mirrors what
        // libsodium or the Argon2 reference implementation would produce
        // for the same parameters.
        const string password = "external-producer";
        byte[] salt = "0123456789ABCDEF"u8.ToArray(); // 16 bytes, not random — golden test
        const int memoryKib = 8192;
        const int iterations = 1;
        const int parallelism = 1;
        const int hashLen = 32;

        byte[] tag;
        using (var argon2 = new Konscious.Security.Cryptography.Argon2id(
            System.Text.Encoding.UTF8.GetBytes(password))
        {
            Salt = salt,
            MemorySize = memoryKib,
            Iterations = iterations,
            DegreeOfParallelism = parallelism,
        })
        {
            tag = argon2.GetBytes(hashLen);
        }

        // PHC string format, base64-nopad, with parameters the same shape
        // that libsodium emits (no keyid, since we used no KnownSecret).
        string phc =
            "$argon2id$v=19$"
            + $"m={memoryKib},t={iterations},p={parallelism}$"
            + Convert.ToBase64String(salt).TrimEnd('=') + "$"
            + Convert.ToBase64String(tag).TrimEnd('=');

        var hasher = new Argon2idPasswordHasher(new Argon2idOptions
        {
            MemorySizeKib = memoryKib,
            Iterations = iterations,
            DegreeOfParallelism = parallelism,
        });

        Assert.True(hasher.VerifyPassword(password, phc),
            "Library failed to verify a PHC string produced by a direct Konscious call. "
            + "PHC: " + phc);
        Assert.False(hasher.VerifyPassword("wrong-password", phc));
    }

    [Fact]
    public void Verify_AcceptsLibrarysOwnEmittedHash()
    {
        // The mirror of the test above: take a hash the library emitted
        // and ensure it round-trips. This is a smoke test for the OTHER
        // direction (we already test it elsewhere, but pairing the two
        // here makes the interop story complete in one file).
        var hasher = new Argon2idPasswordHasher(new Argon2idOptions
        {
            MemorySizeKib = 8192,
            Iterations = 1,
            DegreeOfParallelism = 1,
        });

        string emitted = hasher.HashPassword("interop-roundtrip");
        Assert.StartsWith("$argon2id$v=19$", emitted, StringComparison.Ordinal);
        Assert.True(hasher.VerifyPassword("interop-roundtrip", emitted));
    }

    [Theory]
    [InlineData(8192, 1, 1, 16, 32)]   // CI/test profile
    [InlineData(19456, 2, 1, 16, 32)]  // OWASP minimum
    [InlineData(32768, 3, 1, 16, 32)]  // half-default memory
    public void Verify_AcceptsParametersAcrossArange(
        int memoryKib, int iterations, int parallelism, int saltBytes, int tagBytes)
    {
        var hasher = new Argon2idPasswordHasher(new Argon2idOptions
        {
            MemorySizeKib = memoryKib,
            Iterations = iterations,
            DegreeOfParallelism = parallelism,
            SaltSizeBytes = saltBytes,
            HashSizeBytes = tagBytes,
        });

        string hash = hasher.HashPassword("matrix");
        Assert.True(hasher.VerifyPassword("matrix", hash));
    }
}
