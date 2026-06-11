using CsCheck;
using Xunit;

namespace Argon2id.PasswordHasher.Tests;

/// <summary>
/// Property-based tests (CsCheck). Where the example-based suites pin specific
/// inputs, these assert invariants over randomized input spaces:
/// the PHC parser is total (never throws), encode/parse is an identity,
/// and hash/verify round-trips for arbitrary Unicode passwords.
/// On failure CsCheck prints a seed that reproduces the shrunken counterexample.
/// </summary>
public class PropertyTests
{
    // Deliberately weak parameters: properties run many hashing iterations.
    // Never copy these values into production code.
    private static readonly Argon2idPasswordHasher Hasher = new(new Argon2idOptions
    {
        MemorySizeKib = 8192,
        Iterations = 1,
        DegreeOfParallelism = 1,
    });

    [Fact]
    public void TryParse_IsTotal_OnArbitraryStrings()
    {
        // Statement-body lambda on purpose: an expression lambda returning the
        // bool would bind to CsCheck's predicate overload, where false = fail.
        Gen.String[0, 200].Sample(s => { _ = PhcString.TryParse(s, out _); }, iter: 10_000);
    }

    [Fact]
    public void TryParse_IsTotal_OnAdversarialPhcShapedStrings()
    {
        // Strings built from the PHC grammar's own alphabet drive the parser far
        // deeper than uniformly random text: most samples get past the prefix
        // and exercise the cost/keyid/base64 handling.
        Gen<string> phcShaped =
            Gen.Char["argon2idvmtpkeyAB+/=,.$0123456789"].Array[0, 80]
               .Select(chars => "$argon2id$" + new string(chars));

        phcShaped.Sample(s =>
        {
            if (PhcString.TryParse(s, out PhcString? parsed))
            {
                // Anything the parser accepts must satisfy its own documented bounds.
                Assert.InRange(parsed!.MemorySizeKib, 1, PhcString.MaxMemorySizeKib);
                Assert.InRange(parsed.Iterations, 1, PhcString.MaxIterations);
                Assert.InRange(parsed.DegreeOfParallelism, 1, PhcString.MaxDegreeOfParallelism);
                Assert.InRange(parsed.Salt.Length, PhcString.MinSaltSizeBytes, PhcString.MaxSaltSizeBytes);
                Assert.InRange(parsed.Hash.Length, PhcString.MinHashSizeBytes, PhcString.MaxHashSizeBytes);
            }
        }, iter: 10_000);
    }

    [Fact]
    public void EncodeThenParse_IsIdentity()
    {
        var gen = Gen.Select(
            Gen.Int[1024, PhcString.MaxMemorySizeKib],
            Gen.Int[1, PhcString.MaxIterations],
            Gen.Int[1, PhcString.MaxDegreeOfParallelism],
            Gen.Byte.Array[PhcString.MinSaltSizeBytes, PhcString.MaxSaltSizeBytes],
            Gen.Byte.Array[PhcString.MinHashSizeBytes, PhcString.MaxHashSizeBytes]);

        gen.Sample(t =>
        {
            (int memory, int iterations, int parallelism, byte[] salt, byte[] tag) = t;
            if (memory < 8 * parallelism)
            {
                memory = 8 * parallelism; // parser invariant from the reference implementation
            }

            var options = new Argon2idOptions
            {
                MemorySizeKib = memory,
                Iterations = iterations,
                DegreeOfParallelism = parallelism,
            };

            string encoded = PhcString.Encode(options, salt, tag);

            Assert.True(PhcString.TryParse(encoded, out PhcString? parsed));
            Assert.Equal(memory, parsed!.MemorySizeKib);
            Assert.Equal(iterations, parsed.Iterations);
            Assert.Equal(parallelism, parsed.DegreeOfParallelism);
            Assert.Null(parsed.KeyId);
            Assert.Equal(salt, parsed.Salt);
            Assert.Equal(tag, parsed.Hash);
        }, iter: 2_000);
    }

    [Fact]
    public void EncodeThenParse_RoundTripsKeyId()
    {
        var gen = Gen.Select(
            Gen.Char["abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_."].Array[1, 32]
               .Select(chars => new string(chars)),
            Gen.Byte.Array[16, 16],
            Gen.Byte.Array[32, 32]);

        var options = new Argon2idOptions { MemorySizeKib = 8192, Iterations = 1, DegreeOfParallelism = 1 };

        gen.Sample(t =>
        {
            (string keyId, byte[] salt, byte[] tag) = t;
            string encoded = PhcString.Encode(options, salt, tag, keyId);

            Assert.True(PhcString.TryParse(encoded, out PhcString? parsed));
            Assert.Equal(keyId, parsed!.KeyId);
        }, iter: 2_000);
    }

    [Fact]
    public void HashThenVerify_RoundTrips_ForArbitraryUnicodePasswords()
    {
        // Hashing is the expensive part, so this property runs few iterations;
        // the cheap parser properties above carry the volume.
        Gen.String[1, 32].Sample(password =>
        {
            string encoded = Hasher.HashPassword(password);

            Assert.True(Hasher.VerifyPassword(password, encoded));
            Assert.False(Hasher.VerifyPassword(password + "-wrong", encoded));
        }, iter: 12);
    }

    [Fact]
    public void Verify_IsTotal_AndRejectsArbitraryStoredValues()
    {
        Gen.String[0, 120].Sample(stored =>
            Assert.False(Hasher.VerifyPassword("any-password", stored)), iter: 2_000);
    }
}
