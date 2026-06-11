using System.Globalization;
using System.Text;
using Isopoh.Cryptography.Argon2;
using Xunit;

namespace Argon2id.PasswordHasher.Tests;

/// <summary>
/// Differential testing: computes the same Argon2id inputs through two
/// independent managed implementations — Konscious (the library's engine) and
/// Isopoh — and requires bit-identical tags. A bug would have to be replicated
/// independently in both codebases to slip through, which turns the single
/// pinned KAT in <see cref="PhcInteropTests"/> into continuous cross-validation
/// across a whole parameter matrix.
/// </summary>
/// <remarks>
/// Isopoh is a test-only dependency; it is never referenced by the shipped
/// packages. The randomized cases use a fixed default seed so PR CI is
/// deterministic; the nightly workflow overrides <c>DIFFERENTIAL_SEED</c> to
/// explore fresh parameter combinations every run.
/// </remarks>
[Trait("Category", "Differential")]
public class DifferentialTests
{
    private static byte[] KonsciousTag(
        byte[] password, byte[] salt, int memoryKib, int iterations, int parallelism,
        int tagLength, byte[]? secret)
    {
        using var argon2 = new Konscious.Security.Cryptography.Argon2id(password)
        {
            Salt = salt,
            MemorySize = memoryKib,
            Iterations = iterations,
            DegreeOfParallelism = parallelism,
        };

        if (secret is not null)
        {
            argon2.KnownSecret = secret;
        }

        return argon2.GetBytes(tagLength);
    }

    private static byte[] IsopohTag(
        byte[] password, byte[] salt, int memoryKib, int iterations, int parallelism,
        int tagLength, byte[]? secret)
    {
        var config = new Argon2Config
        {
            Type = Argon2Type.HybridAddressing, // Argon2id
            Version = Argon2Version.Nineteen,
            MemoryCost = memoryKib,
            TimeCost = iterations,
            Lanes = parallelism,
            Threads = parallelism,
            Password = password,
            Salt = salt,
            Secret = secret,
            HashLength = tagLength,
            ClearPassword = false,
            ClearSecret = false,
        };

        using var argon2 = new Argon2(config);
        using Isopoh.Cryptography.SecureArray.SecureArray<byte> tag = argon2.Hash();
        return [.. tag.Buffer];
    }

    public static TheoryData<int, int, int, int, int, string> FixedMatrix => new()
    {
        // memoryKib, iterations, parallelism, saltLen, tagLen, password
        { 8192, 1, 1, 16, 32, "differential-baseline" },
        { 8192, 2, 2, 16, 32, "differential-multi-lane" },
        { 16384, 1, 4, 16, 32, "differential-four-lanes" },
        { 8192, 3, 1, 32, 64, "differential-long-salt-and-tag" },
        { 19456, 2, 1, 16, 32, "differential-owasp-minimum" },
        { 8192, 1, 1, 16, 32, "pässwörd-ünicode-✓" },
        { 8192, 1, 1, 16, 32, "correct horse battery staple correct horse battery staple 12345" },
    };

    [Theory]
    [MemberData(nameof(FixedMatrix))]
    public void KonsciousAndIsopoh_ProduceIdenticalTags(
        int memoryKib, int iterations, int parallelism, int saltLen, int tagLen, string password)
    {
        byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
        byte[] salt = MakeSalt(saltLen, seed: 42);

        byte[] konscious = KonsciousTag(passwordBytes, salt, memoryKib, iterations, parallelism, tagLen, secret: null);
        byte[] isopoh = IsopohTag(passwordBytes, salt, memoryKib, iterations, parallelism, tagLen, secret: null);

        Assert.Equal(Convert.ToHexString(isopoh), Convert.ToHexString(konscious));
    }

    [Fact]
    public void KonsciousAndIsopoh_ProduceIdenticalTags_WithSecret()
    {
        byte[] password = Encoding.UTF8.GetBytes("peppered-differential");
        byte[] salt = MakeSalt(16, seed: 7);
        byte[] secret = Encoding.UTF8.GetBytes("pepper-secret-bytes");

        byte[] konscious = KonsciousTag(password, salt, 8192, 1, 1, 32, secret);
        byte[] isopoh = IsopohTag(password, salt, 8192, 1, 1, 32, secret);

        Assert.Equal(Convert.ToHexString(isopoh), Convert.ToHexString(konscious));
    }

    [Fact]
    public void KonsciousAndIsopoh_ProduceIdenticalTags_RandomizedMatrix()
    {
        // Deterministic by default; the nightly workflow sets DIFFERENTIAL_SEED
        // to a fresh value so every night explores new combinations. The seed is
        // part of the assertion message so any failure is reproducible.
        int seed = int.TryParse(
            Environment.GetEnvironmentVariable("DIFFERENTIAL_SEED"),
            NumberStyles.Integer, CultureInfo.InvariantCulture, out int fromEnv)
            ? fromEnv
            : 20260611;

        var rng = new Random(seed);

        for (int i = 0; i < 8; i++)
        {
            int memoryKib = rng.Next(8192, 32768);
            int parallelism = rng.Next(1, 5);
            int iterations = rng.Next(1, 4);
            int saltLen = rng.Next(8, 33);
            int tagLen = rng.Next(16, 65);

            byte[] password = new byte[rng.Next(1, 65)];
            rng.NextBytes(password);
            byte[] salt = new byte[saltLen];
            rng.NextBytes(salt);

            byte[] konscious = KonsciousTag(password, salt, memoryKib, iterations, parallelism, tagLen, secret: null);
            byte[] isopoh = IsopohTag(password, salt, memoryKib, iterations, parallelism, tagLen, secret: null);

            Assert.True(
                konscious.AsSpan().SequenceEqual(isopoh),
                $"Differential mismatch (seed={seed}, case={i}): "
                + $"m={memoryKib}, t={iterations}, p={parallelism}, salt={saltLen}B, tag={tagLen}B. "
                + $"Konscious={Convert.ToHexString(konscious)}, Isopoh={Convert.ToHexString(isopoh)}");
        }
    }

    [Fact]
    public void Library_VerifiesPhcStringAssembledFromIsopohTag()
    {
        // Cross-implementation interop through the public surface: a PHC string
        // whose tag was produced by Isopoh must verify in this library.
        const string password = "isopoh-interop";
        byte[] salt = MakeSalt(16, seed: 99);
        const int memoryKib = 8192;

        byte[] tag = IsopohTag(
            Encoding.UTF8.GetBytes(password), salt, memoryKib, iterations: 1, parallelism: 1,
            tagLength: 32, secret: null);

        string phc =
            $"$argon2id$v=19$m={memoryKib},t=1,p=1$"
            + Convert.ToBase64String(salt).TrimEnd('=') + "$"
            + Convert.ToBase64String(tag).TrimEnd('=');

        var hasher = new Argon2idPasswordHasher(new Argon2idOptions
        {
            MemorySizeKib = memoryKib,
            Iterations = 1,
            DegreeOfParallelism = 1,
        });

        Assert.True(hasher.VerifyPassword(password, phc));
        Assert.False(hasher.VerifyPassword("wrong-password", phc));
    }

    private static byte[] MakeSalt(int length, int seed)
    {
        byte[] salt = new byte[length];
        var rng = new Random(seed);
        rng.NextBytes(salt);
        return salt;
    }
}
