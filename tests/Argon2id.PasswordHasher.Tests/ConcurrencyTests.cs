using Xunit;

namespace Argon2id.PasswordHasher.Tests;

/// <summary>
/// Exercises the documented thread-safety contract: a single
/// <see cref="Argon2idPasswordHasher"/> instance is safe to share across threads.
/// </summary>
public class ConcurrencyTests
{
    private static readonly Argon2idOptions FastOptions = new()
    {
        MemorySizeKib = 8192,
        Iterations = 1,
        DegreeOfParallelism = 1,
    };

    [Fact]
    public void SharedHasher_ProducesDistinctValidHashes_UnderParallelLoad()
    {
        // A shared singleton must produce N distinct, individually-verifiable hashes
        // when N threads call HashPassword concurrently. Distinctness proves the salt
        // is freshly drawn per call (no shared mutable state); verifiability proves
        // no concurrency bug corrupted any individual hash.
        var hasher = new Argon2idPasswordHasher(FastOptions);
        const string password = "shared singleton";
        const int hashesPerThread = 8;
        int threadCount = Math.Max(4, Environment.ProcessorCount);

        var hashes = new string[threadCount * hashesPerThread];

        Parallel.For(0, threadCount, threadIndex =>
        {
            for (int i = 0; i < hashesPerThread; i++)
            {
                hashes[(threadIndex * hashesPerThread) + i] = hasher.HashPassword(password);
            }
        });

        // Every hash must be unique (proves fresh salt under contention).
        Assert.Equal(hashes.Length, hashes.Distinct(StringComparer.Ordinal).Count());

        // Every hash must verify back (proves no buffer was mid-stomp during parallel runs).
        foreach (string hash in hashes)
        {
            Assert.True(hasher.VerifyPassword(password, hash));
        }
    }

    [Fact]
    public void SharedHasher_ParallelVerifies_AllSucceed()
    {
        var hasher = new Argon2idPasswordHasher(FastOptions);
        const string password = "verify under load";
        string canonical = hasher.HashPassword(password);

        int iterations = Math.Max(32, Environment.ProcessorCount * 4);
        var results = new bool[iterations];

        Parallel.For(0, iterations, i =>
        {
            results[i] = hasher.VerifyPassword(password, canonical);
        });

        Assert.All(results, Assert.True);
    }
}
