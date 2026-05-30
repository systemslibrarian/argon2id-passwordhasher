using BenchmarkDotNet.Attributes;

namespace Argon2id.PasswordHasher.Benchmarks;

/// <summary>
/// Measures the cost of hashing and verifying a password across representative
/// Argon2id parameter sets. Use the results to pick parameters that hit your
/// latency budget on your own hardware (see docs/parameter-tuning.md).
/// </summary>
[MemoryDiagnoser]
public class HashBenchmarks
{
    private const string Password = "correct horse battery staple";

    private Argon2idPasswordHasher _hasher = null!;
    private string _hash = string.Empty;

    /// <summary>Memory cost in KiB: OWASP minimum (19 MiB), library default (64 MiB), and a high setting (128 MiB).</summary>
    [Params(19456, 65536, 131072)]
    public int MemoryKib;

    /// <summary>Time cost (passes over memory).</summary>
    [Params(1, 3)]
    public int Iterations;

    [GlobalSetup]
    public void Setup()
    {
        _hasher = new Argon2idPasswordHasher(new Argon2idOptions
        {
            MemorySizeKib = MemoryKib,
            Iterations = Iterations,
            DegreeOfParallelism = 1,
        });
        _hash = _hasher.HashPassword(Password);
    }

    [Benchmark]
    public string HashPassword() => _hasher.HashPassword(Password);

    [Benchmark]
    public bool VerifyPassword() => _hasher.VerifyPassword(Password, _hash);
}
