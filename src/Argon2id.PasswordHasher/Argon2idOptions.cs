namespace Argon2id.PasswordHasher;

/// <summary>
/// Tunable Argon2id work-factor parameters used when hashing passwords.
/// </summary>
/// <remarks>
/// <para>
/// The defaults are opinionated and chosen to be safe for typical 2026 server
/// hardware while leaving headroom for concurrent logins. They comfortably
/// exceed the OWASP minimum (Argon2id, 19&#160;MiB, t=2, p=1) and follow the
/// RFC&#160;9106 second recommended profile shape.
/// </para>
/// <para>
/// Every hash produced by this library stores its own parameters inside the
/// resulting PHC string, so changing these values never breaks verification of
/// existing hashes. Use <see cref="Argon2idPasswordHasher.NeedsRehash"/> to detect and
/// transparently upgrade older hashes on the next successful login.
/// </para>
/// </remarks>
public sealed record Argon2idOptions
{
    /// <summary>
    /// Memory cost in kibibytes (KiB). Default: 65536 KiB (64&#160;MiB).
    /// Memory hardness is Argon2's primary defense against GPU/ASIC cracking.
    /// </summary>
    public int MemorySizeKib { get; init; } = 65536;

    /// <summary>
    /// Time cost: the number of passes over memory. Default: 3.
    /// </summary>
    public int Iterations { get; init; } = 3;

    /// <summary>
    /// Degree of parallelism (number of lanes / threads). Default: 1.
    /// Kept low so per-hash CPU cost is predictable under concurrent load.
    /// </summary>
    public int DegreeOfParallelism { get; init; } = 1;

    /// <summary>
    /// Salt length in bytes. Default: 16 (128 bits), the RFC&#160;9106 recommendation.
    /// </summary>
    public int SaltSizeBytes { get; init; } = 16;

    /// <summary>
    /// Derived hash (tag) length in bytes. Default: 32 (256 bits).
    /// </summary>
    public int HashSizeBytes { get; init; } = 32;

    /// <summary>
    /// The library's recommended defaults. Equivalent to <c>new Argon2idOptions()</c>.
    /// </summary>
    public static Argon2idOptions Recommended { get; } = new();

    /// <summary>
    /// Validates the parameter set, throwing <see cref="ArgumentOutOfRangeException"/>
    /// for any value outside the safe operating range.
    /// </summary>
    public void Validate()
    {
        // Lower bounds reflect the OWASP / RFC 9106 minimums; below these the
        // configuration would be insecure rather than merely slow.
        if (MemorySizeKib < 8192)
        {
            throw new ArgumentOutOfRangeException(
                nameof(MemorySizeKib), MemorySizeKib,
                "Memory cost must be at least 8192 KiB (8 MiB). The library recommends 65536 KiB (64 MiB).");
        }

        if (Iterations < 1)
        {
            throw new ArgumentOutOfRangeException(
                nameof(Iterations), Iterations, "Iterations (time cost) must be at least 1.");
        }

        if (DegreeOfParallelism < 1)
        {
            throw new ArgumentOutOfRangeException(
                nameof(DegreeOfParallelism), DegreeOfParallelism, "Degree of parallelism must be at least 1.");
        }

        if (SaltSizeBytes < 16)
        {
            throw new ArgumentOutOfRangeException(
                nameof(SaltSizeBytes), SaltSizeBytes, "Salt must be at least 16 bytes (128 bits).");
        }

        if (HashSizeBytes < 16)
        {
            throw new ArgumentOutOfRangeException(
                nameof(HashSizeBytes), HashSizeBytes, "Hash length must be at least 16 bytes (128 bits).");
        }
    }
}
