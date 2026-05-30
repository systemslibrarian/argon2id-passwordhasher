namespace Argon2id.PasswordHasher.Demo.Services;

/// <summary>
/// A view-model decomposition of a PHC-encoded Argon2id hash. Built purely
/// for display purposes so the UI can show users *what's in* the string they
/// would have stored in a database column.
/// </summary>
/// <remarks>
/// The library itself uses an internal parser; this type just splits the
/// string for educational rendering and never inspects the secret hash bytes.
/// </remarks>
public sealed record PhcBreakdown(
    string Algorithm,
    string Version,
    string MemoryCost,
    string TimeCost,
    string Parallelism,
    string? KeyId,
    string SaltBase64,
    string HashBase64)
{
    /// <summary>
    /// Split a PHC string into its visible parts. Returns <see langword="null"/>
    /// if the string is malformed &#8212; this mirrors the library's "fail safe,
    /// not loud" parsing policy.
    /// </summary>
    public static PhcBreakdown? TryParse(string encoded)
    {
        if (string.IsNullOrEmpty(encoded))
        {
            return null;
        }

        // Expected shape: $argon2id$v=19$m=...,t=...,p=...[,keyid=...]$<salt>$<hash>
        string[] parts = encoded.Split('$');
        if (parts.Length != 6 || parts[0].Length != 0)
        {
            return null;
        }

        string algorithm = parts[1];
        string version = parts[2];
        string[] costs = parts[3].Split(',');
        if (costs.Length is < 3 or > 4)
        {
            return null;
        }

        string? keyId = costs.Length == 4 ? costs[3] : null;

        return new PhcBreakdown(
            Algorithm: algorithm,
            Version: version,
            MemoryCost: costs[0],
            TimeCost: costs[1],
            Parallelism: costs[2],
            KeyId: keyId,
            SaltBase64: parts[4],
            HashBase64: parts[5]);
    }
}
