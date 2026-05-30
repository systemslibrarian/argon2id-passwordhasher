namespace Argon2id.PasswordHasher.WasmDemo.Services;

/// <summary>View-model decomposition of a PHC-encoded Argon2id hash.</summary>
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
    public static PhcBreakdown? TryParse(string encoded)
    {
        if (string.IsNullOrEmpty(encoded))
        {
            return null;
        }

        string[] parts = encoded.Split('$');
        if (parts.Length != 6 || parts[0].Length != 0)
        {
            return null;
        }

        string[] costs = parts[3].Split(',');
        if (costs.Length is < 3 or > 4)
        {
            return null;
        }

        string? keyId = costs.Length == 4 ? costs[3] : null;

        return new PhcBreakdown(
            Algorithm: parts[1],
            Version: parts[2],
            MemoryCost: costs[0],
            TimeCost: costs[1],
            Parallelism: costs[2],
            KeyId: keyId,
            SaltBase64: parts[4],
            HashBase64: parts[5]);
    }
}
