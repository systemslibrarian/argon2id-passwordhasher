using System.Globalization;
using System.Text;
using System.Text.Unicode;

namespace Argon2id.PasswordHasher;

/// <summary>
/// Parsed representation of an Argon2id hash encoded in the PHC string format:
/// <c>$argon2id$v=19$m=65536,t=3,p=1$&lt;base64salt&gt;$&lt;base64hash&gt;</c>, with an
/// optional <c>keyid</c> parameter when a pepper (secret key) is in use.
/// </summary>
/// <remarks>
/// The PHC (Password Hashing Competition) format is the de-facto standard used by
/// libsodium, the Argon2 reference implementation, and most modern libraries.
/// Storing parameters alongside the hash makes the value self-describing and
/// portable, and lets verification succeed even after defaults are upgraded.
/// </remarks>
internal sealed record PhcString
{
    /// <summary>The Argon2 version number. Argon2 v1.3 is encoded as 19 (0x13).</summary>
    public const int Argon2Version = 19;

    // Resource-safety bounds enforced on PARSE. Verification recomputes Argon2id
    // with the parameters stored in the hash, so without these caps a crafted
    // stored value (e.g. m=2147483647 KiB) could force a multi-terabyte
    // allocation — an exception/DoS instead of the documented "return false".
    // The caps are far above anything a legitimate producer emits today and are
    // mirrored by Argon2idOptions.Validate() so this library can never emit a
    // hash its own parser would reject.
    internal const int MaxMemorySizeKib = 4 * 1024 * 1024; // 4 GiB
    internal const int MaxIterations = 1024;
    internal const int MaxDegreeOfParallelism = 128;
    internal const int MinSaltSizeBytes = 8;               // RFC 9106 minimum
    internal const int MaxSaltSizeBytes = 64;
    internal const int MinHashSizeBytes = 16;              // below this, the tag itself is the weakness
    internal const int MaxHashSizeBytes = 512;
    internal const int MaxKeyIdBytes = 64;

    public required int MemorySizeKib { get; init; }
    public required int Iterations { get; init; }
    public required int DegreeOfParallelism { get; init; }

    /// <summary>
    /// Identifier of the pepper used to produce this hash, or <see langword="null"/>
    /// if the hash was produced without a pepper. Encoded as the standard PHC
    /// <c>keyid</c> parameter.
    /// </summary>
    public string? KeyId { get; init; }

    public required byte[] Salt { get; init; }
    public required byte[] Hash { get; init; }

    /// <summary>Encodes the given parameters and bytes into a PHC string.</summary>
    public static string Encode(Argon2idOptions options, byte[] salt, byte[] hash, string? keyId = null)
    {
        // Standard "b64" encoding for PHC strings is base64 without padding.
        string saltB64 = ToB64NoPadding(salt);
        string hashB64 = ToB64NoPadding(hash);

        string costs = string.Create(CultureInfo.InvariantCulture,
            $"m={options.MemorySizeKib},t={options.Iterations},p={options.DegreeOfParallelism}");

        if (keyId is not null)
        {
            // keyid carries the pepper identifier so verification can select the
            // right secret. It is the *identifier*, never the secret itself.
            costs += ",keyid=" + ToB64NoPadding(Encoding.UTF8.GetBytes(keyId));
        }

        return string.Create(CultureInfo.InvariantCulture,
            $"$argon2id$v={Argon2Version}${costs}${saltB64}${hashB64}");
    }

    /// <summary>
    /// Attempts to parse a PHC-encoded Argon2id hash. Returns <see langword="false"/>
    /// for any malformed, unsupported, or non-Argon2id input rather than throwing,
    /// so callers can treat unparseable stored values as a failed verification.
    /// </summary>
    public static bool TryParse(string? encoded, out PhcString? result)
    {
        result = null;
        if (string.IsNullOrEmpty(encoded))
        {
            return false;
        }

        // Layout: ["", "argon2id", "v=19", "m=..,t=..,p=..[,keyid=..]", salt, hash]
        string[] parts = encoded.Split('$');
        if (parts.Length != 6 || parts[0].Length != 0)
        {
            return false;
        }

        if (!string.Equals(parts[1], "argon2id", StringComparison.Ordinal))
        {
            return false;
        }

        if (!TryParseTaggedInt(parts[2], "v", out int version) || version != Argon2Version)
        {
            return false;
        }

        string[] costParts = parts[3].Split(',');
        // 3 mandatory cost parameters, with an optional 4th (keyid).
        if (costParts.Length is < 3 or > 4
            || !TryParseTaggedInt(costParts[0], "m", out int memory)
            || !TryParseTaggedInt(costParts[1], "t", out int iterations)
            || !TryParseTaggedInt(costParts[2], "p", out int parallelism))
        {
            return false;
        }

        // Resource-safety caps: verification allocates `m` KiB, so the stored
        // value must not be able to dictate an absurd allocation. The Argon2
        // reference implementation additionally requires m >= 8 * p.
        if (memory > MaxMemorySizeKib
            || iterations > MaxIterations
            || parallelism > MaxDegreeOfParallelism
            || memory < 8L * parallelism)
        {
            return false;
        }

        string? keyId = null;
        if (costParts.Length == 4)
        {
            // keyid carries a pepper *identifier*, which is a string in this
            // library. Bytes that are not valid UTF-8 cannot round-trip through
            // a string (replacement characters would change the re-encoded
            // bytes), so they are rejected rather than silently mangled.
            if (!costParts[3].StartsWith("keyid=", StringComparison.Ordinal)
                || !TryFromB64NoPadding(costParts[3]["keyid=".Length..], out byte[]? keyIdBytes)
                || keyIdBytes!.Length > MaxKeyIdBytes
                || !Utf8.IsValid(keyIdBytes))
            {
                return false;
            }

            keyId = Encoding.UTF8.GetString(keyIdBytes);
        }

        if (!TryFromB64NoPadding(parts[4], out byte[]? salt)
            || !TryFromB64NoPadding(parts[5], out byte[]? hash))
        {
            return false;
        }

        if (salt!.Length is < MinSaltSizeBytes or > MaxSaltSizeBytes
            || hash!.Length is < MinHashSizeBytes or > MaxHashSizeBytes)
        {
            return false;
        }

        result = new PhcString
        {
            MemorySizeKib = memory,
            Iterations = iterations,
            DegreeOfParallelism = parallelism,
            KeyId = keyId,
            Salt = salt!, // non-null: TryFromB64NoPadding returned true above
            Hash = hash!,
        };
        return true;
    }

    private static bool TryParseTaggedInt(string segment, string tag, out int value)
    {
        value = 0;
        // Expect "<tag>=<int>" with a positive integer payload.
        if (!segment.StartsWith(tag + "=", StringComparison.Ordinal))
        {
            return false;
        }

        ReadOnlySpan<char> payload = segment.AsSpan(tag.Length + 1);
        return int.TryParse(payload, NumberStyles.None, CultureInfo.InvariantCulture, out value) && value > 0;
    }

    private static string ToB64NoPadding(byte[] data) =>
        Convert.ToBase64String(data).TrimEnd('=');

    private static bool TryFromB64NoPadding(string value, out byte[]? data)
    {
        data = null;
        if (value.Length == 0)
        {
            return false;
        }

        // Restore the padding that the PHC format strips before decoding.
        int padding = (4 - (value.Length % 4)) % 4;
        string padded = padding == 0 ? value : value + new string('=', padding);

        Span<byte> buffer = new byte[(padded.Length / 4) * 3];
        if (!Convert.TryFromBase64String(padded, buffer, out int written))
        {
            return false;
        }

        data = buffer[..written].ToArray();
        return true;
    }
}
