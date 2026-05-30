using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace Argon2id.PasswordHasher;

/// <summary>
/// An opinionated, secure-by-default Argon2id password hasher.
/// </summary>
/// <remarks>
/// <para>
/// Construct once with the recommended defaults and reuse the instance &#8212; it is
/// stateless and thread-safe. Each call to <see cref="HashPassword(string)"/> generates
/// a fresh cryptographically random salt and returns a self-describing PHC string that
/// already contains every parameter needed to verify it later.
/// </para>
/// <para>
/// Overloads accepting <see cref="ReadOnlySpan{T}"/> of <see cref="char"/> or
/// <see cref="byte"/> let callers avoid materializing the password as a
/// <see cref="string"/>; the hasher zeroes every password-derived buffer it owns.
/// </para>
/// <example>
/// <code>
/// var hasher = new Argon2idPasswordHasher();
/// string stored = hasher.HashPassword("correct horse battery staple");
/// bool ok = hasher.VerifyPassword("correct horse battery staple", stored); // true
/// </code>
/// </example>
/// </remarks>
public sealed class Argon2idPasswordHasher
{
    private readonly Argon2idOptions _options;
    private readonly PepperRing? _pepper;

    /// <summary>
    /// Creates a hasher using the library's recommended defaults
    /// (<see cref="Argon2idOptions.Recommended"/>) and no pepper.
    /// </summary>
    public Argon2idPasswordHasher()
        : this(Argon2idOptions.Recommended, pepper: null)
    {
    }

    /// <summary>
    /// Creates a hasher with custom work-factor parameters and no pepper.
    /// </summary>
    /// <param name="options">The Argon2id parameters to use for new hashes.</param>
    /// <exception cref="ArgumentNullException"><paramref name="options"/> is null.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Any parameter is outside the safe range.</exception>
    public Argon2idPasswordHasher(Argon2idOptions options)
        : this(options, pepper: null)
    {
    }

    /// <summary>
    /// Creates a hasher with custom work-factor parameters and an optional pepper ring.
    /// </summary>
    /// <param name="options">The Argon2id parameters to use for new hashes.</param>
    /// <param name="pepper">
    /// An optional <see cref="PepperRing"/>. When supplied, new hashes are produced with the
    /// ring's active pepper and tagged with its id; verification selects the pepper recorded
    /// in each hash. When <see langword="null"/>, hashing and verification use no pepper.
    /// </param>
    /// <exception cref="ArgumentNullException"><paramref name="options"/> is null.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Any parameter is outside the safe range.</exception>
    public Argon2idPasswordHasher(Argon2idOptions options, PepperRing? pepper)
    {
        ArgumentNullException.ThrowIfNull(options);
        options.Validate();
        _options = options;
        _pepper = pepper;
    }

    /// <summary>The parameters this hasher uses when producing new hashes.</summary>
    public Argon2idOptions Options => _options;

    /// <summary>
    /// Hashes a password with a fresh random salt and returns a PHC-formatted string
    /// suitable for storage (for example, in an <c>AspNetUsers.PasswordHash</c> column).
    /// </summary>
    /// <param name="password">The plaintext password. Must not be null or empty.</param>
    /// <returns>A PHC string, e.g. <c>$argon2id$v=19$m=65536,t=3,p=1$&lt;salt&gt;$&lt;hash&gt;</c>.</returns>
    /// <exception cref="ArgumentException"><paramref name="password"/> is null or empty.</exception>
    public string HashPassword(string password) => HashPassword(password.AsSpan());

    /// <summary>
    /// Hashes a password supplied as a span of characters, avoiding an intermediate
    /// <see cref="string"/>.
    /// </summary>
    /// <param name="password">The plaintext password. Must not be empty.</param>
    /// <returns>A PHC string suitable for storage.</returns>
    /// <exception cref="ArgumentException"><paramref name="password"/> is empty.</exception>
    public string HashPassword(ReadOnlySpan<char> password)
    {
        if (password.IsEmpty)
        {
            throw new ArgumentException("Password must not be null or empty.", nameof(password));
        }

        return HashAndZero(EncodeUtf8(password));
    }

    /// <summary>
    /// Hashes a password supplied as raw bytes (for example a pre-encoded credential).
    /// The caller retains ownership of <paramref name="password"/> and is responsible for
    /// clearing it; the hasher only zeroes its own internal copy.
    /// </summary>
    /// <param name="password">The plaintext password bytes. Must not be empty.</param>
    /// <returns>A PHC string suitable for storage.</returns>
    /// <exception cref="ArgumentException"><paramref name="password"/> is empty.</exception>
    public string HashPassword(ReadOnlySpan<byte> password)
    {
        if (password.IsEmpty)
        {
            throw new ArgumentException("Password must not be empty.", nameof(password));
        }

        return HashAndZero(password.ToArray());
    }

    /// <summary>
    /// Verifies a password against a previously stored PHC hash in constant time.
    /// </summary>
    /// <param name="password">The plaintext password to check.</param>
    /// <param name="encodedHash">The stored PHC string produced by <see cref="HashPassword(string)"/>.</param>
    /// <returns>
    /// <see langword="true"/> if the password matches; otherwise <see langword="false"/>.
    /// Malformed, unsupported, or empty stored values &#8212; and hashes whose pepper is not
    /// available &#8212; return <see langword="false"/> rather than throwing.
    /// </returns>
    public bool VerifyPassword(string password, string encodedHash) =>
        Verify(password.AsSpan(), encodedHash).Success;

    /// <summary>
    /// Verifies a password supplied as a span of characters against a stored PHC hash.
    /// </summary>
    /// <param name="password">The plaintext password to check.</param>
    /// <param name="encodedHash">The stored PHC string.</param>
    /// <returns><see langword="true"/> if the password matches; otherwise <see langword="false"/>.</returns>
    public bool VerifyPassword(ReadOnlySpan<char> password, string encodedHash) =>
        Verify(password, encodedHash).Success;

    /// <summary>
    /// Verifies a password supplied as raw bytes against a stored PHC hash. The caller
    /// retains ownership of <paramref name="password"/>; the hasher zeroes only its own copy.
    /// </summary>
    /// <param name="password">The plaintext password bytes to check.</param>
    /// <param name="encodedHash">The stored PHC string.</param>
    /// <returns><see langword="true"/> if the password matches; otherwise <see langword="false"/>.</returns>
    public bool VerifyPassword(ReadOnlySpan<byte> password, string encodedHash) =>
        Verify(password, encodedHash).Success;

    /// <summary>
    /// Verifies a password and, in one call, reports whether the stored hash should
    /// be replaced with a fresh one. Parses the PHC string once; preferred over
    /// calling <see cref="VerifyPassword(string, string)"/> and
    /// <see cref="NeedsRehash(string)"/> separately.
    /// </summary>
    /// <param name="password">The plaintext password to check.</param>
    /// <param name="encodedHash">The stored PHC string.</param>
    /// <returns>
    /// A <see cref="VerifyResult"/> whose <see cref="VerifyResult.Success"/> indicates
    /// match and whose <see cref="VerifyResult.NeedsRehash"/> is <see langword="true"/>
    /// only when the password matched and the stored parameters / pepper are weaker
    /// than the hasher's current configuration.
    /// </returns>
    public VerifyResult Verify(string password, string encodedHash) =>
        Verify(password.AsSpan(), encodedHash);

    /// <inheritdoc cref="Verify(string, string)" />
    public VerifyResult Verify(ReadOnlySpan<char> password, string encodedHash)
    {
        if (password.IsEmpty || !PhcString.TryParse(encodedHash, out PhcString? parsed))
        {
            RecordParseFailureIfApplicable(encodedHash);
            return VerifyResult.Failed;
        }

        return VerifyAndZero(EncodeUtf8(password), parsed!);
    }

    /// <inheritdoc cref="Verify(string, string)" />
    public VerifyResult Verify(ReadOnlySpan<byte> password, string encodedHash)
    {
        if (password.IsEmpty || !PhcString.TryParse(encodedHash, out PhcString? parsed))
        {
            RecordParseFailureIfApplicable(encodedHash);
            return VerifyResult.Failed;
        }

        return VerifyAndZero(password.ToArray(), parsed!);
    }

    /// <summary>
    /// Increments <c>argon2id.parse.failure.count</c> only when the input was
    /// non-empty. An empty/null stored value is a caller-input issue rather
    /// than a parse failure of the PHC encoder, so we don't pollute the
    /// metric with it.
    /// </summary>
    private static void RecordParseFailureIfApplicable(string? encodedHash)
    {
        if (!string.IsNullOrEmpty(encodedHash))
        {
            Argon2idInstruments.ParseFailureCount.Add(1);
        }
    }

    /// <summary>
    /// Indicates whether a stored hash should be re-hashed on the next successful login,
    /// either because it was produced with weaker parameters than this hasher's current
    /// settings, or because it does not use the active pepper.
    /// </summary>
    /// <param name="encodedHash">The stored PHC string.</param>
    /// <returns>
    /// <see langword="true"/> if the hash is unparseable, any stored parameter is below the
    /// current configuration, or (when a pepper ring is configured) the hash's pepper differs
    /// from the active pepper; otherwise <see langword="false"/>.
    /// </returns>
    /// <remarks>
    /// Prefer <see cref="Verify(string, string)"/> when you also need to verify the
    /// password &#8212; it parses the PHC string only once.
    /// </remarks>
    public bool NeedsRehash(string encodedHash)
    {
        if (!PhcString.TryParse(encodedHash, out PhcString? parsed))
        {
            return true;
        }

        return NeedsRehashCore(parsed!);
    }

    private bool NeedsRehashCore(PhcString parsed)
    {
        if (parsed.MemorySizeKib < _options.MemorySizeKib
            || parsed.Iterations < _options.Iterations
            || parsed.DegreeOfParallelism < _options.DegreeOfParallelism
            || parsed.Hash.Length < _options.HashSizeBytes)
        {
            return true;
        }

        // Upgrade hashes that predate, or use a retired, pepper.
        return _pepper is not null && !string.Equals(parsed.KeyId, _pepper.Active.Id, StringComparison.Ordinal);
    }

    private string HashAndZero(byte[] password)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(_options.SaltSizeBytes);
        byte[]? hash = null;
        long startTicks = Stopwatch.GetTimestamp();
        try
        {
            hash = Compute(password, salt, _options.MemorySizeKib, _options.Iterations,
                _options.DegreeOfParallelism, _options.HashSizeBytes, _pepper?.Active.KnownSecret);
            return PhcString.Encode(_options, salt, hash, _pepper?.Active.Id);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(password);
            CryptographicOperations.ZeroMemory(salt);
            if (hash is not null)
            {
                CryptographicOperations.ZeroMemory(hash);
            }

            // Metrics — recorded last so they always reflect a complete call
            // whether or not we threw mid-flight. Both instruments are no-ops
            // when nothing is listening.
            Argon2idInstruments.HashCount.Add(1);
            Argon2idInstruments.HashDuration.Record(
                Stopwatch.GetElapsedTime(startTicks).TotalMilliseconds);
        }
    }

    private VerifyResult VerifyAndZero(byte[] password, PhcString parsed)
    {
        byte[]? candidate = null;
        VerifyResult outcome = VerifyResult.Failed;
        long startTicks = Stopwatch.GetTimestamp();
        try
        {
            byte[]? secret = null;
            if (parsed.KeyId is not null)
            {
                // The hash was peppered: we can only verify if we hold that pepper.
                if (_pepper is null || !_pepper.TryGet(parsed.KeyId, out Pepper? pepper))
                {
                    return outcome; // VerifyResult.Failed
                }

                secret = pepper.KnownSecret;
            }

            // Recompute using the *stored* parameters so verification keeps working
            // even after the hasher's defaults or active pepper have changed.
            candidate = Compute(password, parsed.Salt, parsed.MemorySizeKib,
                parsed.Iterations, parsed.DegreeOfParallelism, parsed.Hash.Length, secret);

            if (!CryptographicOperations.FixedTimeEquals(candidate, parsed.Hash))
            {
                return outcome; // VerifyResult.Failed
            }

            outcome = new VerifyResult(Success: true, NeedsRehash: NeedsRehashCore(parsed));
            return outcome;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(password);
            if (candidate is not null)
            {
                CryptographicOperations.ZeroMemory(candidate);
            }

            // Metrics — every verify path lands here exactly once.
            Argon2idInstruments.VerifyCount.Add(1);
            Argon2idInstruments.VerifyDuration.Record(
                Stopwatch.GetElapsedTime(startTicks).TotalMilliseconds);
            if (outcome.Success)
            {
                Argon2idInstruments.VerifySuccessCount.Add(1);
                if (outcome.NeedsRehash)
                {
                    Argon2idInstruments.RehashNeededCount.Add(1);
                }
            }
        }
    }

    private static byte[] EncodeUtf8(ReadOnlySpan<char> password)
    {
        byte[] buffer = new byte[Encoding.UTF8.GetByteCount(password)];
        Encoding.UTF8.GetBytes(password, buffer);
        return buffer;
    }

    private static byte[] Compute(byte[] password, byte[] salt, int memoryKib, int iterations,
        int parallelism, int hashLength, byte[]? secret)
    {
        // Fully qualified: the library's own root namespace begins with "Argon2id",
        // which would otherwise shadow the Konscious type name.
        using var argon2 = new Konscious.Security.Cryptography.Argon2id(password)
        {
            Salt = salt,
            MemorySize = memoryKib,
            Iterations = iterations,
            DegreeOfParallelism = parallelism,
        };

        if (secret is not null)
        {
            // Reuse the pepper's cached byte[] (already a defensive copy held by Pepper),
            // avoiding a per-call allocation. Konscious treats KnownSecret as read-only.
            argon2.KnownSecret = secret;
        }

        return argon2.GetBytes(hashLength);
    }
}
