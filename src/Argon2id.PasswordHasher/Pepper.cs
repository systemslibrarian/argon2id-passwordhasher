using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Text.Unicode;

namespace Argon2id.PasswordHasher;

/// <summary>
/// A named secret key ("pepper") mixed into every Argon2id hash. A pepper is an
/// application-level secret kept <b>outside</b> the password database (for example in
/// a key vault or environment variable). If the database leaks but the pepper does
/// not, the stolen hashes cannot be cracked offline.
/// </summary>
/// <remarks>
/// The <see cref="Id"/> is stored in the hash (as the PHC <c>keyid</c> parameter) so
/// verification can select the right pepper; the <see cref="Key"/> bytes are never
/// stored. Rotate peppers over time by introducing a new active pepper and keeping
/// retired ones in a <see cref="PepperRing"/> so existing hashes still verify.
/// </remarks>
public sealed class Pepper
{
    private readonly byte[] _key;

    /// <summary>Creates a pepper.</summary>
    /// <param name="id">
    /// A short, stable identifier (e.g. <c>"2026-05"</c>). Must be non-empty, must be
    /// well-formed Unicode (no unpaired surrogates), and must encode to at most
    /// 64 UTF-8 bytes &#8212; the PHC <c>keyid</c> limit this library's parser enforces.
    /// This value is embedded in every hash produced with the pepper, so never change
    /// the bytes of an existing id &#8212; introduce a new id instead.
    /// </param>
    /// <param name="key">The secret key bytes. Must be at least 16 bytes (128 bits).</param>
    /// <exception cref="ArgumentException">
    /// <paramref name="id"/> is null or empty, contains ill-formed UTF-16 (an unpaired
    /// surrogate), or encodes to more than 64 UTF-8 bytes. These are rejected at
    /// construction because hashes produced with such an id could never be verified:
    /// the PHC parser caps <c>keyid</c> at 64 bytes, and an unpaired surrogate would be
    /// silently rewritten to U+FFFD on encode, so the stored keyid would never match
    /// this pepper's id again.
    /// </exception>
    /// <exception cref="ArgumentNullException"><paramref name="key"/> is null.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="key"/> is shorter than 16 bytes.</exception>
    public Pepper(string id, byte[] key)
    {
        if (string.IsNullOrEmpty(id))
        {
            throw new ArgumentException("Pepper id must not be null or empty.", nameof(id));
        }

        ValidateIdRoundTrips(id);

        ArgumentNullException.ThrowIfNull(key);
        if (key.Length < 16)
        {
            throw new ArgumentOutOfRangeException(
                nameof(key), key.Length, "Pepper key must be at least 16 bytes (128 bits).");
        }

        Id = id;
        // Defensive copy so the caller can zero its own buffer. Held for the lifetime
        // of this Pepper and reused on every hash/verify (see KnownSecret).
        _key = (byte[])key.Clone();
    }

    /// <summary>
    /// Rejects ids that cannot round-trip through the stored hash. The PHC
    /// <c>keyid</c> is the UTF-8 encoding of the id, capped at
    /// <see cref="PhcString.MaxKeyIdBytes"/> bytes by the parser; an id that
    /// exceeds the cap, or contains an unpaired surrogate (which UTF-8 encoding
    /// would silently rewrite to U+FFFD), would produce hashes this library can
    /// never verify — a silent lockout. Fail fast at construction instead.
    /// </summary>
    private static void ValidateIdRoundTrips(string id)
    {
        // UTF-8 never encodes to fewer bytes than UTF-16 code units, so an id
        // longer than the byte cap in chars cannot fit and needs no buffer.
        if (id.Length <= PhcString.MaxKeyIdBytes)
        {
            // Worst case 3 UTF-8 bytes per UTF-16 code unit.
            Span<byte> utf8 = stackalloc byte[PhcString.MaxKeyIdBytes * 3];
            OperationStatus status = Utf8.FromUtf16(
                id, utf8, out _, out int bytesWritten, replaceInvalidSequences: false);

            if (status == OperationStatus.InvalidData)
            {
                throw new ArgumentException(
                    "Pepper id must be well-formed Unicode. It contains an unpaired surrogate, "
                    + "which cannot survive the UTF-8 round-trip through the stored hash's keyid — "
                    + "hashes produced with it could never be verified.", nameof(id));
            }

            if (status == OperationStatus.Done && bytesWritten <= PhcString.MaxKeyIdBytes)
            {
                return;
            }
        }

        throw new ArgumentException(
            $"Pepper id must encode to at most {PhcString.MaxKeyIdBytes} UTF-8 bytes "
            + "(the PHC keyid limit enforced during verification); hashes produced with a "
            + "longer id could never be verified. Note the limit is bytes, not characters — "
            + "non-ASCII characters use 2-4 bytes each.", nameof(id));
    }

    /// <summary>The stable identifier embedded in hashes produced with this pepper.</summary>
    public string Id { get; }

    /// <summary>The secret key bytes. Internal: never serialized or exposed publicly.</summary>
    internal ReadOnlySpan<byte> Key => _key;

    /// <summary>
    /// The cached, defensive copy of the key bytes handed directly to the underlying
    /// Argon2 implementation as its <c>KnownSecret</c>. Reusing the same array avoids
    /// a per-call <see cref="Array.Clone"/>; Konscious treats <c>KnownSecret</c> as
    /// read-only input.
    /// </summary>
    internal byte[] KnownSecret => _key;
}

/// <summary>
/// A set of peppers comprising one <see cref="Active"/> pepper (used for new hashes)
/// and zero or more retired peppers (still accepted when verifying older hashes).
/// This is the unit that gives Argon2id peppering a safe rotation story.
/// </summary>
/// <remarks>
/// To rotate: construct a new ring whose <see cref="Active"/> pepper is the new key and
/// whose retired list contains the previous key(s). Existing hashes keep verifying with
/// their original pepper, and <see cref="Argon2idPasswordHasher.NeedsRehash(string)"/> reports
/// that they should be upgraded to the active pepper on the next successful login.
/// </remarks>
public sealed class PepperRing
{
    private readonly Dictionary<string, Pepper> _byId;

    /// <summary>Creates a pepper ring.</summary>
    /// <param name="active">The pepper used to produce new hashes.</param>
    /// <param name="retired">
    /// Previously active peppers that must still verify existing hashes. Their ids must be
    /// distinct from each other and from <paramref name="active"/>.
    /// </param>
    /// <exception cref="ArgumentNullException"><paramref name="active"/> is null.</exception>
    /// <exception cref="ArgumentException">Two peppers share the same <see cref="Pepper.Id"/>.</exception>
    public PepperRing(Pepper active, params Pepper[] retired)
    {
        ArgumentNullException.ThrowIfNull(active);

        Active = active;
        _byId = new Dictionary<string, Pepper>(StringComparer.Ordinal) { [active.Id] = active };

        foreach (Pepper pepper in retired ?? [])
        {
            ArgumentNullException.ThrowIfNull(pepper);
            if (!_byId.TryAdd(pepper.Id, pepper))
            {
                throw new ArgumentException(
                    $"Duplicate pepper id '{pepper.Id}'. Every pepper in a ring must have a unique id.",
                    nameof(retired));
            }
        }
    }

    /// <summary>The pepper used when producing new hashes.</summary>
    public Pepper Active { get; }

    /// <summary>Looks up a pepper by the id stored in a hash.</summary>
    internal bool TryGet(string id, [NotNullWhen(true)] out Pepper? pepper) =>
        _byId.TryGetValue(id, out pepper);
}
