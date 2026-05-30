namespace Argon2id.PasswordHasher;

/// <summary>
/// The outcome of an Argon2id password verification, combining whether the
/// password matched with whether the stored hash should be re-derived using
/// the hasher's current parameters.
/// </summary>
/// <remarks>
/// <para>
/// Prefer <see cref="Argon2idPasswordHasher.Verify(string, string)"/> over
/// calling <see cref="Argon2idPasswordHasher.VerifyPassword(string, string)"/>
/// and <see cref="Argon2idPasswordHasher.NeedsRehash(string)"/> separately
/// when you want both pieces of information from one call &#8212; the
/// underlying PHC string is parsed once instead of twice.
/// </para>
/// <para>
/// On any failure (wrong password, malformed stored value, unavailable
/// pepper), <see cref="NeedsRehash"/> is always <see langword="false"/>;
/// there's nothing meaningful to rehash when we don't know what the right
/// password is. Use <see cref="Failed"/> for an explicit fail sentinel.
/// </para>
/// </remarks>
/// <param name="Success">
/// <see langword="true"/> if the supplied password matched the stored hash;
/// otherwise <see langword="false"/>.
/// </param>
/// <param name="NeedsRehash">
/// When <see cref="Success"/> is <see langword="true"/>, indicates whether
/// the stored hash was produced with weaker parameters (or a non-active
/// pepper) than this hasher's current settings and should be replaced on the
/// next successful login. Always <see langword="false"/> on failure.
/// </param>
public readonly record struct VerifyResult(bool Success, bool NeedsRehash)
{
    /// <summary>
    /// The canonical failure result: <c>Success = false</c>, <c>NeedsRehash = false</c>.
    /// </summary>
    public static VerifyResult Failed { get; } = new(Success: false, NeedsRehash: false);
}
