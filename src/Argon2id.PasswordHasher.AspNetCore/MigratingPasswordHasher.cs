using Microsoft.AspNetCore.Identity;

using CoreHasher = Argon2id.PasswordHasher.Argon2idPasswordHasher;

namespace Argon2id.PasswordHasher.AspNetCore;

/// <summary>
/// An <see cref="IPasswordHasher{TUser}"/> that routes verification to a
/// legacy hasher (typically <see cref="PasswordHasher{TUser}"/>'s default
/// PBKDF2 implementation) when the stored hash isn't an Argon2id PHC string,
/// then transparently rehashes successful logins to Argon2id on the way out.
/// </summary>
/// <typeparam name="TUser">The Identity user type.</typeparam>
/// <remarks>
/// <para>
/// Use this when you're migrating an existing user store &#8212; the stored
/// hashes are a mix of Argon2id (recent registrations) and whatever you used
/// before (PBKDF2, bcrypt-via-an-adapter, etc.). New hashes always come out
/// as Argon2id; old hashes verify against the legacy hasher and are flagged
/// as <see cref="PasswordVerificationResult.SuccessRehashNeeded"/> so
/// ASP.NET Core Identity rewrites them with <see cref="HashPassword"/>.
/// </para>
/// <para>
/// Routing is purely format-based and uses no allocations: any stored value
/// starting with <c>$argon2id$</c> goes to the Argon2id path. Everything
/// else &#8212; including <see langword="null"/>, empty, and garbage strings
/// &#8212; is handed to the legacy hasher, which is expected to fail safely.
/// </para>
/// <example>
/// <code>
/// // Register the migrating hasher with the default PBKDF2 Identity
/// // hasher as the legacy fallback:
/// builder.Services
///     .AddIdentityCore&lt;IdentityUser&gt;()
///     .AddArgon2idPasswordHasherWithMigration&lt;IdentityUser&gt;();
/// </code>
/// </example>
/// </remarks>
public sealed class MigratingPasswordHasher<TUser> : IPasswordHasher<TUser>
    where TUser : class
{
    private readonly Argon2idPasswordHasher<TUser> _argon2id;
    private readonly IPasswordHasher<TUser> _legacy;

    /// <summary>
    /// Creates the migrating hasher.
    /// </summary>
    /// <param name="argon2id">
    /// The Argon2id hasher used for new hashes and for verifying any stored
    /// PHC strings that begin with <c>$argon2id$</c>.
    /// </param>
    /// <param name="legacy">
    /// The hasher used to verify any stored value that is <i>not</i> an Argon2id
    /// PHC string. When this hasher reports
    /// <see cref="PasswordVerificationResult.Success"/> or
    /// <see cref="PasswordVerificationResult.SuccessRehashNeeded"/>, the
    /// migrating hasher returns <see cref="PasswordVerificationResult.SuccessRehashNeeded"/>
    /// so Identity stores a fresh Argon2id hash.
    /// </param>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="argon2id"/> or <paramref name="legacy"/> is null.
    /// </exception>
    public MigratingPasswordHasher(
        Argon2idPasswordHasher<TUser> argon2id,
        IPasswordHasher<TUser> legacy)
    {
        ArgumentNullException.ThrowIfNull(argon2id);
        ArgumentNullException.ThrowIfNull(legacy);
        _argon2id = argon2id;
        _legacy = legacy;
    }

    /// <inheritdoc />
    public string HashPassword(TUser user, string password)
        => _argon2id.HashPassword(user, password);

    /// <inheritdoc />
    public PasswordVerificationResult VerifyHashedPassword(
        TUser user,
        string hashedPassword,
        string providedPassword)
    {
        if (CoreHasher.IsArgon2idHash(hashedPassword))
        {
            return _argon2id.VerifyHashedPassword(user, hashedPassword, providedPassword);
        }

        // The stock ASP.NET Core Identity PasswordHasher<TUser> throws on
        // null or non-base64 stored values. The Argon2id side of this library
        // fails safe on garbage input — the migrating adapter follows the
        // same contract so callers don't have to special-case legacy data.
        PasswordVerificationResult legacyResult;
        try
        {
            legacyResult = _legacy.VerifyHashedPassword(user, hashedPassword, providedPassword);
        }
        catch (Exception ex) when (ex is FormatException or ArgumentException or ArgumentNullException)
        {
            return PasswordVerificationResult.Failed;
        }

        // The legacy hasher may already report SuccessRehashNeeded for its own
        // internal reasons (e.g. weaker iteration count); we collapse Success
        // and SuccessRehashNeeded into the same Identity signal so the next
        // sign-in rewrites the stored hash as Argon2id.
        return legacyResult switch
        {
            PasswordVerificationResult.Success
                or PasswordVerificationResult.SuccessRehashNeeded
                // The Argon2id hasher (correctly) refuses to hash an empty
                // password, so signalling a rehash for a legacy empty-password
                // account would make Identity call HashPassword("") mid-login
                // and throw. Report plain Success instead: the login works and
                // the account stays on its legacy hash until the password is
                // actually changed.
                => string.IsNullOrEmpty(providedPassword)
                    ? PasswordVerificationResult.Success
                    : PasswordVerificationResult.SuccessRehashNeeded,
            _ => legacyResult,
        };
    }

}

/// <summary>
/// Marker registered by <c>AddArgon2idPasswordHasherWithMigration</c> so a later
/// plain <c>AddArgon2idPasswordHasher</c> call can detect the migrating hasher
/// (registered via factory, so its implementation type is not introspectable)
/// and preserve it instead of silently replacing it — which would lock out
/// every user still on a legacy hash.
/// </summary>
/// <typeparam name="TUser">The Identity user type.</typeparam>
internal sealed class Argon2idMigrationMarker<TUser>
    where TUser : class
{
}
