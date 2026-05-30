using Microsoft.AspNetCore.Identity;

// Alias the core hasher with a global-qualified name. The library's root namespace
// (Argon2id.PasswordHasher) shares its final segment with the type name, so an
// unqualified reference would be ambiguous inside this child namespace.
using CoreHasher = global::Argon2id.PasswordHasher.PasswordHasher;

namespace Argon2id.PasswordHasher.AspNetCore;

/// <summary>
/// An <see cref="IPasswordHasher{TUser}"/> implementation backed by the secure-by-default
/// Argon2id <see cref="CoreHasher"/>, suitable for ASP.NET Core Identity.
/// </summary>
/// <typeparam name="TUser">The Identity user type.</typeparam>
/// <remarks>
/// Verification reports <see cref="PasswordVerificationResult.SuccessRehashNeeded"/> when the
/// stored hash was produced with weaker parameters (or a non-active pepper) than the current
/// configuration, so ASP.NET Core Identity transparently upgrades it on the next sign-in.
/// </remarks>
public sealed class Argon2idPasswordHasher<TUser> : IPasswordHasher<TUser>
    where TUser : class
{
    private readonly CoreHasher _hasher;

    /// <summary>Creates the adapter around a configured core hasher.</summary>
    /// <param name="hasher">The shared, thread-safe core hasher (typically a singleton).</param>
    /// <exception cref="ArgumentNullException"><paramref name="hasher"/> is null.</exception>
    public Argon2idPasswordHasher(CoreHasher hasher)
    {
        ArgumentNullException.ThrowIfNull(hasher);
        _hasher = hasher;
    }

    /// <inheritdoc />
    public string HashPassword(TUser user, string password) => _hasher.HashPassword(password);

    /// <inheritdoc />
    public PasswordVerificationResult VerifyHashedPassword(TUser user, string hashedPassword, string providedPassword)
    {
        if (!_hasher.VerifyPassword(providedPassword, hashedPassword))
        {
            return PasswordVerificationResult.Failed;
        }

        return _hasher.NeedsRehash(hashedPassword)
            ? PasswordVerificationResult.SuccessRehashNeeded
            : PasswordVerificationResult.Success;
    }
}
