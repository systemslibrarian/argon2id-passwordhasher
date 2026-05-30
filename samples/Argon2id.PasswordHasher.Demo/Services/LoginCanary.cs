namespace Argon2id.PasswordHasher.Demo.Services;

/// <summary>
/// A single pre-computed Argon2id hash kept in memory so the login path can
/// "verify against something" even when the requested user does not exist.
/// </summary>
/// <remarks>
/// Without this, a bad username returns instantly and a good username takes the
/// full verification time &#8212; a timing oracle for username enumeration. By
/// running <see cref="Argon2idPasswordHasher.VerifyPassword(string, string)"/>
/// against the canary in the "user not found" branch, both branches take
/// comparable wall-clock time. The actual return value of that verification is
/// discarded.
/// </remarks>
public sealed class LoginCanary
{
    public LoginCanary(Argon2idPasswordHasher hasher)
    {
        ArgumentNullException.ThrowIfNull(hasher);
        // Hash a fixed throwaway value once at startup. The string never
        // matches any real user password, but the verify path it exercises is
        // indistinguishable in cost from a real verify.
        Hash = hasher.HashPassword("login-canary-do-not-use-as-a-real-password");
    }

    /// <summary>The canary PHC string.</summary>
    public string Hash { get; }
}
