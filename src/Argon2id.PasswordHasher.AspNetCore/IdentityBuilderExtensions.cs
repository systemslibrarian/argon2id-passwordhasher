using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;

namespace Argon2id.PasswordHasher.AspNetCore;

/// <summary>
/// Extension methods that let callers wire the Argon2id hasher into the
/// natural ASP.NET Core Identity builder chain.
/// </summary>
/// <example>
/// <code>
/// builder.Services
///     .AddIdentityCore&lt;IdentityUser&gt;()
///     .AddArgon2idPasswordHasher&lt;IdentityUser&gt;();
///
/// // Or with inline configuration:
/// builder.Services
///     .AddIdentityCore&lt;IdentityUser&gt;()
///     .AddArgon2idPasswordHasher&lt;IdentityUser&gt;(opts =&gt; opts.MemorySizeKib = 131072);
/// </code>
/// </example>
public static class IdentityBuilderExtensions
{
    /// <summary>
    /// Registers the Argon2id hasher as the <see cref="IPasswordHasher{TUser}"/> for
    /// <typeparamref name="TUser"/>. Uses the library's recommended defaults unless a
    /// previous <c>services.Configure&lt;Argon2idOptions&gt;(...)</c> call says otherwise.
    /// </summary>
    /// <typeparam name="TUser">
    /// The Identity user type. Must match the type passed to
    /// <c>AddIdentityCore&lt;TUser&gt;()</c>; a mismatch throws.
    /// </typeparam>
    /// <param name="builder">The Identity builder being configured.</param>
    /// <returns>The same <paramref name="builder"/>, for chaining.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="builder"/> is null.</exception>
    /// <exception cref="InvalidOperationException">
    /// <typeparamref name="TUser"/> does not match the user type of <paramref name="builder"/>.
    /// </exception>
    public static IdentityBuilder AddArgon2idPasswordHasher<TUser>(this IdentityBuilder builder)
        where TUser : class
    {
        ArgumentNullException.ThrowIfNull(builder);
        EnsureUserTypeMatches<TUser>(builder);
        builder.Services.AddArgon2idPasswordHasher<TUser>();
        return builder;
    }

    /// <summary>
    /// Registers the Argon2id hasher and configures its options inline.
    /// Same chaining pattern as <see cref="AddArgon2idPasswordHasher{TUser}(IdentityBuilder)"/>.
    /// </summary>
    /// <typeparam name="TUser">
    /// The Identity user type. Must match the type passed to
    /// <c>AddIdentityCore&lt;TUser&gt;()</c>; a mismatch throws.
    /// </typeparam>
    /// <param name="builder">The Identity builder being configured.</param>
    /// <param name="configureOptions">Callback that mutates the options.</param>
    /// <returns>The same <paramref name="builder"/>, for chaining.</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="builder"/> or <paramref name="configureOptions"/> is null.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// <typeparamref name="TUser"/> does not match the user type of <paramref name="builder"/>.
    /// </exception>
    public static IdentityBuilder AddArgon2idPasswordHasher<TUser>(
        this IdentityBuilder builder,
        Action<Argon2idOptions> configureOptions)
        where TUser : class
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configureOptions);
        EnsureUserTypeMatches<TUser>(builder);
        builder.Services.AddArgon2idPasswordHasher<TUser>(configureOptions);
        return builder;
    }

    /// <summary>
    /// Defensively reject mismatched user types early so the consumer sees a
    /// helpful error at registration time rather than a confusing
    /// IPasswordHasher&lt;Wrong&gt; resolution failure later.
    /// </summary>
    private static void EnsureUserTypeMatches<TUser>(IdentityBuilder builder)
    {
        if (builder.UserType != typeof(TUser))
        {
            throw new InvalidOperationException(
                $"AddArgon2idPasswordHasher<{typeof(TUser).Name}> was called on an "
                + $"IdentityBuilder configured for {builder.UserType?.Name ?? "<null>"}. "
                + "These must match — pass the same TUser used in AddIdentityCore<TUser>().");
        }
    }
}
