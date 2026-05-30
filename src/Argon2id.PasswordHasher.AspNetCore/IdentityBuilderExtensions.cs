using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

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
    /// Registers a <see cref="MigratingPasswordHasher{TUser}"/> as the
    /// <see cref="IPasswordHasher{TUser}"/>, using Argon2id for new hashes and the
    /// stock ASP.NET Core Identity <see cref="PasswordHasher{TUser}"/> (PBKDF2)
    /// to verify any stored hash that isn't already Argon2id. Successful legacy
    /// verifications return <see cref="PasswordVerificationResult.SuccessRehashNeeded"/>
    /// so Identity transparently upgrades the stored value on the next sign-in.
    /// </summary>
    /// <remarks>
    /// This is the recommended adapter when migrating an existing user store from
    /// the default ASP.NET Core Identity PBKDF2 hasher to Argon2id. See
    /// <c>MIGRATION.md</c> for the end-to-end story.
    /// </remarks>
    /// <typeparam name="TUser">The Identity user type.</typeparam>
    /// <param name="builder">The Identity builder being configured.</param>
    /// <returns>The same <paramref name="builder"/>, for chaining.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="builder"/> is null.</exception>
    public static IdentityBuilder AddArgon2idPasswordHasherWithMigration<TUser>(
        this IdentityBuilder builder)
        where TUser : class
    {
        ArgumentNullException.ThrowIfNull(builder);
        EnsureUserTypeMatches<TUser>(builder);

        // Wire up the Argon2id hasher first so the migrating hasher has it.
        builder.Services.AddArgon2idPasswordHasher<TUser>();

        // Replace the default IPasswordHasher<TUser> registration with a
        // factory that wraps Argon2idPasswordHasher<TUser> + the stock
        // PasswordHasher<TUser> in a migrating adapter.
        builder.Services.Replace(ServiceDescriptor.Singleton<IPasswordHasher<TUser>>(sp =>
        {
            var argon2id = new Argon2idPasswordHasher<TUser>(
                sp.GetRequiredService<Argon2idPasswordHasher>());
            var legacy = new PasswordHasher<TUser>();
            return new MigratingPasswordHasher<TUser>(argon2id, legacy);
        }));

        return builder;
    }

    /// <summary>
    /// <see cref="AddArgon2idPasswordHasherWithMigration{TUser}(IdentityBuilder)"/> with
    /// inline configuration of the Argon2id options.
    /// </summary>
    /// <typeparam name="TUser">The Identity user type.</typeparam>
    /// <param name="builder">The Identity builder being configured.</param>
    /// <param name="configureOptions">Callback that mutates the Argon2id options.</param>
    /// <returns>The same <paramref name="builder"/>, for chaining.</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="builder"/> or <paramref name="configureOptions"/> is null.
    /// </exception>
    public static IdentityBuilder AddArgon2idPasswordHasherWithMigration<TUser>(
        this IdentityBuilder builder,
        Action<Argon2idOptions> configureOptions)
        where TUser : class
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configureOptions);
        EnsureUserTypeMatches<TUser>(builder);

        builder.Services.AddArgon2idPasswordHasher<TUser>(configureOptions);

        builder.Services.Replace(ServiceDescriptor.Singleton<IPasswordHasher<TUser>>(sp =>
        {
            var argon2id = new Argon2idPasswordHasher<TUser>(
                sp.GetRequiredService<Argon2idPasswordHasher>());
            var legacy = new PasswordHasher<TUser>();
            return new MigratingPasswordHasher<TUser>(argon2id, legacy);
        }));

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
