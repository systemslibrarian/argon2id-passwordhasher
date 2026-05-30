using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

using CoreHasher = global::Argon2id.PasswordHasher.PasswordHasher;

namespace Argon2id.PasswordHasher.AspNetCore;

/// <summary>
/// Dependency-injection helpers for registering the Argon2id password hasher with
/// ASP.NET Core Identity.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers the secure-by-default Argon2id hasher as the
    /// <see cref="IPasswordHasher{TUser}"/> for ASP.NET Core Identity.
    /// </summary>
    /// <typeparam name="TUser">The Identity user type (e.g. <c>IdentityUser</c>).</typeparam>
    /// <param name="services">The service collection.</param>
    /// <param name="options">
    /// Optional Argon2id work-factor parameters. Defaults to
    /// <see cref="Argon2idOptions.Recommended"/> when null.
    /// </param>
    /// <param name="pepper">
    /// Optional <see cref="PepperRing"/> for keyed hashing. When null, no pepper is used.
    /// </param>
    /// <returns>The same <paramref name="services"/> instance, for chaining.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="services"/> is null.</exception>
    /// <example>
    /// <code>
    /// builder.Services
    ///     .AddIdentityCore&lt;IdentityUser&gt;()
    ///     .Services
    ///     .AddArgon2idPasswordHasher&lt;IdentityUser&gt;();
    /// </code>
    /// </example>
    public static IServiceCollection AddArgon2idPasswordHasher<TUser>(
        this IServiceCollection services,
        Argon2idOptions? options = null,
        PepperRing? pepper = null)
        where TUser : class
    {
        ArgumentNullException.ThrowIfNull(services);

        var hasher = new CoreHasher(options ?? Argon2idOptions.Recommended, pepper);

        // Register the shared core hasher once; reuse it across all TUser registrations.
        services.TryAddSingleton(hasher);
        services.Replace(ServiceDescriptor.Singleton<IPasswordHasher<TUser>, Argon2idPasswordHasher<TUser>>());

        return services;
    }
}
