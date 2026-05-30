using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

using CoreHasher = Argon2id.PasswordHasher.Argon2idPasswordHasher;

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
    /// Optional Argon2id work-factor parameters. When <see langword="null"/> the hasher
    /// resolves <see cref="Argon2idOptions"/> from <see cref="IOptions{TOptions}"/>,
    /// so a prior <c>services.Configure&lt;Argon2idOptions&gt;(...)</c> call wins.
    /// If neither is set, <see cref="Argon2idOptions.Recommended"/> is used.
    /// </param>
    /// <param name="pepper">
    /// Optional <see cref="PepperRing"/> for keyed hashing. When <see langword="null"/>,
    /// any <see cref="PepperRing"/> previously registered in <paramref name="services"/>
    /// is picked up at resolution time; otherwise no pepper is used.
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

        if (options is not null)
        {
            // Apply the explicit options through the standard IOptions pipeline so
            // they're discoverable to anything else that resolves IOptions<Argon2idOptions>.
            services.AddOptions<Argon2idOptions>().Configure(o => CopyInto(options, o));
        }

        if (pepper is not null)
        {
            services.TryAddSingleton(pepper);
        }

        return AddArgon2idHasherCore<TUser>(services);
    }

    /// <summary>
    /// Registers the Argon2id hasher and configures its options inline via the
    /// standard .NET Options pattern. Use this overload when you want to read
    /// settings from <c>IConfiguration</c>:
    /// </summary>
    /// <example>
    /// <code>
    /// // Inline:
    /// builder.Services.AddArgon2idPasswordHasher&lt;IdentityUser&gt;(opts =&gt;
    /// {
    ///     opts.MemorySizeKib = 131072;
    ///     opts.Iterations    = 4;
    /// });
    ///
    /// // From appsettings.json (section "Argon2id"):
    /// builder.Services.AddArgon2idPasswordHasher&lt;IdentityUser&gt;(opts =&gt;
    ///     builder.Configuration.GetSection("Argon2id").Bind(opts));
    /// </code>
    /// </example>
    /// <typeparam name="TUser">The Identity user type.</typeparam>
    /// <param name="services">The service collection.</param>
    /// <param name="configureOptions">
    /// Callback that mutates the <see cref="Argon2idOptions"/> instance the hasher
    /// will use. Invoked through <c>IOptions&lt;Argon2idOptions&gt;</c>.
    /// </param>
    /// <returns>The same <paramref name="services"/> instance, for chaining.</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="services"/> or <paramref name="configureOptions"/> is null.
    /// </exception>
    public static IServiceCollection AddArgon2idPasswordHasher<TUser>(
        this IServiceCollection services,
        Action<Argon2idOptions> configureOptions)
        where TUser : class
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configureOptions);

        services.AddOptions<Argon2idOptions>().Configure(configureOptions);

        return AddArgon2idHasherCore<TUser>(services);
    }

    /// <summary>
    /// Common registration tail used by every overload. Wires the validator,
    /// the singleton hasher factory, and replaces <see cref="IPasswordHasher{TUser}"/>.
    /// </summary>
    private static IServiceCollection AddArgon2idHasherCore<TUser>(IServiceCollection services)
        where TUser : class
    {
        services.AddOptions<Argon2idOptions>();
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<Argon2idOptions>, Argon2idOptionsValidator>());

        // Resolve at first request so a downstream Configure call (or a registered
        // PepperRing) can still influence the final hasher.
        services.TryAddSingleton<CoreHasher>(sp =>
        {
            Argon2idOptions opts = sp.GetService<IOptions<Argon2idOptions>>()?.Value
                                   ?? Argon2idOptions.Recommended;
            PepperRing? ring = sp.GetService<PepperRing>();
            return new CoreHasher(opts, ring);
        });

        services.Replace(ServiceDescriptor.Singleton<IPasswordHasher<TUser>, Argon2idPasswordHasher<TUser>>());

        return services;
    }

    private static void CopyInto(Argon2idOptions source, Argon2idOptions target)
    {
        target.MemorySizeKib = source.MemorySizeKib;
        target.Iterations = source.Iterations;
        target.DegreeOfParallelism = source.DegreeOfParallelism;
        target.SaltSizeBytes = source.SaltSizeBytes;
        target.HashSizeBytes = source.HashSizeBytes;
    }
}
