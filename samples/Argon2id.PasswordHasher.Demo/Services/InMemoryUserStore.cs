using System.Collections.Concurrent;

namespace Argon2id.PasswordHasher.Demo.Services;

/// <summary>
/// A thread-safe, in-memory user store. Registered as a singleton in
/// <c>Program.cs</c> so registrations persist for the lifetime of the
/// process (but evaporate on restart &#8212; this is a sample, not a database).
/// </summary>
public sealed class InMemoryUserStore
{
    private readonly ConcurrentDictionary<string, DemoUser> _users =
        new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Snapshot of every user that has registered in this process.</summary>
    public IReadOnlyCollection<DemoUser> AllUsers =>
        _users.Values.OrderBy(u => u.RegisteredAt).ToList();

    /// <summary>True if <paramref name="username"/> is already taken.</summary>
    public bool Exists(string username) => _users.ContainsKey(username);

    /// <summary>Look up a user by username, or <see langword="null"/> if none.</summary>
    public DemoUser? Find(string username) =>
        _users.TryGetValue(username, out DemoUser? user) ? user : null;

    /// <summary>
    /// Register a new user. Returns <see langword="false"/> if the username is
    /// already taken &#8212; collisions are detected here, not at the hashing layer.
    /// </summary>
    public bool TryAdd(DemoUser user)
    {
        ArgumentNullException.ThrowIfNull(user);
        return _users.TryAdd(user.Username, user);
    }

    /// <summary>
    /// Replace a user's stored hash. Used by the login flow when the existing
    /// hash was produced with weaker parameters (rehash-on-login pattern).
    /// </summary>
    public void UpdateHash(string username, string newHash)
    {
        _users.AddOrUpdate(
            username,
            _ => throw new InvalidOperationException("Cannot rehash a user that does not exist."),
            (_, existing) => existing with { PasswordHash = newHash });
    }
}
