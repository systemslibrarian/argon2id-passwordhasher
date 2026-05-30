using System.Collections.Concurrent;

namespace Argon2id.PasswordHasher.WasmDemo.Services;

/// <summary>
/// In-memory user store for the WASM demo. Lifetime is the open tab; reloading
/// the page wipes it. This is intentional &#8212; the demo never claims to be a
/// real account store.
/// </summary>
public sealed class InMemoryUserStore
{
    private readonly ConcurrentDictionary<string, DemoUser> _users =
        new(StringComparer.OrdinalIgnoreCase);

    public IReadOnlyCollection<DemoUser> AllUsers =>
        _users.Values.OrderBy(u => u.RegisteredAt).ToList();

    public bool Exists(string username) => _users.ContainsKey(username);

    public DemoUser? Find(string username) =>
        _users.TryGetValue(username, out DemoUser? user) ? user : null;

    public bool TryAdd(DemoUser user)
    {
        ArgumentNullException.ThrowIfNull(user);
        return _users.TryAdd(user.Username, user);
    }

    public void UpdateHash(string username, string newHash)
    {
        _users.AddOrUpdate(
            username,
            _ => throw new InvalidOperationException("Cannot rehash a user that does not exist."),
            (_, existing) => existing with { PasswordHash = newHash });
    }
}
