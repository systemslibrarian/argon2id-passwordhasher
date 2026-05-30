namespace Argon2id.PasswordHasher.WasmDemo.Services;

/// <summary>
/// A registered user record kept entirely in browser memory.
/// </summary>
public sealed record DemoUser(string Username, string PasswordHash, DateTimeOffset RegisteredAt);
