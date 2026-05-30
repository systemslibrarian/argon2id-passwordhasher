namespace Argon2id.PasswordHasher.Demo.Services;

/// <summary>
/// A registered user record kept entirely in-memory. The only thing that
/// matters for the demo is the <see cref="PasswordHash"/> &#8212; the PHC string
/// produced by <see cref="Argon2idPasswordHasher.HashPassword(string)"/>.
/// </summary>
/// <remarks>
/// In a real application the password hash would live in a database column,
/// and there would be additional fields (email confirmation, claims, etc.).
/// Those concerns are deliberately omitted to keep the sample focused on the
/// hashing flow.
/// </remarks>
public sealed record DemoUser(string Username, string PasswordHash, DateTimeOffset RegisteredAt);
