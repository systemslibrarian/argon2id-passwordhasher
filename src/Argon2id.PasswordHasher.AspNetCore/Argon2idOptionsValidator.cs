using Microsoft.Extensions.Options;

namespace Argon2id.PasswordHasher.AspNetCore;

/// <summary>
/// Validates <see cref="Argon2idOptions"/> at startup when the host calls
/// <c>ValidateOnStart()</c>, by delegating to <see cref="Argon2idOptions.Validate"/>.
/// </summary>
/// <remarks>
/// The core <see cref="Argon2idPasswordHasher"/> constructor also calls
/// <see cref="Argon2idOptions.Validate"/>, so any insecure configuration would
/// throw at first hash. Registering this validator surfaces the same error at
/// host start-up instead, which is the standard ASP.NET Core fail-fast pattern.
/// </remarks>
internal sealed class Argon2idOptionsValidator : IValidateOptions<Argon2idOptions>
{
    public ValidateOptionsResult Validate(string? name, Argon2idOptions options)
    {
        try
        {
            options.Validate();
            return ValidateOptionsResult.Success;
        }
        catch (ArgumentOutOfRangeException ex)
        {
            return ValidateOptionsResult.Fail(ex.Message);
        }
    }
}
