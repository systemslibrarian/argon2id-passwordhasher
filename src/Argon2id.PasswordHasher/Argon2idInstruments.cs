using System.Diagnostics.Metrics;
using System.Reflection;

namespace Argon2id.PasswordHasher;

/// <summary>
/// Internal handles to the instruments exposed under
/// <see cref="Argon2idDiagnostics.MeterName"/>. Created once per process.
/// </summary>
/// <remarks>
/// The <see cref="System.Diagnostics.Metrics.Meter"/> and its instruments are
/// designed to be near-free when no listener is attached: the runtime keeps
/// a fast path that early-outs before any recording work happens. We can
/// therefore call <c>.Add(1)</c> / <c>.Record(ms)</c> from the hot path
/// unconditionally.
/// </remarks>
internal static class Argon2idInstruments
{
    private static readonly Meter Meter = new(
        Argon2idDiagnostics.MeterName,
        typeof(Argon2idInstruments).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
            ?? typeof(Argon2idInstruments).Assembly.GetName().Version?.ToString()
            ?? "0.0.0");

    public static readonly Counter<long> HashCount = Meter.CreateCounter<long>(
        Argon2idDiagnostics.HashCountName,
        unit: "{hash}",
        description: "Number of Argon2id hashes produced.");

    public static readonly Histogram<double> HashDuration = Meter.CreateHistogram<double>(
        Argon2idDiagnostics.HashDurationName,
        unit: "ms",
        description: "Wall-clock time to produce a single Argon2id hash, in milliseconds.");

    public static readonly Counter<long> VerifyCount = Meter.CreateCounter<long>(
        Argon2idDiagnostics.VerifyCountName,
        unit: "{verify}",
        description: "Number of verification attempts, regardless of outcome.");

    public static readonly Counter<long> VerifySuccessCount = Meter.CreateCounter<long>(
        Argon2idDiagnostics.VerifySuccessCountName,
        unit: "{verify}",
        description: "Number of verification attempts where the tag matched.");

    public static readonly Histogram<double> VerifyDuration = Meter.CreateHistogram<double>(
        Argon2idDiagnostics.VerifyDurationName,
        unit: "ms",
        description: "Wall-clock time of a single verify call, in milliseconds.");

    public static readonly Counter<long> RehashNeededCount = Meter.CreateCounter<long>(
        Argon2idDiagnostics.RehashNeededCountName,
        unit: "{hash}",
        description: "Successful verifies whose stored parameters were below current configuration.");

    public static readonly Counter<long> ParseFailureCount = Meter.CreateCounter<long>(
        Argon2idDiagnostics.ParseFailureCountName,
        unit: "{verify}",
        description: "Verify attempts where the stored value could not be parsed as PHC-encoded Argon2id.");
}
