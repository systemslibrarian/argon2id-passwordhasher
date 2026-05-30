namespace Argon2id.PasswordHasher;

/// <summary>
/// Public names of the <see cref="System.Diagnostics.Metrics"/> meter and
/// instruments emitted by this library. Subscribe to these from your
/// observability stack (OpenTelemetry, Prometheus exporter, etc.) to get
/// hash/verify counts, durations, and rehash signals without any code
/// changes inside the hasher.
/// </summary>
/// <remarks>
/// <para>
/// All instruments live on a single meter named <see cref="MeterName"/>.
/// Subscribing to that meter is the recommended way to enable everything:
/// </para>
/// <example>
/// <code>
/// // OpenTelemetry:
/// builder.Services.AddOpenTelemetry()
///     .WithMetrics(m =&gt; m.AddMeter(Argon2idDiagnostics.MeterName));
///
/// // Or with a raw MeterListener:
/// var listener = new MeterListener();
/// listener.InstrumentPublished = (inst, l) =&gt;
/// {
///     if (inst.Meter.Name == Argon2idDiagnostics.MeterName)
///         l.EnableMeasurementEvents(inst);
/// };
/// listener.Start();
/// </code>
/// </example>
/// <para>
/// Recording is essentially free when nothing is listening. There is no
/// per-call allocation. The instruments are created lazily by the BCL.
/// </para>
/// </remarks>
public static class Argon2idDiagnostics
{
    /// <summary>
    /// The name of the <see cref="System.Diagnostics.Metrics.Meter"/> that
    /// emits every instrument below. Use this with
    /// <c>AddMeter(Argon2idDiagnostics.MeterName)</c> on any OpenTelemetry
    /// or other metrics provider.
    /// </summary>
    public const string MeterName = "Argon2id.PasswordHasher";

    /// <summary>Counter incremented each time a new hash is produced.</summary>
    public const string HashCountName = "argon2id.hash.count";

    /// <summary>Histogram of wall-clock hash duration, in milliseconds.</summary>
    public const string HashDurationName = "argon2id.hash.duration";

    /// <summary>
    /// Counter incremented each time a verification is attempted, regardless of outcome.
    /// </summary>
    public const string VerifyCountName = "argon2id.verify.count";

    /// <summary>
    /// Counter incremented each time a verification succeeds (tag matched).
    /// Subtract from <see cref="VerifyCountName"/> to get the failure count.
    /// </summary>
    public const string VerifySuccessCountName = "argon2id.verify.success.count";

    /// <summary>Histogram of wall-clock verify duration, in milliseconds.</summary>
    public const string VerifyDurationName = "argon2id.verify.duration";

    /// <summary>
    /// Counter incremented each time a successful verify also indicated
    /// <see cref="VerifyResult.NeedsRehash"/>. Use this to track migration
    /// progress and the rate of work-factor upgrades.
    /// </summary>
    public const string RehashNeededCountName = "argon2id.rehash.needed.count";

    /// <summary>
    /// Counter incremented each time a stored value could not be parsed as a
    /// PHC-encoded Argon2id hash during a verify call. Spikes here usually
    /// indicate corrupted data or an unexpected hash format in the store.
    /// </summary>
    public const string ParseFailureCountName = "argon2id.parse.failure.count";
}
