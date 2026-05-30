using System.Diagnostics.Metrics;
using Xunit;

namespace Argon2id.PasswordHasher.Tests;

/// <summary>
/// Collection marker that forces every <see cref="MetricsTests"/> case to run
/// sequentially. The instruments live on a process-wide Meter, so two parallel
/// tests would cross-pollute each other's <see cref="MeterListener"/>.
/// </summary>
[CollectionDefinition(nameof(MetricsTestGroup), DisableParallelization = true)]
public sealed class MetricsTestGroup;

/// <summary>
/// Verifies that the instruments under <see cref="Argon2idDiagnostics.MeterName"/>
/// fire on every hash / verify call. We use a raw <see cref="MeterListener"/>
/// to avoid an OpenTelemetry dependency in the test pack.
/// </summary>
[Collection(nameof(MetricsTestGroup))]
public class MetricsTests
{
    private static readonly Argon2idOptions FastOptions = new()
    {
        MemorySizeKib = 8192,
        Iterations = 1,
        DegreeOfParallelism = 1,
    };

    private sealed class Capture : IDisposable
    {
        public readonly List<KeyValuePair<string, double>> Measurements = [];
        private readonly MeterListener _listener;

        public Capture()
        {
            _listener = new MeterListener
            {
                InstrumentPublished = (instrument, listener) =>
                {
                    if (instrument.Meter.Name == Argon2idDiagnostics.MeterName)
                    {
                        listener.EnableMeasurementEvents(instrument);
                    }
                },
            };
            _listener.SetMeasurementEventCallback<long>(
                (inst, val, _, _) => Measurements.Add(new(inst.Name, val)));
            _listener.SetMeasurementEventCallback<double>(
                (inst, val, _, _) => Measurements.Add(new(inst.Name, val)));
            _listener.Start();
        }

        public void Dispose() => _listener.Dispose();
    }

    [Fact]
    public void HashPassword_RecordsCountAndDuration()
    {
        using var capture = new Capture();
        var hasher = new Argon2idPasswordHasher(FastOptions);

        _ = hasher.HashPassword("metrics-hash");

        Assert.Contains(capture.Measurements, m => m.Key == Argon2idDiagnostics.HashCountName && m.Value == 1);
        Assert.Contains(capture.Measurements, m => m.Key == Argon2idDiagnostics.HashDurationName && m.Value > 0);
    }

    [Fact]
    public void VerifyPassword_Success_RecordsCountAndSuccessAndDuration()
    {
        using var capture = new Capture();
        var hasher = new Argon2idPasswordHasher(FastOptions);
        string stored = hasher.HashPassword("metrics-verify");
        capture.Measurements.Clear(); // ignore the setup hash

        bool ok = hasher.VerifyPassword("metrics-verify", stored);

        Assert.True(ok);
        Assert.Contains(capture.Measurements, m => m.Key == Argon2idDiagnostics.VerifyCountName && m.Value == 1);
        Assert.Contains(capture.Measurements, m => m.Key == Argon2idDiagnostics.VerifySuccessCountName && m.Value == 1);
        Assert.Contains(capture.Measurements, m => m.Key == Argon2idDiagnostics.VerifyDurationName && m.Value > 0);
    }

    [Fact]
    public void VerifyPassword_WrongPassword_RecordsVerifyCount_AndDoesNotIncrementSuccess()
    {
        using var capture = new Capture();
        var hasher = new Argon2idPasswordHasher(FastOptions);
        string stored = hasher.HashPassword("right");

        // Snapshot how many success/verify events the listener has seen so far,
        // so we can verify ONLY the delta caused by our wrong-password call.
        int verifyBefore = capture.Measurements.Count(m =>
            m.Key == Argon2idDiagnostics.VerifyCountName);
        int successBefore = capture.Measurements.Count(m =>
            m.Key == Argon2idDiagnostics.VerifySuccessCountName);

        bool ok = hasher.VerifyPassword("wrong", stored);

        Assert.False(ok);

        int verifyAfter = capture.Measurements.Count(m =>
            m.Key == Argon2idDiagnostics.VerifyCountName);
        int successAfter = capture.Measurements.Count(m =>
            m.Key == Argon2idDiagnostics.VerifySuccessCountName);

        Assert.True(verifyAfter > verifyBefore);
        Assert.Equal(successBefore, successAfter);
    }

    [Fact]
    public void Verify_NeedsRehash_FiresRehashCounter()
    {
        using var capture = new Capture();
        var weak = new Argon2idPasswordHasher(FastOptions);
        string oldHash = weak.HashPassword("rehash-metric");

        var strong = new Argon2idPasswordHasher(new Argon2idOptions
        {
            MemorySizeKib = 16384,
            Iterations = 2,
            DegreeOfParallelism = 1,
        });

        capture.Measurements.Clear();
        VerifyResult result = strong.Verify("rehash-metric", oldHash);

        Assert.True(result.Success);
        Assert.True(result.NeedsRehash);
        Assert.Contains(capture.Measurements, m => m.Key == Argon2idDiagnostics.RehashNeededCountName && m.Value == 1);
    }

    [Fact]
    public void Verify_MalformedHash_FiresParseFailureCounter()
    {
        using var capture = new Capture();
        var hasher = new Argon2idPasswordHasher(FastOptions);

        // Non-empty but garbage — should record a parse failure.
        _ = hasher.VerifyPassword("anything", "not-a-phc-string");

        Assert.Contains(capture.Measurements, m => m.Key == Argon2idDiagnostics.ParseFailureCountName && m.Value == 1);
    }

    [Fact]
    public void Verify_NullOrEmptyHash_DoesNotFireParseFailure()
    {
        using var capture = new Capture();
        var hasher = new Argon2idPasswordHasher(FastOptions);

        _ = hasher.VerifyPassword("anything", "");
        _ = hasher.VerifyPassword("anything", null!);

        // Empty / null is treated as a caller-input issue, not a parser drama.
        Assert.DoesNotContain(capture.Measurements, m => m.Key == Argon2idDiagnostics.ParseFailureCountName);
    }
}
