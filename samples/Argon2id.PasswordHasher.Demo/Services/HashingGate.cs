namespace Argon2id.PasswordHasher.Demo.Services;

/// <summary>
/// Caps the number of Argon2id operations that can run concurrently across all
/// circuits in this process, so a flood of registrations or logins can't pin
/// the server on memory (each hash holds 64 MiB by default).
/// </summary>
/// <remarks>
/// Sized to <c>Environment.ProcessorCount</c> by default: enough headroom to keep
/// the CPU busy, low enough that a thousand concurrent users won't trigger an
/// OOM. Excess work waits for a slot rather than failing &#8212; the queue is the
/// throttle. For a real service you would likely also cap the queue and shed
/// load past it.
/// </remarks>
public sealed class HashingGate : IDisposable
{
    private readonly SemaphoreSlim _gate;

    public HashingGate() : this(Environment.ProcessorCount)
    {
    }

    public HashingGate(int maxConcurrent)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(maxConcurrent, 1);
        _gate = new SemaphoreSlim(maxConcurrent, maxConcurrent);
        MaxConcurrent = maxConcurrent;
    }

    /// <summary>The configured ceiling on simultaneous hashes.</summary>
    public int MaxConcurrent { get; }

    /// <summary>
    /// Runs <paramref name="work"/> on the thread pool while holding a gate slot.
    /// Awaiters queue when the gate is full.
    /// </summary>
    public async Task<T> RunAsync<T>(Func<T> work, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(work);

        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            return await Task.Run(work, ct).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    public void Dispose() => _gate.Dispose();
}
