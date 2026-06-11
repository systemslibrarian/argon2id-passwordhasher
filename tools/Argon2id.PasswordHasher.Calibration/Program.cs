using System.Diagnostics;
using System.Globalization;
using Argon2id.PasswordHasher;

// Argon2id calibration tool.
//
// Measures real Argon2id latency on THIS machine and recommends the most
// expensive (memory * iterations) configuration that still fits a target
// latency budget. Run it on hardware representative of production:
//
//   dotnet run -c Release --project tools/Argon2id.PasswordHasher.Calibration -- --target-ms 250
//
// Options:
//   --target-ms <n>        latency budget per hash in milliseconds (default 250)
//   --max-memory-mib <n>   upper bound on memory cost in MiB (default 512)
//   --parallelism <n>      degree of parallelism to calibrate for (default 1)
//   --samples <n>          timed samples per candidate; median is used (default 5)

const int MinMemoryKib = 19_456; // OWASP minimum for Argon2id (19 MiB)
const int MaxIterationsToTry = 4;

int targetMs = 250;
int maxMemoryMib = 512;
int parallelism = 1;
int samples = 5;

for (int i = 0; i < args.Length; i++)
{
    string flag = args[i];
    if (flag is "--help" or "-h" or "/?")
    {
        PrintUsage();
        return 0;
    }

    if (i + 1 >= args.Length || !int.TryParse(args[i + 1], NumberStyles.Integer, CultureInfo.InvariantCulture, out int value) || value <= 0)
    {
        Console.Error.WriteLine(Invariant($"Error: '{flag}' requires a positive integer value."));
        PrintUsage();
        return 1;
    }

    switch (flag)
    {
        case "--target-ms":
            targetMs = value;
            break;
        case "--max-memory-mib":
            maxMemoryMib = value;
            break;
        case "--parallelism":
            parallelism = value;
            break;
        case "--samples":
            samples = value;
            break;
        default:
            Console.Error.WriteLine(Invariant($"Error: unknown option '{flag}'."));
            PrintUsage();
            return 1;
    }

    i++; // consume the value
}

int maxMemoryKib = (int)Math.Min((long)maxMemoryMib * 1024, 4L * 1024 * 1024 * 1024 / 1024);
if (maxMemoryKib < MinMemoryKib)
{
    Console.Error.WriteLine(Invariant($"Error: --max-memory-mib must allow at least {MinMemoryKib / 1024} MiB (the OWASP minimum)."));
    return 1;
}

Console.WriteLine("Argon2id calibration");
Console.WriteLine("====================");
Console.WriteLine(Invariant($"Target latency : {targetMs} ms per hash"));
Console.WriteLine(Invariant($"Memory ceiling : {maxMemoryMib} MiB"));
Console.WriteLine(Invariant($"Parallelism    : {parallelism}"));
Console.WriteLine(Invariant($"Samples        : {samples} (median)"));
Console.WriteLine(Invariant($"Machine        : {Environment.ProcessorCount} logical cores, 64-bit process: {Environment.Is64BitProcess}"));
Console.WriteLine();

// --- Probe: estimate cost-per-(KiB * iteration) from one mid-sized measurement.
int probeMemoryKib = Math.Min(64 * 1024, maxMemoryKib);
Console.WriteLine(Invariant($"Probing with m={probeMemoryKib} KiB, t=1, p={parallelism}..."));
double probeMs = MeasureMedianMs(probeMemoryKib, iterations: 1, parallelism, samples);
double msPerKibIteration = probeMs / probeMemoryKib;
Console.WriteLine(Invariant($"Probe median: {probeMs:F1} ms ({msPerKibIteration * 1024 * 1024:F1} ms/GiB/iteration)"));
Console.WriteLine();

// --- Candidates: for each iteration count, pick the memory size the cost model
// predicts will land on the latency target, then measure it for real.
var candidates = new List<(int MemoryKib, int Iterations)>();
for (int t = 1; t <= MaxIterationsToTry; t++)
{
    int idealKib = (int)Math.Min(int.MaxValue, (long)(targetMs / (msPerKibIteration * t)));
    int memoryKib = Math.Clamp(idealKib, MinMemoryKib, maxMemoryKib);
    memoryKib = Math.Max(memoryKib / 1024 * 1024, MinMemoryKib); // round down to a whole MiB
    memoryKib = Math.Max(memoryKib, 8 * parallelism);

    if (!candidates.Contains((memoryKib, t)))
    {
        candidates.Add((memoryKib, t));
    }
}

Console.WriteLine("Measuring candidates:");
Console.WriteLine();
Console.WriteLine("  memory (MiB)  iterations  median (ms)");
Console.WriteLine("  ------------  ----------  -----------");

var results = new List<(int MemoryKib, int Iterations, double MedianMs)>();
foreach ((int memoryKib, int t) in candidates)
{
    double medianMs = MeasureMedianMs(memoryKib, t, parallelism, samples);
    results.Add((memoryKib, t, medianMs));
    Console.WriteLine(Invariant($"  {memoryKib / 1024.0,12:F0}  {t,10}  {medianMs,11:F1}"));
}

Console.WriteLine();

// --- Recommendation: highest total cost (m * t) that fits the budget with a
// 15% tolerance; prefer more memory over more iterations on ties.
double toleranceMs = targetMs * 1.15;
var fitting = results
    .Where(r => r.MedianMs <= toleranceMs)
    .OrderByDescending(r => (long)r.MemoryKib * r.Iterations)
    .ThenByDescending(r => r.MemoryKib)
    .ToList();

(int MemoryKib, int Iterations, double MedianMs) pick;
if (fitting.Count > 0)
{
    pick = fitting[0];
}
else
{
    pick = results.OrderBy(r => r.MedianMs).First();
    Console.WriteLine(Invariant($"WARNING: no candidate fit the {targetMs} ms budget, even at the OWASP"));
    Console.WriteLine("minimum memory cost. Recommending the cheapest measured configuration;");
    Console.WriteLine("consider a larger latency budget or faster hardware.");
    Console.WriteLine();
}

Console.WriteLine(Invariant($"Recommended configuration (~{pick.MedianMs:F0} ms measured):"));
Console.WriteLine();
Console.WriteLine("    var options = new Argon2idOptions");
Console.WriteLine("    {");
Console.WriteLine(Invariant($"        MemorySizeKib = {pick.MemoryKib},{"",-4} // {pick.MemoryKib / 1024} MiB"));
Console.WriteLine(Invariant($"        Iterations = {pick.Iterations},"));
Console.WriteLine(Invariant($"        DegreeOfParallelism = {parallelism},"));
Console.WriteLine("    };");
Console.WriteLine();
Console.WriteLine("Notes:");
Console.WriteLine("  - Re-run on production-representative hardware; laptops and CI runners differ.");
Console.WriteLine("  - Budget for concurrency: peak logins * memory cost must fit in RAM.");
Console.WriteLine("  - Existing hashes are upgraded automatically on next login via NeedsRehash.");

return 0;

static double MeasureMedianMs(int memoryKib, int iterations, int parallelism, int samples)
{
    var options = new Argon2idOptions
    {
        MemorySizeKib = memoryKib,
        Iterations = iterations,
        DegreeOfParallelism = parallelism,
    };
    var hasher = new Argon2idPasswordHasher(options);

    // Warm-up: JIT + first big allocation.
    hasher.HashPassword("calibration-warmup-password");

    double[] timings = new double[samples];
    var stopwatch = new Stopwatch();
    for (int i = 0; i < samples; i++)
    {
        GC.Collect();
        GC.WaitForPendingFinalizers();
        stopwatch.Restart();
        hasher.HashPassword("calibration-sample-password");
        stopwatch.Stop();
        timings[i] = stopwatch.Elapsed.TotalMilliseconds;
    }

    Array.Sort(timings);
    return timings.Length % 2 == 1
        ? timings[timings.Length / 2]
        : (timings[timings.Length / 2 - 1] + timings[timings.Length / 2]) / 2.0;
}

static string Invariant(FormattableString formattable) =>
    formattable.ToString(CultureInfo.InvariantCulture);

static void PrintUsage()
{
    Console.WriteLine("Usage: dotnet run -c Release --project tools/Argon2id.PasswordHasher.Calibration -- [options]");
    Console.WriteLine();
    Console.WriteLine("Options:");
    Console.WriteLine("  --target-ms <n>        Latency budget per hash in ms (default 250)");
    Console.WriteLine("  --max-memory-mib <n>   Memory cost ceiling in MiB (default 512)");
    Console.WriteLine("  --parallelism <n>      Degree of parallelism (default 1)");
    Console.WriteLine("  --samples <n>          Timed samples per candidate (default 5)");
}
