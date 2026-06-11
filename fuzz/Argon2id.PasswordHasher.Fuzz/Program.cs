using System.Text;
using Argon2id.PasswordHasher;
using SharpFuzz;

// Coverage-guided fuzzing entry point for the PHC parser (libFuzzer mode via
// SharpFuzz). The harness asserts two invariants on every input:
//
//   1. Totality — PhcString.TryParse never throws, whatever the bytes.
//   2. Round-trip — anything the parser ACCEPTS must re-encode and re-parse
//      to an identical value (no lossy or ambiguous accepted inputs).
//
// The Argon2 computation itself is deliberately NOT fuzzed here: it is
// memory-hard by design, so feeding it attacker-shaped parameters would
// turn the fuzzer into an OOM generator instead of a parser explorer.
//
// Run locally / in CI: see .github/workflows/fuzz.yml. The committed seed
// corpus under fuzz/corpus is also replayed as plain unit tests by
// FuzzCorpusReplayTests, so every historical finding becomes a regression test.

Fuzzer.LibFuzzer.Run(span =>
{
    string input = Encoding.UTF8.GetString(span);

    _ = Argon2idPasswordHasher.IsArgon2idHash(input);

    if (!PhcString.TryParse(input, out PhcString? parsed))
    {
        return;
    }

    var options = new Argon2idOptions
    {
        MemorySizeKib = parsed!.MemorySizeKib,
        Iterations = parsed.Iterations,
        DegreeOfParallelism = parsed.DegreeOfParallelism,
    };

    string reencoded = PhcString.Encode(options, parsed.Salt, parsed.Hash, parsed.KeyId);

    if (!PhcString.TryParse(reencoded, out PhcString? reparsed))
    {
        throw new InvalidOperationException($"Re-encoded form failed to parse: {reencoded}");
    }

    if (reparsed!.MemorySizeKib != parsed.MemorySizeKib
        || reparsed.Iterations != parsed.Iterations
        || reparsed.DegreeOfParallelism != parsed.DegreeOfParallelism
        || !string.Equals(reparsed.KeyId, parsed.KeyId, StringComparison.Ordinal)
        || !reparsed.Salt.AsSpan().SequenceEqual(parsed.Salt)
        || !reparsed.Hash.AsSpan().SequenceEqual(parsed.Hash))
    {
        throw new InvalidOperationException($"Round-trip mismatch for accepted input: {input} -> {reencoded}");
    }
});
