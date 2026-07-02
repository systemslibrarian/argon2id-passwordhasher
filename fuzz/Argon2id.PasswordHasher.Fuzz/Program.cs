using System.Buffers.Binary;
using System.Text;
using Argon2id.PasswordHasher;
using SharpFuzz;

// Coverage-guided fuzzing entry point for the PHC layer (libFuzzer mode via
// SharpFuzz). Two phases run on every input:
//
// PHASE 1 (consumer direction) asserts, for arbitrary bytes as a stored hash:
//   1. Totality — PhcString.TryParse never throws, whatever the bytes.
//   2. Round-trip — anything the parser ACCEPTS must re-encode and re-parse
//      to an identical value (no lossy or ambiguous accepted inputs).
//
// PHASE 2 (producer direction) asserts the reverse invariant, which phase 1
// is structurally blind to: EVERYTHING a correctly-constructed hasher can
// emit must parse back losslessly. The fuzz bytes are interpreted as producer
// inputs — parameters clamped into the valid domain, and a candidate pepper
// id gated through the real Pepper constructor, exactly as production code
// would be. This is the phase that would have caught the pepper-id
// encode/parse asymmetry (an id over the keyid byte cap produced hashes the
// parser rejected — a silent permanent lockout).
//
// The Argon2 computation itself is deliberately NOT fuzzed here: it is
// memory-hard by design, so feeding it attacker-shaped parameters would
// turn the fuzzer into an OOM generator instead of a parser explorer.
// PhcString.Encode is pure string/base64 work, so phase 2 stays fast.
//
// Run locally / in CI: see .github/workflows/fuzz.yml. The committed seed
// corpus under fuzz/corpus is also replayed as plain unit tests by
// FuzzCorpusReplayTests, so every historical finding becomes a regression test.

Fuzzer.LibFuzzer.Run(span =>
{
    ParserPhase(span);
    ProducerPhase(span);
});

static void ParserPhase(ReadOnlySpan<byte> span)
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
}

static void ProducerPhase(ReadOnlySpan<byte> span)
{
    if (span.Length < 9)
    {
        return;
    }

    // Derive producer inputs from the fuzz bytes, clamped into the domain a
    // correctly-constructed hasher can actually occupy (Argon2idOptions.Validate()
    // bounds). p <= 128 means 8*p <= 1024 < the 8192 memory floor, so the
    // parser's m >= 8p rule is satisfied by construction.
    int memory = 8192 + (int)(BinaryPrimitives.ReadUInt32LittleEndian(span) % (4u * 1024 * 1024 - 8192 + 1));
    int iterations = 1 + span[4] % 250;
    int parallelism = 1 + span[5] % 128;
    int saltLength = 16 + span[6] % 49;                                              // 16..64
    int hashLength = 16 + BinaryPrimitives.ReadUInt16LittleEndian(span[7..]) % 497;  // 16..512

    var options = new Argon2idOptions
    {
        MemorySizeKib = memory,
        Iterations = iterations,
        DegreeOfParallelism = parallelism,
        SaltSizeBytes = saltLength,
        HashSizeBytes = hashLength,
    };
    options.Validate(); // a throw here is a harness bug, and should crash loudly

    // The remaining bytes become a candidate pepper id, gated through the REAL
    // Pepper constructor — if production code can build the pepper, the hash it
    // produces must be verifiable. Ids Pepper rejects are simply not peppered.
    string? keyId = null;
    if (span.Length > 9)
    {
        string candidate = Encoding.UTF8.GetString(span[9..]);
        try
        {
            keyId = new Pepper(candidate, new byte[16]).Id;
        }
        catch (ArgumentException)
        {
            // Rejected at construction — exactly the fail-fast contract.
        }
    }

    byte[] salt = FillFrom(span, saltLength);
    byte[] hash = FillFrom(span, hashLength);

    string encoded = PhcString.Encode(options, salt, hash, keyId);

    if (!PhcString.TryParse(encoded, out PhcString? parsed))
    {
        throw new InvalidOperationException(
            $"Producer invariant violated: the library emitted a hash its own parser rejects: {encoded}");
    }

    if (parsed!.MemorySizeKib != memory
        || parsed.Iterations != iterations
        || parsed.DegreeOfParallelism != parallelism
        || !string.Equals(parsed.KeyId, keyId, StringComparison.Ordinal)
        || !parsed.Salt.AsSpan().SequenceEqual(salt)
        || !parsed.Hash.AsSpan().SequenceEqual(hash))
    {
        throw new InvalidOperationException(
            $"Producer round-trip mismatch (keyid '{keyId}'): {encoded}");
    }
}

static byte[] FillFrom(ReadOnlySpan<byte> source, int length)
{
    byte[] result = new byte[length];
    for (int i = 0; i < length; i++)
    {
        result[i] = source[i % source.Length];
    }

    return result;
}
