using System.Text;
using Xunit;

namespace Argon2id.PasswordHasher.Tests;

/// <summary>
/// Replays the committed fuzz seed corpus (<c>fuzz/corpus</c>) through the same
/// invariants the SharpFuzz harness enforces. Every input the fuzzer has ever
/// found interesting — including any future crash reproducer that gets added to
/// the corpus — is exercised as a plain unit test on every CI run, on every OS
/// and TFM, without needing the fuzzing toolchain.
/// </summary>
public class FuzzCorpusReplayTests
{
    public static TheoryData<string> CorpusFiles()
    {
        var data = new TheoryData<string>();
        string dir = Path.Combine(AppContext.BaseDirectory, "FuzzCorpus");
        foreach (string file in Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories))
        {
            data.Add(Path.GetFileName(file));
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(CorpusFiles))]
    public void CorpusInput_SatisfiesParserInvariants(string fileName)
    {
        byte[] bytes = File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "FuzzCorpus", fileName));
        string input = Encoding.UTF8.GetString(bytes);

        // Invariant 1: totality — parsing never throws (the call below either
        // returns or the test fails with the exception, which is the point).
        bool accepted = PhcString.TryParse(input, out PhcString? parsed);

        if (!accepted)
        {
            return;
        }

        // Invariant 2: accepted inputs round-trip losslessly.
        var options = new Argon2idOptions
        {
            MemorySizeKib = parsed!.MemorySizeKib,
            Iterations = parsed.Iterations,
            DegreeOfParallelism = parsed.DegreeOfParallelism,
        };

        string reencoded = PhcString.Encode(options, parsed.Salt, parsed.Hash, parsed.KeyId);

        Assert.True(PhcString.TryParse(reencoded, out PhcString? reparsed));
        Assert.Equal(parsed.MemorySizeKib, reparsed!.MemorySizeKib);
        Assert.Equal(parsed.Iterations, reparsed.Iterations);
        Assert.Equal(parsed.DegreeOfParallelism, reparsed.DegreeOfParallelism);
        Assert.Equal(parsed.KeyId, reparsed.KeyId);
        Assert.Equal(parsed.Salt, reparsed.Salt);
        Assert.Equal(parsed.Hash, reparsed.Hash);
    }

    [Fact]
    public void Corpus_ContainsBothAcceptedAndRejectedSeeds()
    {
        // Guards against the corpus silently not being deployed, and against a
        // parser change that flips the whole corpus to one side.
        int accepted = 0, rejected = 0;
        string dir = Path.Combine(AppContext.BaseDirectory, "FuzzCorpus");

        foreach (string file in Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories))
        {
            string input = Encoding.UTF8.GetString(File.ReadAllBytes(file));
            if (PhcString.TryParse(input, out _))
            {
                accepted++;
            }
            else
            {
                rejected++;
            }
        }

        Assert.True(accepted >= 2, $"Expected at least 2 parseable seeds, found {accepted}.");
        Assert.True(rejected >= 4, $"Expected at least 4 unparseable seeds, found {rejected}.");
    }
}
