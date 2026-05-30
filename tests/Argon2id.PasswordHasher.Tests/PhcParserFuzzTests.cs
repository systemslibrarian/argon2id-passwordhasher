using Xunit;

namespace Argon2id.PasswordHasher.Tests;

/// <summary>
/// Adversarial inputs for the internal PHC string parser, exercised through
/// the public <see cref="Argon2idPasswordHasher.Verify(string, string)"/>
/// surface. Every case here must return <see cref="VerifyResult.Failed"/>
/// and never throw — the library's "fail safe, not loud" contract.
/// </summary>
public class PhcParserFuzzTests
{
    private static readonly Argon2idPasswordHasher Hasher = new(new Argon2idOptions
    {
        MemorySizeKib = 8192,
        Iterations = 1,
        DegreeOfParallelism = 1,
    });

    public static TheoryData<string> MalformedCases() => new()
    {
        // Truncated / structurally invalid
        "",
        " ",
        "$",
        "$$",
        "$$$$$$",
        "no-dollars-here",
        "$argon2id",
        "$argon2id$",
        "$argon2id$v=19",
        "$argon2id$v=19$m=8192,t=1,p=1",
        "$argon2id$v=19$m=8192,t=1,p=1$onlysalt",

        // Wrong algorithm
        "$argon2i$v=19$m=8192,t=1,p=1$c2FsdHNhbHQ$aGFzaA",
        "$argon2d$v=19$m=8192,t=1,p=1$c2FsdHNhbHQ$aGFzaA",
        "$bcrypt$v=19$m=8192,t=1,p=1$c2FsdHNhbHQ$aGFzaA",
        "$ARGON2ID$v=19$m=8192,t=1,p=1$c2FsdHNhbHQ$aGFzaA", // case-sensitive

        // Wrong version
        "$argon2id$v=10$m=8192,t=1,p=1$c2FsdHNhbHQ$aGFzaA",
        "$argon2id$v=16$m=8192,t=1,p=1$c2FsdHNhbHQ$aGFzaA",
        "$argon2id$v=20$m=8192,t=1,p=1$c2FsdHNhbHQ$aGFzaA",
        "$argon2id$ver=19$m=8192,t=1,p=1$c2FsdHNhbHQ$aGFzaA",

        // Malformed cost segment
        "$argon2id$v=19$$c2FsdHNhbHQ$aGFzaA",
        "$argon2id$v=19$m=$c2FsdHNhbHQ$aGFzaA",
        "$argon2id$v=19$m=abc,t=1,p=1$c2FsdHNhbHQ$aGFzaA",
        "$argon2id$v=19$m=-1,t=1,p=1$c2FsdHNhbHQ$aGFzaA",
        "$argon2id$v=19$m=0,t=1,p=1$c2FsdHNhbHQ$aGFzaA",
        "$argon2id$v=19$m=99999999999999,t=1,p=1$c2FsdHNhbHQ$aGFzaA", // overflows int
        "$argon2id$v=19$m=8192,t=1$c2FsdHNhbHQ$aGFzaA",                // missing p
        "$argon2id$v=19$m=8192,t=1,p=1,extra=42$c2FsdHNhbHQ$aGFzaA",   // unknown extra

        // Bad base64 in salt / tag
        "$argon2id$v=19$m=8192,t=1,p=1$!!!notbase64!!!$aGFzaA",
        "$argon2id$v=19$m=8192,t=1,p=1$c2FsdHNhbHQ$!!!notbase64!!!",
        "$argon2id$v=19$m=8192,t=1,p=1$$aGFzaA",
        "$argon2id$v=19$m=8192,t=1,p=1$c2FsdHNhbHQ$",
    };

    [Theory]
    [MemberData(nameof(MalformedCases))]
    public void Malformed_PHC_ReturnsFailed_NeverThrows(string encoded)
    {
        bool ok = Hasher.VerifyPassword("anything", encoded);
        Assert.False(ok);

        VerifyResult result = Hasher.Verify("anything", encoded);
        Assert.Equal(VerifyResult.Failed, result);
    }

    [Fact]
    public void RandomGarbage_NeverThrows()
    {
        // Throw a few thousand random ASCII payloads at the parser to flush
        // out any path that throws instead of returning Failed.
        var rng = new Random(1337);
        for (int i = 0; i < 500; i++)
        {
            int length = rng.Next(0, 200);
            char[] chars = new char[length];
            for (int j = 0; j < length; j++)
            {
                chars[j] = (char)rng.Next(32, 127); // printable ASCII
            }
            string payload = new(chars);

            // Must not throw under ANY input.
            bool ok = Hasher.VerifyPassword("anything", payload);
            Assert.False(ok);
        }
    }

    [Fact]
    public void RawBytesGarbage_NeverThrows()
    {
        // Same idea but with arbitrary bytes (including bytes that don't
        // form valid UTF-8 sequences) — the input becomes a string via
        // ASCII-bound decoding.
        var rng = new Random(0xC0FFEE);
        for (int i = 0; i < 500; i++)
        {
            byte[] bytes = new byte[rng.Next(0, 200)];
            rng.NextBytes(bytes);

            // Wrap as a "string" with surrogate-safe round-trip — yes this
            // produces nonsense, but the parser still has to fail-safe.
            string payload = System.Text.Encoding.Latin1.GetString(bytes);

            bool ok = Hasher.VerifyPassword("anything", payload);
            Assert.False(ok);
        }
    }
}
