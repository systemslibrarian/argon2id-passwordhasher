using Xunit;

namespace Argon2id.PasswordHasher.Tests;

/// <summary>
/// Locks the parser's resource-safety bounds. Verification recomputes Argon2id
/// with the parameters stored in the hash, so the parser must refuse stored
/// values that would dictate an absurd allocation (e.g. m=2147483647 KiB is a
/// ~2 TiB request). Out-of-bounds input must produce a clean
/// <see langword="false"/> — never an exception.
/// </summary>
public class PhcParserBoundsTests
{
    private static string B64(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=');

    private static string Phc(string costs, int saltLen = 16, int tagLen = 32) =>
        $"$argon2id$v=19${costs}${B64(new byte[saltLen])}${B64(new byte[tagLen])}";

    [Theory]
    [InlineData("m=2147483647,t=1,p=1")]              // ~2 TiB memory request
    [InlineData("m=4194305,t=1,p=1")]                 // just above the 4 GiB cap
    [InlineData("m=8192,t=1025,p=1")]                 // above iteration cap
    [InlineData("m=8192,t=1,p=129")]                  // above parallelism cap
    [InlineData("m=64,t=1,p=16")]                     // violates m >= 8 * p
    public void TryParse_RejectsOutOfBoundsCostParameters(string costs)
    {
        Assert.False(PhcString.TryParse(Phc(costs), out _));
    }

    [Theory]
    [InlineData("m=4194304,t=1,p=1")]                 // exactly the 4 GiB cap
    [InlineData("m=8192,t=1024,p=1")]                 // exactly the iteration cap
    [InlineData("m=8192,t=1,p=128")]                  // exactly the parallelism cap
    [InlineData("m=128,t=1,p=16")]                    // exactly m == 8 * p
    public void TryParse_AcceptsBoundaryCostParameters(string costs)
    {
        Assert.True(PhcString.TryParse(Phc(costs), out _));
    }

    [Theory]
    [InlineData(7, 32)]    // salt below RFC 9106 minimum
    [InlineData(65, 32)]   // salt above cap
    [InlineData(16, 15)]   // tag below minimum
    [InlineData(16, 513)]  // tag above cap
    public void TryParse_RejectsOutOfBoundsSaltOrTagLengths(int saltLen, int tagLen)
    {
        Assert.False(PhcString.TryParse(Phc("m=8192,t=1,p=1", saltLen, tagLen), out _));
    }

    [Theory]
    [InlineData(8, 16)]    // both at minimum
    [InlineData(64, 512)]  // both at cap
    public void TryParse_AcceptsBoundarySaltAndTagLengths(int saltLen, int tagLen)
    {
        Assert.True(PhcString.TryParse(Phc("m=8192,t=1,p=1", saltLen, tagLen), out _));
    }

    [Fact]
    public void TryParse_RejectsOversizedKeyId()
    {
        string keyId = B64(new byte[65]); // 65 raw bytes > MaxKeyIdBytes
        Assert.False(PhcString.TryParse(Phc($"m=8192,t=1,p=1,keyid={keyId}"), out _));
    }

    [Fact]
    public void TryParse_RejectsKeyIdThatIsNotValidUtf8()
    {
        // 0xFF bytes are never valid UTF-8. Decoding them into a string would
        // produce replacement characters, whose re-encoded bytes differ from
        // the stored ones — a lossy accept the parser must refuse.
        string keyId = B64([0xFF, 0xFF, 0xFF]);
        Assert.False(PhcString.TryParse(Phc($"m=8192,t=1,p=1,keyid={keyId}"), out _));
    }

    [Fact]
    public void TryParse_AcceptsKeyIdAtCap()
    {
        string keyId = B64(new byte[64]);
        Assert.True(PhcString.TryParse(Phc($"m=8192,t=1,p=1,keyid={keyId}"), out _));
    }

    [Fact]
    public void VerifyPassword_ReturnsFalse_DoesNotThrow_ForHugeMemoryParameter()
    {
        var hasher = new Argon2idPasswordHasher(new Argon2idOptions
        {
            MemorySizeKib = 8192,
            Iterations = 1,
            DegreeOfParallelism = 1,
        });

        // Without the parse-side cap this would attempt a ~2 TiB allocation.
        Assert.False(hasher.VerifyPassword("password", Phc("m=2147483647,t=1,p=1")));
    }

    [Fact]
    public void NeedsRehash_ReturnsTrue_ForOutOfBoundsStoredParameters()
    {
        var hasher = new Argon2idPasswordHasher(new Argon2idOptions
        {
            MemorySizeKib = 8192,
            Iterations = 1,
            DegreeOfParallelism = 1,
        });

        Assert.True(hasher.NeedsRehash(Phc("m=2147483647,t=1,p=1")));
    }

    [Theory]
    [InlineData(4194305, 3, 1, 16, 32)]   // memory above cap
    [InlineData(65536, 1025, 1, 16, 32)]  // iterations above cap
    [InlineData(65536, 3, 129, 16, 32)]   // parallelism above cap
    [InlineData(65536, 3, 1, 65, 32)]     // salt above cap
    [InlineData(65536, 3, 1, 16, 513)]    // tag above cap
    public void Validate_ThrowsForParametersTheParserWouldReject(
        int memoryKib, int iterations, int parallelism, int saltBytes, int tagBytes)
    {
        var options = new Argon2idOptions
        {
            MemorySizeKib = memoryKib,
            Iterations = iterations,
            DegreeOfParallelism = parallelism,
            SaltSizeBytes = saltBytes,
            HashSizeBytes = tagBytes,
        };

        Assert.Throws<ArgumentOutOfRangeException>(options.Validate);
    }
}
