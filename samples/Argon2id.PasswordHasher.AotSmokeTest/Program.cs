using Argon2id.PasswordHasher;

// Native AOT smoke test. CI publishes this with PublishAot and runs the binary;
// a non-zero exit code fails the build. It proves the library's IsAotCompatible
// claim with a real trimmed, ahead-of-time compiled executable — not just the
// absence of analyzer warnings.
//
// Parameters are deliberately weak (8 MiB, t=1) so the test is fast; never use
// them in production.

var options = new Argon2idOptions
{
    MemorySizeKib = 8192,
    Iterations = 1,
    DegreeOfParallelism = 1,
};
var hasher = new Argon2idPasswordHasher(options);

const string Password = "aot-smoke-test-pässword-🔒";

string encoded = hasher.HashPassword(Password);

bool failed = false;

void Check(bool condition, string name)
{
    Console.WriteLine($"{(condition ? "PASS" : "FAIL")}  {name}");
    failed |= !condition;
}

Check(Argon2idPasswordHasher.IsArgon2idHash(encoded), "IsArgon2idHash recognizes own output");
Check(encoded.StartsWith(Argon2idPasswordHasher.PhcPrefix, StringComparison.Ordinal), "hash carries PHC prefix");
Check(hasher.VerifyPassword(Password, encoded), "correct password verifies");
Check(!hasher.VerifyPassword(Password + "x", encoded), "wrong password rejected");
Check(!hasher.VerifyPassword(Password, "$argon2id$v=19$not-a-hash"), "malformed hash rejected without throwing");
Check(!hasher.NeedsRehash(encoded), "fresh hash needs no rehash");

var stronger = new Argon2idPasswordHasher(new Argon2idOptions
{
    MemorySizeKib = 16384,
    Iterations = 1,
    DegreeOfParallelism = 1,
});
Check(stronger.NeedsRehash(encoded), "weaker hash flagged for rehash under stronger policy");

(bool success, bool needsRehash) = stronger.Verify(Password, encoded);
Check(success && needsRehash, "Verify reports success + rehash in one call");

Console.WriteLine(failed ? "AOT smoke test FAILED" : "AOT smoke test passed");
return failed ? 1 : 0;
