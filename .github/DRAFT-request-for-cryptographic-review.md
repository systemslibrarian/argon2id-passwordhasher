# DRAFT — pinned GitHub issue: Request for cryptographic review

Maintainer working document. Post with:

```
gh issue create \
  --repo systemslibrarian/argon2id-passwordhasher \
  --title "Standing request: independent cryptographic review welcome" \
  --label "help wanted" \
  --body-file .github/DRAFT-request-for-cryptographic-review.md
gh issue pin <number>
```

(Delete everything above the rule before posting.)

---

## Standing request: independent cryptographic review welcome

This library hashes passwords for other people's users, so it should be
held to a higher standard of scrutiny than we can generate alone. We
cannot currently fund a commercial audit
([KNOWN-GAPS.md §11](../blob/main/KNOWN-GAPS.md)), so this is a
standing, public invitation: **if you have cryptographic or .NET
security expertise, we would genuinely value adversarial review — and
we will credit it.**

### Where to start

- **[THREAT-MODEL.md](../blob/main/THREAT-MODEL.md)** — what we defend
  against and what we explicitly don't.
- **[KNOWN-GAPS.md](../blob/main/KNOWN-GAPS.md)** — every limitation we
  already know about, so you don't spend time rediscovering them.
- The interesting code is small and deliberate:
  - `src/Argon2id.PasswordHasher/PhcString.cs` — PHC parse/encode
    (fuzzed nightly; corpus in `fuzz/`)
  - `src/Argon2id.PasswordHasher/Argon2idPasswordHasher.cs` — hash /
    verify / rehash paths, memory zeroing, `FixedTimeEquals`
  - `src/Argon2id.PasswordHasher/Pepper.cs` / `PepperRing.cs` — keyed
    hashing + rotation

### Questions we would most value an outside answer to

1. Is the pepper (keyed-hashing) design sound — in particular the
   `keyid` handling and the fast-fail-on-unknown-keyid timing note in
   KNOWN-GAPS §12?
2. Are the parser resource caps (m ≤ 4 GiB, t ≤ 1024, p ≤ 128, salt
   8–64 B, tag 16–512 B) the right bounds, and is the fail-closed
   behavior correct in all paths?
3. Does the memory-hygiene story (zeroing everything we own, span
   overloads) have holes we've missed?
4. Anything in the verify path that throws (rather than returning
   `false`) on adversarial stored data?

### Ground rules

- **Suspected vulnerabilities:** please use
  [private reporting](../security/advisories/new), not this issue.
- Design critique, nitpicks, and "this claim is over-stated" feedback:
  right here, publicly.
- All findings get credited (in the CHANGELOG and, for anything
  substantive, a permanent acknowledgement in SECURITY.md) unless you
  prefer anonymity.

Reproducing our verification work is easy: `dotnet test` runs the
full suite including the RFC 9106 known-answer vectors and the
differential tests against an independent Argon2 implementation.
