# DRAFT — OSTIF audit-sponsorship inquiry

Maintainer working document — not published. OSTIF (Open Source
Technology Improvement Fund, https://ostif.org) funds security audits
for open-source projects, typically prioritizing widely-adopted
infrastructure. A small library is a long shot, but the inquiry is
free and the worst case is a polite no. Contact via the form at
https://ostif.org/contact-us/ or the email listed there.

Similar no-budget avenues worth one email each:
- **GitHub Security Lab** (securitylab.github.com) — reviews
  open-source code, especially where CodeQL modeling is interesting.
- **University crypto/security groups** — a wrapper library with a
  complete threat model, KAT corpus, and fuzz harness is a
  well-scoped student/course audit project. (A professor can assign
  it; you get a report.)
- **.NET Foundation** (dotnetfoundation.org/projects/apply) — not an
  audit, but membership adds governance legitimacy and community reach.

---

Subject: Audit-sponsorship inquiry — Argon2id.PasswordHasher (.NET password-hashing library)

Hello OSTIF team,

I maintain Argon2id.PasswordHasher
(https://github.com/systemslibrarian/argon2id-passwordhasher), an
MIT-licensed, secure-by-default Argon2id password-hashing library for
.NET, published on NuGet. It wraps a managed Argon2 implementation in
a hard-to-misuse API (PHC-format hashes, constant-time verification,
enforced parameter floors, keyed peppering with rotation) and is aimed
at the large population of .NET applications still on PBKDF2 defaults.

I'm writing to ask whether the project would be eligible for a
sponsored security review, at whatever scope you consider proportionate
— even a brief targeted review of the PHC parser and the keyed-hashing
(pepper) design would be valuable to downstream users.

The project is deliberately structured to make an audit cheap:

- Complete published threat model (THREAT-MODEL.md) and a frank
  known-limitations register (KNOWN-GAPS.md).
- Small attack surface: one parser, one hash/verify path, ~70 public
  API lines, locked by PublicApiAnalyzers.
- Existing verification the auditors can build on: a
  reference-C-cross-checked known-answer-vector corpus (including the
  RFC 9106 §5.3 vector), differential testing against an independent
  implementation, coverage-guided fuzzing with a committed corpus,
  property-based tests, and mutation testing.
- Reproducible builds with provenance attestations and CycloneDX SBOMs
  on every release; OpenSSF Scorecard and CodeQL run continuously.

The main open assurance gap — documented publicly in KNOWN-GAPS.md §11
— is precisely that no independent party has reviewed the work. There
is no commercial budget behind the project.

Happy to provide anything else that would help you evaluate this.

Thank you for the work you do,
Paul Clark
Maintainer, Argon2id.PasswordHasher
