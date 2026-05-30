# Security Policy

## Supported versions

This project is in early preview. Security fixes are applied to the latest
`0.x` preview only until a `1.0.0` release is published.

| Version | Supported |
| --- | --- |
| `0.1.x-preview` | ✅ |
| `< 0.1.0` | ❌ |

## Reporting a vulnerability

**Please do not open public GitHub issues for security vulnerabilities.**

Instead, report privately using GitHub's
[**Security Advisories**](https://github.com/systemslibrarian/argon2id-passwordhasher/security/advisories/new)
("Report a vulnerability"). If you cannot use that channel, contact the maintainer
through the email on the GitHub profile.

When reporting, please include:

- A clear description of the issue and its impact.
- Steps to reproduce or a proof of concept.
- Affected version(s) and environment details.

You can expect an acknowledgement within a few days. We will work with you on a
fix and coordinate disclosure. Credit is given to reporters unless you prefer to
remain anonymous.

## Scope

This library hashes and verifies passwords. The following are **in scope**:

- Incorrect Argon2id usage that weakens the resulting hash.
- Hash encoding/parsing flaws (PHC string handling).
- Timing side channels in verification.
- Parameter-validation gaps that allow insecure configurations.

The following are **out of scope** (see [`KNOWN-GAPS.md`](KNOWN-GAPS.md) for detail):

- The lifetime of a plaintext `string` password in managed memory (a .NET runtime
  constraint, not something a library can fully control).
- Vulnerabilities in the underlying
  [Konscious.Security.Cryptography.Argon2](https://github.com/kmaragon/Konscious.Security.Cryptography)
  package — report those upstream (we will help coordinate).
- Misuse such as logging plaintext passwords, transmitting them insecurely, or
  storing the resulting hashes without access control.

## Cryptographic guidance

This library follows:

- [RFC 9106 — Argon2 Memory-Hard Function](https://www.rfc-editor.org/rfc/rfc9106)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

Default parameters (`m = 64 MiB`, `t = 3`, `p = 1`) exceed the current OWASP minimum.
Operators should still benchmark on their own hardware and tune to their latency budget.
