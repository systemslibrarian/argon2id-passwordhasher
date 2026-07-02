# OpenSSF Best Practices badge — evidence map

Maintainer working document. The [OpenSSF Best Practices
badge](https://www.bestpractices.dev/) is a free self-attestation that
enterprise adopters check alongside Scorecard. Only the maintainer can
submit it (sign in with GitHub at bestpractices.dev, add the project,
answer the questionnaire). This file maps every **passing**-level
criterion to the evidence in this repo so the submission takes minutes,
and lists the honest answer where we fall short.

Once earned, add the badge to README (bestpractices.dev provides the
markdown snippet, e.g.
`[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/<ID>/badge)](https://www.bestpractices.dev/projects/<ID>)`).

## Basics

| Criterion | Answer | Evidence |
| --- | --- | --- |
| Project website | Met | https://systemslibrarian.github.io/argon2id-passwordhasher/ |
| Description of what the software does | Met | `README.md` intro |
| How to obtain / provide feedback / contribute | Met | `README.md`, `CONTRIBUTING.md`, `SUPPORT.md` |
| FLOSS license | Met | MIT, `LICENSE`, SPDX id in package metadata |
| License posted in standard location | Met | `/LICENSE` |
| Basic documentation | Met | README + DocFx API site (`/docs/`) |
| Reference documentation for external interface | Met | DocFx generates from XML docs for every public member |
| HTTPS site | Met | GitHub Pages |
| Discussion mechanism | Met | GitHub Issues + Discussions |
| English supported | Met | — |
| Maintained | Met | Active commits, CHANGELOG, release cadence in `SUPPORT.md` |

## Change control

| Criterion | Answer | Evidence |
| --- | --- | --- |
| Public version-controlled source repo | Met | GitHub |
| Interim versions available for review | Met | Every commit public; preview releases on NuGet |
| Unique version numbering | Met | SemVer + preview suffixes, single source in `Directory.Build.props` |
| Semantic Versioning | Met | `SUPPORT.md` § Versioning |
| Release notes per release | Met | `CHANGELOG.md` (Keep-a-Changelog) + GitHub Releases with generated notes |
| Release notes identify fixed vulnerabilities | Met | CHANGELOG has explicit `### Security` sections (see 0.4.0-preview.5) |

## Reporting

| Criterion | Answer | Evidence |
| --- | --- | --- |
| Bug reporting process | Met | Issue templates in `.github/ISSUE_TEMPLATE/` |
| Bug tracker archive | Met | GitHub Issues |
| Vulnerability reporting process published | Met | `SECURITY.md` (private GitHub Security Advisories) |
| Vulnerability report response ≤ 14 days | Met | `SECURITY.md` commits to acknowledgement within a few days / 72 h target |
| Responses to bug reports | Met | Triage targets in `SUPPORT.md` |

## Quality

| Criterion | Answer | Evidence |
| --- | --- | --- |
| Working build system | Met | `dotnet build`, pinned SDK via `global.json` |
| Automated test suite | Met | 606 xUnit tests across net8/9/10 |
| New functionality adds tests | Met | Policy in `CLAUDE.md`/`CONTRIBUTING.md`; enforced in review |
| Warning flags / max warnings | Met | `TreatWarningsAsErrors`, analyzers at `latest-recommended`, `dotnet format --verify-no-changes` in CI |
| Tests run in CI | Met | `ci.yml` matrix: 3 OSes × 3 TFMs |
| Test coverage measured (SUGGESTED at passing) | Met | Coverlet, 80% line gate in CI (actual: ~96% core / ~89% adapter) |

## Security

| Criterion | Answer | Evidence |
| --- | --- | --- |
| Secure development knowledge | Met | `THREAT-MODEL.md`, `SECURITY.md`, RFC 9106 / OWASP alignment |
| Use basic good crypto practices | Met | Argon2id only, `RandomNumberGenerator` salts, `FixedTimeEquals`, `ZeroMemory`; this *is* a crypto library — parameters documented in `docs/parameter-tuning.md` |
| Published crypto algorithms only | Met | Argon2 (RFC 9106), implementation delegated to Konscious (documented trade-off) |
| No unfixed publicly-known vulnerabilities of medium+ severity > 60 days | Met | None known; NuGetAudit + Dependabot + CodeQL monitor continuously |
| No leaked private credentials in repo | Met | API key file gitignored; secret-scanning on |
| Delivery over HTTPS | Met | NuGet.org |
| Static analysis | Met | CodeQL (security-and-quality) + .NET analyzers |
| Dynamic analysis (SUGGESTED) | Met | Coverage-guided fuzzing (`fuzz.yml`), property-based tests, differential tests |

## Gaps to answer honestly (they do not block "passing")

- **Two-person review / bus factor** (silver/gold criteria): single
  maintainer — answer "Unmet" where asked; point to
  `SUPPORT.md` § Governance for mitigations.
- **External security review** (gold): none yet — `KNOWN-GAPS.md` §11.
- **Signed releases**: no Authenticode/author signing
  (`KNOWN-GAPS.md` §10), but build-provenance attestations exist on
  every artifact (`gh attestation verify`) — describe that in the
  justification text box; attestations generally satisfy the intent.
- **Hardening mechanisms**: managed .NET runtime defaults (ASLR/DEP via
  CLR); note that in the justification field.

## Silver level — realistic near-term pickups

Most silver criteria are already met (DCO/contribution policy,
governance doc, threat model, SBOM, reproducible builds, test policy,
coverage). The honest blockers at silver are the two-person-review and
security-review items above. Submit for passing first; enable the
silver questionnaire afterwards and let the unmet items stand with
written justifications — partial silver progress is itself a signal.
