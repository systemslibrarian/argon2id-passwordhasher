<!--
Thanks for sending a pull request! A few quick checks before you submit:
-->

## Summary

<!-- What does this change do, and why? Link any related issues. -->

## Type of change

- [ ] Bug fix (non-breaking)
- [ ] New feature (non-breaking)
- [ ] Breaking change (API / behavior / hash format)
- [ ] Documentation only
- [ ] Build / CI / repo tooling

## Security impact

<!-- Does this change touch hashing, parsing, parameter validation, comparison,
     or peppering? If yes, summarize the threat model implications. -->

- [ ] No security impact
- [ ] Security-relevant — `SECURITY.md` and/or `KNOWN-GAPS.md` updated

## Checklist

- [ ] `dotnet format --verify-no-changes` passes locally
- [ ] `dotnet build -c Release -warnaserror` produces no warnings
- [ ] `dotnet test -c Release` passes (all TFMs you can run locally)
- [ ] New tests cover the behavior change (round-trip, malformed, tamper, rehash
      where applicable)
- [ ] Any public API additions appear in `PublicAPI.Unshipped.txt`
- [ ] `CHANGELOG.md` updated under `## [Unreleased]` for user-visible changes
- [ ] No new runtime dependencies without justification
