# Publishing to NuGet

NuGet publication is a deliberately **manual CLI step**, not part of the
GitHub Actions release workflow. This document tells a maintainer exactly
how to do it.

The Actions release workflow only runs on tag push and produces:

- The two `.nupkg` packages + their `.snupkg` symbol packages
- CycloneDX SBOMs per package
- SLSA-style build-provenance attestations
- A GitHub Release with all of the above attached

What it deliberately does **not** do:

- Push to `nuget.org`. That's this document.

## Why manual

Pushing to a public registry is irreversible (NuGet supports
*unlisting* but not deletion). Forcing the maintainer to look at the
packed artifacts and run the push by hand catches:

- Accidental tags pushed from a stale or wrong branch
- Versions where the test matrix passed but the resulting package
  is somehow off (icon, metadata, missing assets)
- Pre-1.0 preview-bump mistakes (e.g. tagging `v0.4.0-preview.3`
  when the CHANGELOG/version property still says `0.3`)

Once the project is post-1.0 and release cadence stabilizes, this
policy can be revisited.

## Prerequisites

1. **Local clone** of the repo, on the tagged commit:
   ```bash
   git fetch --tags
   git checkout v0.4.0-preview.3
   ```
2. **NuGet API key** stored locally at the repo root in `.nuget-api-key`
   (already covered by `.gitignore`). The key on nuget.org should be
   scoped to:
   - **Scopes:** Push + Push new packages and package versions (nothing else).
   - **Packages glob:** `Argon2id.PasswordHasher*`
   - **Expiration:** 365 days; calendar a rotation reminder.
3. **`dotnet`** SDK 10.0+ on PATH (the pinned `global.json` version is fine).

## The push

Either pack fresh locally, or download the artifacts from the
GitHub Release for the tag.

### Option A — pack fresh from the tagged commit (recommended)

```bash
# From the repo root, on the tagged commit:
rm -rf artifacts
dotnet pack src/Argon2id.PasswordHasher/Argon2id.PasswordHasher.csproj \
  -c Release -o artifacts
dotnet pack src/Argon2id.PasswordHasher.AspNetCore/Argon2id.PasswordHasher.AspNetCore.csproj \
  -c Release -o artifacts

ls artifacts/  # should show 2 .nupkg + 2 .snupkg at the tagged version
```

### Option B — download the GitHub-Release-built artifacts

```bash
gh release download v0.4.0-preview.3 \
  --repo systemslibrarian/argon2id-passwordhasher \
  --pattern '*.nupkg' \
  --pattern '*.snupkg' \
  --dir artifacts
```

Option A is recommended because it lets you verify the pack output
against a clean local build before publishing. Option B is faster if
you trust the workflow output and just want to mirror it to NuGet.

### Verify provenance before publishing

If you took Option B (or any time you want to double-check), verify
each artifact's GitHub-issued provenance attestation matches the
expected source repo and ref:

```bash
gh attestation verify artifacts/Argon2id.PasswordHasher.0.4.0-preview.3.nupkg \
  --repo systemslibrarian/argon2id-passwordhasher
gh attestation verify artifacts/Argon2id.PasswordHasher.AspNetCore.0.4.0-preview.3.nupkg \
  --repo systemslibrarian/argon2id-passwordhasher
```

Both should print a green ✓ matched against the tagged commit's
workflow run.

### Push

```bash
# Read the key once into a shell variable (NOT exported to subprocesses).
KEY="$(cat .nuget-api-key | tr -d '\r\n')"

# Push each .nupkg individually — dotnet auto-discovers and pushes the
# matching .snupkg to the symbols server. --skip-duplicate makes the
# command idempotent if the version already exists on NuGet.
dotnet nuget push artifacts/Argon2id.PasswordHasher.0.4.0-preview.3.nupkg \
  --api-key "$KEY" \
  --source https://api.nuget.org/v3/index.json \
  --skip-duplicate

dotnet nuget push artifacts/Argon2id.PasswordHasher.AspNetCore.0.4.0-preview.3.nupkg \
  --api-key "$KEY" \
  --source https://api.nuget.org/v3/index.json \
  --skip-duplicate

# Forget the variable.
unset KEY
```

Each push should print four `Created` lines (the `.nupkg` + the
auto-discovered `.snupkg` per package).

### Confirm

Within 5–15 minutes of NuGet indexing, both packages are visible:

- https://www.nuget.org/packages/Argon2id.PasswordHasher
- https://www.nuget.org/packages/Argon2id.PasswordHasher.AspNetCore

## Updating the GitHub Release after publishing

Once the NuGet publish is confirmed, edit the auto-generated GitHub
Release to remove the "NuGet publication is a separate, manual CLI
step" status banner — the workflow inserts it because at the moment
of release creation, the publish hasn't happened yet:

```bash
gh release edit v0.4.0-preview.3 \
  --repo systemslibrarian/argon2id-passwordhasher \
  --notes "$(gh release view v0.4.0-preview.3 --json body -q .body \
    | sed '/^## Status/,/^## Auto-generated notes$/d')"
```

(Or just open the release in the GitHub UI and edit the description.)

## Rotating the API key

NuGet API keys expire at 365 days max. To rotate:

1. Create a new key on nuget.org with the same name (e.g. append the
   current year) and the same `Argon2id.PasswordHasher*` glob scope.
2. Overwrite `.nuget-api-key` with the new value.
3. Revoke the old key in the nuget.org dashboard.

The next push uses the new key automatically.

---

*To God be the glory — 1 Corinthians 10:31.*
