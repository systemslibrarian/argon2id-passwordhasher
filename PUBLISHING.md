# Publishing to NuGet

Publication uses **NuGet Trusted Publishing** (OIDC): the release workflow
exchanges a GitHub-issued identity token for a **short-lived NuGet API key**
at publish time. There is no long-lived API key anywhere — not in repository
secrets, not on a workstation.

The deliberate-publish property of the old manual flow is preserved by an
**approval gate**: the `publish-nuget` job runs in the `nuget` GitHub
environment, which requires maintainer review. Tagging *prepares* a release;
a human *makes it public*.

## The flow

1. **Tag the release** (from the correct commit on `main`):

   ```bash
   git tag v1.0.0-rc.1 && git push origin v1.0.0-rc.1
   ```

2. **The workflow prepares everything**: full test matrix (3 OSes × 3 TFMs),
   pack, CycloneDX SBOMs, build-provenance attestations, and a GitHub
   Release with all artifacts attached. Then the `publish-nuget` job **stops
   and waits** for environment approval.

3. **Inspect before approving.** Download the artifacts from the GitHub
   Release (or the workflow run) and check whatever you'd have checked in
   the manual flow — version number matches the CHANGELOG, icon + metadata
   present, attestation verifies:

   ```bash
   gh attestation verify Argon2id.PasswordHasher.<version>.nupkg \
     --repo systemslibrarian/argon2id-passwordhasher
   ```

4. **Approve the deployment** — on the workflow run page, "Review
   deployments" → approve `nuget`. The job exchanges its OIDC token for a
   temporary key and pushes both `.nupkg`s (symbols auto-discovered,
   `--skip-duplicate` makes re-approval idempotent). It pushes the *exact
   attested bytes* from the prepare job — no rebuild.

5. **Confirm** (5–15 min for indexing):
   - https://www.nuget.org/packages/Argon2id.PasswordHasher
   - https://www.nuget.org/packages/Argon2id.PasswordHasher.AspNetCore

6. **Tidy the GitHub Release**: remove the "publication awaits approval"
   status banner from the notes:

   ```bash
   gh release edit <tag> \
     --repo systemslibrarian/argon2id-passwordhasher \
     --notes "$(gh release view <tag> --json body -q .body \
       | sed '/^## Status/,/^## Auto-generated notes$/d')"
   ```

## One-time setup (already done — recorded for disaster recovery)

Recreating this from scratch requires both halves to match exactly:

- **nuget.org** → profile → *Trusted Publishing* → policy with:
  - Package owner: `systemslibrarian`
  - Repository owner: `systemslibrarian`
  - Repository: `argon2id-passwordhasher`
  - Workflow file: `release.yml`
  - Environment: `nuget`
- **GitHub** → repo → Settings → Environments → `nuget` with **Required
  reviewers** = the maintainer. (Created via
  `gh api -X PUT repos/systemslibrarian/argon2id-passwordhasher/environments/nuget`.)
- The workflow's `NuGet/login` step's `user:` must equal the nuget.org
  username that owns the policy.

If the policy and workflow drift (renamed workflow file, different
environment name), the OIDC exchange fails closed with a clear error —
nothing publishes.

## Why the approval gate

Pushing to a public registry is irreversible (NuGet supports *unlisting*
but not deletion). The gate catches:

- Accidental tags pushed from a stale or wrong branch
- Versions where the test matrix passed but the resulting package is
  somehow off (icon, metadata, missing assets)
- Version-bump mistakes (e.g. tagging `v1.0.1` while
  `Directory.Build.props` still says `1.0.0`)

## Fallback: manual CLI push

If GitHub Actions is unavailable, a maintainer can still publish from a
workstation. This requires creating a **temporary** API key on nuget.org
(scopes: Push only; glob `Argon2id.PasswordHasher*`; shortest expiry
offered) and revoking it immediately after:

```bash
# From the repo root, on the tagged commit:
rm -rf artifacts
dotnet pack src/Argon2id.PasswordHasher/Argon2id.PasswordHasher.csproj -c Release -o artifacts
dotnet pack src/Argon2id.PasswordHasher.AspNetCore/Argon2id.PasswordHasher.AspNetCore.csproj -c Release -o artifacts

dotnet nuget push artifacts/Argon2id.PasswordHasher.<version>.nupkg \
  --api-key "<temporary-key>" --source https://api.nuget.org/v3/index.json --skip-duplicate
dotnet nuget push artifacts/Argon2id.PasswordHasher.AspNetCore.<version>.nupkg \
  --api-key "<temporary-key>" --source https://api.nuget.org/v3/index.json --skip-duplicate
```

Then revoke the key on nuget.org. Do not store it.

---

*To God be the glory — 1 Corinthians 10:31.*
