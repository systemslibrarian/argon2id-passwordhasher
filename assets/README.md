# Package assets

Files in this directory are bundled into the published NuGet packages.

## `icon.png` — NuGet package icon

Both `Argon2id.PasswordHasher` and `Argon2id.PasswordHasher.AspNetCore`
reference `icon.png` from this folder via their `.csproj` files:

```xml
<PackageIcon>icon.png</PackageIcon>
<None Include="../../assets/icon.png" Pack="true" PackagePath="\" Visible="false" />
```

### Constraints (from nuget.org)

| Requirement | Value |
| --- | --- |
| Format | PNG (transparent background recommended) or JPG |
| Recommended size | **128 × 128** pixels |
| Aspect ratio | Square |
| File size | ≤ 1 MB |

### How to verify it landed in the package

```bash
dotnet pack src/Argon2id.PasswordHasher/Argon2id.PasswordHasher.csproj -c Release -o artifacts
unzip -l artifacts/Argon2id.PasswordHasher.<version>.nupkg | grep icon.png
```

Both `.nupkg` and `.snupkg` should list `icon.png` at the root, and
the `<icon>` element in the embedded `.nuspec` should reference it.

### After updating the icon

NuGet caches package metadata aggressively. After publishing a new
version with an updated icon, the package page on nuget.org may show
the old icon for ~10–15 minutes while the CDN refreshes.
