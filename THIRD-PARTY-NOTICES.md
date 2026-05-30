# Third-Party Notices

`Argon2id.PasswordHasher` redistributes — and depends at runtime on — the
following third-party components. Their licenses are reproduced or linked
below.

---

## Konscious.Security.Cryptography.Argon2

- **Project:** <https://github.com/kmaragon/Konscious.Security.Cryptography>
- **License:** MIT
- **Purpose:** The vetted managed Argon2id implementation that this library
  wraps. All actual hashing happens inside Konscious.

```
The MIT License (MIT)

Copyright (c) Keef Aragon

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
```

---

## Microsoft.Extensions.Identity.Core *(adapter package only)*

- **Project:** <https://github.com/dotnet/aspnetcore>
- **License:** MIT
- **Purpose:** Provides the `IPasswordHasher<TUser>` contract that the
  `Argon2id.PasswordHasher.AspNetCore` adapter implements.

Full text: <https://github.com/dotnet/aspnetcore/blob/main/LICENSE.txt>

---

## Microsoft.SourceLink.GitHub *(build-time only, `PrivateAssets="All"`)*

- **Project:** <https://github.com/dotnet/sourcelink>
- **License:** MIT
- **Purpose:** Embeds source-link metadata into the published assemblies so
  debuggers can step into this library's source. Not redistributed.

Full text: <https://github.com/dotnet/sourcelink/blob/main/License.txt>

---

If you spot a missing attribution, please open an issue or pull request.

*To God be the glory — 1 Corinthians 10:31.*
