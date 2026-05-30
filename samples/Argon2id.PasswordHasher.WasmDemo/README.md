# Argon2id.PasswordHasher — WASM Demo

A Blazor WebAssembly version of the sample. The entire app — **including the
Argon2id hashing** — runs in your browser. No backend.

This sample is what's published to GitHub Pages: it's the always-on public
demo. Use this when you want to try the library without cloning the repo. Use
the [Blazor Server demo](../Argon2id.PasswordHasher.Demo) when you want to see
how the library plugs into a real ASP.NET Core application (DI, antiforgery,
rate limiting, HSTS, CSP).

## Live URL

After the next deploy, the demo is at:

<https://systemslibrarian.github.io/argon2id-passwordhasher/>

## Run locally

```bash
# From the repo root:
dotnet run --project samples/Argon2id.PasswordHasher.WasmDemo
```

then open the URL the dev server prints (typically `http://localhost:5100`).

The first run is slow — Blazor WebAssembly is downloading the .NET runtime
into the browser. Subsequent runs are cached.

## How is this possible?

The `Argon2id.PasswordHasher` library is pure managed .NET. The underlying
Argon2id implementation
([Konscious](https://github.com/kmaragon/Konscious.Security.Cryptography))
uses only BCL primitives, so it compiles to WebAssembly like any other .NET
code. When the user clicks Register, the browser spins up a WASM Argon2
computation that burns ~64 MiB and a few hundred ms of CPU.

## Expected performance

- **Hash:** 1–3 seconds in WASM at the library's default secure parameters
  (m=64 MiB, t=3, p=1).
- **Verify:** about the same — verification re-runs Argon2id.
- **Cold start:** ~2 MB of WASM runtime + assemblies, cached after first load.

That delay is the security feature, not a bug. Argon2id is *designed* to be
slow so brute-force attacks are expensive.

## Project layout

```
App.razor              — Router + default layout
Program.cs             — WebAssemblyHostBuilder, DI wiring
_Imports.razor         — usings shared by every component
Layout/
  MainLayout.razor     — sidebar + content shell
  NavMenu.razor        — left-hand navigation
Pages/
  Home.razor             — overview + code snippet
  Register.razor         — registration form, displays the stored hash
  Login.razor            — verification flow
  Users.razor            — list of every registered user
  PhcBreakdownView.razor — reusable PHC-decomposition component
Services/
  DemoUser.cs            — in-memory user record
  InMemoryUserStore.cs   — singleton concurrent dictionary
  PhcBreakdown.cs        — view-model that splits a PHC string for display
wwwroot/
  index.html             — bootstrap HTML; `<base href>` rewritten at publish for GH Pages
  app.css                — dependency-free dark theme
```

## What's real, what's just a demo

| Real | Demo-only |
| --- | --- |
| `Argon2idPasswordHasher` is the real, secure-by-default library API. | Users live in tab memory and disappear on reload. |
| Hashing uses the library's recommended defaults (64 MiB / t=3 / p=1). | The PHC string is shown on screen — never do this in production UI. |
| Verification uses constant-time comparison (`FixedTimeEquals`). | There is no rate limiting, account lockout, MFA, or breached-password check. |
| Rehash-on-login is wired up the way a real app would do it. | There is no session, cookie, or "current user" — purely a hashing showcase. |

---

*To God be the glory — 1 Corinthians 10:31.*
