# Argon2id.PasswordHasher — Demo

A minimal, runnable Blazor Server sample that demonstrates the
[`Argon2id.PasswordHasher`](../../src/Argon2id.PasswordHasher) library end-to-end:
user registration, login, and a live breakdown of the PHC hash string the
library produces.

The demo uses a `ProjectReference` to the in-tree library, so it always exercises
the version you're working on.

## Run it

```bash
# From the repo root:
dotnet run --project samples/Argon2id.PasswordHasher.Demo
```

then open the URL the host prints (typically `https://localhost:5001`).

## What you can do

| Page | Purpose |
| --- | --- |
| **Overview** (`/`) | Walk-through of what the library does and the demo flow. |
| **Register** (`/register`) | Submit a username + password; see the exact PHC string the library stored. |
| **Log in** (`/login`) | Verify the password; see the constant-time comparison happen and (if applicable) a rehash-on-login upgrade. |
| **Registered users** (`/users`) | List every account registered in this process, each with its hash decomposed into algorithm, version, parameters, salt, and tag. |

## What is real, what is just a demo

| Real | Demo-only |
| --- | --- |
| `Argon2idPasswordHasher` is the real, secure-by-default library API. | Users live in process memory and disappear on restart. |
| Hashing uses the library's recommended defaults (64 MiB / t=3 / p=1). | The PHC string is shown on screen so you can inspect it — never do this in production UI. |
| Verification uses constant-time comparison (`FixedTimeEquals`). | There is no rate limiting, account lockout, MFA, or breached-password check. |
| Rehash-on-login is wired up the way a real app would do it. | There is no session, cookie, or "current user" — this is purely a hashing showcase. |

## Project layout

```
Components/
  App.razor            — root HTML + script tag for Blazor Server
  Routes.razor         — router + default layout
  Layout/
    MainLayout.razor   — sidebar + content shell
    NavMenu.razor      — left-hand navigation
  Pages/
    Home.razor             — overview + code snippet
    Register.razor         — registration form, displays the stored hash
    Login.razor            — verification + rehash-on-login demo
    Users.razor            — list of every registered user
    PhcBreakdownView.razor — reusable PHC-decomposition component
Services/
  DemoUser.cs          — in-memory user record
  InMemoryUserStore.cs — singleton concurrent dictionary
  PhcBreakdown.cs      — view-model that splits a PHC string for display
Program.cs             — DI wiring + Blazor Server pipeline
wwwroot/app.css        — dependency-free dark theme
```

## Adapting it to your app

The two lines that matter for the library are in `Program.cs`:

```csharp
// 1. Register the hasher as a thread-safe singleton (it is stateless).
builder.Services.AddSingleton(new Argon2idPasswordHasher());

// 2. Inject it wherever you need to hash or verify a password.
//    On registration:  string stored = hasher.HashPassword(password);
//    On login:         bool ok       = hasher.VerifyPassword(password, stored);
//    On login (cont.): if (hasher.NeedsRehash(stored)) ... // upgrade in place
```

If you're using ASP.NET Core Identity, the
[`Argon2id.PasswordHasher.AspNetCore`](../../src/Argon2id.PasswordHasher.AspNetCore)
package replaces `IPasswordHasher<TUser>` with one DI extension call:

```csharp
builder.Services
    .AddIdentityCore<IdentityUser>()
    .Services
    .AddArgon2idPasswordHasher<IdentityUser>();
```

---

*To God be the glory — 1 Corinthians 10:31.*
