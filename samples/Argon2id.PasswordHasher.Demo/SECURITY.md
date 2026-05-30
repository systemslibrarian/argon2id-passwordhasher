# Demo security posture

This sample is a **demo**, not a starter template. Some things are deliberately
hardened so it survives being put on the internet for a few minutes; some things
are deliberately left open so it remains useful as a teaching tool.

## What's hardened

| Concern | Mitigation |
| --- | --- |
| **XSS via stored input** | Razor auto-encodes every `@expression`. Inputs are also restricted by a username allow-list (`^[A-Za-z0-9._-]{1,32}$`) and password length cap (256 chars). |
| **Missing security headers** | `Middleware/SecurityHeadersMiddleware.cs` sets a strict Content-Security-Policy (`script-src 'self'`), `X-Content-Type-Options`, `Referrer-Policy: no-referrer`, `Permissions-Policy` (disables camera/mic/geolocation/etc.), `X-Frame-Options: DENY`, `Cross-Origin-Opener-Policy`, and `Cross-Origin-Resource-Policy`. |
| **Clickjacking** | `frame-ancestors 'none'` in the CSP, plus the legacy `X-Frame-Options: DENY`. |
| **HSTS** | `AddHsts` configured for 365 days, `includeSubDomains`, `preload`-eligible. Active only outside the Development environment. |
| **Memory-cost DoS** | `Services/HashingGate.cs` caps concurrent Argon2id operations at `Environment.ProcessorCount` slots, queueing excess work. Each hash holds 64 MiB; without the gate, a flood of registrations would pin the process. |
| **HTTP scrape / page-load spam** | ASP.NET Core `RateLimiter` with a sliding-window policy (60 req/min per remote IP) applied to the Razor Components endpoints. The Blazor SignalR endpoint (`/_blazor`) is intentionally excluded so interactive sessions aren't cut. |
| **Username enumeration via login timing** | `Services/LoginCanary.cs` pre-computes a throwaway hash at startup. When the requested username does not exist, the login path still runs `VerifyPassword` against the canary, so wall-clock time is the same whether or not the username exists. |
| **Antiforgery (CSRF)** | `app.UseAntiforgery()` is wired before the Razor Components endpoint. `EditForm` posts carry the antiforgery token automatically. |
| **HTTPS** | `app.UseHttpsRedirection()` and HSTS in non-Development. |
| **Server header leakage** | The `Server` response header is stripped. |
| **Input bounds** | DataAnnotations on `RegisterInput` / `LoginInput` enforce username regex + length and password length before any hashing work happens. |

## What's deliberately left as-is

These are **demo decisions, not oversights** — flipping them would defeat the
demo's purpose.

| Behavior | Why it's intentional |
| --- | --- |
| **Hash strings shown on screen** | The whole point of the demo is to make the PHC string visible so users can *see* what gets stored. Real apps never render this to the client. |
| **Registration is open to anyone** | Visitors need to be able to create users to walk through the flow. |
| **No email confirmation, no MFA, no account lockout** | These belong at the identity / application layer; the library is a hashing layer. See [`KNOWN-GAPS.md`](../../KNOWN-GAPS.md) §7. |
| **Users live in process memory** | `ConcurrentDictionary<string, DemoUser>` keyed by username. No database, no persistence, evaporates on restart. |
| **No session / cookies / authenticated state** | The demo never claims to log a user "in" beyond the success message. There is no current-user context. |
| **No password strength / breached-password check** | Out of scope for the library and the demo. Plug in [Pwned Passwords](https://haveibeenpwned.com/Passwords) or a strength meter at your application layer. |
| **Wide `'unsafe-inline'` for styles in the CSP** | Blazor's reconnect modal and a few components inject inline `style="..."` attributes. Locking this down would require nonces and is overkill for a demo. Scripts remain `'self'`-only. |

## How to verify the hardening

After running `dotnet run --project samples/Argon2id.PasswordHasher.Demo`:

```bash
# Headers (replace the port with whatever Kestrel prints):
curl -sI https://localhost:5001/ | sort

# Should include at minimum:
#   content-security-policy: default-src 'self'; script-src 'self'; ...
#   referrer-policy: no-referrer
#   x-content-type-options: nosniff
#   x-frame-options: DENY
#   permissions-policy: accelerometer=(), camera=(), ...

# Rate limiter (this should start returning 429 after ~60 requests in a minute):
for i in $(seq 1 80); do curl -s -o /dev/null -w "%{http_code}\n" https://localhost:5001/; done | sort | uniq -c

# Anti-enumeration (both should take comparable time):
time curl -s -o /dev/null https://localhost:5001/login  # baseline
# … then submit a Login form for a real user vs a made-up one and compare.
```

If any of the above headers are missing or the rate limiter doesn't kick in,
something in `Program.cs` regressed.

---

*To God be the glory — 1 Corinthians 10:31.*
