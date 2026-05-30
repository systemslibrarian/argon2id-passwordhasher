using System.Threading.RateLimiting;
using Argon2id.PasswordHasher;
using Argon2id.PasswordHasher.Demo.Components;
using Argon2id.PasswordHasher.Demo.Middleware;
using Argon2id.PasswordHasher.Demo.Services;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

// Don't advertise the server. Middleware can't strip this header reliably —
// Kestrel writes it before middleware OnStarting callbacks fire.
builder.WebHost.ConfigureKestrel(options => options.AddServerHeader = false);

// --- Blazor Server (Razor Components, interactive Server mode) ----------------
builder.Services
    .AddRazorComponents()
    .AddInteractiveServerComponents();

// --- HSTS: preload-ready (365 days, includeSubDomains, preload) ---------------
// Default UseHsts() sets a 30-day max-age, which is below the HSTS preload list's
// 1-year floor. Crank it up so the headers are actually preload-eligible.
builder.Services.AddHsts(options =>
{
    options.MaxAge = TimeSpan.FromDays(365);
    options.IncludeSubDomains = true;
    options.Preload = true;
});

// --- HTTP rate limiting -------------------------------------------------------
// Sliding window per remote IP. Protects the static page handlers from
// scrape/spam; SignalR circuit traffic ('/_blazor') is left unthrottled so
// legitimate interactive sessions don't get cut off mid-render.
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.AddPolicy("ui", httpContext =>
    {
        string partitionKey = httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        return RateLimitPartition.GetSlidingWindowLimiter(
            partitionKey,
            _ => new SlidingWindowRateLimiterOptions
            {
                PermitLimit = 60,
                Window = TimeSpan.FromMinutes(1),
                SegmentsPerWindow = 6,
                QueueLimit = 0,
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
            });
    });
});

// --- Argon2id.PasswordHasher --------------------------------------------------
// Shared singleton — the hasher is stateless and thread-safe. We use the
// library's recommended defaults (m=64 MiB, t=3, p=1) so the demo accurately
// reflects production behavior. Each hash takes ~100–300 ms on typical hardware.
builder.Services.AddSingleton(new Argon2idPasswordHasher());

// In-memory user "database" kept alive across requests as a singleton. A real
// app would persist users to a database; here we deliberately keep it simple so
// the demo stays focused on the hashing flow.
builder.Services.AddSingleton<InMemoryUserStore>();

// Concurrency gate around all hash work. With 64 MiB per hash, unbounded
// concurrent hashing is a memory-cost DoS vector. The gate queues excess work.
builder.Services.AddSingleton<HashingGate>();

// Pre-compute the canary hash used to make the login path constant-time when
// the requested username does not exist.
builder.Services.AddSingleton<LoginCanary>();

WebApplication app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseSecurityHeaders();
app.UseRateLimiter();
app.UseAntiforgery();

// Use UseStaticFiles rather than MapStaticAssets: the latter's runtime patcher
// chokes on the virtual `_framework/blazor.web.js` path in this configuration.
// We don't need fingerprinted-asset URLs for a demo.
app.UseStaticFiles();

app.MapRazorComponents<App>()
   .AddInteractiveServerRenderMode()
   .RequireRateLimiting("ui");

app.Run();
