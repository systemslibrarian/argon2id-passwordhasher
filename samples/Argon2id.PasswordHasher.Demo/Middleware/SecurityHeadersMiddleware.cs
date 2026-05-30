namespace Argon2id.PasswordHasher.Demo.Middleware;

/// <summary>
/// Sets a tight set of security response headers on every response.
/// </summary>
/// <remarks>
/// <para>
/// The CSP is locked down to <c>'self'</c> for scripts, the only inline allowance
/// is for styles (Blazor injects a few inline style attributes for its reconnect
/// modal). WebSocket connections are permitted to the same origin so the Blazor
/// Server SignalR circuit works in both HTTP (dev) and HTTPS (prod).
/// </para>
/// <para>
/// <c>frame-ancestors 'none'</c> in the CSP supersedes the older
/// <c>X-Frame-Options: DENY</c> for modern browsers, but we set both so legacy
/// clients also reject framing.
/// </para>
/// </remarks>
public sealed class SecurityHeadersMiddleware(RequestDelegate next)
{
    private const string ContentSecurityPolicy =
        "default-src 'self'; " +
        "script-src 'self'; " +
        "style-src 'self' 'unsafe-inline'; " +
        "img-src 'self' data:; " +
        "font-src 'self'; " +
        "connect-src 'self' ws: wss:; " +
        "frame-ancestors 'none'; " +
        "base-uri 'self'; " +
        "form-action 'self'; " +
        "object-src 'none'";

    public Task InvokeAsync(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        // Set BEFORE the response starts streaming so they're not dropped.
        context.Response.OnStarting(static state =>
        {
            HttpContext ctx = (HttpContext)state;
            IHeaderDictionary h = ctx.Response.Headers;

            // Content-Security-Policy: defense-in-depth against XSS.
            h["Content-Security-Policy"] = ContentSecurityPolicy;

            // Block MIME sniffing — prevents the browser from interpreting
            // a served file as a different type than declared.
            h["X-Content-Type-Options"] = "nosniff";

            // Clickjacking protection for legacy browsers.
            h["X-Frame-Options"] = "DENY";

            // Don't leak the URL we came from to third-party origins.
            h["Referrer-Policy"] = "no-referrer";

            // Disable powerful APIs we never use.
            h["Permissions-Policy"] =
                "accelerometer=(), camera=(), geolocation=(), gyroscope=(), " +
                "magnetometer=(), microphone=(), payment=(), usb=()";

            // Isolate this origin's browsing context.
            h["Cross-Origin-Opener-Policy"] = "same-origin";

            // Help with cross-origin resource policy.
            h["Cross-Origin-Resource-Policy"] = "same-origin";

            return Task.CompletedTask;
        }, context);

        return next(context);
    }
}

/// <summary>Extension to register <see cref="SecurityHeadersMiddleware"/>.</summary>
public static class SecurityHeadersMiddlewareExtensions
{
    public static IApplicationBuilder UseSecurityHeaders(this IApplicationBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);
        return app.UseMiddleware<SecurityHeadersMiddleware>();
    }
}
