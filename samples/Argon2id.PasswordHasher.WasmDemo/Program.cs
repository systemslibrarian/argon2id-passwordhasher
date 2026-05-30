using Argon2id.PasswordHasher;
using Argon2id.PasswordHasher.WasmDemo;
using Argon2id.PasswordHasher.WasmDemo.Services;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;

WebAssemblyHostBuilder builder = WebAssemblyHostBuilder.CreateDefault(args);
builder.RootComponents.Add<App>("#app");
builder.RootComponents.Add<HeadOutlet>("head::after");

// Same library, same defaults as the Server demo. Hashing here happens on the
// user's CPU inside the browser's WebAssembly sandbox — no backend involved.
builder.Services.AddSingleton(new Argon2idPasswordHasher());

// In-memory user "database". Resets on page reload (no localStorage by design —
// the demo is intentionally a single-session showcase, not a real account store).
builder.Services.AddSingleton<InMemoryUserStore>();

await builder.Build().RunAsync();
