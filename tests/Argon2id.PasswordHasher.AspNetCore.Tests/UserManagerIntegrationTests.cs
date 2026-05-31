using System.Security.Claims;
using Argon2id.PasswordHasher;
using Argon2id.PasswordHasher.AspNetCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Argon2id.PasswordHasher.AspNetCore.Tests;

/// <summary>
/// End-to-end integration tests that drive the real ASP.NET Core Identity
/// <see cref="UserManager{TUser}"/> through our hasher. This proves that the
/// full Identity contract works against <see cref="Argon2idPasswordHasher{TUser}"/>
/// &#8212; not just the <see cref="IPasswordHasher{TUser}"/> interface in
/// isolation, but the actual UserManager pipeline that real apps use.
/// </summary>
public class UserManagerIntegrationTests
{
    /// <summary>Minimal user shape; UserManager only cares about the Id + Name handling.</summary>
    public sealed class TestUser
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public string UserName { get; set; } = "";
        public string NormalizedUserName { get; set; } = "";
        public string? PasswordHash { get; set; }
        public string? SecurityStamp { get; set; }
        public int AccessFailedCount { get; set; }
        public bool LockoutEnabled { get; set; }
    }

    /// <summary>
    /// Smallest IUserStore + IUserPasswordStore implementation that satisfies
    /// UserManager's lookup needs. Stores are by Id only; UserManager handles
    /// password hashing through our injected <see cref="IPasswordHasher{TUser}"/>.
    /// </summary>
    private sealed class InMemoryUserStore : IUserStore<TestUser>, IUserPasswordStore<TestUser>
    {
        private readonly Dictionary<string, TestUser> _byId = new(StringComparer.Ordinal);
        private readonly Dictionary<string, TestUser> _byNormalizedName = new(StringComparer.Ordinal);

        public Task<IdentityResult> CreateAsync(TestUser user, CancellationToken _)
        {
            _byId[user.Id] = user;
            if (user.NormalizedUserName is { Length: > 0 })
            {
                _byNormalizedName[user.NormalizedUserName] = user;
            }
            return Task.FromResult(IdentityResult.Success);
        }

        public Task<IdentityResult> UpdateAsync(TestUser user, CancellationToken _)
        {
            _byId[user.Id] = user;
            return Task.FromResult(IdentityResult.Success);
        }

        public Task<IdentityResult> DeleteAsync(TestUser user, CancellationToken _)
        {
            _byId.Remove(user.Id);
            return Task.FromResult(IdentityResult.Success);
        }

        public Task<TestUser?> FindByIdAsync(string userId, CancellationToken _) =>
            Task.FromResult(_byId.GetValueOrDefault(userId));

        public Task<TestUser?> FindByNameAsync(string normalizedUserName, CancellationToken _) =>
            Task.FromResult(_byNormalizedName.GetValueOrDefault(normalizedUserName));

        public Task<string> GetUserIdAsync(TestUser user, CancellationToken _) => Task.FromResult(user.Id);
        public Task<string?> GetUserNameAsync(TestUser user, CancellationToken _) => Task.FromResult<string?>(user.UserName);
        public Task SetUserNameAsync(TestUser user, string? userName, CancellationToken _) { user.UserName = userName ?? ""; return Task.CompletedTask; }
        public Task<string?> GetNormalizedUserNameAsync(TestUser user, CancellationToken _) => Task.FromResult<string?>(user.NormalizedUserName);
        public Task SetNormalizedUserNameAsync(TestUser user, string? normalizedName, CancellationToken _) { user.NormalizedUserName = normalizedName ?? ""; return Task.CompletedTask; }

        public Task SetPasswordHashAsync(TestUser user, string? passwordHash, CancellationToken _) { user.PasswordHash = passwordHash; return Task.CompletedTask; }
        public Task<string?> GetPasswordHashAsync(TestUser user, CancellationToken _) => Task.FromResult(user.PasswordHash);
        public Task<bool> HasPasswordAsync(TestUser user, CancellationToken _) => Task.FromResult(user.PasswordHash is { Length: > 0 });

        public void Dispose() { }
    }

    private static (ServiceProvider sp, UserManager<TestUser> userManager) BuildHost(
        Action<Argon2idOptions>? configureOptions = null)
    {
        var services = new ServiceCollection();
        services.AddSingleton<IUserStore<TestUser>, InMemoryUserStore>();
        services.AddLogging();
        services.AddSingleton<IPasswordValidator<TestUser>>(new PasswordValidator<TestUser>());

        IdentityBuilder builder = services.AddIdentityCore<TestUser>(opts =>
        {
            // Make the integration tests run fast — turn off the bits that
            // would require additional store interfaces we haven't implemented.
            opts.User.RequireUniqueEmail = false;
            opts.Password.RequireDigit = false;
            opts.Password.RequireLowercase = false;
            opts.Password.RequireUppercase = false;
            opts.Password.RequireNonAlphanumeric = false;
            opts.Password.RequiredLength = 1;
        });

        if (configureOptions is null)
        {
            builder.AddArgon2idPasswordHasher<TestUser>(opts =>
            {
                // CI-test parameters; never use in production.
                opts.MemorySizeKib = 8192;
                opts.Iterations = 1;
                opts.DegreeOfParallelism = 1;
            });
        }
        else
        {
            builder.AddArgon2idPasswordHasher<TestUser>(configureOptions);
        }

        ServiceProvider sp = services.BuildServiceProvider();
        return (sp, sp.GetRequiredService<UserManager<TestUser>>());
    }

    [Fact]
    public async Task UserManager_CreateAsync_StoresArgon2idHash()
    {
        (ServiceProvider sp, UserManager<TestUser> users) = BuildHost();
        using (sp)
        {
            var user = new TestUser { UserName = "alice", NormalizedUserName = "ALICE" };

            IdentityResult result = await users.CreateAsync(user, "alice-password");

            Assert.True(result.Succeeded, string.Join(", ", result.Errors.Select(e => e.Description)));
            Assert.NotNull(user.PasswordHash);
            Assert.True(Argon2idPasswordHasher.IsArgon2idHash(user.PasswordHash));
        }
    }

    [Fact]
    public async Task UserManager_CheckPasswordAsync_AcceptsCorrectPassword()
    {
        (ServiceProvider sp, UserManager<TestUser> users) = BuildHost();
        using (sp)
        {
            var user = new TestUser { UserName = "bob", NormalizedUserName = "BOB" };
            await users.CreateAsync(user, "bob-pw");

            bool ok = await users.CheckPasswordAsync(user, "bob-pw");

            Assert.True(ok);
        }
    }

    [Fact]
    public async Task UserManager_CheckPasswordAsync_RejectsWrongPassword()
    {
        (ServiceProvider sp, UserManager<TestUser> users) = BuildHost();
        using (sp)
        {
            var user = new TestUser { UserName = "carol", NormalizedUserName = "CAROL" };
            await users.CreateAsync(user, "carol-pw");

            bool ok = await users.CheckPasswordAsync(user, "wrong");

            Assert.False(ok);
        }
    }

    [Fact]
    public async Task UserManager_FindByNameAsync_RoundTrip_WorksAcrossCreateAndVerify()
    {
        (ServiceProvider sp, UserManager<TestUser> users) = BuildHost();
        using (sp)
        {
            await users.CreateAsync(
                new TestUser { UserName = "dave", NormalizedUserName = "DAVE" },
                "dave-pw");

            TestUser? found = await users.FindByNameAsync("DAVE");
            Assert.NotNull(found);

            bool ok = await users.CheckPasswordAsync(found!, "dave-pw");
            Assert.True(ok);
        }
    }

    [Fact]
    public async Task UserManager_RehashOnLogin_UpgradesWeakerStoredHash()
    {
        // 1. Create a user with weak (test-only) parameters; capture the hash.
        (ServiceProvider weakSp, UserManager<TestUser> weakUsers) = BuildHost(opts =>
        {
            opts.MemorySizeKib = 8192;
            opts.Iterations = 1;
            opts.DegreeOfParallelism = 1;
        });
        string weakHash;
        TestUser user;
        using (weakSp)
        {
            user = new TestUser { UserName = "eve", NormalizedUserName = "EVE" };
            await weakUsers.CreateAsync(user, "eve-pw");
            weakHash = user.PasswordHash!;
            Assert.True(Argon2idPasswordHasher.IsArgon2idHash(weakHash));
        }

        // 2. Spin up a stronger host. Simulate the user existing in this
        //    host's store by re-creating with the same id + the weak hash
        //    we captured.
        (ServiceProvider strongSp, UserManager<TestUser> strongUsers) = BuildHost(opts =>
        {
            opts.MemorySizeKib = 16384;  // stronger
            opts.Iterations = 2;
        });
        using (strongSp)
        {
            var movedUser = new TestUser
            {
                Id = user.Id,
                UserName = "eve",
                NormalizedUserName = "EVE",
                PasswordHash = weakHash,
            };
            var store = strongSp.GetRequiredService<IUserStore<TestUser>>();
            await store.CreateAsync(movedUser, CancellationToken.None);

            // 3. CheckPasswordAsync exercises the SuccessRehashNeeded path
            //    internally and rewrites the stored hash via UpdateAsync.
            bool ok = await strongUsers.CheckPasswordAsync(movedUser, "eve-pw");
            Assert.True(ok);

            // 4. The stored hash should now be the stronger one
            //    (m=16384,t=2), not the original (m=8192,t=1).
            Assert.Contains("m=16384,t=2", movedUser.PasswordHash!, StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task UserManager_WithMigrationAdapter_AcceptsLegacyPbkdf2AndUpgrades()
    {
        // Simulates the real migration scenario: existing user store has
        // PBKDF2 hashes produced by the stock Identity hasher. After we
        // switch to the migrating adapter, a successful login should
        // transparently rewrite the hash as Argon2id.
        var services = new ServiceCollection();
        services.AddSingleton<IUserStore<TestUser>, InMemoryUserStore>();
        services.AddLogging();
        services.AddSingleton<IPasswordValidator<TestUser>>(new PasswordValidator<TestUser>());

        services.AddIdentityCore<TestUser>(opts =>
        {
            opts.User.RequireUniqueEmail = false;
            opts.Password.RequireDigit = false;
            opts.Password.RequireLowercase = false;
            opts.Password.RequireUppercase = false;
            opts.Password.RequireNonAlphanumeric = false;
            opts.Password.RequiredLength = 1;
        })
        .AddArgon2idPasswordHasherWithMigration<TestUser>(opts =>
        {
            opts.MemorySizeKib = 8192;
            opts.Iterations = 1;
            opts.DegreeOfParallelism = 1;
        });

        using ServiceProvider sp = services.BuildServiceProvider();
        var users = sp.GetRequiredService<UserManager<TestUser>>();

        // Manually pre-load a legacy PBKDF2 hash into the store (as if it
        // had been written there by a previous version of the app).
        string legacyHash = new PasswordHasher<TestUser>().HashPassword(new TestUser(), "legacy-pw");
        Assert.False(Argon2idPasswordHasher.IsArgon2idHash(legacyHash));

        var user = new TestUser
        {
            UserName = "frank",
            NormalizedUserName = "FRANK",
            PasswordHash = legacyHash,
        };
        await sp.GetRequiredService<IUserStore<TestUser>>().CreateAsync(user, CancellationToken.None);

        // Verify through the full UserManager pipeline. Because the
        // migrating adapter returns SuccessRehashNeeded for legacy hashes,
        // UserManager rewrites the stored value with a fresh Argon2id one.
        bool ok = await users.CheckPasswordAsync(user, "legacy-pw");
        Assert.True(ok);
        Assert.True(Argon2idPasswordHasher.IsArgon2idHash(user.PasswordHash!),
            "Stored hash was not upgraded to Argon2id after a successful login through UserManager.");
    }
}
