using Argon2id.PasswordHasher;
using Argon2id.PasswordHasher.AspNetCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Argon2id.PasswordHasher.AspNetCore.Tests;

public class IdentityBuilderExtensionsTests
{
    // Local user type — Microsoft.AspNetCore.Identity.IdentityUser lives in
    // Microsoft.Extensions.Identity.Stores which is intentionally NOT referenced
    // here, and the adapter doesn't care about the user shape anyway.
    private sealed class TestUser
    {
        public string Id { get; set; } = "";
    }

    private sealed class OtherUser
    {
        public string Id { get; set; } = "";
    }

    [Fact]
    public void AddArgon2idPasswordHasher_OnBuilder_RegistersIPasswordHasher()
    {
        var services = new ServiceCollection();

        services.AddIdentityCore<TestUser>()
            .AddArgon2idPasswordHasher<TestUser>();

        using ServiceProvider sp = services.BuildServiceProvider();

        var resolved = sp.GetRequiredService<IPasswordHasher<TestUser>>();
        Assert.IsType<Argon2idPasswordHasher<TestUser>>(resolved);
    }

    [Fact]
    public void AddArgon2idPasswordHasher_OnBuilder_AppliesInlineOptions()
    {
        var services = new ServiceCollection();

        services.AddIdentityCore<TestUser>()
            .AddArgon2idPasswordHasher<TestUser>(opts =>
            {
                opts.MemorySizeKib = 16384;
                opts.Iterations = 2;
            });

        using ServiceProvider sp = services.BuildServiceProvider();

        Argon2idPasswordHasher hasher = sp.GetRequiredService<Argon2idPasswordHasher>();
        Assert.Equal(16384, hasher.Options.MemorySizeKib);
        Assert.Equal(2, hasher.Options.Iterations);
    }

    [Fact]
    public void AddArgon2idPasswordHasher_ReturnsTheSameBuilderForChaining()
    {
        var services = new ServiceCollection();

        IdentityBuilder builder = services.AddIdentityCore<TestUser>();
        IdentityBuilder returned = builder.AddArgon2idPasswordHasher<TestUser>();

        Assert.Same(builder, returned);
    }

    [Fact]
    public void AddArgon2idPasswordHasher_MismatchedUserType_Throws()
    {
        IdentityBuilder builder = new ServiceCollection().AddIdentityCore<TestUser>();

        var ex = Assert.Throws<InvalidOperationException>(
            () => builder.AddArgon2idPasswordHasher<OtherUser>());

        Assert.Contains("OtherUser", ex.Message, StringComparison.Ordinal);
        Assert.Contains("TestUser", ex.Message, StringComparison.Ordinal);
    }
}
