using Argon2id.PasswordHasher.Benchmarks;
using BenchmarkDotNet.Running;

// Run with:  dotnet run -c Release --project benchmarks/Argon2id.PasswordHasher.Benchmarks
BenchmarkSwitcher.FromAssembly(typeof(HashBenchmarks).Assembly).Run(args);
