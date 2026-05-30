# Operations guide

For platform engineers and SREs running services that authenticate
users through `Argon2id.PasswordHasher`. Covers capacity planning,
parameter baselines by environment class, monitoring, alerting, and
the failure modes you'll actually see.

If you're integrating the library, start with the [`README`](README.md).
If you're migrating an existing store, see
[`MIGRATION.md`](MIGRATION.md). This document picks up after you're in
production.

## Capacity planning

Argon2id is intentionally resource-intensive — that's the point. The
two numbers that govern your capacity envelope are **memory per hash**
(set by `Argon2idOptions.MemorySizeKib`, default `65 536` = 64 MiB)
and **wall-clock time per hash** (a function of `MemorySizeKib`,
`Iterations`, `DegreeOfParallelism`, and your CPU).

### Memory envelope

For an instance serving concurrent logins:

```
worst-case RAM held for hashing  =  MemorySizeKib  ×  concurrent_in_flight_hashes
```

Worked example: a single 8-vCPU pod with the library defaults
(`64 MiB`), running at peak with 16 in-flight login operations:
**16 × 64 MiB = 1 024 MiB ≈ 1 GiB** of working set just for Argon2,
on top of whatever else the process is doing.

This is why the demo's
[`HashingGate`](samples/Argon2id.PasswordHasher.Demo/Services/HashingGate.cs)
caps concurrency at `Environment.ProcessorCount`. In production you
should pick a similar ceiling and queue (or shed) excess work past it.

### Time envelope

Wall-clock time per hash is approximately linear in `MemorySizeKib × Iterations`
on modern CPUs. Use the
[benchmarks](benchmarks/Argon2id.PasswordHasher.Benchmarks) to measure
on your actual fleet hardware rather than extrapolating from a laptop.

| Parameter set | Approx hash time on a 2024 server CPU |
| --- | --- |
| OWASP minimum (`m = 19 456 KiB`, `t = 2`) | ~30–60 ms |
| Library default (`m = 65 536 KiB`, `t = 3`) | ~150–250 ms |
| Conservative (`m = 131 072 KiB`, `t = 4`) | ~400–600 ms |

A common interactive-login budget is **100–500 ms** per hash. Anything
faster wastes security budget; anything slower visibly degrades the
sign-in experience.

## Parameter baselines by environment class

These are **starting points**, not targets. Always measure on your
actual hardware and tune for your latency budget.

| Environment | Memory | Iterations | Parallelism | Notes |
| --- | --- | --- | --- | --- |
| **Consumer SaaS, latency-sensitive** | 64 MiB | 3 | 1 | Library defaults. Good general-purpose baseline. |
| **Internal / B2B app, latency-tolerant** | 128 MiB | 4 | 1 | Higher security ceiling at the cost of ~2× latency. |
| **High-value enterprise (banking, healthcare)** | 256 MiB | 5 | 1 | Approaching RFC 9106's second profile. Pair with low-concurrency tier. |
| **Constrained / mobile-first BaaS** | 32 MiB | 4 | 1 | Half the default memory; compensate with iterations. Above OWASP minimum. |
| **CI / test only** | 8 MiB | 1 | 1 | DO NOT ship to production. This is what the test suite uses for speed. |

Keep `DegreeOfParallelism = 1` on shared servers. Multi-lane Argon2 is
designed for offline use cases where you control CPU exclusively;
under concurrent load it degrades total throughput.

## Monitoring

The library emits seven instruments under the meter name
`Argon2id.PasswordHasher` (exposed as
`Argon2idDiagnostics.MeterName`). Subscribe with OpenTelemetry,
Prometheus, or any other meter-aware backend:

```csharp
builder.Services.AddOpenTelemetry()
    .WithMetrics(m => m
        .AddMeter(Argon2idDiagnostics.MeterName)
        .AddPrometheusExporter());
```

| Instrument | Type | Why you watch it |
| --- | --- | --- |
| `argon2id.hash.count` | Counter | Registration / password-change volume |
| `argon2id.hash.duration` | Histogram (ms) | Per-hash latency; this is your tuning signal |
| `argon2id.verify.count` | Counter | Login attempt volume |
| `argon2id.verify.success.count` | Counter | Successful logins |
| `argon2id.verify.duration` | Histogram (ms) | Per-verify latency; should track `hash.duration` |
| `argon2id.rehash.needed.count` | Counter | Migration progress signal |
| `argon2id.parse.failure.count` | Counter | Data corruption / unexpected format leakage |

Two derived signals worth dashboarding:

- **Verify failure rate** = `1 - (verify.success.count / verify.count)`.
  Sustained above 5–10% suggests credential stuffing or a bug; spikes
  past 50% suggest enumeration probing.
- **Rehash share over time** = `rehash.needed.count / verify.success.count`.
  Right after a parameter or pepper rotation this should spike, then
  decay to roughly zero over your active-user window. Flat at zero
  means nobody's logging in (different problem); flat at high means
  you have lots of dormant users.

## Alerting

Suggested SRE rules, expressed in PromQL style:

```promql
# Hash latency p95 above 1s — your work factor is too high or
# something is starving CPU.
histogram_quantile(0.95,
  sum by (le) (rate(argon2id_hash_duration_bucket[5m]))) > 1000

# Sudden spike in verify failures — credential stuffing or a bug.
rate(argon2id_verify_count[5m]) - rate(argon2id_verify_success_count[5m])
  > 5 * rate(argon2id_verify_count[1h] offset 1d)

# Stored data corruption indicator — every legitimate hash should parse.
rate(argon2id_parse_failure_count[10m]) > 0

# Long-tail migration warning — months after a rotation, no movement.
rate(argon2id_rehash_needed_count[1h]) == 0
  and ARGON2ID_KNOWN_TO_HAVE_LEGACY_HASHES == 1
```

The exact thresholds depend on your traffic shape. Start permissive,
tighten after a week of baseline.

## Common failure modes

| Symptom | Likely cause | First check |
| --- | --- | --- |
| Hashes take 5–10× expected time | CPU contention (other tenants, k8s noisy-neighbour) | `nodepool.cpu.throttled` / `kubelet.container.cpu.throttled` |
| OOMKilled pods correlated with login spikes | Memory-cost DoS — too many concurrent hashes | Tighten the application-level concurrency gate; verify the rate limiter is in place |
| Sustained spike in `verify.failure` | Credential stuffing OR a misconfigured client | Application-layer rate limit + check WAF logs |
| `parse.failure.count` continuously non-zero | Stored hash field is being written by something other than this library, OR DB column is being truncated | Schema audit; check for `varchar(64)` when the PHC string needs ~100 chars |
| New users register but cannot log in | Pepper ring's `Active` was changed without re-deploying the registration path | The pepper id in the hash must be in the verifier's ring |
| Old users cannot log in after a deploy | A retired pepper was removed from the ring before all users were rehashed | Restore the retired pepper to the ring; let `NeedsRehash` migrate them on next login |

## Failure-mode signatures

In log analysis, distinguish:

- `PasswordVerificationResult.Failed` with `argon2id.verify.count++`
  and no `argon2id.parse.failure.count++` → **wrong password**. Normal.
- `PasswordVerificationResult.Failed` with `argon2id.parse.failure.count++`
  → **malformed stored hash**. Investigate the data layer.
- An exception thrown out of `Verify(...)` → **library bug**.
  This should never happen. File a security advisory.

## Scaling-out checklist

When you outgrow a single instance:

- [ ] The hasher is registered as a **singleton**. (It's stateless and
  thread-safe.)
- [ ] Concurrent hash work is bounded per instance (semaphore /
  `Channel<T>` / `HashingGate` pattern). Do not let one instance
  consume unbounded memory.
- [ ] Login traffic is rate-limited at the edge (per-IP and per-account)
  before it hits the hashing path. This protects against
  memory-cost DoS regardless of intra-process limits.
- [ ] Metrics from every instance are aggregated centrally with the
  hostname/pod label preserved, so a noisy-neighbour spike is
  attributable.
- [ ] Pepper key material is loaded at startup and held in memory; the
  pod is never expected to fetch it mid-request.
- [ ] Health checks do NOT hash a password. A liveness probe that
  hashes is a self-induced DoS amplifier under heavy load.

## Cost model

For ~100 ms per hash:

- 1 vCPU sustained → ~10 hashes/s
- 10 RPS of logins → 1 vCPU of pure hash work, plus ~0.6 GiB of working set

Scale linearly. A login-heavy service planning 1 000 RPS at sign-in
peak needs ~100 vCPU-equivalent and ~60 GiB of RAM available for
Argon2 alone. This is dramatic but expected; the alternative is fast
hashes which are also fast to brute-force.

## Where to ask

- Operational questions: GitHub Discussions.
- Security incidents: private channel in [`SECURITY.md`](SECURITY.md).
- Lifecycle / support questions: [`SUPPORT.md`](SUPPORT.md).

---

*To God be the glory — 1 Corinthians 10:31.*
