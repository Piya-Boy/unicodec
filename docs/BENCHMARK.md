# UBC Benchmarking

How UBC performance is measured and the targets to hold. Concrete numbers are filled in
once the reference SDKs exist (Phase 1); this document defines *what* and *how* to measure
so results are comparable across SDKs and over time.

---

## 1. What to measure

| Metric | Definition |
|--------|------------|
| Encode throughput | MiB/s of plaintext → container, plain and encrypted |
| Decode throughput | MiB/s of container → plaintext, plain and encrypted |
| Verify throughput | MiB/s for integrity-only (no plaintext release) |
| Peak memory | Max RSS above baseline during streaming a large file |
| Allocations/op | Heap allocations per operation (where the runtime exposes it) |
| Overhead ratio | container_size / input_size across chunk sizes |

Encrypted vs plain is always reported as a pair so the AEAD cost is visible.

---

## 2. How to measure

- **Inputs:** fixed corpus of sizes — 0, 1 KiB, 1 MiB, 16 MiB, 256 MiB, 1 GiB — plus a
  highly-compressible and an incompressible sample (compression is future, but keep the
  corpus stable for later comparison).
- **Chunk sizes:** sweep 64 KiB, 256 KiB, 1 MiB, 4 MiB to show the size/throughput/overhead
  tradeoff.
- **Streaming path only** for large inputs (measure the memory goal, not buffered-in-RAM).
- **Warm runs:** discard first run; report median + p95 of N runs.
- **Report environment:** CPU (note AES-NI presence), OS, language/runtime version.
- Each SDK uses its native bench harness (Go `testing.B`, Node `tinybench`/`node:perf`),
  but reports the same metric table for apples-to-apples comparison.

---

## 3. Targets (directional, refined after Phase 1)

These are goals to validate, not yet-measured facts:

- **Streaming memory:** bounded by O(chunk_size), not O(file_size). A 1 GiB file MUST NOT
  require ~1 GiB RSS. This is the primary, non-negotiable target.
- **Plain throughput:** dominated by SHA-256; target within a small constant factor of a
  raw SHA-256 pass over the data.
- **Encrypted throughput:** dominated by AES-256-GCM; on AES-NI hardware, target within a
  small constant factor of a raw AES-GCM pass.
- **Overhead:** per-chunk overhead = 4 bytes (`clen`) + 16 bytes (tag, encrypted) per
  chunk, plus fixed 40-byte header + 36-byte footer + metadata. At 1 MiB chunks this is
  well under 0.01% for plain and ~0.002% tag overhead — verify empirically.

Numbers (MiB/s, RSS) are recorded here per SDK once Phase 1 lands. **TBD until then** —
this is intentional, not an omission.

---

## 4. Cross-SDK comparison

Because output is byte-identical, benchmarks compare pure implementation efficiency, not
behavior. A large gap between SDKs on the same metric flags an implementation issue (extra
copies, non-streaming path, missing hardware crypto) to investigate.

---

## 5. Regression tracking

- Bench runs in CI on a fixed runner class; store results per commit.
- Flag >X% regression (threshold set after baselines exist) on any core metric.
