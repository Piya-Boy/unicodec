# AGENT_STATE.md

Loop memory for the UBC build. The agent reads and updates this every iteration so work
resumes across runs without re-deriving context. See [AGENTS.md](../AGENTS.md) for the loop.

**Legend:** `[ ]` todo · `[~]` in progress · `[x]` checker-confirmed done · `[!]` blocked

---

## Current phase: 1 — Reference implementations + vectors (technical gate complete)

## In progress
- (none)

## Done
- [x] PRD.md
- [x] spec/SPEC.md — normative byte format
- [x] docs/ALGORITHM.md
- [x] docs/SECURITY.md
- [x] docs/API.md
- [x] docs/SDK.md
- [x] docs/STORAGE.md
- [x] docs/ROADMAP.md
- [x] docs/TESTING.md
- [x] docs/BENCHMARK.md
- [x] docs/RFC.md
- [x] docs/FAQ.md
- [x] AGENTS.md — autonomous agent guide
- [x] Phase 1: Test vectors FIRST (Go canonical generator) — checker-confirmed 2026-08-07
- [x] Phase 1: Go SDK header encode/decode + validation — checker-confirmed 2026-08-07
- [x] Phase 1: Go SDK metadata TLV — checker-confirmed 2026-08-07
- [x] Phase 1: Go SDK plain payload chunking + flat root hash — checker-confirmed 2026-08-07
- [x] Phase 1: Go SDK AES-256-GCM per-chunk — checker-confirmed 2026-08-07
- [x] Phase 1: Go SDK streaming Encoder/Decoder — checker-confirmed 2026-08-07
- [x] Phase 1: Go SDK DoS caps on untrusted length fields — checker-confirmed 2026-08-07
- [x] Phase 1: Node SDK full conformance implementation — checker-confirmed 2026-08-08
- [x] Phase 1: Cross-decode Go ↔ Node — checker-confirmed 2026-08-08
- [x] RFC 0001 authenticated encrypted roots and canonical grammar — checker-confirmed 2026-08-08
- [x] Git repository initialized with initial spec/docs commit

## Open issues / blockers
- (none; RFC 0001 was accepted by the human on 2026-08-08 after the release audit.)

## Next (ordered)
- [x] Freeze v1 format after RFC 0001 acceptance and checker confirmation — 2026-08-08.
      No byte-layout changes after this point without an RFC.

---

## Phase 1 — Reference implementations + vectors (queued)

### Next (ordered)
- [x] Go SDK: header, metadata, plain payload, and AES-GCM — checker-confirmed 2026-08-07
- [x] Go SDK: streaming Encoder/Decoder (io.Writer/io.Reader) — checker-confirmed 2026-08-07
- [x] Go SDK: DoS caps on untrusted length fields — checker-confirmed 2026-08-07
- [x] Test vectors (Go canonical generator) — checker-confirmed 2026-08-07
- [x] Node SDK: full implementation against vectors (BigInt for 64-bit fields)
      Goal: 100% vector pass byte-exact; chunk_count/total_size handled as BigInt.
      Maker: gpt-5.6-terra · Checker: gpt-5.6-sol — confirmed 2026-08-08
- [x] Cross-decode Go ↔ Node
      Goal: each decodes the other's containers; round-trip identity holds.
      Maker: gpt-5.6-terra · Checker: gpt-5.6-sol — confirmed 2026-08-08

### Phase 1 exit gate
- All conformance vectors pass on Go and Node (byte-exact + negatives with exact ids).
- Cross-decode Go↔Node green. No bespoke expected values. DoS caps present. Stdlib crypto only.

---

## Phase 2+ (not yet queued)
See ROADMAP.md. Do not start until Phase 1 exit gate is green.
