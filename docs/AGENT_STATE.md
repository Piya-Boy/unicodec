# AGENT_STATE.md

Loop memory for the UBC build. The agent reads and updates this every iteration so work
resumes across runs without re-deriving context. See [AGENTS.md](../AGENTS.md) for the loop.

**Legend:** `[ ]` todo · `[~]` in progress · `[x]` checker-confirmed done · `[!]` blocked

---

## Current phase: 0 — Specification

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

## Open issues / blockers
- (none)

## Next (ordered)
- [ ] Freeze format v1 — final human review of SPEC.md; no byte-layout changes after this
      without an RFC. Goal: spec reviewed, zero open format questions.
- [ ] git init + initial commit of spec/docs (branch, not main)

---

## Phase 1 — Reference implementations + vectors (queued)

### Next (ordered)
- [ ] Go SDK: header encode/decode + validation
      Goal: header round-trips; negative headers reject with exact error ids (SPEC.md §5).
      Maker: gpt-5.6-sol · Checker: gpt-5.5
- [ ] Go SDK: metadata TLV (ascending tag, no-dup, pass-through unknown)
      Goal: TLV round-trips; malformed/out-of-order/dup → ERR_META_MALFORMED.
      Maker: gpt-5.6-terra · Checker: gpt-5.5
- [ ] Go SDK: plain payload chunking + flat root hash
      Goal: byte-exact to plain vectors; ERR_ROOT_MISMATCH on flipped byte.
      Maker: gpt-5.6-sol · Checker: gpt-5.5
- [ ] Go SDK: AES-256-GCM per-chunk (nonce=base XOR i, AAD=header‖i, verify-before-release)
      Goal: byte-exact to fixed-nonce encrypted vectors; ERR_CHUNK_AUTH on tag flip;
      no plaintext emitted on failure (fail closed). CRYPTO-CRITICAL.
      Maker: gpt-5.6-sol · Checker: gpt-5.5 (checker MUST differ from maker)
- [ ] Go SDK: streaming Encoder/Decoder (io.Writer/io.Reader)
      Goal: streaming output byte-identical to one-shot; memory bounded by chunk size.
      Maker: gpt-5.6-terra · Checker: gpt-5.5
- [ ] Go SDK: DoS caps on untrusted length fields (SECURITY.md §5)
      Goal: oversized meta_len/clen/chunk_count rejected before allocation.
      Maker: gpt-5.6-sol · Checker: gpt-5.5
- [ ] Test vectors (Go canonical generator): plain + encrypted(fixed nonce) + edge + negatives
      Goal: vectors.json + inputs/ + expected/ complete per TESTING.md §2; committed as
      the shared contract.
      Maker: gpt-5.6-sol · Checker: gpt-5.5
- [ ] Node SDK: full implementation against vectors (BigInt for 64-bit fields)
      Goal: 100% vector pass byte-exact; chunk_count/total_size handled as BigInt.
      Maker: gpt-5.6-terra · Checker: gpt-5.5
- [ ] Cross-decode Go ↔ Node
      Goal: each decodes the other's containers; round-trip identity holds.
      Maker: gpt-5.6-terra · Checker: gpt-5.5

### Phase 1 exit gate
- All conformance vectors pass on Go and Node (byte-exact + negatives with exact ids).
- Cross-decode Go↔Node green. No bespoke expected values. DoS caps present. Stdlib crypto only.

---

## Phase 2+ (not yet queued)
See ROADMAP.md. Do not start until Phase 1 exit gate is green.
