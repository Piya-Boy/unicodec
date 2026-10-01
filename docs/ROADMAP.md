# UBC Roadmap

Phased delivery. The ordering exists to prove cross-language determinism cheaply before
scaling to many SDKs — porting is only safe once the format is frozen and vectors exist.

This file is the **single source of work**. Agents read it (via prompt.md), do the first
unchecked task under "Active work", and update its checkbox + status here. Legend:
`[ ]` todo · `[~]` in progress · `[x]` done (checker-confirmed).

---

## Active work (do these first, top to bottom)

**Phase 3 — Java SDK.** Port the frozen format to `sdk/java/` (a Maven module `dev.ubc:ubc`,
built via the vendored Maven Wrapper — `./mvnw` / `mvnw.cmd`, no system Maven install
required). The Go SDK, Python SDK, Rust SDK, and shared vectors in spec/vectors are the
contract — the port must match byte-for-byte and cross-decode with Go/Node/Python/Rust.
Crypto from the JDK's own `javax.crypto`/`java.security` (JCA/JCE: `MessageDigest`,
`Mac`, `Cipher` with `AES/GCM/NoPadding`) — stdlib only, zero third-party runtime
dependencies, matching every other SDK. No format change. `chunk_count`/`total_size` are
true uint64: store as Java `long` and treat every bit pattern (including a set sign bit)
as valid — never reject on `< 0`, never compare with signed `<`/`>` near 2^63 without
`Long.compareUnsigned`. Idiomatic Java: unchecked `UbcException` carrying a stable
`ErrorCode` enum (mirrors Go's sentinel-error / Python's exception ergonomics — no
`throws` clutter on every call); no `Unsafe`; defensive copies on any mutable array
field. Keep the public API equivalent to the other SDKs: encode/decode (one-shot),
streaming encoder/decoder (`InputStream`/`OutputStream`), verify, inspect.

- [x] Java scaffold: `sdk/java/` Maven module (`dev.ubc:ubc`) with vendored `mvnw`/
      `mvnw.cmd` wrapper (Apache Maven Wrapper 3.3.2, `only-script` distribution, no
      system Maven install, no jar — bootstraps real Maven 3.9.9 on first run), `ErrorCode`
      enum mapping every stable error id (SPEC.md §5), `UbcException`, header + TLV
      encode/parse. Goal: header/TLV round-trip; matches the header/metadata bytes in the
      shared vectors.
      (solo maker+checker+human-gate 2026-10-01 — no second Codex model available this
      session, so TEST/CHECK/SECURITY all run by Claude against SPEC.md directly, same
      rigor as the Rust human gate. 6/6 JUnit tests pass: all positive vectors' headers
      round-trip byte-exact, plain-metadata TLV round-trips byte-exact, 9 header/metadata
      negative vectors return their exact stable error ids, metadata encoder sorts tags
      and rejects duplicates, metadata length cap is checked before copying entries.
      `mvnw test` clean, `-Xlint:all -Werror` clean. SECURITY (codex review --uncommitted):
      found and fixed two real issues — (1) mvnw.cmd had USE_MVND/default branches for
      MVNW_REPOURL mirror-path rewriting swapped (vendored file bug, only triggers under
      an enterprise Maven mirror override, fixed to match the correct mvnw/bash version);
      (2) Header's base_nonce byte array was stored and exposed by reference, letting a
      caller mutate a validated header after construction and break the
      plain-mode-nonce-must-be-zero invariant — fixed with defensive copies in the
      constructor and a cloning accessor, field made private. Retested clean after fixes.
      No crypto/format code yet — JCA wiring starts next task (plain path).)
      Maker/Checker/Human gate: Claude
- [x] Java plain path: chunking + SHA-256 flat root; one-shot encode/decode.
      Goal: byte-exact to every plain vector; ERR_ROOT_MISMATCH on a flipped byte.
      (solo maker+checker+human-gate 2026-10-01. `Payload.encodePlain`/`decodePlain` added
      using `java.security.MessageDigest` (JCA SHA-256), stdlib only. 10/10 JUnit tests pass:
      all 6 plain vectors (empty, one-byte, chunk-1m, chunk-1m-plus-one, multi-3m, metadata)
      encode byte-exact and decode back to their exact input bytes; a flipped payload byte
      returns ERR_ROOT_MISMATCH; negative-truncated/root-mismatch/trailing-data/oversized-clen
      vectors return their exact stable error ids. `mvnw test` clean. CHECK: reader precedence
      (header → metadata → missing-key → payload framing/truncated-footer → root mismatch →
      trailing-data) matches SPEC.md §5 exactly. SECURITY: hostile self-review (codex CLI
      review hit a `--uncommitted`+prompt argument conflict in the installed version and the
      no-prompt retry produced no verdict after rerunning `mvnw test` itself — treated as
      inconclusive, not a pass, so Claude did a full manual pass instead) — confirmed DoS
      caps (`maxChunkLen`/`maxChunkCount`/`maxTotalSize`) are checked before any chunk bytes
      are copied or hashed, `chunk_count`/`total_size` true-uint64 comparisons use
      `Long.compareUnsigned` throughout (not signed `<`/`>`, which would mishandle a legal
      value with the sign bit set), and the plain-mode chunking loop uses `long` stride/offset
      arithmetic so a chunk_size above `Integer.MAX_VALUE` (legal for plain mode up to uint32
      max) can't wrap a negative `int` stride. No format or crypto algorithm change.)
      Maker/Checker/Human gate: Claude

---

## Completed: Phase 3 — Rust SDK

Port the frozen format to `sdk/rust/` (a Cargo crate `ubc`). The Go SDK, Python SDK, and
shared vectors in spec/vectors are the contract — the port matches byte-for-byte and
cross-decodes with Go/Node/Python. Crypto from well-vetted crates: `sha2`, `hmac`, `hkdf`,
and `aes-gcm` (RustCrypto) — no custom crypto. `u64` for chunk_count/total_size,
little-endian throughout. `Result<_, UbcError>` with an error enum mapping every stable
error id; no `unwrap` on untrusted input; `#![forbid(unsafe_code)]`.

- [x] Rust scaffold: `sdk/rust/` cargo crate, `UbcError` enum mapping every stable error id
      (SPEC.md §5), header + TLV encode/parse. Goal: header/TLV round-trip; matches the
      header/metadata bytes in the shared vectors. `#![forbid(unsafe_code)]`.
      (toolchain installed; cargo build + 6 tests pass, header/metadata vectors byte-exact,
      negative vectors use stable error ids. human-verified 2026-08-09)
      Maker: gpt-5.6-terra · Checker: gpt-5.6-sol
- [x] Rust plain path: chunking + SHA-256 flat root; one-shot encode/decode.
      Goal: byte-exact to every plain vector; ERR_ROOT_MISMATCH on a flipped byte.
      (human-verified byte-exact vs all plain vectors; 9 tests pass; flipped→ROOT_MISMATCH;
      clippy -D warnings and fmt --check clean. 2026-08-10)
      Maker: gpt-5.6-sol · Checker: gpt-5.6-sol (fresh context)
- [x] Rust encrypted path: AES-256-GCM per-chunk, nonce = base XOR i, AAD = header ‖
      sha256(meta) ‖ i, HMAC-SHA-256 root (HKDF-derived), verify-before-release.
      Goal: byte-exact to fixed-nonce encrypted vectors; ERR_CHUNK_AUTH on tag flip; no
      plaintext on failure. CRYPTO-CRITICAL — checker MUST differ from maker.
      (checker-confirmed 2026-08-10: all fixed-nonce encrypted vectors byte-exact; encrypted
      negatives return stable error ids; fail-closed decode, missing-key precedence, and
      configurable caps verified; 14 Rust tests, clippy -D warnings, fmt --check, Go
      test/vet/race, and security review pass.)
      Maker: gpt-5.6-sol · Checker: gpt-5.6-terra
- [x] Rust streaming encoder/decoder (Read/Write) + verify + inspect; DoS caps on
      untrusted lengths. Goal: streaming output identical to one-shot; fail-closed; caps
      enforced before allocation. Constant-time compare for the encrypted root.
      (checker 2026-08-10: TEST gate passes — cargo test --all-targets (20), fmt, all-target
      clippy, and Go test/vet/race. SECURITY gate failed: Encoder::finish allocates a full
      chunk_size buffer even for empty/small input, so a valid large chunk_size can OOM/abort.
      Bound allocation by actual remaining input or enforce an encoder limit, add regression
      coverage, then rerun fresh CHECK/SECURITY. No commit/push. Maker 2026-08-10 bounded
      the encoder buffer to min(total_size, chunk_size), added u32::MAX chunk-size regression
      coverage, and reran TEST: cargo test --all-targets (21), fmt, all-target clippy, and Go
      test/vet/race pass. Fresh checker 2026-08-10 confirmed TEST remains green but
      CHECK/SECURITY failed: the final encrypted chunk is authenticated before a missing
      footer is classified, violating ERR_TRUNCATED-before-ERR_CHUNK_AUTH precedence; and a
      successful Encoder::finish retains its plaintext TempSpool until drop. Preflight the
      final footer before authenticating the last chunk, remove the encoder spool immediately
      after successful finalization, add regression coverage for both, then rerun fresh
      TEST/CHECK/SECURITY. No commit/push. Maker 2026-08-10 preflighted and retained the
      complete final footer before last-chunk authentication, and purges/removes the plaintext
      spool immediately after successful finish; regressions cover ERR_TRUNCATED precedence
      over a corrupted final tag and post-finish spool removal. Gates green: cargo test
      --all-targets (23), cargo clippy --all-targets -- -D warnings, cargo fmt --check,
      canonical Go vector check + go test ./..., and Python tests (22); Rust byte-exact
      round-trip and Go/Python shared-vector cross-decode remain green. Human gate 2026-08-10:
      Claude reran cargo test --all-targets (23), clippy -D warnings, fmt --check — all clean;
      verified footer-preflight precedence, post-finish spool purge, byte-exact streaming
      output vs shared vectors, and fail-closed decode. lib.rs re-exports the streaming API;
      crypto.rs only widened internals to pub(crate) — no format or crypto change.)
      Maker: gpt-5.6-terra · Checker: gpt-5.6-sol · Human gate: Claude
- [x] Rust conformance + cross-decode: run all shared vectors (positive byte-exact,
      negative with exact error ids); decode Go/Node/Python containers and vice versa.
      Goal: 100% vector pass; cross-decode Go↔Node↔Python↔Rust green. `cargo test`,
      `cargo clippy -- -D warnings`, `cargo fmt --check` clean.
      (maker + independent checker 2026-08-10: manifest-driven Rust conformance covers all
      12 positive vectors byte-exact on encode and clean on decode, all 25 negatives return
      their exact stable error ids, and every checked-in artifact matches its manifest SHA-256.
      Fresh Go/Node/Python/Rust containers cross-decode in every direction for all 12 positive
      vectors. Gates green: cargo test --all-targets (25), cargo clippy --all-targets --
      -D warnings, cargo fmt --check, Go vector check/test/vet, Node tests (55), Python tests
      (22), independent CHECK `No issues`, and security review found no blocking issues.
      Human gate 2026-10-01: Claude reran cargo test --all-targets (25 passed), cargo clippy
      --all-targets -- -D warnings (clean), cargo fmt --check (clean), node
      scripts/cross-decode.mjs (all 12 positive vectors, Go/Node/Python/Rust 4-way
      cross-decode passed), go build/vet/test ./... (all green). No format or crypto change.)
      Maker: gpt-5.6-sol · Checker: gpt-5.6-terra · Human gate: Claude

Phase 3 (Rust) exit gate: MET 2026-10-01 — sdk/rust passes 100% of shared vectors byte-exact,
rejects negatives with exact error ids, cross-decodes with Go/Node/Python, RustCrypto crates
only, no unsafe, clippy/fmt clean, public API equivalent to the other SDKs.

---

## Phase 0 — Specification (this repo, now)

- [x] PRD
- [x] SPEC.md (normative byte format)
- [x] ALGORITHM.md, SECURITY.md, API.md, SDK.md, STORAGE.md, TESTING.md, BENCHMARK.md, RFC.md, FAQ.md
- [ ] Freeze format v1 (no byte-layout changes after this without a version bump)

Exit criteria: spec reviewed, no open format questions, RFC process in place.

## Phase 1 — Reference implementations + vectors

- [x] Go SDK (canonical generator)
- [x] Test vectors generated by Go: plain, encrypted (fixed nonce), edge cases, negatives
- [x] Node.js SDK
- [x] Conformance: both SDKs pass all vectors byte-exact
- [x] Cross-decode: Go↔Node round-trip
- [x] Go/Node public-API parity — checker-confirmed 2026-08-08

Exit criteria: two SDKs produce byte-identical output, cross-decode, AND expose equivalent
public APIs. This is the proof that the format is language-agnostic.

## Phase 2 — CLI

- [x] `ubc encode | decode | verify | inspect` (built on the Go SDK, single binary) (checker-confirmed 2026-08-09)
- [x] CLI conformance against vectors (checker-confirmed 2026-08-09)

Exit criteria: CLI usable end-to-end; verified against vectors.

## Phase 3 — SDK expansion

Port from frozen spec + shared vectors (mechanical once Phase 1 holds):
- [x] Python
- [x] Rust
- [ ] Java
- [ ] .NET
- [ ] PHP

Each SDK gate: 100% vector pass + cross-decode with Go/Node. No SDK ships without it.

## Phase 4 — Framework wrappers

- [ ] React / Next.js / NestJS helpers over the Node SDK (upload, stream, verify helpers)

## Phase 5 — Post-v1 format features (each behind version bump or new algo id)

- [ ] Key management module (HKDF, Argon2id password keys, key wrapping)
- [ ] Digital signatures (publisher authenticity)
- [ ] Additional AEAD (ChaCha20-Poly1305) via `aead_algo`
- [ ] Compression plugin (pre-encryption), negotiated via a header field
- [ ] Optional full Merkle tree for partial verification
- [ ] Metadata encryption + length padding (privacy modes)

## Future SDKs

Swift, Kotlin, Dart, Ruby — same port process as Phase 3.

---

## Guiding rules

- The format is frozen at end of Phase 0. Changes go through the RFC process (RFC.md).
- No SDK is "done" until it passes the shared conformance suite.
- Vectors are the contract; SDKs never carry bespoke expected values.
