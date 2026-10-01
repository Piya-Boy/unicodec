# UBC Roadmap

Phased delivery. The ordering exists to prove cross-language determinism cheaply before
scaling to many SDKs — porting is only safe once the format is frozen and vectors exist.

This file is the **single source of work**. Agents read it (via prompt.md), do the first
unchecked task under "Active work", and update its checkbox + status here. Legend:
`[ ]` todo · `[~]` in progress · `[x]` done (checker-confirmed).

---

## Active work (do these first, top to bottom)

**Future SDKs tier — Kotlin SDK.** Port the frozen format to `sdk/kotlin/` (package
`dev.ubc`, plain `kotlinc` CLI — no Gradle; see `sdk/kotlin/run-tests.ps1`). The Go SDK,
Python SDK, Rust SDK, Java SDK, .NET SDK, PHP SDK, Dart SDK, and shared vectors in
spec/vectors are the contract — the port must match byte-for-byte and cross-decode with
Go/Node/Python/Rust/Java/.NET/PHP/Dart. Neither Gradle nor kotlinc were present on this
machine; kotlinc was downloaded as a standalone release zip and extracted under the
session scratchpad (no system install, no elevation) after a `choco install kotlinc`
attempt failed on a lock-file conflict while not running elevated — confirmed with the
human to skip the system package manager rather than request elevation. Kotlin runs on
the JVM, so unlike Dart it has full interop access to `java.security`/`javax.crypto` —
genuinely stdlib-equivalent crypto via JVM interop, not a third-party package, matching the
Java SDK's approach exactly (`MessageDigest`, `Mac`, `Cipher` with `AES/GCM/NoPadding`). No
format change. `chunk_count`/`total_size` are true uint64: stored as Kotlin's `Long` (JVM
signed 64-bit, identical constraint to the Java port) — every bit pattern treated as valid,
no `Long.compareUnsigned`-free shortcuts assumed. Idiomatic Kotlin: `UbcException :
RuntimeException` with a `code: ErrorCode` property (no collision risk the way PHP's
`$code`/`\Exception::$code` or a hypothetical JVM `Throwable.code` would — `Throwable` has
no such property, confirmed before assuming it was safe) carrying a stable `ErrorCode` enum
with a `stableId` field. No test framework (no JUnit/Gradle) — a minimal hand-written
`TestRunner` object registers named test closures and reports pass/fail, confirmed as the
deliberate choice over setting up a second build-tool bootstrap this session. Keep the
public API equivalent to the other SDKs: encode/decode (one-shot), streaming encoder/
decoder, verify, inspect.

- [x] Kotlin scaffold: `sdk/kotlin/` package `dev.ubc`, `ErrorCode` enum with a `stableId`
      field mapping every stable error id (SPEC.md §5), `UbcException`, header + TLV
      encode/parse. Goal: header/TLV round-trip; matches the header/metadata bytes in the
      shared vectors.
      (solo maker+checker+human-gate 2026-10-02, continuing per "ต่อ" instruction. kotlinc
      wasn't on PATH; `choco install kotlinc -y` failed not-elevated with a lock-file
      conflict on its own bundled OpenJDK dependency (ignoring the JDK 17 already present
      from the Java SDK work) — surfaced this to the human rather than retrying elevated,
      and per explicit confirmation skipped choco entirely: downloaded the official
      `kotlin-compiler-2.1.0.zip` release directly from the JetBrains GitHub releases page
      and extracted it under the session scratchpad, no system install, no elevation.
      Confirmed with kotlinc -version that it correctly picks up the existing JDK 17 via
      JAVA_HOME. No Gradle either — confirmed explicitly with the human to use plain
      kotlinc CLI compilation instead of bootstrapping a second build-tool wrapper dance
      this session (already did one for Java's Maven Wrapper); wrote a minimal
      `TestRunner` object (register named closures, run them all, report pass/fail, exit
      non-zero on any failure) since no JUnit/Gradle test runner is available, plus
      `run-tests.ps1` wrapping the compile+run invocation. Applied the Java port's
      defensive-copy lesson for `Header.baseNonce` from the very first draft (constructor
      copies on the way in, `baseNonce()` accessor copies on the way out) instead of
      shipping the mutable-array bug and rediscovering it via security review. 19/19 tests
      pass (hand-written harness, not a framework test count): all positive vectors'
      headers round-trip byte-exact, plain-metadata TLV round-trips byte-exact, 9
      header/metadata negative vectors return their exact stable error ids, metadata
      encoder sorts tags and rejects duplicates, metadata length cap is checked before
      copying entries. `kotlinc` compiles with no warnings. CHECK: `UbcException`'s `code`
      property doesn't collide with anything on JVM `Throwable` (confirmed by checking —
      unlike PHP's `\Exception::$code`, Kotlin/Java's `Throwable` declares no such
      property, so no rename was needed the way PHP required `errorCode`). SECURITY
      (manual): DoS-relevant length checks in `Metadata.parse` happen before any entry
      value is copied out of the input buffer. No crypto/format code yet — JVM-interop
      crypto wiring (java.security/javax.crypto, same as the Java SDK) starts next task
      (plain path).)
      Maker/Checker/Human gate: Claude
- [x] Kotlin plain path: chunking + SHA-256 flat root; one-shot encode/decode.
      Goal: byte-exact to every plain vector; ERR_ROOT_MISMATCH on a flipped byte.
      (solo maker+checker+human-gate 2026-10-02. `Payload.encodePlain`/`decodePlain` added
      using `java.security.MessageDigest` (JCA SHA-256, JVM interop, stdlib-equivalent —
      same reasoning and same primitive as the Java SDK). Applied the Java port's
      chunk-size-above-Int.MAX_VALUE fix from the first draft: the chunking loop uses `Long`
      stride/offset arithmetic throughout (`var offset = 0L`, `offset += chunkSize`) and
      only narrows to `Int` for the per-slice `copyOfRange` call, which is always bounded by
      the real array length — never risked rediscovering the stride-wrapping bug the Java
      port needed a security review to catch. 26/26 tests pass (19 carried forward + 7
      new): all 6 plain vectors (empty, one-byte, chunk-1m, chunk-1m-plus-one, multi-3m,
      metadata) encode byte-exact and decode back to their exact input bytes; a flipped
      payload byte returns ERR_ROOT_MISMATCH; negative-truncated/root-mismatch/trailing-
      data/oversized-clen vectors return their exact stable error ids. `kotlinc` compiles
      clean. CHECK: reader precedence (header → metadata → missing-key → payload framing/
      truncated-footer → root mismatch → trailing-data) matches SPEC.md §5 exactly, same
      order as every other SDK. SECURITY (manual): DoS caps (`maxChunkLen`/`maxChunkCount`/
      `maxTotalSize`) checked before any chunk bytes are copied or hashed;
      `MessageDigest.isEqual` used for the root comparison (constant-time, the correct JCA
      primitive — not a hand-rolled compare, unlike the Dart port which had no such
      primitive available). No format or crypto algorithm change.)
      Maker/Checker/Human gate: Claude
- [x] Kotlin encrypted path: AES-256-GCM per-chunk, nonce = base XOR i, AAD = header ‖
      sha256(meta) ‖ i, HMAC-SHA-256 root (HKDF-derived), verify-before-release.
      Goal: byte-exact to fixed-nonce encrypted vectors; ERR_CHUNK_AUTH on tag flip; no
      plaintext on failure. CRYPTO-CRITICAL.
      (solo maker+checker+human-gate 2026-10-02. `Crypto.encodeEncrypted`/
      `encodeEncryptedWithFixedNonce`/`decodeEncrypted` added as a direct line-by-line port
      of the Java SDK's already-security-reviewed `CryptoInternal`/`Crypto`/
      `RootAccumulator` via JVM interop (`javax.crypto.Cipher`
      "AES/GCM/NoPadding", `javax.crypto.Mac` "HmacSHA256") — same stdlib primitives, same
      nonce/AAD/root-key derivation logic, no new crypto surface to independently re-derive
      or re-verify from scratch. 37/37 tests pass (26 carried forward + 11 new): all 6
      encrypted vectors encode byte-exact and decode back to exact input; the HKDF
      `root_key` derivation matches spec/vectors.json's standalone known-answer fixture
      independent of any container, confirming the ported logic reproduces the Java port's
      already-verified result rather than just being internally self-consistent;
      negative-chunk-auth/encrypted-short-clen/encrypted-metadata-tamper return
      ERR_CHUNK_AUTH; negative-missing-key/encrypted-cap-missing-key (decoded with no key)
      return ERR_MISSING_KEY; negative-encrypted-empty-wrong-key (decoded with the vector's
      own wrong key) returns ERR_ROOT_MISMATCH; a wrong key against a non-empty container
      also returns ERR_CHUNK_AUTH (GCM tag fails before the root is ever reached). `kotlinc`
      compiles clean. CHECK: nonce = base_nonce XOR le96(i) matches spec exactly; AAD =
      header_bytes ‖ SHA-256(meta_region) ‖ le64(i); PRK = HMAC-SHA-256(base_nonce, key),
      root_key = HMAC-SHA-256(PRK, "UBC1 root authentication" ‖ 0x01) — both directions
      derive the root key identically. SECURITY (manual): `Cipher.doFinal` in GCM mode is
      atomic (same guarantee already verified for the Java port — returns full plaintext
      only after the tag verifies, or throws with zero bytes released); `clen < 16` is
      rejected as ERR_CHUNK_AUTH before any decrypt attempt; reader precedence matches
      SPEC.md §5; root hash comparison uses `MessageDigest.isEqual` (constant-time);
      base_nonce for `encodeEncrypted` comes from `java.security.SecureRandom` (CSPRNG,
      never reused across containers); `Header.baseNonce()` already returns a defensive
      copy (scaffold task) so the per-chunk XOR nonce can't be corrupted by external
      mutation. No format change; crypto matches SPEC.md §3-4 exactly, no deviation from
      the Java port it was ported from.)
      Maker/Checker/Human gate: Claude
- [x] Kotlin streaming encoder/decoder (InputStream/OutputStream) + verify + inspect; DoS
      caps on untrusted lengths. Goal: streaming output identical to one-shot; fail-closed;
      caps enforced before allocation. Constant-time compare for the encrypted root.
      (solo maker+checker+human-gate 2026-10-02. `Encoder`/`Decoder` are direct ports of
      the Java SDK's already-security-reviewed streaming classes via JVM interop
      (`java.io.OutputStream`/`InputStream`), applying every fix that port's three security
      rounds found from the first draft instead of rediscovering any of them: (1) the
      encoder's chunk buffer is `min(totalSize, chunkSize)`, not `chunkSize`; (2) the
      decoder preflights the 36-byte footer before authenticating the final encrypted
      chunk, so ERR_TRUNCATED wins over ERR_CHUNK_AUTH per SPEC.md §5; (3) the encoder's
      plaintext spool file is created via `Files.createTempFile` with owner-only POSIX
      permissions where supported (falling back to the platform default on non-POSIX
      filesystems), `deleteOnExit()` registered as a safety net, and the spool deleted
      immediately after a successful finish in a try/finally. 45/45 tests pass (37 carried
      forward + 8 new): streamed plain output is byte-exact vs the one-shot plain-multi-3m
      vector even written in two unequal chunks, and decodes correctly through a
      deliberately pathological `InputStream` that only ever returns 1 byte per `read()`
      call; streamed encrypted output is byte-exact vs the one-shot encrypted-chunk-1m-
      plus-one vector; a corrupted footer and a trailing extra byte are both caught before
      the decoder yields -1 (root withheld until verified); the truncated+corrupted-final-
      tag scenario returns ERR_TRUNCATED, not ERR_CHUNK_AUTH; an encoder with a 256 MiB
      chunk_size against a 3-byte input round-trips without the over-allocation bug; a
      streaming decoder with max_chunk_len=4 against 1 MiB chunks throws ERR_TRUNCATED on
      the first read(); verify() reports ok=false with the correct error code on a
      corrupted container and inspect() reads only the header+metadata region, unaffected
      by a mangled footer. `kotlinc` compiles clean. CHECK: confirmed (same finding as the
      Java/.NET/PHP/Dart ports) that Go's canonical `sdk/go/decoder.go` releases plain-mode
      chunks incrementally per-read with no full-buffering spool, so Kotlin's `Decoder` was
      built unbuffered for both modes to match that cross-SDK convention from the start.
      SECURITY (manual): the encoder's plaintext spool permissions/deleteOnExit/purge-on-
      finish logic is byte-for-byte the already-reviewed Java approach; chunk-length DoS
      caps checked before any allocation in the decoder, matching the one-shot path's
      bound. No format or crypto algorithm change from the already-reviewed encrypted-path
      task.)
      Maker/Checker/Human gate: Claude
- [x] Kotlin conformance + cross-decode: run all shared vectors (positive byte-exact,
      negative with exact error ids); decode Go/Node/Python/Rust/Java/.NET/PHP/Dart
      containers and vice versa. Goal: 100% vector pass; cross-decode
      Go↔Node↔Python↔Rust↔Java↔.NET↔PHP↔Dart↔Kotlin green.
      (solo maker+checker+human-gate 2026-10-02. Added a manifest-driven `ConformanceTest`
      walking every vector in spec/vectors/vectors.json — all 12 positive, all 25 negative —
      backed by a `MiniJson` reader ported directly from the Java port's hand-rolled parser
      (Kotlin/JVM has no JSON in the bare JDK either, same reasoning as Java: test/tooling-
      only code, not worth a dependency). `Vector.decode()` auto-detects plain vs encrypted
      from the container's own header bytes, matching Go's single `DecodeBytes` dispatcher
      — applied from the start instead of rediscovering the key-less-negative-vector
      pitfall the Java port hit first. Added a `CrossDecode` CLI under `src/tools/kotlin/`
      (`--vectors --work --cases --write|--verify`, same contract as every other SDK's
      CLI), compiled alongside the test sources via a new `build-crossdecode.ps1` so it can
      reuse `VectorManifest`/`MiniJson` without duplicating them. Wired Kotlin in as the
      ninth cross-decode producer: `--kotlin` flag in tools/crossdecode/main.go, `"kotlin"`
      added to cross-decode-python.py's producer loop, and scripts/cross-decode.mjs now
      builds the CrossDecode jar and invokes it — hit the exact same `.bat`-can't-spawn-
      directly issue the Maven/.NET/Dart wrappers already hit in this same file
      (`kotlinc.bat` on Windows), fixed the same way: route through `cmd.exe /c`. Since
      there's no system kotlinc on this machine, `KOTLINC`/`JAVA_EXE` env vars must point
      at the scratchpad-extracted toolchain explicitly — documented as a real environment
      dependency of this script, not silently assumed to resolve via PATH the way the
      other eight producers do. `node scripts/cross-decode.mjs` passes for all 12 positive
      vectors, 9-way byte-identical across
      Go/Node/Python/Rust/Java/.NET/PHP/Dart/Kotlin. Gates green: hand-written `TestRunner`
      (46 tests: the new ConformanceTest plus every earlier suite), `kotlinc` compiles
      clean, `go build/vet/test ./...` clean, Python 22/22, Node 55/55. SECURITY (manual):
      the CLI's `safeChild` resolves to a canonical path and appends a separator before the
      containment check, same pattern as every other SDK's CLI; case IDs validated against
      the same `^[a-z0-9]+(-[a-z0-9]+)*$` pattern used everywhere else; the
      `kotlinc`/`cmd.exe`/`java` subprocesses are all invoked with argv arrays, never a
      shell-interpolated string. No format or crypto change — this task adds only
      test/tooling code.)
      Maker/Checker/Human gate: Claude

Future SDKs — Kotlin: MET 2026-10-02 — sdk/kotlin passes 100% of shared vectors
byte-exact, rejects negatives with exact error ids, cross-decodes with
Go/Node/Python/Rust/Java/.NET/PHP/Dart, JVM-interop crypto only (java.security/
javax.crypto, the same stdlib-equivalent primitives as the Java SDK — no third-party
runtime dependency, unlike Dart which needed one), public API equivalent to the other
SDKs (one-shot plain/encrypted, streaming encoder/decoder, verify, inspect).

---

## Completed: Future SDKs tier — Dart SDK

Port the frozen format to `sdk/dart/` (a pub package `ubc`, Dart >=3.0). Dart's core SDK
has zero built-in crypto — the human explicitly chose `package:crypto` (dart-lang-team-
maintained, SHA-256/HMAC) plus `package:cryptography` (community, pure Dart, AES-GCM) as
the project's first non-stdlib runtime dependency, confirming this proceed rather than
halt as a stop-and-ask new-dependency decision. `chunk_count`/`total_size` use Dart's
signed 64-bit `int` (VM target), matching the Java/PHP ports' tradeoff. `UbcException
implements Exception` with an `ErrorCode` enum carrying a `stableId` field. Encrypted path
is `Future`-based throughout — `package:cryptography`'s sync methods are internal-only.

- [x] Dart encrypted path: AES-256-GCM per-chunk, nonce = base XOR i, AAD = header ‖
      sha256(meta) ‖ i, HMAC-SHA-256 root (HKDF-derived), verify-before-release.
      Goal: byte-exact to fixed-nonce encrypted vectors; ERR_CHUNK_AUTH on tag flip; no
      plaintext on failure. CRYPTO-CRITICAL.
      (solo maker+checker+human-gate 2026-10-01. `Crypto.encodeEncrypted`/
      `encodeEncryptedWithFixedNonce`/`decodeEncrypted` added using `package:cryptography`'s
      `AesGcm` and `package:crypto`'s `Hmac`. Discovered mid-implementation that
      `encryptSync`/`decryptSync` exist only on the package's internal `DartAesGcm` class,
      not on the public `AesGcm` type returned by `AesGcm.with256bits()` — confirmed by
      reading the package source, not by trial and error against the compiler alone — so
      the one-shot and (later) streaming encrypted paths had to become `Future`-based
      throughout, a real divergence from every prior SDK's synchronous one-shot API, forced
      by the dependency rather than a Dart idiom choice. Before trusting fail-closed
      behavior, read `DartAesGcm.decryptSync`'s source directly and confirmed the MAC
      comparison (`if (calculatedMac != mac) throw SecretBoxAuthenticationError()`) happens
      before the XOR-decrypt loop that produces plaintext runs at all — verify-before-release
      holds by construction. Independently verified the `rootKey` HKDF derivation against
      spec/vectors.json's standalone known-answer fixture via a throwaway test file *before*
      writing Crypto.dart itself (not after), since `package:crypto`'s `Hmac(hash, key)`
      constructor's key-first argument order is an easy place to transpose silently;
      confirmed byte-exact on the first attempt once the order was worked out deliberately.
      37/37 `dart test` pass (26 carried forward + 11 new): all 6 encrypted vectors encode
      byte-exact and decode back to exact input; the HKDF root_key derivation matches the
      shared known-answer fixture independent of any container; negative-chunk-auth/
      encrypted-short-clen/encrypted-metadata-tamper return ERR_CHUNK_AUTH; negative-
      missing-key/encrypted-cap-missing-key (decoded with no key) return ERR_MISSING_KEY;
      negative-encrypted-empty-wrong-key (decoded with the vector's own wrong key) returns
      ERR_ROOT_MISMATCH; a wrong key against a non-empty container also returns
      ERR_CHUNK_AUTH. `dart analyze` clean. CHECK: nonce = base_nonce XOR le96(i), AAD =
      header_bytes ‖ SHA-256(meta_region) ‖ le64(i) match spec exactly; both directions
      derive the root key identically. SECURITY (manual): `Random.secure()` (Dart's CSPRNG,
      not plain `Random()`) generates `encodeEncrypted`'s base_nonce, never reused across
      containers; root comparison reuses the same hand-rolled constant-time XOR-accumulate
      compare from the plain path (still the one real primitive gap vs. every prior SDK's
      platform constant-time-compare function); `clen < CryptoInternal.gcmTagSize` rejected
      as ERR_CHUNK_AUTH before any decrypt attempt; reader precedence matches SPEC.md §5.
      No format change; crypto matches SPEC.md §3-4 exactly. One residual, explicitly
      accepted risk carried from the human's package choice: `package:cryptography`'s
      AES-GCM is a pure-Dart reimplementation of the algorithm, not a binding to a
      hardware-accelerated/widely-audited native library the way OpenSSL/BoringSSL/JCA
      back every other SDK's AEAD — correctness here rests on this one community package's
      own implementation and test suite, not an independent cryptographic library with a
      much larger audit history.)
      Maker/Checker/Human gate: Claude
- [x] Dart streaming encoder/decoder (request-based pull async API) + verify + inspect;
      DoS caps on untrusted lengths. Goal: streaming output identical to one-shot;
      fail-closed; caps enforced before allocation. Constant-time compare for the
      encrypted root.
      (solo maker+checker+human-gate 2026-10-01. Confirmed via explicit choice (not
      assumed) that the streaming API should be pull-based async `read(length)`/
      `write(bytes)` methods — same conceptual shape as every other SDK's streaming API —
      rather than a native `Stream<List<int>>`/`StreamTransformer` pipeline, to stay
      parallel to the other 7 ports despite Dart's crypto-forced async. `Decoder`'s
      constructor cannot itself be async (Dart constructors never are), so unlike every
      other SDK — where header/metadata errors throw synchronously from the constructor —
      Dart needed an explicit `Decoder.open()` async factory that eagerly parses the header
      before returning, so callers still get the "bad header fails immediately" behavior
      the other SDKs give for free; documented why this extra factory exists rather than
      silently diverging. Applied the same three Rust-derived fixes from the start (re-read
      that task's full security history in this file before writing any code): (1) the
      encoder's chunk buffer is `min(totalSize, chunkSize)`, not `chunkSize`; (2) the
      decoder preflights the 36-byte footer before authenticating the final encrypted
      chunk, so ERR_TRUNCATED wins over ERR_CHUNK_AUTH per SPEC.md §5; (3) the encoder's
      spool file is deleted in a try/finally inside `finish()`. Verified experimentally
      (not assumed) that `RandomAccessFile.readInto(buffer, start, end)`'s `start`/`end`
      are buffer offsets (not a length), since misreading that signature would have
      silently corrupted chunk reads — confirmed with a throwaway script before trusting
      the loop logic already written. Documented explicitly (Dart has neither
      `deleteOnExit()` nor a finalizer mechanism) that an Encoder whose `finish()` is never
      called leaks its spool file — unlike Java/.NET which have a safety net for this and
      PHP where the runtime provides one natively, Dart genuinely has no fallback here; this
      is a real, accepted gap, not an oversight. 45/45 `dart test` pass (37 carried forward
      + 8 new): streamed plain output is byte-exact vs the one-shot plain-multi-3m vector
      even written in two unequal chunks, and decodes correctly through a decoder source
      that only ever returns 1 byte per call regardless of requested length; streamed
      encrypted output is byte-exact vs the one-shot encrypted-chunk-1m-plus-one vector; a
      corrupted footer and a trailing extra byte are both caught before the decoder returns
      empty (root withheld until verified); the truncated+corrupted-final-tag scenario
      returns ERR_TRUNCATED, not ERR_CHUNK_AUTH; an encoder with a 256 MiB chunk_size
      against a 3-byte input round-trips without over-allocating; a streaming decoder with
      max_chunk_len=4 against 1 MiB chunks throws ERR_TRUNCATED on the first read(); verify()
      reports ok=false with the correct error code on a corrupted container and inspect()
      reads only the header+metadata region, unaffected by a mangled footer. `dart analyze`
      clean (one lint fixed: an unused-after-assignment loop variable in `verify()`,
      restructured to avoid declaring it at all). CHECK: confirmed (same finding as the
      Java/.NET ports) that Go's canonical `sdk/go/decoder.go` releases plain-mode chunks
      incrementally per-read with no full-buffering spool, so Dart's `Decoder` was built
      unbuffered for both modes to match that cross-SDK convention. SECURITY (manual):
      chunk-length DoS caps checked before any `_readExact` allocation in the decoder,
      matching the one-shot path's bound; root comparison reuses the hand-rolled
      constant-time compare. No format or crypto algorithm change from the already-reviewed
      encrypted-path task.)
      Maker/Checker/Human gate: Claude
- [x] Dart conformance + cross-decode: run all shared vectors (positive byte-exact,
      negative with exact error ids); decode Go/Node/Python/Rust/Java/.NET/PHP containers
      and vice versa. Goal: 100% vector pass; cross-decode
      Go↔Node↔Python↔Rust↔Java↔.NET↔PHP↔Dart green.
      (solo maker+checker+human-gate 2026-10-01. Added a manifest-driven `conformance_test`
      walking every vector in spec/vectors/vectors.json — all 12 positive, all 25 negative —
      backed by a `VectorManifest` helper in test/support/ using `dart:convert`'s built-in
      `json.decode` (core, no package needed — same reasoning as the PHP port's
      `json_decode`, unlike the Rust/Java/.NET ports which hand-rolled JSON readers because
      their languages' stdlib genuinely has none). `Vector.decode()` auto-detects plain vs
      encrypted from the container's own header bytes, matching Go's single `DecodeBytes`
      dispatcher — applied this design from the start instead of rediscovering the key-less-
      negative-vector pitfall the Java port hit first. Added `bin/cross_decode.dart`
      (`--vectors --work --cases --write|--verify`, same contract as the other CLIs),
      importing the test support file by relative path across the `bin`/`test` directory
      boundary — Dart has no project-reference mechanism, so this is the same category of
      workaround as Rust's `#[path]` include, .NET's linked `<Compile Include>`, and PHP's
      direct `require`. Wired Dart in as the eighth cross-decode producer: `--dart` flag in
      tools/crossdecode/main.go, `"dart"` added to cross-decode-python.py's producer loop,
      and scripts/cross-decode.mjs now runs the Dart CLI — hit the same class of issue the
      Java/.NET wrappers hit earlier in this same file (`spawn dart ENOENT`): on this
      Windows machine `dart` resolves to `dart.bat` alongside an extensionless `dart`
      wrapper, and Node's `execFile` cannot spawn a `.bat` directly, so `execDartCrossDecode`
      routes through `cmd.exe /c` on Windows like the Maven/.NET wrappers already do.
      `node scripts/cross-decode.mjs` passes for all 12 positive vectors, 8-way
      byte-identical across Go/Node/Python/Rust/Java/.NET/PHP/Dart. Gates green: `dart test`
      (46 tests: the new conformance test plus every earlier suite), `dart analyze` clean,
      `go build/vet/test ./...` clean, Python 22/22, Node 55/55. SECURITY (manual): the
      CLI's `safeChild` normalizes the candidate path and appends a trailing separator to
      the root before the `startsWith` containment check (same reasoning as every other
      SDK's CLI — a raw string-prefix check without the separator could be defeated by a
      sibling directory sharing a name prefix); case IDs validated against the same
      `^[a-z0-9]+(-[a-z0-9]+)*$` pattern used everywhere else; the `dart`/`cmd.exe`
      subprocess is invoked with an argv array, not a shell-interpolated string. No format
      or crypto change — this task adds only test/tooling code.)
      Maker/Checker/Human gate: Claude

Future SDKs — Dart: MET 2026-10-01 — sdk/dart passes 100% of shared vectors byte-exact,
rejects negatives with exact error ids, cross-decodes with
Go/Node/Python/Rust/Java/.NET/PHP, package:crypto + package:cryptography only (the one
pair of third-party runtime dependencies across all 8 SDKs so far, required because Dart's
core SDK has no crypto at all — confirmed and explicitly chosen by the human rather than
assumed), public API equivalent to the other SDKs (one-shot plain/encrypted, pull-based
async streaming encoder/decoder, verify, inspect).

---

## Completed: Phase 3 — PHP SDK

Port the frozen format to `sdk/php/` (a Composer package `ubc/ubc`, PHP >=8.2, PHPUnit
dev-only). The Go SDK, Python SDK, Rust SDK, Java SDK, .NET SDK, and shared vectors in
spec/vectors are the contract — the port matches byte-for-byte and cross-decodes with
Go/Node/Python/Rust/Java/.NET. Crypto from PHP core/ext-openssl/ext-hash
(`hash()`/`hash_hmac()`/`hash_equals()`, `openssl_encrypt`/`openssl_decrypt` with
`aes-256-gcm`) — bundled extensions, not third-party packages. `chunk_count`/`total_size`
use PHP's signed 64-bit `int` with no unsigned-compare helper (ext-gmp declined as
unneeded for an unreachable boundary). `UbcException extends \RuntimeException` with an
`errorCode` property (not `code` — collides with `\Exception::$code`); binary data as PHP
`string` throughout.

- [x] PHP scaffold + plain path: `sdk/php/` Composer package `ubc/ubc`, `ErrorCode` backed
      enum mapping every stable error id (SPEC.md §5), `UbcException`, header + TLV
      encode/parse, chunking + SHA-256 flat root one-shot encode/decode. Goal: header/TLV
      round-trip matching shared vector bytes; plain path byte-exact to every plain vector;
      ERR_ROOT_MISMATCH on a flipped byte. (Scaffold and plain path combined into one task
      here — both are mechanical ports with no crypto, unlike the finer-grained split used
      for Rust/Java/.NET.)
      (solo maker+checker+human-gate 2026-10-01, continuing per "keep going" instruction.
      PHP 8.3.33 + Composer 2.9.7 already present, openssl/hash/mbstring extensions all
      loaded, no bootstrap needed. 26/26 PHPUnit tests pass (19 header/metadata + 7 plain):
      all positive vectors' headers round-trip byte-exact, plain-metadata TLV round-trips
      byte-exact, 9 header/metadata negative vectors return their exact stable error ids,
      metadata encoder sorts tags and rejects duplicates, metadata length cap is checked
      before copying entries; all 6 plain vectors (empty, one-byte, chunk-1m,
      chunk-1m-plus-one, multi-3m, metadata) encode byte-exact and decode back to exact
      input; a flipped payload byte returns ERR_ROOT_MISMATCH; negative-truncated/root-
      mismatch/trailing-data/oversized-clen return their exact stable error ids.
      `vendor/bin/phpunit` clean. CHECK: UTF-8 filename validation uses
      `mb_check_encoding()`, experimentally confirmed to reject overlong encodings (0xC0
      0x80) and unpaired surrogates (0xED 0xA0 0x80) the same way the Java/.NET strict
      decoders do, not just ASCII-subset validation. SECURITY (manual): DoS caps
      (`maxChunkLen`/`maxChunkCount`/`maxTotalSize`) checked before any `substr` copy of
      untrusted chunk bytes; root comparison uses `hash_equals()` (PHP's constant-time
      compare primitive, the correct choice here — not a hand-rolled `===`). No format or
      crypto algorithm change — scaffold + plain only, no AEAD code yet.)
      Maker/Checker/Human gate: Claude
- [x] PHP encrypted path: AES-256-GCM per-chunk, nonce = base XOR i, AAD = header ‖
      sha256(meta) ‖ i, HMAC-SHA-256 root (HKDF-derived), verify-before-release.
      Goal: byte-exact to fixed-nonce encrypted vectors; ERR_CHUNK_AUTH on tag flip; no
      plaintext on failure. CRYPTO-CRITICAL.
      (solo maker+checker+human-gate 2026-10-01. `Crypto::encodeEncrypted`/
      `encodeEncryptedWithFixedNonce`/`decodeEncrypted` added using `openssl_encrypt`/
      `openssl_decrypt` with `aes-256-gcm` and `hash_hmac`/incremental `hash_init(...,
      HASH_HMAC, ...)`, bundled ext-openssl/ext-hash only. Before trusting fail-closed
      behavior, verified experimentally (not assumed) that `openssl_decrypt` returns the
      boolean `false` — not an exception, not partial plaintext — on a tag mismatch; the
      decrypt helper uses a strict `=== false` check specifically because a legitimately
      empty-string plaintext is also falsy in PHP and a loose check would misclassify it as
      an auth failure. Also independently verified the `root_key` derivation against
      spec/vectors.json's standalone known-answer fixture via a one-off script before
      writing any tests, since `hash_hmac(algo, data, key, raw)`'s data-before-key argument
      order (opposite of most languages' hmac(key, data) convention) is an easy place to
      transpose silently — confirmed byte-exact on the first attempt once the argument
      order was worked out deliberately rather than guessed. 37/37 PHPUnit tests pass (26
      carried forward + 11 new): all 6 encrypted vectors encode byte-exact and decode back
      to exact input; the HKDF root_key derivation matches the shared known-answer fixture
      independent of any container; negative-chunk-auth/encrypted-short-clen/encrypted-
      metadata-tamper return ERR_CHUNK_AUTH; negative-missing-key/encrypted-cap-missing-key
      (decoded with no key) return ERR_MISSING_KEY; negative-encrypted-empty-wrong-key
      (decoded with the vector's own wrong key) returns ERR_ROOT_MISMATCH; a wrong key
      against a non-empty container also returns ERR_CHUNK_AUTH. `vendor/bin/phpunit`
      clean. CHECK: nonce = base_nonce XOR le96(i), AAD = header_bytes ‖ SHA-256(meta_region)
      ‖ le64(i) match spec exactly; both encode and decode derive the root key identically.
      SECURITY (manual): `random_bytes()` (CSPRNG, not `rand()`/`mt_rand()`) generates
      `encodeEncrypted`'s base_nonce; `hash_equals()` used for the root comparison;
      `clen < CryptoInternal::GCM_TAG_SIZE` rejected as ERR_CHUNK_AUTH before any decrypt
      attempt; reader precedence matches SPEC.md §5. No format change; crypto matches
      SPEC.md §3-4 exactly.)
      Maker/Checker/Human gate: Claude
- [x] PHP streaming encoder/decoder (PHP stream resources) + verify + inspect; DoS caps on
      untrusted lengths. Goal: streaming output identical to one-shot; fail-closed; caps
      enforced before allocation. Constant-time compare for the encrypted root.
      (solo maker+checker+human-gate 2026-10-01. Confirmed via explicit tool-call (not
      assumed) that PHP has no Stream/InputStream base class, then built Encoder/Decoder
      around plain PHP stream resources (`fopen`/`fread`/`fwrite`) — PHP's own native idiom,
      works with any real stream (file, `php://temp`, socket) with no adapter interface.
      Extracted shared nonce/AAD/root-key/GCM primitives into `CryptoInternal` (and a
      `RootAccumulator` wrapping the plain-SHA-256-vs-keyed-HMAC branch) before writing
      Encoder/Decoder, same approach as the Java and .NET ports. Applied the same three
      Rust-derived fixes from the start (re-read that task's full security history in this
      file before writing any code): (1) the encoder reads exactly `min(totalSize,
      chunkSize)` per chunk via a bounded `readExact`, never over-allocates; (2) the decoder
      preflights the 36-byte footer before authenticating the final encrypted chunk, so
      ERR_TRUNCATED wins over ERR_CHUNK_AUTH per SPEC.md §5; (3) the encoder's spool —
      unlike Java/.NET, PHP's `tmpfile()` already creates the spool with safe permissions
      and auto-removes it on close or script end, even for an abandoned Encoder, so neither
      a `deleteOnExit()`-style call nor a finalizer was needed here; documented why rather
      than silently omitting the safety net the other two ports needed. 45/45 PHPUnit tests
      pass (37 carried forward + 8 new): streamed plain output is byte-exact vs the one-shot
      plain-multi-3m vector even written in two unequal chunks, and decodes correctly
      through a decoder read one byte at a time; streamed encrypted output is byte-exact vs
      the one-shot encrypted-chunk-1m-plus-one vector; a corrupted footer and a trailing
      extra byte are both caught before the decoder returns an empty string (root withheld
      until verified); the truncated+corrupted-final-tag scenario returns ERR_TRUNCATED, not
      ERR_CHUNK_AUTH; an encoder with a 256 MiB chunk_size against a 3-byte input round-trips
      without over-allocating; a streaming decoder with max_chunk_len=4 against 1 MiB chunks
      throws ERR_TRUNCATED on the first read(); verify() reports ok=false with the correct
      error code on a corrupted container and inspect() reads only the header+metadata
      region, unaffected by a mangled footer. `vendor/bin/phpunit` clean. CHECK: confirmed
      `fread()` at true end-of-stream returns `''` (empty string), not `false`, for
      `php://temp`-style wrappers — verified experimentally before relying on it for the
      trailing-data check, rather than assuming PHP's EOF-signaling convention matched
      another language's. SECURITY (manual): chunk-length DoS caps checked before any
      `readExact` allocation in the decoder, matching the one-shot path's bound; `hash_equals()`
      used for the root comparison. No format or crypto algorithm change from the
      already-reviewed encrypted-path task.)
      Maker/Checker/Human gate: Claude
- [x] PHP conformance + cross-decode: run all shared vectors (positive byte-exact, negative
      with exact error ids); decode Go/Node/Python/Rust/Java/.NET containers and vice versa.
      Goal: 100% vector pass; cross-decode Go↔Node↔Python↔Rust↔Java↔.NET↔PHP green.
      (solo maker+checker+human-gate 2026-10-01. Added a manifest-driven `ConformanceTest`
      walking every vector in spec/vectors/vectors.json — all 12 positive, all 25 negative —
      backed by a `VectorManifest` helper in tests/Support/ using PHP's native `json_decode`
      directly (unlike the Rust/Java/.NET ports, PHP's JSON support is core/bundled, so
      hand-rolling a parser the way those three test-support layers did would have been
      pointless extra code for no dependency benefit). `Vector::decode()` auto-detects plain
      vs encrypted from the container's own header bytes, matching Go's single `DecodeBytes`
      dispatcher — applied this design from the start instead of rediscovering the key-less-
      negative-vector pitfall the Java port hit first. Added `bin/cross-decode.php` (`--vectors
      --work --cases --write|--verify`, same contract as the other four CLIs), requiring the
      test support file directly since PHP has no project-reference mechanism — closest
      analog to Rust's `#[path]` include and .NET's linked-file `<Compile Include>`. Wired
      PHP in as the seventh cross-decode producer: `--php` flag in tools/crossdecode/main.go,
      `"php"` added to cross-decode-python.py's producer loop, and scripts/cross-decode.mjs
      now runs `php bin/cross-decode.php` to write and verify PHP containers alongside the
      other six. `node scripts/cross-decode.mjs` passes for all 12 positive vectors, 7-way
      byte-identical across Go/Node/Python/Rust/Java/.NET/PHP. Gates green: `vendor/bin/phpunit`
      (46 tests: the new ConformanceTest plus every earlier suite, 241 assertions),
      `go build/vet/test ./...` clean, Python 22/22, Node 55/55. SECURITY (manual): the
      CLI's `safeChild` normalizes both the candidate path and the root to forward slashes
      before the containment check (Windows path-separator mixing could otherwise defeat a
      naive comparison); case IDs validated against the same `^[a-z0-9]+(-[a-z0-9]+)*$`
      pattern used by every other producer's CLI; the `php` subprocess is invoked with an
      argv array, not a shell-interpolated string. No format or crypto change — this task
      adds only test/tooling code.)
      Maker/Checker/Human gate: Claude

Phase 3 (PHP) exit gate: MET 2026-10-01 — sdk/php passes 100% of shared vectors byte-exact,
rejects negatives with exact error ids, cross-decodes with Go/Node/Python/Rust/Java/.NET,
PHP core/ext-openssl/ext-hash/ext-mbstring only (no third-party runtime packages), public
API equivalent to the other SDKs (one-shot plain/encrypted, streaming encoder/decoder,
verify, inspect).

---

## Completed: Phase 3 — .NET SDK

Port the frozen format to `sdk/dotnet/` (a class library `Ubc`, targeting `net8.0` LTS,
with a `Ubc.sln` tying the library and its xUnit test project together). The Go SDK,
Python SDK, Rust SDK, Java SDK, and shared vectors in spec/vectors are the contract — the
port matches byte-for-byte and cross-decodes with Go/Node/Python/Rust/Java. Crypto from
`System.Security.Cryptography` (`SHA256`, `HMACSHA256`, `AesGcm`) — stdlib only.
`chunk_count`/`total_size` use `ulong`, natively unsigned in .NET, so ordinary `<`/`>`/`==`
operators are already correct. `UbcException : Exception` carrying a stable `ErrorCode`
enum plus a `ToStableId()` extension method; no `unsafe`; `Span<byte>`/`ReadOnlySpan<byte>`
for zero-copy parsing; defensive copies on any mutable byte array field.

- [x] .NET scaffold: `sdk/dotnet/` class library `Ubc` (net8.0) with `Ubc.sln`,
      `ErrorCode` enum + `ToStableId()` mapping every stable error id (SPEC.md §5),
      `UbcException`, header + TLV encode/parse. Goal: header/TLV round-trip; matches the
      header/metadata bytes in the shared vectors.
      (solo maker+checker+human-gate 2026-10-01, continuing without the human-review pause
      used after Rust/Java per explicit instruction to keep going. dotnet SDK 10.0.400 and
      runtime already present; targeted net8.0 LTS instead of net10.0 for consumer
      compatibility per explicit confirmation. 19/19 xUnit tests pass (Theory cases count
      individually, same coverage as Java's 6 JUnit methods): all positive vectors' headers
      round-trip byte-exact, plain-metadata TLV round-trips byte-exact, 9 header/metadata
      negative vectors return their exact stable error ids, metadata encoder sorts tags and
      rejects duplicates, metadata length cap is checked before copying entries. `dotnet
      build`/`dotnet test` clean with `TreatWarningsAsErrors=true` (the .NET analyzer
      equivalent of clippy -D warnings) — caught and fixed one real finding before green:
      CA2014 flagged a `stackalloc` inside a `foreach` loop in `Metadata.Encode` as a
      potential stack-overflow risk on large metadata entry counts; moved the 6-byte TLV
      entry-header buffer outside the loop so a single stack slot is reused across
      iterations instead of allocating one per entry. CHECK: SPEC.md's true-uint64
      chunk_count/total_size fields map directly to .NET's natively-unsigned `ulong` with
      no sign-bit edge cases to special-case, unlike the Java port's `long`-based
      workarounds. No format or crypto change — scaffold only, no crypto code yet.)
      Maker/Checker/Human gate: Claude
- [x] .NET plain path: chunking + SHA-256 flat root; one-shot encode/decode.
      Goal: byte-exact to every plain vector; ERR_ROOT_MISMATCH on a flipped byte.
      (solo maker+checker+human-gate 2026-10-01. `Payload.EncodePlain`/`DecodePlain` added
      using `System.Security.Cryptography.SHA256`'s incremental `TransformBlock`/
      `TransformFinalBlock` API, stdlib only. 26/26 xUnit tests pass (19 carried forward +
      7 new): all 6 plain vectors (empty, one-byte, chunk-1m, chunk-1m-plus-one, multi-3m,
      metadata) encode byte-exact and decode back to their exact input bytes; a flipped
      payload byte returns ERR_ROOT_MISMATCH; negative-truncated/root-mismatch/trailing-
      data/oversized-clen vectors return their exact stable error ids. `dotnet test` clean,
      `TreatWarningsAsErrors` clean. CHECK: reader precedence (header → metadata →
      missing-key → payload framing/truncated-footer → root mismatch → trailing-data)
      matches SPEC.md §5 exactly, same order as every other SDK. SECURITY (manual):
      `chunkLength > opts.MaxChunkLen` is checked before `container.Slice(offset,
      (int)chunkLength)` ever runs, so the DoS cap bounds the slice before any copy;
      `CryptographicOperations.FixedTimeEquals` used for the root comparison (constant-
      time, the correct .NET primitive for this — not a hand-rolled compare); `ulong`
      arithmetic throughout means no analog of the Java port's chunk_size-above-
      Integer.MAX_VALUE stride-wrapping class of bug is even possible here. No format or
      crypto algorithm change.)
      Maker/Checker/Human gate: Claude
- [x] .NET encrypted path: AES-256-GCM per-chunk, nonce = base XOR i, AAD = header ‖
      sha256(meta) ‖ i, HMAC-SHA-256 root (HKDF-derived), verify-before-release.
      Goal: byte-exact to fixed-nonce encrypted vectors; ERR_CHUNK_AUTH on tag flip; no
      plaintext on failure. CRYPTO-CRITICAL.
      (solo maker+checker+human-gate 2026-10-01. `Crypto.EncodeEncrypted`/
      `EncodeEncryptedWithFixedNonce`/`DecodeEncrypted` added using `System.Security.
      Cryptography.AesGcm` and `HMACSHA256`, stdlib only. Before trusting the AEAD's
      fail-closed behavior, wrote and ran a disposable console program exercising
      `AesGcm.Decrypt` with a deliberately flipped tag: confirmed it throws
      `AuthenticationTagMismatchException` (a `CryptographicException` subtype) AND actively
      zeroes the output buffer rather than leaving partial/garbage plaintext — stronger than
      just "doesn't return" plaintext on failure. 37/37 xUnit tests pass (26 carried forward
      + 11 new): all 6 encrypted vectors encode byte-exact and decode back to exact input;
      the HKDF `root_key` derivation matches spec/vectors.json's standalone
      `cryptoKnownAnswers[0]` fixture independent of any container; negative-chunk-auth/
      encrypted-short-clen/encrypted-metadata-tamper return ERR_CHUNK_AUTH;
      negative-missing-key/encrypted-cap-missing-key (decoded with no key) return
      ERR_MISSING_KEY; negative-encrypted-empty-wrong-key (decoded with the vector's own
      wrong key) returns ERR_ROOT_MISMATCH; a wrong key against a non-empty container
      returns ERR_CHUNK_AUTH. `dotnet test` clean, `TreatWarningsAsErrors` clean. CHECK:
      nonce = base_nonce XOR le96(i), AAD = header_bytes ‖ SHA-256(meta_region) ‖ le64(i),
      PRK = HMAC-SHA-256(base_nonce, key), root_key = HMAC-SHA-256(PRK, "UBC1 root
      authentication" ‖ 0x01) all match spec exactly and both directions derive identically
      (known-answer test proves the derivation itself, not just self-consistency).
      SECURITY (manual): `RandomNumberGenerator.Fill` (CSPRNG) generates `EncodeEncrypted`'s
      base_nonce, never reused across containers; `CryptographicOperations.FixedTimeEquals`
      used for the root comparison; `clen < CryptoInternal.GcmTagSize` rejected as
      ERR_CHUNK_AUTH before any decrypt attempt; reader precedence matches SPEC.md §5;
      `Header.BaseNonce()` already returns a defensive copy (scaffold task) so the per-chunk
      XOR nonce can't be corrupted by external mutation. No format change; crypto matches
      SPEC.md §3-4 exactly.)
      Maker/Checker/Human gate: Claude
- [x] .NET streaming encoder/decoder (`Stream`) + verify + inspect; DoS caps on untrusted
      lengths. Goal: streaming output identical to one-shot; fail-closed; caps enforced
      before allocation. Constant-time compare for the encrypted root.
      (solo maker+checker+human-gate 2026-10-01. Extracted shared nonce/AAD/root-key/GCM
      primitives into internal `CryptoInternal` (and a `RootAccumulator` wrapping the
      plain-SHA-256-vs-keyed-HMAC branch) before writing `Encoder`/`Decoder`, so the
      one-shot and streaming paths share one implementation — same approach as the Java
      port. Applied the same three Rust-derived fixes from the start (re-read that task's
      full security history in this file before writing any code): (1) the encoder's chunk
      buffer is `Math.Min(totalSize, chunkSize)`, not `chunkSize`; (2) the decoder
      preflights the 36-byte footer before authenticating the final encrypted chunk, so
      ERR_TRUNCATED wins over ERR_CHUNK_AUTH per SPEC.md §5; (3) the encoder's plaintext
      spool file is deleted immediately after a successful finish (try/finally). .NET has
      no deterministic destructor, so added a safety net the Java port's JVM-level
      `deleteOnExit()` doesn't need an equivalent for elsewhere: a finalizer on `Encoder`
      that best-effort-deletes the spool file if a caller never disposes it, with
      `GC.SuppressFinalize` on the normal dispose path so the finalizer only runs in the
      abandoned-encoder case. The spool file itself is created with
      `FileStreamOptions.UnixCreateMode = UserRead|UserWrite` on non-Windows (owner-only
      permissions set atomically at creation, no window of default permissions); gated
      behind `OperatingSystem.IsWindows()` because the analyzer (CA1416) correctly flags
      that property as unsupported on Windows — gating was the fix, not suppressing the
      warning. 45/45 xUnit tests pass (37 carried forward + 8 new): streamed plain output
      is byte-exact vs the one-shot plain-multi-3m vector even written in two unequal
      chunks, and decodes correctly through a deliberately pathological `Stream` that only
      ever returns 1 byte per `Read()` call; streamed encrypted output is byte-exact vs the
      one-shot encrypted-chunk-1m-plus-one vector; a corrupted footer and a trailing extra
      byte are both caught before the decoder returns 0 (root withheld until verified); the
      truncated+corrupted-final-tag scenario returns ERR_TRUNCATED, not ERR_CHUNK_AUTH; an
      encoder with a 256 MiB chunk_size against a 3-byte input round-trips without
      over-allocating; a streaming decoder with max_chunk_len=4 against 1 MiB chunks throws
      ERR_TRUNCATED on the first Read(); Verify() reports Ok=false with the correct error
      code on a corrupted container and Inspect() reads only the header+metadata region,
      unaffected by a mangled footer. `dotnet test` clean, `TreatWarningsAsErrors` clean
      (including the CA1416 fix above). CHECK: confirmed (same finding as the Java port)
      that Go's canonical `sdk/go/decoder.go` releases plain-mode chunks incrementally
      per-read with no full-buffering spool, so .NET's `Decoder` was built unbuffered for
      both modes to match that cross-SDK convention, not the more conservative buffered
      approach Rust's streaming decoder initially used for plain mode. SECURITY (manual):
      `Decoder` disposes its `RootAccumulator` (which wraps a disposable `HashAlgorithm` or
      `HMAC`); chunk-length DoS caps checked before any `ReadExact` allocation, matching the
      one-shot path's bound; the encoder's `FileShare.None` prevents another process from
      opening the spool file concurrently while it's in use. No format or crypto algorithm
      change from the already-reviewed encrypted-path task.)
      Maker/Checker/Human gate: Claude
- [x] .NET conformance + cross-decode: run all shared vectors (positive byte-exact,
      negative with exact error ids); decode Go/Node/Python/Rust/Java containers and vice
      versa. Goal: 100% vector pass; cross-decode Go↔Node↔Python↔Rust↔Java↔.NET green.
      (solo maker+checker+human-gate 2026-10-01. Added a manifest-driven `ConformanceTests`
      walking every vector in spec/vectors/vectors.json — all 12 positive, all 25 negative —
      backed by a dependency-free `MiniJson` reader and a `VectorManifest` helper whose
      `Decode()` auto-detects plain vs encrypted from the container's own header bytes
      (matching Go's single `DecodeBytes` dispatcher), same design as the Java port's
      conformance test after the same early mistake was avoided this time by starting from
      that lesson directly instead of rediscovering it: the two key-less negative vectors
      (negative-missing-key, negative-encrypted-cap-missing-key) decode with no key on
      purpose, every other negative decodes with the vector's own or the canonical key.
      Added a `tools/CrossDecode` console project (`--vectors --work --cases
      --write|--verify`, same contract as the Rust and Java CLIs) that links the test
      project's `MiniJson.cs`/`VectorManifest.cs` by path via `<Compile Include>` instead of
      duplicating them — the C# equivalent of the Rust example's `#[path = "..."]` module
      include. Wired .NET in as the sixth cross-decode producer: `--dotnet` flag in
      tools/crossdecode/main.go, `"dotnet"` added to cross-decode-python.py's producer loop,
      and scripts/cross-decode.mjs now runs `dotnet run --project tools/CrossDecode`
      (compiles on demand, like `cargo run` and `mvn exec:java`, so there's no separate
      "build sdk/dotnet first" step) to write and verify .NET containers alongside the
      other five. `node scripts/cross-decode.mjs` passes for all 12 positive vectors,
      6-way byte-identical across Go/Node/Python/Rust/Java/.NET. Gates green: `dotnet test`
      (46 tests: the new ConformanceTests plus every earlier suite), `TreatWarningsAsErrors`
      clean, `go build/vet/test ./...` clean, Python 22/22, Node 55/55. SECURITY (manual):
      the CLI's `SafeChild` appends a trailing separator to the resolved root before the
      `StartsWith` containment check — necessary in C# specifically because
      `string.StartsWith` is a raw string comparison (unlike Java's `Path.startsWith`, which
      is already path-component-aware and didn't need the same guard); case IDs validated
      against the same `^[a-z0-9]+(-[a-z0-9]+)*$` pattern used elsewhere; the `dotnet`
      subprocess is invoked with an argv array, not a shell-interpolated string. No format
      or crypto change — this task adds only test/tooling code.)
      Maker/Checker/Human gate: Claude

Phase 3 (.NET) exit gate: MET 2026-10-01 — sdk/dotnet passes 100% of shared vectors
byte-exact, rejects negatives with exact error ids, cross-decodes with
Go/Node/Python/Rust/Java, System.Security.Cryptography stdlib only, public API equivalent
to the other SDKs (one-shot plain/encrypted, streaming encoder/decoder, verify, inspect).

---

## Completed: Phase 3 — Java SDK

Port the frozen format to `sdk/java/` (a Maven module `dev.ubc:ubc`, built via the
vendored Maven Wrapper — `./mvnw` / `mvnw.cmd`, no system Maven install required). The Go
SDK, Python SDK, Rust SDK, and shared vectors in spec/vectors are the contract — the port
matches byte-for-byte and cross-decodes with Go/Node/Python/Rust. Crypto from the JDK's
own `javax.crypto`/`java.security` (JCA/JCE: `MessageDigest`, `Mac`, `Cipher` with
`AES/GCM/NoPadding`) — stdlib only, zero third-party runtime dependencies. `chunk_count`/
`total_size` are true uint64: stored as Java `long`, every bit pattern (including a set
sign bit) treated as valid — `Long.compareUnsigned` used throughout instead of signed
`<`/`>`. Unchecked `UbcException` carrying a stable `ErrorCode` enum; no `Unsafe`;
defensive copies on any mutable array field.

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
- [x] Java encrypted path: AES-256-GCM per-chunk, nonce = base XOR i, AAD = header ‖
      sha256(meta) ‖ i, HMAC-SHA-256 root (HKDF-derived), verify-before-release.
      Goal: byte-exact to fixed-nonce encrypted vectors; ERR_CHUNK_AUTH on tag flip; no
      plaintext on failure. CRYPTO-CRITICAL.
      (solo maker+checker+human-gate 2026-10-01 — same no-second-model constraint as the
      earlier Java tasks; user explicitly confirmed proceeding with Claude self-review given
      codex CLI's unreliable verdict in this environment, instead of blocking or debugging
      the CLI further. `Crypto.encodeEncrypted`/`encodeEncryptedWithFixedNonce`/
      `decodeEncrypted` added using `javax.crypto.Cipher` (AES/GCM/NoPadding) and
      `javax.crypto.Mac` (HmacSHA256), stdlib JCA only. 17/17 JUnit tests pass: all 6
      encrypted vectors (empty, one-byte, chunk-1m, chunk-1m-plus-one, multi-3m, metadata)
      encode byte-exact and decode back to exact input; the HKDF `root_key` derivation
      matches spec/vectors.json's standalone `cryptoKnownAnswers[0]` fixture independent of
      any container; negative-chunk-auth/encrypted-short-clen/encrypted-metadata-tamper
      return ERR_CHUNK_AUTH; negative-missing-key/encrypted-cap-missing-key (decoded with no
      key) return ERR_MISSING_KEY; negative-encrypted-empty-wrong-key (decoded with the
      vector's own wrong key) returns ERR_ROOT_MISMATCH; a wrong key against a non-empty
      container also returns ERR_CHUNK_AUTH (GCM tag fails before the root is ever reached).
      `mvnw test` clean, `-Xlint:all -Werror` clean. CHECK: nonce = base_nonce XOR le96(i)
      matches spec exactly (8-byte LE chunk index in the low bytes, top 4 bytes zero — index
      never exceeds 2^64); AAD = header_bytes ‖ SHA-256(meta_region) ‖ le64(i); PRK =
      HMAC-SHA-256(base_nonce, key), root_key = HMAC-SHA-256(PRK, "UBC1 root authentication"
      ‖ 0x01) — both directions (encode and decode) derive the root key identically and the
      known-answer test proves the derivation itself is correct, not just self-consistent.
      SECURITY (manual, per user direction): JCA `Cipher.doFinal` in GCM mode is atomic —
      it returns full plaintext only after the tag verifies, or throws with zero bytes
      released, so fail-closed/verify-before-release holds by construction (not by a
      length check Claude could get wrong); `clen < 16` is rejected as ERR_CHUNK_AUTH before
      any decrypt attempt; reader precedence (header → metadata → missing-key → caps →
      payload framing/truncated-footer → chunk auth → root mismatch → trailing-data) matches
      SPEC.md §5; root hash comparison uses `MessageDigest.isEqual` (constant-time); base_nonce
      for `encodeEncrypted` comes from `java.security.SecureRandom` (CSPRNG, never reused
      across containers); `Header.baseNonce()` already returns a defensive clone (fixed in
      the scaffold task) so the per-chunk XOR nonce can't be corrupted by external mutation.
      No format change; crypto matches SPEC.md §3-4 exactly, no deviation.)
      Maker/Checker/Human gate: Claude
- [x] Java streaming encoder/decoder (InputStream/OutputStream) + verify + inspect; DoS caps
      on untrusted lengths. Goal: streaming output identical to one-shot; fail-closed; caps
      enforced before allocation. Constant-time compare for the encrypted root.
      (solo maker+checker+human-gate 2026-10-01. Extracted the nonce/AAD/root-key/GCM
      primitives shared by the one-shot and streaming paths into package-private
      `CryptoInternal` (and a `RootAccumulator` wrapping the plain-SHA-256-vs-keyed-HMAC
      branch) so the two paths cannot silently diverge — `Crypto.java` now delegates to it
      instead of carrying its own copies. Before writing `Encoder`/`Decoder`, re-read the
      Rust streaming task's full security history (3 checker rounds) in this same roadmap
      file and applied its three fixes from the start instead of rediscovering them:
      (1) the encoder's chunk buffer is sized `min(totalSize, chunkSize)`, not `chunkSize`,
      so a large declared chunk_size on small/empty input can't over-allocate; (2) the
      decoder preflights (reads) the 36-byte footer before authenticating the final
      encrypted chunk, so a stream that is both truncated and has a corrupted final tag
      surfaces ERR_TRUNCATED, matching SPEC.md §5's truncation-before-chunk-auth precedence,
      instead of the misleading ERR_CHUNK_AUTH a naive implementation would raise; (3) the
      encoder's plaintext spool file is deleted immediately after a successful finish (in a
      try/finally so this also runs on any mid-finish failure).
      25/25 JUnit tests pass: streamed plain output is byte-exact vs the one-shot plain-multi-
      3m vector even when written in two unequal chunks, and decodes correctly through a
      deliberately pathological InputStream that only ever returns 1 byte per read() call;
      streamed encrypted output is byte-exact vs the one-shot encrypted-chunk-1m-plus-one
      vector; a corrupted footer and a trailing extra byte are both caught before the
      decoder yields -1 (root withheld until verified); the truncated+corrupted-final-tag
      scenario returns ERR_TRUNCATED, not ERR_CHUNK_AUTH; an encoder with a 256 MiB
      chunk_size against a 3-byte input round-trips without the old Rust-class
      over-allocation bug; a streaming decoder with max_chunk_len=4 against 1 MiB chunks
      throws ERR_TRUNCATED on the first read(); verify() reports ok=false with the correct
      error code on a corrupted container and inspect() reads only the header+metadata
      region, unaffected by a mangled footer. `mvnw test` clean, `-Xlint:all -Werror` clean.
      CHECK: confirmed Go (the canonical reference SDK, sdk/go/decoder.go) and Python both
      release plain-mode chunks incrementally per-read with no full-buffering spool before
      Rust's streaming Decoder was initially written to buffer entire plain-mode output
      before releasing it — once confirmed that Go's canonical behavior is unbuffered,
      Java's Decoder was built to match Go/Python's cross-SDK convention (unbuffered,
      matches SPEC.md §5's "MAY release per-chunk" language, which textually applies per-tag
      to encrypted mode but Go/Python extend the same early-release convention to plain mode
      and that is the behavior this port must stay consistent with). SECURITY (manual):
      the encoder's plaintext spool file is created via `Files.createTempFile` with
      owner-only POSIX permissions where supported, falling back to the platform default
      (already owner-restricted under NTFS) on non-POSIX filesystems; `deleteOnExit()` is
      registered at spool creation as a safety net in case a caller never calls `close()`;
      chunk-length DoS caps (`maxChunkLen`) are checked before any `readExact` allocation in
      the decoder, matching the one-shot path's bound. No format or crypto algorithm change
      from the already-reviewed encrypted-path task.)
      Maker/Checker/Human gate: Claude
- [x] Java conformance + cross-decode: run all shared vectors (positive byte-exact,
      negative with exact error ids); decode Go/Node/Python/Rust containers and vice versa.
      Goal: 100% vector pass; cross-decode Go↔Node↔Python↔Rust↔Java green.
      (solo maker+checker+human-gate 2026-10-01. Added a manifest-driven `ConformanceTest`
      (`src/test/java/dev/ubc/ConformanceTest.java`) that walks every vector in
      spec/vectors/vectors.json — not a hand-picked subset like the earlier per-mode test
      files — verifying the expected artifact's own SHA-256, byte-exact encode, decode
      round-trip, and metadata for all 12 positive vectors, plus the exact stable error id
      for all 25 negatives. Backing it: a hand-rolled, dependency-free `MiniJson` reader
      (test-scope only, same choice the Rust port's test support already made for this same
      file rather than add a JSON library) and a `VectorManifest` helper whose `decode()`
      auto-detects plain vs encrypted from the container's own header bytes — matching Go's
      single `DecodeBytes` dispatcher — instead of trusting the caller's guess, after an
      early version that branched on key-presence misdecoded the two key-less negative
      vectors (negative-missing-key, negative-encrypted-cap-missing-key are decoded with no
      key on purpose; every other negative decodes with the vector's own or the canonical
      key so a missing-key short-circuit can't mask the error the vector is meant to
      exercise). Added `dev.ubc.support.CrossDecodeCli` (`--vectors --work --cases
      --write|--verify`, same contract as the Rust example) wired into the build via the
      `exec-maven-plugin` (build-time only, invoked as `mvnw -q exec:java@cross-decode`;
      never packaged into the library jar, so this is not a new runtime dependency), and
      wired Java as a fifth producer everywhere the other four already were: `--java` flag
      in tools/crossdecode/main.go, `"java"` added to cross-decode-python.py's producer
      loop, and scripts/cross-decode.mjs now runs `mvnw(.cmd)` (via `cmd.exe /c` on Windows
      since Node's execFile cannot spawn a .cmd batch file directly — hit a `spawn EINVAL`
      confirming this before the fix) to write and verify Java containers alongside the
      other four. `node scripts/cross-decode.mjs` passes for all 12 positive vectors,
      5-way byte-identical across Go/Node/Python/Rust/Java. Gates green: `mvnw test` (26
      tests: the new ConformanceTest plus every earlier per-mode suite), `-Xlint:all
      -Werror` clean, `go build/vet/test ./...` clean, Python 22/22, Node 55/55.
      SECURITY (manual): CrossDecodeCli's `safeChild` resolves+normalizes then requires
      `target.startsWith(root)` before any read/write, rejecting path traversal in manifest-
      or CLI-supplied relative paths; case IDs are validated against the same
      `[a-z0-9]+(-[a-z0-9]+)*` pattern used elsewhere before being joined into any argument
      list; the Maven subprocess is invoked with an argv array (not a shell-interpolated
      string), so no injection surface even though vectorsRoot/workDir/caseIDs ultimately
      flow into a child-process command line. No format or crypto change — this task adds
      only test/tooling code.)
      Maker/Checker/Human gate: Claude

Phase 3 (Java) exit gate: MET 2026-10-01 — sdk/java passes 100% of shared vectors
byte-exact, rejects negatives with exact error ids, cross-decodes with Go/Node/Python/Rust,
JCA/JCE stdlib only, public API equivalent to the other SDKs (one-shot plain/encrypted,
streaming encoder/decoder, verify, inspect).

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
- [x] Java
- [x] .NET
- [x] PHP

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

Same port process as Phase 3 (scaffold+plain, encrypted, streaming, conformance +
cross-decode). Toolchain availability checked 2026-10-01 on this Windows dev machine:
Dart 3.13.2 present; Swift (poor native Windows support), Kotlin (needs separate kotlinc
install), and Ruby (not installed) all absent — Dart started first for that reason, not
priority order. Kotlin's kotlinc was subsequently obtained 2026-10-02 as a standalone
release zip (no system install) after a `choco install` attempt failed not-elevated.

- [x] Dart
- [x] Kotlin
- [ ] Swift
- [ ] Ruby

---

## Guiding rules

- The format is frozen at end of Phase 0. Changes go through the RFC process (RFC.md).
- No SDK is "done" until it passes the shared conformance suite.
- Vectors are the contract; SDKs never carry bespoke expected values.
