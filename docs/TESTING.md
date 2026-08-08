# UBC Testing & Conformance

Testing strategy centered on shared test vectors — the mechanism that proves every SDK
produces and accepts byte-identical containers. Format is defined by
[`spec/SPEC.md`](../spec/SPEC.md).

---

## 1. Test vectors are the contract

The vectors are the single source of truth for behavior. No SDK writes its own expected
output; every SDK is checked against the same golden bytes. If an SDK disagrees with a
vector, the SDK is wrong (or the vector/spec needs an RFC change).

```
spec/vectors/
  vectors.json          # manifest: id, description, input ref, options, expected refs, expected error
  inputs/               # raw input files
  expected/             # golden .ubc containers + their SHA-256
```

`vectors.json` entry shape (illustrative):
```json
{
  "id": "plain-multichunk",
  "input": "inputs/3mib.bin",
  "options": { "chunkSize": 1048576 },
  "expected": "expected/plain-multichunk.ubc",
  "expectedSha256": "…",
  "expectError": null
}
```

Encrypted vectors additionally fix `key` and `baseNonce` so output is reproducible.

---

## 2. Vector categories

### 2.1 Positive — plain mode
- empty input (0 chunks)
- 1 byte
- exactly `chunk_size` (single full chunk)
- `chunk_size + 1` (boundary → 2 chunks, second is 1 byte)
- multi-chunk (e.g. 3 MiB at 1 MiB chunks)
- metadata present: filename (UTF-8, incl. non-ASCII), mime_type, created_at
- metadata with user tags ≥ 0x1000
- no-metadata container

### 2.2 Positive — encrypted mode (fixed key + nonce)
- same size matrix as plain
- with and without metadata (verify metadata stays authenticated, not encrypted), including an
  encrypted empty container with a wrong key

### 2.3 Negative — must reject with exact error id
- bad magic → `ERR_BAD_MAGIC`
- version = 2 → `ERR_UNSUPPORTED_VER`
- hash_algo/aead_algo unknown → `ERR_UNSUPPORTED_ALGO`
- reserved flag bit set → `ERR_RESERVED_BITS`
- inconsistent flags (encrypted=1, aead_algo=0) → `ERR_RESERVED_BITS`
- truncated payload / missing `UBCE` → `ERR_TRUNCATED`
- flipped payload byte → `ERR_ROOT_MISMATCH`
- flipped ciphertext/tag byte → `ERR_CHUNK_AUTH`
- encrypted container, no key → `ERR_MISSING_KEY`
- metadata TLV out-of-order / duplicate tag / length overrun → `ERR_META_MALFORMED`
- oversized length field beyond input → `ERR_TRUNCATED` (DoS guard)
- zero `chunk_size` → `ERR_RESERVED_BITS`; empty metadata block → `ERR_META_MALFORMED`
- trailing bytes after footer → `ERR_TRAILING_DATA`

### 2.4 Metadata ordering
- encoder given unsorted tags MUST emit sorted; duplicate tags MUST be rejected at encode.

---

## 3. Test levels per SDK

1. **Unit** — header/meta/crypto encode-decode in isolation.
2. **Conformance** — run the full vector manifest:
   - `encode(input, options)` bytes == `expected` (byte-exact).
   - `decode(expected)` == `input`.
   - negative vectors raise the specified error id.
3. **Round-trip property** — random inputs/sizes: `decode(encode(x)) == x`.
4. **Cross-decode** — decode containers produced by other SDKs (Go↔Node in Phase 1).

Run the Phase 1 Go↔Node gate after building the Node SDK:

```powershell
npm run build --prefix sdk/node
node scripts/cross-decode.mjs
```

---

## 4. Determinism tests

- Encode the same input twice (plain) → identical bytes.
- Encode across SDKs (plain) → identical bytes.
- Encrypted determinism only holds with a fixed `baseNonce`; production nonces are random
  by design, so encrypted determinism is tested only via fixed-nonce vectors.

---

## 5. CI gates

- No SDK merges without 100% conformance-vector pass.
- Cross-decode job runs across all implemented SDKs.
- Negative vectors must fail with the exact error id (not just "some error").
- Vector changes require an RFC (RFC.md) since they can alter the frozen format.
