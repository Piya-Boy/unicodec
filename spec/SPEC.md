# Universal Binary Container (UBC) — Format Specification

**Version:** 1
**Status:** Draft
**Magic:** `UBC1` / `UBCE`

This document is the normative byte-level specification. Every SDK MUST produce
byte-identical output for identical input and options. When this document and any
SDK disagree, this document wins.

---

## 1. Conventions

- All multi-byte integers are **little-endian (LE)**, unsigned unless stated.
- Fields appear in the exact order listed. No padding, no alignment gaps.
- Byte offsets are relative to the start of the container.
- `SHA-256` refers to FIPS 180-4 SHA-256, producing 32 bytes.
- `AES-256-GCM` refers to NIST SP 800-38D with a 256-bit key, 96-bit nonce, 128-bit (16-byte) tag.
- Keyword meaning (MUST / MUST NOT / SHOULD / MAY) follows RFC 2119.

---

## 2. Container Layout

```
┌──────────────────────────────────────────────┐
│ HEADER                                         │
│ METADATA BLOCK   (present iff flags.bit1 = 1)  │
│ PAYLOAD          (chunk_count chunks)          │
│ FOOTER                                         │
└──────────────────────────────────────────────┘
```

### 2.1 Header

| Offset | Field         | Type       | Size | Notes |
|-------:|---------------|------------|-----:|-------|
| 0      | `magic`       | bytes      | 4    | MUST equal ASCII `UBC1` (`0x55 0x42 0x43 0x31`) |
| 4      | `version`     | uint8      | 1    | MUST equal `1` |
| 5      | `flags`       | uint8      | 1    | see 2.1.1 |
| 6      | `hash_algo`   | uint8      | 1    | plain: `0` = SHA-256 checksum; encrypted: `1` = HMAC-SHA-256 root authentication |
| 7      | `aead_algo`   | uint8      | 1    | `0` = none, `1` = AES-256-GCM. Others reserved |
| 8      | `chunk_size`  | uint32 LE  | 4    | Plaintext bytes per chunk; MUST be nonzero. Readers rely on per-chunk `clen` for framing |
| 12     | `chunk_count` | uint64 LE  | 8    | Number of chunks in payload |
| 20     | `total_size`  | uint64 LE  | 8    | Total plaintext byte length across all chunks |
| 28     | `base_nonce`  | bytes      | 12   | Base nonce for AEAD. MUST be all-zero when `aead_algo = 0` |

Header is a fixed **40 bytes**.

#### 2.1.1 flags (bit 0 = LSB)

| Bit | Name          | Meaning |
|----:|---------------|---------|
| 0   | `encrypted`   | `1` = payload chunks are AES-256-GCM ciphertext+tag |
| 1   | `has_metadata`| `1` = metadata block present |
| 2–7 | reserved      | MUST be `0`. Reader MUST reject if any set |

Consistency rules:
- `encrypted = 1` MUST imply `aead_algo = 1`, `hash_algo = 1`, and `chunk_size <= 0xffff_ffef`.
  `encrypted = 0` MUST imply `aead_algo = 0` and `hash_algo = 0`.
- `encrypted = 0` MUST imply `base_nonce` is all-zero.

### 2.2 Metadata Block

Present only when `flags.has_metadata = 1`.

`meta_len` MUST be nonzero when the block is present.

| Field      | Type      | Size       | Notes |
|------------|-----------|-----------:|-------|
| `meta_len` | uint32 LE | 4          | Byte length of `meta_tlv` |
| `meta_tlv` | bytes     | `meta_len` | Sequence of TLV entries (2.2.1) |

When absent, no bytes are emitted (not even `meta_len`).

#### 2.2.1 TLV Entry

Each entry, repeated until `meta_len` bytes consumed:

| Field    | Type      | Size    | Notes |
|----------|-----------|--------:|-------|
| `tag`    | uint16 LE | 2       | Field identifier (2.2.2) |
| `length` | uint32 LE | 4       | Byte length of `value` |
| `value`  | bytes     | length  | Field payload |

Rules:
- Entries MUST be ordered by ascending `tag`. Duplicate tags MUST NOT appear.
  (Deterministic ordering; readers MUST reject out-of-order or duplicate tags.)
- Unknown tags MUST be preserved on decode and passed through on re-encode, but
  MUST still obey ascending-order and no-duplicate rules.
- A malformed block (empty block, truncated entry, length overruns `meta_len`, invalid reserved
  value) → `ERR_META_MALFORMED`.

#### 2.2.2 Reserved Tags

| Tag    | Name        | Value encoding |
|-------:|-------------|----------------|
| 0x0001 | `filename`  | valid UTF-8 bytes, no BOM, no NUL |
| 0x0002 | `mime_type` | ASCII bytes in `0x01..0x7f` |
| 0x0003 | `created_at`| int64 LE, Unix milliseconds UTC |
| 0x1000+| user-defined| opaque bytes (application-owned) |

### 2.3 Payload

Exactly `chunk_count` chunks, concatenated, no separators:

| Field  | Type      | Size   | Notes |
|--------|-----------|-------:|-------|
| `clen` | uint32 LE | 4      | Byte length of this chunk's `data` |
| `data` | bytes     | `clen` | Chunk body |

- **Plain mode** (`encrypted = 0`): `data` = raw plaintext bytes. `clen` = plaintext length.
- **Encrypted mode** (`encrypted = 1`): `data` = ciphertext followed by the 16-byte
  GCM tag. `clen` = ciphertext length + 16. Plaintext length of the chunk = `clen - 16`.
  `clen < 16` → `ERR_CHUNK_AUTH`.

The sum of plaintext lengths across all chunks MUST equal `total_size`.

Chunking rule for encoders: split plaintext into chunks of `chunk_size` bytes; the
final chunk holds the remainder and MAY be smaller. A zero-length input produces
`chunk_count = 0` and no chunk bytes.

### 2.4 Footer

| Field       | Type  | Size | Notes |
|-------------|-------|-----:|-------|
| `root_hash` | bytes | 32   | see Section 4 |
| `magic_end` | bytes | 4    | MUST equal ASCII `UBCE` (`0x55 0x42 0x43 0x45`) |

Absence of `magic_end` at the expected offset → `ERR_TRUNCATED`.
Bytes after the footer → `ERR_TRAILING_DATA`.

---

## 3. Encryption (AEAD)

Applies only when `flags.encrypted = 1`.

- Algorithm: **AES-256-GCM**. Key is 32 bytes, supplied by the caller. This spec
  defines no key derivation, password handling, or key storage — out of scope for v1.
- **Per-chunk encryption:** each chunk is an independent AEAD operation. Its plaintext
  is encrypted to `data = ciphertext || tag`.
- **Nonce per chunk:** `nonce_i = base_nonce XOR le96(i)`, where `i` is the zero-based
  chunk index and `le96(i)` is `i` encoded as a 12-byte little-endian integer.
  `base_nonce` MUST be generated from a cryptographically secure RNG per container and
  MUST NOT be reused across containers with the same key.
- **AAD per chunk:** `AAD_i = header_bytes || SHA-256(meta_region) || le64(i)`, where
  `header_bytes` is the full 40-byte header, `meta_region` is empty when absent, and
  `le64(i)` is the chunk index. This binds every chunk to the header, metadata, and position.
- Decrypt MUST verify the tag for chunk `i` **before** releasing any of its plaintext.
  A failing tag → `ERR_CHUNK_AUTH`, and no further plaintext is emitted (fail closed).

---

## 4. Integrity (root_hash)

`root_hash` binds header, metadata, and every chunk. First compute:

```
h_i       = SHA-256( chunk_i.data )            # over on-disk bytes (ciphertext+tag if encrypted)
leaf_cat  = h_0 || h_1 || ... || h_(N-1)       # empty if chunk_count = 0
root_input = header_bytes || meta_region || leaf_cat
```

Where:
- `header_bytes` = the 40 header bytes.
- `meta_region` = the exact bytes of the metadata block as serialized (`meta_len` +
  `meta_tlv`) when present; empty when `has_metadata = 0`.
- `h_i` is over `chunk_i.data` (the `clen`-length body), **not** including the `clen` prefix.

For plain containers (`hash_algo = 0`), `root_hash = SHA-256(root_input)`.

For encrypted containers (`hash_algo = 1`), derive `root_key` with HKDF-SHA-256:

```
PRK      = HMAC-SHA-256(base_nonce, encryption_key)
root_key = HMAC-SHA-256(PRK, ASCII("UBC1 root authentication") || 0x01)
root_hash = HMAC-SHA-256(root_key, root_input)
```

Verification recomputes `root_hash` and compares it in constant time for encrypted
containers. Mismatch → `ERR_ROOT_MISMATCH`. This also authenticates the key for an
encrypted zero-chunk container.

The plain SHA-256 root detects accidental corruption only: an active attacker can recompute
it. Encrypted containers use the keyed root plus GCM tags for authenticated confidentiality;
the root still MUST be checked.

---

## 5. Reader Requirements (fail closed)

A conforming reader MUST reject, before emitting any plaintext, when:

| Condition | Error |
|-----------|-------|
| `magic` != `UBC1` | `ERR_BAD_MAGIC` |
| `version` != 1 | `ERR_UNSUPPORTED_VER` |
| `hash_algo` or `aead_algo` unknown | `ERR_UNSUPPORTED_ALGO` |
| any reserved flag bit set | `ERR_RESERVED_BITS` |
| flag/algo/nonce/chunk-size consistency (2.1.1) violated | `ERR_RESERVED_BITS` |
| truncated stream / missing `magic_end` | `ERR_TRUNCATED` |
| `root_hash` mismatch | `ERR_ROOT_MISMATCH` |
| GCM tag failure on a chunk | `ERR_CHUNK_AUTH` |
| `encrypted = 1` but no key supplied | `ERR_MISSING_KEY` |
| malformed metadata TLV | `ERR_META_MALFORMED` |
| bytes after the footer | `ERR_TRAILING_DATA` |

Error identifiers are stable across all SDKs. Each SDK maps them to a language-native
error type but MUST expose the same identifier/code.

**Streaming verification order:** in encrypted mode a reader releases a chunk's
plaintext only after that chunk's GCM tag verifies. `root_hash` covers the whole
container, so a reader performing full verification MUST confirm `root_hash` before
declaring the container valid; a streaming reader MAY release per-chunk plaintext as
tags pass and confirm `root_hash` at end-of-stream, but MUST surface
`ERR_ROOT_MISMATCH` if the final check fails.

When a container has multiple faults, readers apply this precedence order:

1. Header length, magic, version, algorithm, flag, mode-combination, and `chunk_size` validation.
2. Metadata presence, bounds, TLV order, and reserved-value validation.
3. Missing or invalid encryption key.
4. Payload framing and length/cap validation, including a truncated footer.
5. Per-chunk GCM authentication, including encrypted `clen < 16`.
6. Footer root value or root-MAC verification.
7. Trailing-byte detection.

Within a stage, the first condition encountered in wire order wins.

---

## 6. Determinism Requirements

Given identical input bytes and identical options (`chunk_size`, key presence,
metadata entries), every SDK MUST emit byte-identical containers, **except**
`base_nonce` which is random. For reproducible test vectors, encryption vectors fix
`base_nonce` to a specified value (see conformance vectors).

Sources of nondeterminism that MUST be controlled:
- Integer endianness → always LE.
- Field ordering → fixed by this spec.
- Metadata TLV ordering → ascending `tag`, no duplicates.
- No implicit timestamps, no locale, no platform padding.

---

## 7. Versioning & Extensibility

- `version` gates the whole layout. Unknown version → hard fail.
- `hash_algo` / `aead_algo` reserve room for future algorithms without a layout break.
- Reserved flag bits and tags ≥ 0x1000 provide extension space.
- Any future additive change that is not backward-compatible MUST bump `version` and
  the trailing magic (`UBC2` / accordingly).

---

## 8. Conformance

An implementation conforms when it:
1. Produces byte-identical output to the published test vectors for every plain-mode vector.
2. Produces byte-identical output for encryption vectors when `base_nonce` is fixed to the vector's value.
3. Round-trips every vector (decode∘encode = identity on input; encode∘decode = identity on container).
4. Cross-decodes: decodes containers produced by any other conforming SDK.
5. Rejects every negative vector with the specified error identifier.
