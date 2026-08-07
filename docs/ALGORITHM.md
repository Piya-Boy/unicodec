# UBC Algorithms

Non-normative companion to [`spec/SPEC.md`](../spec/SPEC.md). Explains the *why* and
gives reference pseudocode. Byte layout, field sizes, and error codes are defined by
SPEC.md — this document never redefines them.

---

## 1. Overview

UBC packages arbitrary bytes into one self-contained container with three guarantees:

1. **Lossless** — decode returns the exact input bytes.
2. **Deterministic** — same input + options → byte-identical container (except the
   random `base_nonce` in encrypted mode).
3. **Integrity-verified** — tampering with any byte is detectable via `root_hash`,
   and in encrypted mode via per-chunk AEAD tags.

The container is processed as a stream of fixed-size plaintext chunks, so large files
never need to be fully buffered.

---

## 2. Chunking

Plaintext is split into chunks of `chunk_size` bytes (default 1 MiB). The final chunk
holds the remainder and may be shorter. Zero-length input yields zero chunks.

Rationale for fixed-size chunking over content-defined chunking (CDC):
- CDC (rolling hash boundaries) helps deduplication but makes output depend on content
  in ways that are harder to reproduce identically across languages. UBC v1 favors
  determinism and simplicity. CDC can be a future opt-in mode.

```
def split(plaintext, chunk_size):
    i = 0
    while i < len(plaintext):
        yield plaintext[i : i + chunk_size]
        i += chunk_size
```

`chunk_size` is stored as advisory metadata only. Readers reconstruct chunk boundaries
from each chunk's `clen`, never from the header value — this keeps readers correct even
if a producer used a nonstandard size.

---

## 3. Integrity: per-chunk hash + bound root

UBC uses a **one-level hash** (flat Merkle): each chunk is hashed, and the root hashes
the header, metadata, and the concatenation of chunk hashes.

```
h_i      = SHA-256(chunk_i.data)          # data = on-disk bytes (ciphertext+tag if encrypted)
leaf_cat = h_0 || h_1 || ... || h_(N-1)   # empty when N = 0
root     = SHA-256(header_bytes || meta_region || leaf_cat)
```

Why this shape:
- **Streaming-friendly:** a reader hashes each chunk as it arrives; no need to buffer
  the whole payload to verify.
- **Locates corruption:** a bad `h_i` identifies which chunk is damaged.
- **Binds structure:** including `header_bytes` and `meta_region` stops an attacker from
  flipping flags, editing metadata, or changing `chunk_count` while keeping a valid root.
  (A naive design that hashes only chunk bodies leaves the header/metadata unauthenticated.)

Why **not** a full binary Merkle tree in v1:
- A full tree buys partial/random-access verification, which is not a v1 goal.
- Full trees add cross-language divergence risk (leaf/node domain separation, odd-node
  duplication rules — the classic CVE-2012-2459 footgun). Flat hashing removes those
  ambiguities. A full tree can be introduced later behind a `version` bump.

Hashing over `data` (post-encryption bytes) rather than plaintext lets a reader verify
the container's integrity without holding the key — useful for storage/transit checks.

---

## 4. Encryption: per-chunk AES-256-GCM

When `encrypted = 1`, each chunk is sealed independently:

```
nonce_i = base_nonce XOR le96(i)          # 12-byte LE index XORed into base nonce
aad_i   = header_bytes || le64(i)         # binds chunk to header + position
ct_i, tag_i = AES_256_GCM_Seal(key, nonce_i, aad_i, plaintext_i)
data_i  = ct_i || tag_i                   # tag is 16 bytes
```

Design decisions:
- **Per-chunk sealing** (not one tag over the whole payload) keeps true streaming safe:
  a decryptor verifies `tag_i` before releasing chunk `i`'s plaintext, so no unverified
  bytes ever leave the SDK.
- **Nonce = base XOR index** gives a unique nonce per chunk without storing 12 bytes per
  chunk. `base_nonce` is random per container (CSPRNG); reusing a (key, nonce) pair in
  GCM is catastrophic, so `base_nonce` MUST NOT be reused across containers under one key.
- **AAD binds header + index**, preventing chunk reordering, truncation-as-valid, and
  header tampering from producing a container that still authenticates.

Key management (derivation, passwords, storage, rotation) is deliberately **out of scope**
for v1. The SDK takes a raw 32-byte key from the caller. See SECURITY.md.

---

## 5. Encode pipeline

```
1. Serialize metadata TLV (ascending tag, no dups) → meta_region (or empty)
2. Choose base_nonce (random) if encrypted, else zero
3. Build header_bytes (40 bytes) with counts/sizes/flags/algos
4. For each chunk i:
     plaintext_i = next chunk
     if encrypted: data_i = seal(i, plaintext_i); else data_i = plaintext_i
     h_i = SHA-256(data_i)
     emit [clen=len(data_i)][data_i]
5. root = SHA-256(header_bytes || meta_region || h_0..h_{N-1})
6. emit footer [root][UBCE]
```

`chunk_count`, `total_size`, and (for encrypted) `base_nonce` must be known when the
header is written. A streaming encoder that cannot know `chunk_count`/`total_size` up
front MAY buffer counts or reserve+backfill the header; either way the emitted bytes MUST
match a single-pass encoder for the same input (determinism requirement).

---

## 6. Decode / verify pipeline

```
1. Read + validate header (magic, version, flags, algos, consistency) → else error
2. Read metadata block if present → meta_region
3. running_leaf_hash = SHA-256 init; feed header_bytes, meta_region
4. For each chunk i in 0..chunk_count-1:
     read [clen][data_i]
     h_i = SHA-256(data_i); feed h_i into running root computation
     if encrypted: verify tag_i (AAD_i); on fail → ERR_CHUNK_AUTH (stop, fail closed)
     release plaintext_i (raw or decrypted)
5. Read footer; require magic_end else ERR_TRUNCATED
6. Compare recomputed root vs stored root_hash → mismatch = ERR_ROOT_MISMATCH
```

Verify-only mode runs the same pipeline but never releases plaintext — it only reports
whether tags and root check out.

---

## 7. Determinism checklist

Every SDK MUST guarantee:
- little-endian integers everywhere;
- fixed field order (per SPEC.md);
- metadata entries sorted by ascending tag, duplicates rejected;
- no timestamps/locale/platform padding injected implicitly;
- identical chunk boundaries for identical `chunk_size`.

The only permitted per-run variation is `base_nonce`. Test vectors fix `base_nonce` so
encrypted output is reproducible.
