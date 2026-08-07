# UBC Security Model

Non-normative companion to [`spec/SPEC.md`](../spec/SPEC.md). Describes the threat model,
what UBC protects, what it deliberately does not, and the reasoning behind the crypto
choices. Error identifiers and byte layout are defined by SPEC.md.

---

## 1. Security goals

| Goal | Mechanism |
|------|-----------|
| Integrity / tamper detection | `root_hash` binds header + metadata + all chunk hashes |
| Confidentiality (optional) | AES-256-GCM per chunk |
| Authenticity of encrypted data | GCM tag per chunk, AAD binds header + chunk index |
| Fail-closed decoding | Reject before releasing plaintext on any check failure |
| Deterministic, auditable format | No hidden fields, no ambient state |

UBC follows one rule: **never invent cryptographic primitives.** It uses SHA-256 and
AES-256-GCM — standardized, widely reviewed, present in every target language's standard
or well-vetted library.

---

## 2. Threat model

### In scope (UBC defends)

- **Tampering at rest / in transit.** Any byte flip in header, metadata, or payload is
  detected: `root_hash` for all modes; GCM tag for encrypted payloads.
- **Chunk reordering / truncation.** AAD binds each chunk to its index and the header;
  the root binds `chunk_count`. Reordered or dropped chunks fail authentication or root.
- **Header/metadata substitution.** Header and metadata are inside `root_hash` and (in
  encrypted mode) inside every chunk's AAD, so they cannot be swapped silently.
- **Downgrade via version/algo confusion.** Unknown `version`/`hash_algo`/`aead_algo`
  and any set reserved bit cause a hard fail (`ERR_UNSUPPORTED_*` / `ERR_RESERVED_BITS`).
- **Partial-plaintext leakage on corruption.** Decrypt verifies each chunk's tag before
  emitting its plaintext; a failure stops output (fail closed).

### Out of scope (v1)

- **Key management.** No key derivation, password handling, key storage, or rotation.
  The caller supplies a raw 32-byte key. Protecting that key is the application's job.
- **Confidentiality of metadata in encrypted mode.** Header and metadata block are
  **not encrypted** (they are authenticated). Filenames, MIME types, sizes are visible.
  Applications needing metadata secrecy must place sensitive data inside the payload.
- **Length hiding.** `total_size` and chunk lengths reveal plaintext size. No padding
  scheme in v1.
- **Access control, authentication of principals, authorization.** Application concern.
- **Denial of service from hostile inputs** beyond basic bounds checks (see §5).
- **Side-channel resistance** beyond what the underlying crypto library provides.

---

## 3. Cryptographic choices

### 3.1 Hash — SHA-256

- In every target stdlib; zero external dependency; guarantees identical bytes across
  all SDKs (a hard requirement for the determinism goal).
- `hash_algo` field reserves room for BLAKE3 etc. later, but v1 ships SHA-256 only so
  no SDK depends on a third-party hash whose version could drift.

### 3.2 AEAD — AES-256-GCM

- Standard authenticated encryption; hardware-accelerated (AES-NI) on common CPUs;
  present in Go `crypto/aes`+`cipher`, Node `crypto`, Python `cryptography`, Java JCE,
  .NET, Rust `aes-gcm`.
- 96-bit nonce, 128-bit tag (SP 800-38D recommended sizes).

### 3.3 Nonce discipline

- `base_nonce` is generated per container from a CSPRNG and stored in the header.
- Per-chunk nonce = `base_nonce XOR le96(index)`.
- **GCM nonce reuse under the same key is catastrophic** (leaks keystream, forges tags).
  Requirements:
  - A given `base_nonce` MUST be used for only one container per key.
  - Encoders MUST source `base_nonce` from a cryptographically secure RNG.
  - Test vectors that fix `base_nonce` are for conformance only and MUST NOT be reused
    on real data under a real key.
- Chunk count per container is bounded by the 96-bit nonce space in principle; in
  practice `chunk_count` (uint64) and realistic file sizes stay far below any risk.

### 3.4 AAD binding

`AAD_i = header_bytes || le64(i)`. This authenticates the entire header and the chunk's
position with every chunk, so an attacker cannot:
- change algorithms/flags/sizes in the header (breaks all chunk tags),
- reorder or splice chunks between containers (index / header mismatch).

---

## 4. Fail-closed guarantees

A conforming reader MUST NOT emit any plaintext derived from data that has not yet
passed its integrity check:

- Encrypted mode: chunk plaintext is released only after its GCM tag verifies.
- All modes: a full verification MUST confirm `root_hash`. A streaming reader may emit
  per-chunk plaintext as tags pass but MUST raise `ERR_ROOT_MISMATCH` at end if the root
  fails, and callers relying on whole-container integrity SHOULD use verify-before-use
  (two-pass) for untrusted inputs.

The error identifiers (`ERR_ROOT_MISMATCH`, `ERR_CHUNK_AUTH`, `ERR_TRUNCATED`, …) are
defined in SPEC.md §5 and are stable across SDKs.

---

## 5. Robustness against hostile containers

Readers parse attacker-controlled bytes and MUST bound resource use:

- Validate `meta_len`, `clen`, `chunk_count`, `total_size` against the actual available
  input before allocating. Reject values that exceed remaining bytes → `ERR_TRUNCATED`
  or `ERR_META_MALFORMED`.
- Do not pre-allocate buffers sized by an untrusted length field without a sanity cap;
  stream instead. SDKs SHOULD expose a configurable max sizes (e.g. max metadata bytes,
  max chunk size) for untrusted input.
- Reject a metadata block whose TLV entries overrun `meta_len` or violate ascending /
  no-duplicate tag order.

These are implementation requirements for Codex to honor; they protect against
memory-exhaustion DoS from crafted headers.

---

## 6. Cross-language consistency as a security property

Divergent behavior between SDKs is itself a security risk: a container accepted by one
SDK and rejected (or differently parsed) by another enables confusion attacks. The
conformance suite (see TESTING.md) — shared test vectors, negative vectors with exact
error identifiers, and cross-decode tests — is therefore part of the security surface,
not just quality assurance.

---

## 7. Future security work (post-v1)

- Key management module: KDF (e.g. HKDF), password-based keys (Argon2id), key wrapping.
- Digital signatures (detached / embedded) for publisher authenticity.
- Optional metadata encryption and length padding for size/metadata privacy.
- Additional AEAD (ChaCha20-Poly1305) via `aead_algo`.
- Optional full Merkle tree for partial verification via a `version` bump.
