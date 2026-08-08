# RFC 0001: Authenticated encrypted roots and canonical v1 grammar

Status: Draft

## Motivation

The current draft defines `root_hash` as an unkeyed SHA-256 digest. It detects
accidental corruption but an active attacker can recompute it. In encrypted
containers, per-chunk AES-GCM authenticates only `header_bytes || le64(i)`, so
metadata can be altered and the root recomputed without causing a tag failure.
An encrypted empty container has no AEAD operation, so any 32-byte key is
accepted when its unkeyed root matches.

These properties contradict the draft security model's claims that encrypted
metadata is authenticated and that the root detects tampering. This RFC fixes
the encrypted-mode authentication gap, accurately scopes plain mode, and makes
the reader grammar canonical before v1 is frozen.

## Specification delta

### Header integrity algorithm

The byte layout remains 40 bytes. Reinterpret `hash_algo` as the root integrity
algorithm:

| Value | Name | Allowed mode |
|------:|------|--------------|
| `0` | SHA-256 checksum | plain only |
| `1` | HMAC-SHA-256 root authentication | encrypted only |

All other values are unsupported and fail with `ERR_UNSUPPORTED_ALGO`. A mode
and `hash_algo` combination outside this table fails with `ERR_RESERVED_BITS`.

Plain containers continue to compute:

```
root_hash = SHA-256(header_bytes || meta_region || leaf_cat)
```

This is an accidental-corruption checksum, not an authenticity or active-tamper
guarantee. The security model must not claim otherwise.

For encrypted containers, derive a root-MAC key with HKDF-SHA-256 as specified
by RFC 5869. All values below are raw bytes; `info` is the 24 ASCII bytes of
`UBC1 root authentication` without a terminator:

```
PRK      = HMAC-SHA-256(base_nonce, encryption_key)
root_key = HMAC-SHA-256(PRK, info || 0x01)

root_hash = HMAC-SHA-256(root_key, header_bytes || meta_region || leaf_cat)
```

The output length is 32 bytes, so HKDF-Expand emits exactly `T(1)` and no
additional blocks. With the current vector key
`000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f` and
base nonce `f0e0d0c0b0a0908070605040`, `root_key` is
`52c04b400d73df15d8a0db6ba58919f46fe822fff200fb50d8dee097af3c688c`.
The regenerated shared vectors MUST include this known-answer assertion.

`root_hash` remains the existing 32-byte footer field; the field name in the
specification should become `root_auth` to reflect its conditional semantics.
This RFC deliberately uses HKDF for internal key separation, not for password
handling or caller key derivation.

Readers MUST compare the computed and stored encrypted root values with a
constant-time equality primitive.

### AEAD associated data

For encrypted containers, replace the current AAD construction with:

```
metadata_hash = SHA-256(meta_region)
AAD_i = header_bytes || metadata_hash || le64(i)
```

`meta_region` is the exact serialized metadata block, including `meta_len`, or
the empty byte string when metadata is absent. The fixed 32-byte
`metadata_hash` avoids repeating attacker-controlled metadata in every chunk's
AAD while binding its exact bytes through SHA-256. Its collision-resistance is
the same assumption already used for `leaf_cat`.

The root MAC authenticates encrypted empty containers. Including metadata in
every chunk's AAD also makes metadata authentication fail before releasing the
first encrypted chunk's plaintext.

### Canonical reader grammar

Add these rules and exact errors:

- `chunk_size` MUST be greater than zero. A zero value fails with
  `ERR_RESERVED_BITS`.
- In encrypted mode, `chunk_size` MUST be at most `0xffff_ffef`, so ciphertext
  plus its 16-byte tag always fits `clen`. An encrypted `clen` smaller than 16
  bytes fails with `ERR_CHUNK_AUTH` after its declared body is available.
- `has_metadata = 1` MUST have `meta_len > 0`; an empty metadata block fails
  with `ERR_META_MALFORMED`.
- Encoder and decoder both validate reserved metadata values. `filename` is a
  well-formed UTF-8 byte sequence, does not start `ef bb bf`, and contains no
  `00` byte. `mime_type` contains only bytes in `01..7f`. `created_at` is
  exactly 8 bytes. A violation fails with `ERR_META_MALFORMED`.
- One-shot decoding and verification require the footer to be the final input
  bytes. Trailing bytes fail with the new stable identifier `ERR_TRAILING_DATA`.
  A streaming decoder likewise fails if its container source supplies bytes
  after the footer; concatenated containers require an outer framing protocol.
- One-shot decode and verify release no plaintext until full verification
  succeeds. A streaming decoder MAY release an encrypted chunk after its GCM
  tag verifies, and MAY release a plain chunk before the final checksum; it
  MUST surface final root failure at end-of-stream. Callers that require
  whole-container validity before use MUST use verify-before-use.

When a container has multiple faults, readers apply this precedence order:

1. Header length, magic, version, algorithm, flag, mode-combination, and
   `chunk_size` validation.
2. Metadata presence, bounds, TLV order, and reserved-value validation.
3. Missing or invalid encryption key.
4. Payload framing and length/cap validation, including a truncated footer.
5. Per-chunk GCM authentication, including encrypted `clen < 16`.
6. Footer root value or root-MAC verification.
7. Trailing-byte detection.

Within a stage, the first condition encountered in wire order wins. This order
is part of the stable cross-SDK error contract.

## Version / magic impact

Before acceptance, a maintainer records a release audit covering Git tags,
published packages, released vectors, documentation examples, and known
downstream consumers. If it confirms no draft artifact is a compatibility
commitment, this RFC retains `version = 1` and `UBC1` / `UBCE`, and all draft
vectors are regenerated together. Otherwise this incompatible semantic change
MUST use a new version and magic under the normal RFC process.

## Security impact

- Encrypted metadata becomes authenticated by both GCM and the footer MAC.
- Encrypted empty containers authenticate the supplied key through the footer
  MAC.
- Root-key derivation provides domain separation from the AES-GCM encryption
  key.
- Plain mode is explicitly non-authenticating. Applications needing active
  tamper resistance for unencrypted data must use encryption, an application
  MAC, or a future signature feature.
- The grammar rules remove cross-SDK ambiguity for header, metadata, footer,
  and input boundaries. Byte-identical re-encoding applies only when the
  original encode options, including a deterministic nonce where encrypted, are
  supplied; readers are not required to preserve arbitrary noncanonical chunk
  boundaries.

## Vector changes

- Regenerate every encrypted expected container with `hash_algo = 1`, the new
  AAD, and the root MAC.
- Keep plain vectors byte-identical except where a new grammar-negative case is
  introduced.
- Add negatives for: encrypted metadata changed from one semantically valid
  filename to another and paired with a recomputed legacy SHA-256 root, wrong
  key on encrypted empty input, zero or oversized encrypted chunk size,
  encrypted `clen < 16`, empty metadata block, malformed reserved metadata
  values, and trailing bytes.
- Assert `ERR_CHUNK_AUTH` for the semantically valid encrypted metadata change
  when a payload chunk exists, `ERR_ROOT_MISMATCH` for a wrong key on encrypted
  empty input, and `ERR_TRAILING_DATA` for trailing bytes.
- Add the HKDF root-key known-answer vector stated above and constant-time root
  comparison tests for both reference SDKs.

## Migration notes

After acceptance, the Go generator, Go SDK, Node SDK, shared vectors, and
cross-decode gate change in one coordinated branch. Existing draft containers
are not accepted by the new encrypted reader rules.

No application data migration is required because v1 is not frozen or released.

## Alternatives considered

1. Add only metadata to GCM AAD. Rejected: encrypted empty containers still do
   not authenticate the key.
2. Add a separate footer GCM tag. Rejected: it changes footer layout and adds a
   second nonce/operation design when the existing 32-byte root field can carry
   an authenticated root.
3. Use HMAC-SHA-256 directly with the AES key. Rejected: HKDF gives explicit,
   portable domain separation at negligible cost.
4. Provide active-tamper protection for plain mode. Deferred: without a caller
   key or signer, an unkeyed digest cannot authenticate. Introducing either
   belongs to a separately designed key-management or signature feature.

## Acceptance criteria

- A maintainer records the required release audit and chooses whether the draft
  can retain v1 or must receive a new version and magic.
- Maintainers accept the plain-mode security boundary, encrypted root-MAC
  construction, AAD metadata digest, error precedence, and grammar rules.
- After acceptance, implementation is complete only when `SPEC.md`,
  `SECURITY.md`, `API.md`, and `SDK.md` agree; Go and Node pass regenerated
  vectors and cross-decode; and a fresh security checker confirms the new
  negative cases.
