# UBC API Contract

Language-neutral API surface. Every SDK exposes these operations with identical
semantics; naming follows each language's idioms (see SDK.md). Byte format and error
identifiers are defined by [`spec/SPEC.md`](../spec/SPEC.md).

---

## 1. Operations

UBC exposes four verbs, each in a **one-shot** (in-memory) and a **streaming** form.

| Verb    | Purpose |
|---------|---------|
| encode  | Package bytes → UBC container |
| decode  | UBC container → original bytes (+ metadata) |
| verify  | Check integrity/auth without releasing plaintext |
| inspect | Read header + metadata without touching payload |

### 1.1 encode

```
encodeBytes(data: bytes, meta: Metadata?, opts: EncodeOptions) -> bytes
newEncoder(sink: Writer, meta: Metadata?, opts: EncodeOptions) -> Encoder
  Encoder.write(p: bytes)      # append plaintext; may be called repeatedly
  Encoder.close()              # finalize: flush chunks, write footer
```

### 1.2 decode

```
decodeBytes(container: bytes, opts: DecodeOptions) -> (data: bytes, meta: Metadata)
newDecoder(source: Reader, opts: DecodeOptions) -> Decoder
  Decoder.read(p: bytes) -> n  # streamed plaintext; released only after per-chunk auth
  Decoder.meta() -> Metadata   # available after header/metadata parsed
```

### 1.3 verify

```
verify(source: Reader, opts: VerifyOptions) -> VerifyReport
```

Runs the full decode pipeline but never emits plaintext. Reports whether tags and
`root_hash` check out, and which chunk failed if any.

### 1.4 inspect

```
inspect(source: Reader) -> ContainerInfo   # header fields + metadata, no payload read
```

---

## 2. Types

### 2.1 EncodeOptions

| Field       | Type       | Default | Notes |
|-------------|------------|---------|-------|
| `key`       | bytes(32)? | none    | Present → encrypted mode (AES-256-GCM). Absent → plain mode |
| `chunkSize` | uint32     | 1 MiB   | Advisory; must be > 0 |
| `baseNonce` | bytes(12)? | random  | Test/reproducibility only. Production MUST leave unset (random per container) |

Supplying `baseNonce` in production is a misuse hazard (nonce reuse). SDKs SHOULD gate
it behind an explicitly-named "unsafe/deterministic" option.

### 2.2 DecodeOptions / VerifyOptions

| Field         | Type       | Default | Notes |
|---------------|------------|---------|-------|
| `key`         | bytes(32)? | none    | Required iff container is encrypted; else `ERR_MISSING_KEY` |
| `maxMetaBytes`| uint       | impl    | Cap for untrusted metadata (DoS guard) |
| `maxChunkLen` | uint       | impl    | Cap for untrusted chunk length (DoS guard) |

### 2.3 Metadata

Ordered map of `tag -> value`. Reserved tags (SPEC.md §2.2.2): `filename`, `mime_type`,
`created_at`. User tags ≥ 0x1000. SDKs provide typed accessors for reserved tags and a
raw map for the rest. On encode, SDK sorts by tag and rejects duplicates.

### 2.4 VerifyReport

```
{ ok: bool, error: ErrorId?, failedChunk: uint64? }
```

### 2.5 ContainerInfo

```
{ version, flags{encrypted,hasMetadata}, hashAlgo, aeadAlgo,
  chunkSize, chunkCount, totalSize, metadata }
```

---

## 3. Errors

Every operation surfaces the stable error identifiers from SPEC.md §5
(`ERR_BAD_MAGIC`, `ERR_UNSUPPORTED_VER`, `ERR_UNSUPPORTED_ALGO`, `ERR_RESERVED_BITS`,
`ERR_TRUNCATED`, `ERR_ROOT_MISMATCH`, `ERR_CHUNK_AUTH`, `ERR_MISSING_KEY`,
`ERR_META_MALFORMED`). Each SDK maps them onto a native error type but exposes the same
identifier so callers can branch portably.

---

## 4. Semantic guarantees

- `decode(encode(x)) == x` for all inputs (lossless round-trip).
- `encode` is deterministic given identical options, except random `baseNonce`.
- No operation emits plaintext that has not passed its integrity check (fail closed).
- `verify` and `inspect` never mutate input and never release plaintext.
- Streaming and one-shot forms produce/accept byte-identical containers.
