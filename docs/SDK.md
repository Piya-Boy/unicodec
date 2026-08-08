# UBC SDKs

Per-language guidance for the two reference SDKs (Go, Node.js). Both implement the
language-neutral contract in [API.md](./API.md) against [`spec/SPEC.md`](../spec/SPEC.md)
and MUST pass the shared conformance vectors (see [TESTING.md](./TESTING.md)).

Reference SDKs are the source of truth for behavior; the remaining SDKs
(Python, PHP, Java, .NET, Rust, React/Next/Nest wrappers) port from them and the vectors.

---

## 1. Reference SDKs

| SDK  | Package (proposed) | Role |
|------|--------------------|------|
| Go   | `github.com/ubc/go` | Canonical generator for test vectors; strict byte control |
| Node | `@ubc/node`         | Dynamic-language reference; surfaces JS integer/Buffer quirks |

---

## 2. Go SDK

### Layout
```
sdk/go/
  payload.go         # one-shot plain encoder: EncodePlain
  crypto.go          # encrypted encoders: EncodeEncrypted (+ fixed-nonce test helper)
  decode.go          # one-shot decoder: DecodeBytes
  encoder.go         # streaming Encoder (io.Writer sink)
  decoder.go         # streaming Decoder (io.Reader source)
  verify.go          # Verify and VerifyReport
  inspect.go         # Inspect and ContainerInfo
  header.go         # header encode/decode + validation
  meta.go           # TLV encode/decode, ordering/dup checks
  errors.go         # ErrBadMagic ... mapped to stable identifiers
  *_test.go         # vector-backed unit and streaming tests
```

### Idioms
- Streaming via `io.Reader` / `io.Writer`. `Encoder` implements `io.WriteCloser`,
  `Decoder` implements `io.Reader`.
- Errors are package-level `*Error` sentinel values (for example `ErrRootMismatch`)
  carrying a stable `ErrorCode`; callers use `errors.Is` and `ErrorCodeOf`.
- Integers via `encoding/binary` LittleEndian. No `unsafe`.
- Crypto from `crypto/sha256`, `crypto/aes`, `crypto/cipher` (stdlib only).
- Zero third-party runtime dependencies.

### Example
```go
entries := []ubc.MetadataEntry{{Tag: 1, Value: []byte("report.pdf")}}
c, _ := ubc.EncodeEncrypted(data, key, entries, 1<<20)
out, meta, _ := ubc.DecodeBytes(c, ubc.DecodeOptions{Key: key})
```

### Exported surface

- One-shot encoding: `EncodePlain`, `EncodeEncrypted`; deterministic
  `EncodeEncryptedWithFixedNonce` is for tests/conformance only.
- Streaming: `NewEncoder(sink io.Writer, entries []MetadataEntry, options EncodeOptions)`;
  the returned `Encoder` implements `io.WriteCloser`.
- One-shot decoding: `DecodeBytes(container []byte, options DecodeOptions)` returns
  `([]byte, []MetadataEntry, error)`.
- Streaming: `NewDecoder(source io.Reader, options DecodeOptions)`; the returned
  `Decoder` implements `io.Reader` and exposes `Metadata() []MetadataEntry`.
- Verification: `Verify(source io.Reader, options DecodeOptions) VerifyReport`. There is
  no Go `VerifyOptions` type; `VerifyReport` has `OK bool` and `Error ErrorCode`.
- Inspection: `Inspect(source io.Reader) (ContainerInfo, error)` reads only header and
  metadata. `ContainerInfo.Metadata` is `[]MetadataEntry`; `ChunkCount` and `TotalSize`
  are `uint64`.

---

## 3. Node.js SDK

### Layout
```
sdk/node/
  src/index.ts      # public API, codec, stream classes, metadata, and errors
  test/conformance.test.ts
```

### Idioms
- TypeScript, compiled to ESM + CJS. `Buffer`/`Uint8Array` for byte data.
- Streaming via `node:stream` (`Writable` encoder, `Readable` decoder).
- **Integer hazard:** `chunk_count` and `total_size` are uint64. JS `number` is safe only
  to 2^53. Use `BigInt` for these fields end-to-end; never round-trip them through
  `number`. This is the primary cross-language trap the Node reference exists to catch.
- Crypto from `node:crypto` (`createHash('sha256')`, `createCipheriv('aes-256-gcm')`).
- Errors: single `UbcError extends Error` with `.code` = stable identifier.

### Example
```ts
const c = encodeBytes(data, { filename: "report.pdf" }, { key });
const { data: out, meta } = decodeBytes(c, { key });
```

### Exported surface

- `encodeBytes(data: Uint8Array, metadata?: MetadataInput, options?: EncodeOptions): Buffer`.
- `decodeBytes(containerBytes: Uint8Array, options?: DecodeOptions): { data: Buffer; meta: Metadata }`.
- `newEncoder(sink: Writable, metadata?: MetadataInput, options?: EncodeOptions): Encoder`;
  `Encoder` extends `Writable`.
- `newDecoder(source: Readable, options?: DecodeOptions): Decoder`; `Decoder` extends
  `Transform` (a readable decoded-output stream).
- `verify(container: Uint8Array, options?: DecodeOptions): VerifyReport` and
  `verifyStream(source: Readable, options?: DecodeOptions): Promise<VerifyReport>`.
- `inspect(containerBytes: Uint8Array, options?: Pick<DecodeOptions, "maxMetaBytes">):
  ContainerInfo` and `inspectStream(source: Readable, options?:
  Pick<DecodeOptions, "maxMetaBytes">): Promise<ContainerInfo>`.

---

## 4. Shared requirements (all SDKs)

- Pass 100% of conformance vectors (plain + fixed-nonce encrypted) byte-exact.
- Round-trip and cross-decode with every other SDK.
- Expose the same error identifiers (API.md §3).
- Enforce DoS caps on untrusted length fields (SECURITY.md §5).
- No proprietary crypto; stdlib/vetted libs only.

---

## 5. Porting checklist (future SDKs)

1. Implement header/meta/payload/footer per SPEC.md, LE integers, fixed order.
2. Implement SHA-256 plain roots, HMAC-SHA-256 encrypted roots, and per-chunk AES-256-GCM per SPEC.md.
3. Handle 64-bit fields with a real 64-bit type (language-appropriate).
4. Wire the shared vectors as the test suite; do not write bespoke expectations.
5. Map errors to the stable identifiers.
