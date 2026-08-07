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
  ubc.go            # public API: EncodeBytes, DecodeBytes, Verify, Inspect
  encoder.go        # streaming Encoder (io.Writer sink)
  decoder.go        # streaming Decoder (io.Reader source)
  header.go         # header encode/decode + validation
  meta.go           # TLV encode/decode, ordering/dup checks
  crypto.go         # SHA-256 root, AES-256-GCM per-chunk seal/open
  errors.go         # ErrBadMagic ... mapped to stable identifiers
  ubc_test.go       # conformance runner over spec/vectors
```

### Idioms
- Streaming via `io.Reader` / `io.Writer`. `Encoder` implements `io.WriteCloser`,
  `Decoder` implements `io.Reader`.
- Errors are package-level sentinel values (`var ErrRootMismatch = errors.New(...)`)
  wrapping a stable `Code` field; callers use `errors.Is`.
- Integers via `encoding/binary` LittleEndian. No `unsafe`.
- Crypto from `crypto/sha256`, `crypto/aes`, `crypto/cipher` (stdlib only).
- Zero third-party runtime dependencies.

### Example
```go
c, _ := ubc.EncodeBytes(data, ubc.Meta{Filename: "report.pdf"}, ubc.EncodeOptions{Key: key})
out, meta, _ := ubc.DecodeBytes(c, ubc.DecodeOptions{Key: key})
```

---

## 3. Node.js SDK

### Layout
```
sdk/node/
  src/index.ts      # public API
  src/encoder.ts    # stream.Writable-based encoder
  src/decoder.ts    # stream.Readable-based decoder
  src/header.ts
  src/meta.ts
  src/crypto.ts     # node:crypto sha256 + aes-256-gcm
  src/errors.ts     # UbcError with stable .code
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
2. Implement flat-root SHA-256 and per-chunk AES-256-GCM per ALGORITHM.md.
3. Handle 64-bit fields with a real 64-bit type (language-appropriate).
4. Wire the shared vectors as the test suite; do not write bespoke expectations.
5. Map errors to the stable identifiers.
