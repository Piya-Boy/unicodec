# UBC v1 Conformance Vectors

`vectors.json` is the shared contract for every SDK. Positive entries reference an input,
encode options, and an expected container. Negative entries reference a deliberately invalid
container and the exact `expectError` a decoder must report. Every expected artifact has a
SHA-256 in the manifest.

Regenerate the contract with:

```powershell
go run ./tools/vectorgen
```

Verify that checked-in artifacts match the canonical generator with:

```powershell
go run ./tools/vectorgen -check
```

The fixed encryption key and base nonce are conformance-only values and must never be used
for production data.
