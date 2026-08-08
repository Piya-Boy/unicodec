# UBC — Universal Binary Container

One self-contained byte format for packaging binary data plus metadata, with built-in
integrity and optional AES-256-GCM encryption, producing **byte-identical output across
every language**.

> Status: **Phase 0 — Specification.** No SDK code yet. The format and docs are being
> frozen before reference implementations begin.

## Why

Modern systems pass binary data between services in many languages, each reimplementing
encoding, validation, and storage. UBC replaces that with one spec, one container, one
consistent developer experience. See [docs/PRD.md](./docs/PRD.md).

## What UBC guarantees

- **Lossless** — decode returns the exact input bytes.
- **Deterministic** — same input + options → identical container across languages.
- **Integrity** — tamper/corruption detected via a header/metadata-bound root hash.
- **Optional confidentiality** — per-chunk AES-256-GCM, verified before plaintext release.
- **Streaming-first** — memory bounded by chunk size, not file size.

## Documentation

| Doc | Purpose |
|-----|---------|
| [spec/SPEC.md](./spec/SPEC.md) | **Normative** byte format (source of truth) |
| [docs/ALGORITHM.md](./docs/ALGORITHM.md) | Hashing, chunking, encryption reasoning |
| [docs/SECURITY.md](./docs/SECURITY.md) | Threat model, crypto choices, scope |
| [docs/API.md](./docs/API.md) | Language-neutral API contract |
| [docs/SDK.md](./docs/SDK.md) | Go + Node reference SDK guidance |
| [docs/STORAGE.md](./docs/STORAGE.md) | Storing/transporting containers |
| [docs/TESTING.md](./docs/TESTING.md) | Conformance vectors = the contract |
| [docs/BENCHMARK.md](./docs/BENCHMARK.md) | Performance metrics + method |
| [docs/ROADMAP.md](./docs/ROADMAP.md) | Phased delivery plan |
| [docs/RFC.md](./docs/RFC.md) | Format change process |
| [docs/FAQ.md](./docs/FAQ.md) | Design rationale Q&A |
| [AGENTS.md](./AGENTS.md) | Autonomous agent build loop |

## Building with AI agents

This project is built via [loop engineering](https://addyosmani.com/blog/loop-engineering/):
agents implement, test, and verify against shared vectors with a strict maker ≠ checker
split. See [AGENTS.md](./AGENTS.md) and [docs/ROADMAP.md](./docs/ROADMAP.md).

## License

TBD.
