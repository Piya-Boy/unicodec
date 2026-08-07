# UBC Change Process (RFC)

How the UBC format and its normative documents change. The format is frozen at the end of
Phase 0 (ROADMAP.md); after that, byte-layout changes go through this process. The point
is stability — implementers must be able to trust that `version 1` means one thing forever.

---

## 1. What requires an RFC

An RFC is required to change anything that affects bytes on the wire or cross-SDK behavior:

- SPEC.md byte layout, field sizes/order, semantics
- Error identifiers or reader accept/reject rules
- Algorithms (hash, AEAD, nonce/AAD construction)
- The shared test vectors (they encode the format)
- Anything that could make two SDKs disagree

Non-normative docs (STORAGE, BENCHMARK numbers, FAQ, wording) can change via ordinary PRs.

---

## 2. Compatibility rules

- **Backward-incompatible layout change** → new `version` value **and** new trailing magic
  (`UBC2`/`UBCE`→`UBC2`/`…`). Readers hard-fail unknown versions, so old readers safely
  reject new containers.
- **Additive, negotiated features** (new `hash_algo`/`aead_algo` id, new reserved tag,
  new reserved flag bit) may extend v1 *only if* an unaware reader still behaves safely:
  unknown algo ids and set-but-unknown flag bits already hard-fail per SPEC.md, so such
  additions are effectively new-version-gated in practice. Prefer a version bump when in
  doubt.
- No silent reinterpretation of existing fields. Ever.

---

## 3. RFC lifecycle

```
Draft → Discussion → Accepted → Implemented → Shipped
                  ↘ Rejected / Withdrawn
```

1. **Draft** — a markdown file `rfcs/NNNN-title.md` with: motivation, exact spec delta,
   compatibility impact, security impact, required vector changes, migration notes.
2. **Discussion** — reviewers weigh determinism, security, and cross-language cost.
3. **Accepted** — maintainers agree; version/magic decision recorded.
4. **Implemented** — SPEC.md updated, vectors added/updated, reference SDKs (Go, Node)
   updated and passing.
5. **Shipped** — released; ROADMAP.md and CHANGELOG updated.

An RFC is not "Implemented" until the reference SDKs pass the new/updated vectors.

---

## 4. RFC template

```
# RFC NNNN: <title>
Status: Draft
## Motivation
## Specification delta        # exact bytes/fields/rules changed
## Version / magic impact
## Security impact
## Vector changes             # which vectors added/changed
## Migration notes
## Alternatives considered
```

---

## 5. Principles

- Determinism and cross-SDK agreement are invariants, not features to trade away.
- Never invent crypto; only adopt standardized, reviewed primitives.
- Prefer a clean version bump over a clever backward-compatible hack.
- Every normative change is proven by vectors before it ships.
