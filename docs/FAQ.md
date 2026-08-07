# UBC FAQ

Common questions and the reasoning behind key design choices. Non-normative;
[`spec/SPEC.md`](../spec/SPEC.md) is authoritative.

---

**What is UBC in one sentence?**
A single, self-contained byte format that packages binary data plus metadata with built-in
integrity (and optional encryption), producing byte-identical output across every language.

**Why one container instead of separate metadata + file storage?**
To remove the class of bugs that come from keeping them apart: orphaned files, dangling DB
references, split backups, temp-file leaks. One blob moves, backs up, and restores as a
unit. See STORAGE.md.

**How is "identical output across languages" actually guaranteed?**
Three things: a byte-exact spec (little-endian, fixed field order, canonical TLV), only
stdlib primitives (SHA-256, AES-256-GCM) that behave identically everywhere, and a shared
conformance vector suite every SDK must match byte-for-byte. See TESTING.md.

**Why SHA-256 and not BLAKE3?**
SHA-256 is in every target language's standard library, so all SDKs hash identically with
zero third-party dependency. BLAKE3 is faster but not universally in stdlib, risking
version drift and breaking the determinism guarantee. The `hash_algo` field reserves room
to add BLAKE3 later. See SECURITY.md §3.

**Why AES-256-GCM?**
Standard authenticated encryption, hardware-accelerated, and present in every target
language. UBC never invents crypto.

**Why per-chunk encryption instead of one tag over the whole file?**
So streaming decryption stays safe: each chunk's tag is verified before its plaintext is
released, meaning no unverified bytes ever leave the SDK. A single whole-file tag would
force buffering the entire file before any output. See ALGORITHM.md §4.

**Is the metadata encrypted?**
No. In encrypted mode the header and metadata are *authenticated* (tamper-detected) but
*not* confidential — filenames, MIME types, and sizes are visible. Put anything secret in
the payload. Metadata encryption is future work. See SECURITY.md §2.

**Does UBC manage encryption keys?**
No. The caller supplies a raw 32-byte key. Key derivation, passwords, storage, and rotation
are out of scope for v1 (application concern / future module).

**Why not a full Merkle tree?**
A full tree only pays off for partial/random verification, which isn't a v1 goal, and it
adds cross-language divergence risk (leaf/node rules, odd-node handling — the classic
CVE-2012-2459 footgun). UBC uses a flat hash of chunk hashes bound to the header/metadata.
A full tree can arrive later behind a version bump. See ALGORITHM.md §3.

**What does the root hash actually protect?**
Header, metadata, and every chunk. Flipping a flag, editing metadata, changing
`chunk_count`, or corrupting a chunk all break the root. In encrypted mode, per-chunk GCM
tags add authenticated confidentiality on top.

**Can I stream very large files without buffering them?**
Yes — that's the design. Memory use is bounded by chunk size, not file size. See
BENCHMARK.md §3.

**Which languages are supported?**
v1 reference SDKs: Go and Node.js. Then Python, Rust, Java, .NET, PHP, and framework
wrappers (React/Next/Nest), porting from the frozen spec + vectors. See ROADMAP.md.

**Why Go and Node as the two reference SDKs?**
Go gives strict byte control for the canonical generator; Node surfaces dynamic-language
traps early — notably JS's 53-bit integer limit, which forces correct 64-bit (BigInt)
handling of `chunk_count`/`total_size`. Together they stress-test the format across a
static and a dynamic language. See SDK.md.

**How do I know two SDKs won't silently disagree?**
Disagreement is treated as a security bug (confusion attacks). Shared positive vectors,
negative vectors with exact error identifiers, and cross-decode tests are CI gates. See
TESTING.md, SECURITY.md §6.

**Can the format change later?**
Yes, through the RFC process, with a `version` bump for anything backward-incompatible.
Unknown versions hard-fail, so old readers safely reject newer containers. See RFC.md.

**What is explicitly NOT in v1?**
Cloud storage, sync, CDN, auth/authorization, user management, key management, compression,
signatures, and query-over-payload. These are application-layer or future features.
