# UBC Storage Guide

How to store and transport UBC containers. Non-normative. A UBC container is a single
opaque byte blob — this is the core simplification UBC offers over split
metadata+file architectures.

---

## 1. The single-blob model

A UBC container holds metadata **and** binary payload in one self-contained byte string.
Wherever you can store bytes, you can store a container: one column, one object, one file,
one message body. No sidecar files, no separate metadata table required.

Consequences:
- **Backup/restore** is atomic — one blob moves as a unit; no orphaned files, no dangling
  DB references.
- **No temp files** — encode/decode work in memory or via streams; nothing hits disk
  unless the application writes the blob itself.
- **Portability** — the same blob round-trips identically through any SDK/language.

---

## 2. Databases

### Relational (Postgres, MySQL, SQLite, SQL Server)
- Store in a binary column: `BYTEA` (Postgres), `LONGBLOB` (MySQL), `BLOB` (SQLite),
  `VARBINARY(MAX)` (SQL Server).
- For large payloads, prefer streaming interfaces (Postgres large objects / `lo`,
  MySQL streaming, JDBC `setBinaryStream`) so the container is not fully buffered.
- Index searchable fields separately if you need queryability — extract selected metadata
  (filename, mime, created_at) into normal columns at write time. The container stays the
  source of truth; the columns are a derived index.

### Document / KV (Mongo, Redis, DynamoDB, S3-compatible)
- Store as a binary value. Mind per-item size limits (e.g. DynamoDB 400 KB, Redis value
  limits) — use object storage for large containers and keep a reference in the DB.

---

## 3. Object storage & files

- Write the container as a single object/file (suggested extension `.ubc`,
  media type `application/vnd.ubc`).
- Streaming upload/download maps directly onto UBC's chunked payload; no full buffering.
- Integrity: `verify` before use for untrusted sources; `root_hash` detects corruption
  in transit or at rest.

---

## 4. Network transport

- Send the container as an HTTP body or message payload. `inspect` reads header+metadata
  cheaply for routing without downloading/decoding the whole payload (range-read the head).
- `total_size` in the header lets a receiver set `Content-Length` / pre-size buffers
  (subject to the DoS caps in SECURITY.md §5).

---

## 5. What UBC does not do (v1)

- No CDN, cloud sync, replication, lifecycle, or dedup — application/storage-layer concerns.
- No encryption key storage — the caller holds the key (SECURITY.md §2).
- No query engine over payload contents — extract a metadata index if you need search.
