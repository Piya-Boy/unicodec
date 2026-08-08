#!/usr/bin/env python3
"""Generate and validate Python UBC containers for the shared cross-decode gate."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
PYTHON_SDK_ROOT = REPO_ROOT / "sdk" / "python"
sys.path.insert(0, str(PYTHON_SDK_ROOT))

from ubc import DecodeOptions, MetadataEntry, UbcError, decode_encrypted, decode_plain, encode_encrypted, encode_plain


CASE_IDS = (
    "plain-one-byte",
    "plain-chunk-1m-plus-one",
    "plain-metadata",
    "encrypted-one-byte",
    "encrypted-chunk-1m-plus-one",
    "encrypted-metadata",
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vectors", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--cases", required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--verify", action="store_true")
    args = parser.parse_args()

    vectors_root = _existing_directory(args.vectors, "vectors")
    work_dir = _existing_directory(args.work, "work")
    case_ids = _parse_cases(args.cases)
    manifest = _read_manifest(vectors_root)

    if args.write:
        for case_id in case_ids:
            vector = manifest[case_id]
            encoded = _encode_vector(vectors_root, vector)
            _safe_child(work_dir, f"{case_id}.python.ubc").write_bytes(encoded)
        return

    for case_id in case_ids:
        vector = manifest[case_id]
        expected = _encode_vector(vectors_root, vector)
        for producer in ("go", "node", "python"):
            container = _safe_child(work_dir, f"{case_id}.{producer}.ubc").read_bytes()
            data, metadata = _decode_vector(container, vector)
            input_bytes = _safe_child(vectors_root, vector["input"]).read_bytes()
            if data != input_bytes:
                raise ValueError(f"{case_id}: {producer}-decoded plaintext differs from manifest input")
            if metadata != _metadata_entries(vector):
                raise ValueError(f"{case_id}: {producer}-decoded metadata differs from manifest metadata")
            if _encode_from_decoded(data, metadata, vector) != expected:
                raise ValueError(f"{case_id}: {producer}-to-Python re-encode is not byte-identical")
            if container != expected:
                raise ValueError(f"{case_id}: fresh Python and {producer} containers differ")


def _existing_directory(path: Path, label: str) -> Path:
    resolved = path.resolve()
    if not resolved.is_dir():
        raise ValueError(f"{label} path is not a directory: {path}")
    return resolved


def _parse_cases(value: str) -> tuple[str, ...]:
    case_ids = tuple(value.split(","))
    if not case_ids or len(set(case_ids)) != len(case_ids):
        raise ValueError("cases must be a non-empty, duplicate-free list")
    if any(case_id not in CASE_IDS for case_id in case_ids):
        raise ValueError("cases include an unapproved shared cross-decode case")
    return case_ids


def _read_manifest(vectors_root: Path) -> dict[str, dict[str, object]]:
    manifest = json.loads(_safe_child(vectors_root, "vectors.json").read_text(encoding="utf-8"))
    vectors = manifest.get("vectors")
    if not isinstance(vectors, list):
        raise ValueError("manifest vectors must be an array")
    by_id = {vector.get("id"): vector for vector in vectors if isinstance(vector, dict)}
    if len(by_id) != len(vectors) or any(case_id not in by_id for case_id in CASE_IDS):
        raise ValueError("manifest does not contain the approved shared cross-decode cases")
    return by_id


def _safe_child(root: Path, child: str) -> Path:
    if not child or Path(child).is_absolute():
        raise ValueError("path must be a non-empty relative path")
    target = (root / child).resolve()
    if target.parent != root and root not in target.parents:
        raise ValueError(f"path escapes its root: {child}")
    return target


def _metadata_entries(vector: dict[str, object]) -> list[MetadataEntry]:
    options = vector.get("options")
    if not isinstance(options, dict):
        raise ValueError("positive vector has no options")
    metadata = options.get("metadata", [])
    if not isinstance(metadata, list):
        raise ValueError("metadata must be an array")
    entries: list[MetadataEntry] = []
    for entry in metadata:
        if not isinstance(entry, dict) or not isinstance(entry.get("tag"), str) or not isinstance(entry.get("valueHex"), str):
            raise ValueError("metadata entry is invalid")
        entries.append(MetadataEntry(tag=int(entry["tag"], 16), value=bytes.fromhex(entry["valueHex"])))
    return entries


def _options(vector: dict[str, object]) -> tuple[int, bytes | None, bytes | None]:
    options = vector.get("options")
    if not isinstance(options, dict) or not isinstance(options.get("chunkSize"), int):
        raise ValueError("vector has an invalid chunkSize")
    chunk_size = options["chunkSize"]
    key_hex = options.get("key")
    nonce_hex = options.get("baseNonce")
    if (key_hex is None) != (nonce_hex is None):
        raise ValueError("encrypted vector must provide both key and baseNonce")
    if key_hex is None:
        return chunk_size, None, None
    if not isinstance(key_hex, str) or not isinstance(nonce_hex, str):
        raise ValueError("vector encryption options are invalid")
    key, nonce = bytes.fromhex(key_hex), bytes.fromhex(nonce_hex)
    if len(key) != 32 or len(nonce) != 12:
        raise ValueError("vector encryption option has an invalid length")
    return chunk_size, key, nonce


def _encode_vector(vectors_root: Path, vector: dict[str, object]) -> bytes:
    input_path = vector.get("input")
    if not isinstance(input_path, str):
        raise ValueError("positive vector has no input")
    return _encode_from_decoded(_safe_child(vectors_root, input_path).read_bytes(), _metadata_entries(vector), vector)


def _encode_from_decoded(data: bytes, metadata: list[MetadataEntry], vector: dict[str, object]) -> bytes:
    chunk_size, key, nonce = _options(vector)
    if key is None:
        return encode_plain(data, metadata, chunk_size)
    return encode_encrypted(data, key, metadata, chunk_size, base_nonce=nonce)


def _decode_vector(container: bytes, vector: dict[str, object]) -> tuple[bytes, list[MetadataEntry]]:
    _, key, _ = _options(vector)
    try:
        if key is None:
            return decode_plain(container)
        return decode_encrypted(container, DecodeOptions(key=key))
    except UbcError as error:
        raise ValueError(f"container rejected with {error.code.value}") from error


if __name__ == "__main__":
    main()
