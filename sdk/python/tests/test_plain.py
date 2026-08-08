from __future__ import annotations

import json
from pathlib import Path
import struct
import unittest

from ubc import (
    AEAD_AES_256_GCM,
    DEFAULT_MAX_CHUNK_COUNT,
    DEFAULT_MAX_TOTAL_SIZE,
    DecodeOptions,
    ErrorCode,
    FLAG_ENCRYPTED,
    FLAG_HAS_METADATA,
    HASH_HMAC_SHA256,
    MetadataEntry,
    UbcError,
    decode_plain,
    encode_plain,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
VECTOR_ROOT = REPOSITORY_ROOT / "spec" / "vectors"


class PlainVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        manifest = json.loads((VECTOR_ROOT / "vectors.json").read_text(encoding="utf-8"))
        cls.vectors = {vector["id"]: vector for vector in manifest["vectors"]}

    def test_encode_matches_every_plain_shared_vector(self) -> None:
        for vector_id in (
            "plain-empty",
            "plain-one-byte",
            "plain-chunk-1m",
            "plain-chunk-1m-plus-one",
            "plain-multi-3m",
            "plain-metadata",
        ):
            with self.subTest(vector_id=vector_id):
                vector = self.vectors[vector_id]
                entries = [
                    MetadataEntry(tag=int(entry["tag"], 16), value=bytes.fromhex(entry["valueHex"]))
                    for entry in vector["options"].get("metadata", [])
                ]
                encoded = encode_plain(
                    (VECTOR_ROOT / vector["input"]).read_bytes(),
                    entries,
                    vector["options"]["chunkSize"],
                )
                self.assertEqual(encoded, (VECTOR_ROOT / vector["expected"]).read_bytes())

    def test_decode_matches_every_plain_shared_vector(self) -> None:
        for vector_id in (
            "plain-empty",
            "plain-one-byte",
            "plain-chunk-1m",
            "plain-chunk-1m-plus-one",
            "plain-multi-3m",
            "plain-metadata",
        ):
            with self.subTest(vector_id=vector_id):
                vector = self.vectors[vector_id]
                decoded, metadata = decode_plain((VECTOR_ROOT / vector["expected"]).read_bytes())
                self.assertEqual(decoded, (VECTOR_ROOT / vector["input"]).read_bytes())
                self.assertEqual(
                    metadata,
                    [
                        MetadataEntry(tag=int(entry["tag"], 16), value=bytes.fromhex(entry["valueHex"]))
                        for entry in vector["options"].get("metadata", [])
                    ],
                )

    def test_flipped_plain_payload_returns_root_mismatch(self) -> None:
        vector = self.vectors["negative-root-mismatch"]
        with self.assertRaises(UbcError) as caught:
            decode_plain((VECTOR_ROOT / vector["expected"]).read_bytes())
        self.assertEqual(caught.exception.code, ErrorCode.ROOT_MISMATCH)

    def test_rejects_header_lengths_that_exceed_default_caps(self) -> None:
        container = bytearray((VECTOR_ROOT / self.vectors["plain-one-byte"]["expected"]).read_bytes())

        with self.subTest(field="chunk_count"):
            struct.pack_into("<Q", container, 12, DEFAULT_MAX_CHUNK_COUNT + 1)
            with self.assertRaises(UbcError) as caught:
                decode_plain(container)
            self.assertEqual(caught.exception.code, ErrorCode.TRUNCATED)

        with self.subTest(field="total_size"):
            struct.pack_into("<Q", container, 12, 1)
            struct.pack_into("<Q", container, 20, DEFAULT_MAX_TOTAL_SIZE + 1)
            with self.assertRaises(UbcError) as caught:
                decode_plain(container)
            self.assertEqual(caught.exception.code, ErrorCode.TRUNCATED)

    def test_rejects_configured_caps_before_copying_metadata_or_payload(self) -> None:
        with self.subTest(field="meta_len"):
            container = (VECTOR_ROOT / self.vectors["plain-metadata"]["expected"]).read_bytes()
            with self.assertRaises(UbcError) as caught:
                decode_plain(container, DecodeOptions(max_meta_bytes=1))
            self.assertEqual(caught.exception.code, ErrorCode.META_MALFORMED)

        with self.subTest(field="clen"):
            container = (VECTOR_ROOT / self.vectors["plain-one-byte"]["expected"]).read_bytes()
            with self.assertRaises(UbcError) as caught:
                decode_plain(container, DecodeOptions(max_chunk_len=0))
            self.assertEqual(caught.exception.code, ErrorCode.TRUNCATED)

        with self.subTest(field="chunk_count"):
            container = (VECTOR_ROOT / self.vectors["plain-one-byte"]["expected"]).read_bytes()
            with self.assertRaises(UbcError) as caught:
                decode_plain(container, DecodeOptions(max_chunk_count=0))
            self.assertEqual(caught.exception.code, ErrorCode.TRUNCATED)

        with self.subTest(field="total_size"):
            container = (VECTOR_ROOT / self.vectors["plain-one-byte"]["expected"]).read_bytes()
            with self.assertRaises(UbcError) as caught:
                decode_plain(container, DecodeOptions(max_total_size=0))
            self.assertEqual(caught.exception.code, ErrorCode.TRUNCATED)

    def test_metadata_errors_precede_later_validation_failures(self) -> None:
        container = bytearray((VECTOR_ROOT / self.vectors["plain-metadata"]["expected"]).read_bytes())
        struct.pack_into("<I", container, 40, 0)

        with self.subTest(later_failure="chunk_count_cap"):
            struct.pack_into("<Q", container, 12, DEFAULT_MAX_CHUNK_COUNT + 1)
            with self.assertRaises(UbcError) as caught:
                decode_plain(container)
            self.assertEqual(caught.exception.code, ErrorCode.META_MALFORMED)

        with self.subTest(later_failure="total_size_cap"):
            struct.pack_into("<Q", container, 12, 1)
            struct.pack_into("<Q", container, 20, DEFAULT_MAX_TOTAL_SIZE + 1)
            with self.assertRaises(UbcError) as caught:
                decode_plain(container)
            self.assertEqual(caught.exception.code, ErrorCode.META_MALFORMED)

        with self.subTest(later_failure="missing_key"):
            container[5] = FLAG_ENCRYPTED | FLAG_HAS_METADATA
            container[6] = HASH_HMAC_SHA256
            container[7] = AEAD_AES_256_GCM
            container[28:40] = b"\x01" * 12
            with self.assertRaises(UbcError) as caught:
                decode_plain(container)
            self.assertEqual(caught.exception.code, ErrorCode.META_MALFORMED)
