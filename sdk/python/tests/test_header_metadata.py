from __future__ import annotations

import json
from pathlib import Path
import unittest

from ubc import ErrorCode, MetadataEntry, UbcError, encode_metadata, parse_header, parse_metadata


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
VECTOR_ROOT = REPOSITORY_ROOT / "spec" / "vectors"


class HeaderAndMetadataVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        manifest = json.loads((VECTOR_ROOT / "vectors.json").read_text(encoding="utf-8"))
        cls.vectors = {vector["id"]: vector for vector in manifest["vectors"]}

    def test_plain_header_round_trips_shared_vector_bytes(self) -> None:
        container = self._container("plain-one-byte")

        header = parse_header(container)

        self.assertFalse(header.encrypted)
        self.assertFalse(header.has_metadata)
        self.assertEqual(header.to_bytes(), container[:40])

    def test_error_types_cover_all_shared_vector_error_ids(self) -> None:
        vector_error_ids = {
            vector["expectError"] for vector in self.vectors.values() if vector["expectError"]
        }
        self.assertEqual({code.value for code in ErrorCode}, vector_error_ids)

    def test_metadata_round_trips_shared_vector_bytes(self) -> None:
        container = self._container("plain-metadata")
        vector = self.vectors["plain-metadata"]

        header = parse_header(container)
        metadata, consumed = parse_metadata(container[40:])

        expected_entries = [
            MetadataEntry(tag=int(entry["tag"], 16), value=bytes.fromhex(entry["valueHex"]))
            for entry in vector["options"]["metadata"]
        ]
        self.assertTrue(header.has_metadata)
        self.assertEqual(metadata, expected_entries)
        self.assertEqual(encode_metadata(reversed(expected_entries)), container[40 : 40 + consumed])

    def test_shared_negative_headers_map_to_stable_errors(self) -> None:
        for vector_id in (
            "negative-bad-magic",
            "negative-version-two",
            "negative-hash-algo",
            "negative-aead-algo",
            "negative-reserved-flag",
            "negative-inconsistent-encryption",
            "negative-zero-chunk-size",
            "negative-encrypted-zero-chunk-size",
            "negative-encrypted-oversized-chunk-size",
        ):
            with self.subTest(vector_id=vector_id), self.assertRaises(UbcError) as caught:
                parse_header(self._container(vector_id))
            self.assertEqual(caught.exception.code.value, self.vectors[vector_id]["expectError"])

    def test_shared_negative_metadata_maps_to_stable_error(self) -> None:
        for vector_id in (
            "negative-meta-out-of-order",
            "negative-meta-duplicate",
            "negative-meta-overrun",
            "negative-empty-metadata",
            "negative-encrypted-reserved-metadata",
            "negative-reserved-metadata",
        ):
            with self.subTest(vector_id=vector_id), self.assertRaises(UbcError) as caught:
                parse_metadata(self._container(vector_id)[40:])
            self.assertEqual(caught.exception.code.value, ErrorCode.META_MALFORMED.value)
            self.assertEqual(caught.exception.code.value, self.vectors[vector_id]["expectError"])

    def _container(self, vector_id: str) -> bytes:
        expected = self.vectors[vector_id]["expected"]
        return (VECTOR_ROOT / expected).read_bytes()
