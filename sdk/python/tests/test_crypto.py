from __future__ import annotations

import json
from pathlib import Path
import unittest

from ubc import DecodeOptions, ErrorCode, MetadataEntry, UbcError, decode_encrypted, encode_encrypted
from ubc.crypto import _root_key


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
VECTOR_ROOT = REPOSITORY_ROOT / "spec" / "vectors"


class EncryptedVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        manifest = json.loads((VECTOR_ROOT / "vectors.json").read_text(encoding="utf-8"))
        cls.vectors = {vector["id"]: vector for vector in manifest["vectors"]}

    def test_encode_matches_every_encrypted_shared_vector(self) -> None:
        for vector_id in (
            "encrypted-empty",
            "encrypted-one-byte",
            "encrypted-chunk-1m",
            "encrypted-chunk-1m-plus-one",
            "encrypted-multi-3m",
            "encrypted-metadata",
        ):
            with self.subTest(vector_id=vector_id):
                vector = self.vectors[vector_id]
                entries = [
                    MetadataEntry(tag=int(entry["tag"], 16), value=bytes.fromhex(entry["valueHex"]))
                    for entry in vector["options"].get("metadata", [])
                ]
                encoded = encode_encrypted(
                    (VECTOR_ROOT / vector["input"]).read_bytes(),
                    bytes.fromhex(vector["options"]["key"]),
                    entries,
                    vector["options"]["chunkSize"],
                    base_nonce=bytes.fromhex(vector["options"]["baseNonce"]),
                )
                self.assertEqual(encoded, (VECTOR_ROOT / vector["expected"]).read_bytes())

    def test_decode_matches_every_encrypted_shared_vector(self) -> None:
        for vector_id in (
            "encrypted-empty",
            "encrypted-one-byte",
            "encrypted-chunk-1m",
            "encrypted-chunk-1m-plus-one",
            "encrypted-multi-3m",
            "encrypted-metadata",
        ):
            with self.subTest(vector_id=vector_id):
                vector = self.vectors[vector_id]
                decoded, metadata = decode_encrypted(
                    (VECTOR_ROOT / vector["expected"]).read_bytes(),
                    DecodeOptions(key=bytes.fromhex(vector["options"]["key"])),
                )
                self.assertEqual(decoded, (VECTOR_ROOT / vector["input"]).read_bytes())
                self.assertEqual(
                    metadata,
                    [
                        MetadataEntry(tag=int(entry["tag"], 16), value=bytes.fromhex(entry["valueHex"]))
                        for entry in vector["options"].get("metadata", [])
                    ],
                )

    def test_encrypted_shared_negative_vectors_use_exact_error_ids(self) -> None:
        for vector_id in (
            "negative-chunk-auth",
            "negative-missing-key",
            "negative-encrypted-short-clen",
            "negative-encrypted-metadata-tamper",
            "negative-encrypted-reserved-metadata",
            "negative-encrypted-cap-missing-key",
            "negative-encrypted-empty-wrong-key",
        ):
            with self.subTest(vector_id=vector_id):
                vector = self.vectors[vector_id]
                if vector_id in ("negative-missing-key", "negative-encrypted-cap-missing-key"):
                    options = DecodeOptions()
                else:
                    key = vector.get("options", {}).get("key")
                    options = DecodeOptions(key=bytes.fromhex(key)) if key else DecodeOptions(key=_vector_key())
                with self.assertRaises(UbcError) as caught:
                    decode_encrypted((VECTOR_ROOT / vector["expected"]).read_bytes(), options)
                self.assertEqual(caught.exception.code.value, vector["expectError"])

    def test_root_key_matches_shared_known_answer(self) -> None:
        known_answer = json.loads((VECTOR_ROOT / "vectors.json").read_text(encoding="utf-8"))["cryptoKnownAnswers"][0]
        self.assertEqual(
            _root_key(bytes.fromhex(known_answer["key"]), bytes.fromhex(known_answer["baseNonce"])),
            bytes.fromhex(known_answer["rootKey"]),
        )


def _vector_key() -> bytes:
    return bytes(range(32))
