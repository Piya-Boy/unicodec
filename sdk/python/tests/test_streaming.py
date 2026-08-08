from __future__ import annotations

import io
import json
from pathlib import Path
import struct
import unittest

from ubc import (
    DecodeOptions,
    EncodeOptions,
    ErrorCode,
    MetadataEntry,
    UbcError,
    inspect,
    new_decoder,
    new_encoder,
    verify,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
VECTOR_ROOT = REPOSITORY_ROOT / "spec" / "vectors"


class FragmentedReader(io.BytesIO):
    def __init__(self, data: bytes, fragment_size: int = 113) -> None:
        super().__init__(data)
        self._fragment_size = fragment_size

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            size = self._fragment_size
        return super().read(min(size, self._fragment_size))


class BodyGuardReader(FragmentedReader):
    def __init__(self, data: bytes, max_offset: int) -> None:
        super().__init__(data, fragment_size=7)
        self._max_offset = max_offset
        self.read_past_max_offset = False

    def read(self, size: int = -1) -> bytes:
        if self.tell() >= self._max_offset:
            self.read_past_max_offset = True
            raise AssertionError("body read attempted after cap rejection")
        return super().read(min(size, self._max_offset - self.tell()))


class StreamingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        manifest = json.loads((VECTOR_ROOT / "vectors.json").read_text(encoding="utf-8"))
        cls.vectors = [vector for vector in manifest["vectors"] if vector["expectError"] is None]
        cls.negative_vectors = [vector for vector in manifest["vectors"] if vector["expectError"] is not None]

    def test_streaming_encoder_matches_every_positive_vector(self) -> None:
        for vector in self.vectors:
            with self.subTest(vector_id=vector["id"]):
                output = io.BytesIO()
                options = vector["options"]
                encoder = new_encoder(
                    output,
                    _metadata_entries(vector),
                    EncodeOptions(
                        chunk_size=options["chunkSize"],
                        key=bytes.fromhex(options["key"]) if "key" in options else None,
                        base_nonce=bytes.fromhex(options["baseNonce"]) if "baseNonce" in options else None,
                    ),
                )
                input_bytes = (VECTOR_ROOT / vector["input"]).read_bytes()
                for offset in range(0, len(input_bytes), 4093):
                    self.assertEqual(encoder.write(input_bytes[offset : offset + 4093]), min(4093, len(input_bytes) - offset))
                encoder.close()
                self.assertEqual(output.getvalue(), (VECTOR_ROOT / vector["expected"]).read_bytes())

    def test_streaming_decoder_and_verify_accept_every_positive_vector(self) -> None:
        for vector in self.vectors:
            with self.subTest(vector_id=vector["id"]):
                options = vector["options"]
                decode_options = DecodeOptions(key=bytes.fromhex(options["key"])) if "key" in options else DecodeOptions()
                container = (VECTOR_ROOT / vector["expected"]).read_bytes()
                decoder = new_decoder(FragmentedReader(container), decode_options)
                decoded = bytearray()
                while chunk := decoder.read(97):
                    decoded.extend(chunk)
                self.assertEqual(bytes(decoded), (VECTOR_ROOT / vector["input"]).read_bytes())
                self.assertEqual(decoder.metadata, tuple(_metadata_entries(vector)))
                self.assertEqual(verify(FragmentedReader(container), decode_options).ok, True)

    def test_small_reads_retain_pending_chunk_without_copying(self) -> None:
        vector = next(vector for vector in self.vectors if vector["id"] == "plain-multi-3m")
        decoder = new_decoder(FragmentedReader((VECTOR_ROOT / vector["expected"]).read_bytes()))

        self.assertEqual(len(decoder.read(1)), 1)
        pending = decoder._pending
        self.assertIsNotNone(pending)
        self.assertEqual(decoder._pending_offset, 1)

        self.assertEqual(len(decoder.read(1)), 1)
        self.assertIs(decoder._pending, pending)
        self.assertEqual(decoder._pending_offset, 2)

    def test_streaming_decoder_rejects_every_negative_vector_with_exact_error(self) -> None:
        for vector in self.negative_vectors:
            with self.subTest(vector_id=vector["id"]):
                key = vector.get("options", {}).get("key")
                if vector["id"] in {"negative-missing-key", "negative-encrypted-cap-missing-key"}:
                    options = DecodeOptions()
                else:
                    options = DecodeOptions(key=bytes.fromhex(key)) if key else DecodeOptions(key=bytes(range(32)))
                with self.assertRaises(UbcError) as caught:
                    decoder = new_decoder(FragmentedReader((VECTOR_ROOT / vector["expected"]).read_bytes()), options)
                    while decoder.read(257):
                        pass
                self.assertEqual(caught.exception.code.value, vector["expectError"])

    def test_inspect_reads_only_header_and_metadata(self) -> None:
        vector = next(vector for vector in self.vectors if vector["id"] == "plain-metadata")
        container = (VECTOR_ROOT / vector["expected"]).read_bytes()
        metadata_end = 40 + 4 + struct.unpack_from("<I", container, 40)[0]
        source = BodyGuardReader(container, metadata_end)
        info = inspect(source)
        self.assertTrue(info.flags.has_metadata)
        self.assertFalse(info.flags.encrypted)
        self.assertEqual(info.metadata, tuple(_metadata_entries(vector)))
        self.assertEqual(source.tell(), metadata_end)
        self.assertFalse(source.read_past_max_offset)

    def test_caps_reject_before_body_read(self) -> None:
        plain = next(vector for vector in self.vectors if vector["id"] == "plain-one-byte")
        metadata = next(vector for vector in self.vectors if vector["id"] == "plain-metadata")
        plain_container = (VECTOR_ROOT / plain["expected"]).read_bytes()
        metadata_container = (VECTOR_ROOT / metadata["expected"]).read_bytes()

        with self.subTest(field="metadata"):
            source = BodyGuardReader(metadata_container, 44)
            with self.assertRaises(UbcError) as caught:
                new_decoder(source, DecodeOptions(max_meta_bytes=1))
            self.assertEqual(caught.exception.code, ErrorCode.META_MALFORMED)
            self.assertEqual(source.tell(), 44)
            self.assertFalse(source.read_past_max_offset)

        with self.subTest(field="chunk_count"):
            container = bytearray(plain_container)
            struct.pack_into("<Q", container, 12, 1)
            source = BodyGuardReader(bytes(container), 40)
            with self.assertRaises(UbcError) as caught:
                new_decoder(source, DecodeOptions(max_chunk_count=0))
            self.assertEqual(caught.exception.code, ErrorCode.TRUNCATED)
            self.assertEqual(source.tell(), 40)
            self.assertFalse(source.read_past_max_offset)

        with self.subTest(field="total_size"):
            container = bytearray(plain_container)
            struct.pack_into("<Q", container, 20, 1)
            source = BodyGuardReader(bytes(container), 40)
            with self.assertRaises(UbcError) as caught:
                new_decoder(source, DecodeOptions(max_total_size=0))
            self.assertEqual(caught.exception.code, ErrorCode.TRUNCATED)
            self.assertEqual(source.tell(), 40)
            self.assertFalse(source.read_past_max_offset)

        with self.subTest(field="clen"):
            source = BodyGuardReader(plain_container, 44)
            decoder = new_decoder(source, DecodeOptions(max_chunk_len=0))
            with self.assertRaises(UbcError) as caught:
                decoder.read(1)
            self.assertEqual(caught.exception.code, ErrorCode.TRUNCATED)
            self.assertEqual(source.tell(), 44)
            self.assertFalse(source.read_past_max_offset)

    def test_verify_returns_error_without_plaintext(self) -> None:
        vector = next(vector for vector in self.negative_vectors if vector["id"] == "negative-chunk-auth")
        report = verify(
            FragmentedReader((VECTOR_ROOT / vector["expected"]).read_bytes()),
            DecodeOptions(key=bytes(range(32))),
        )
        self.assertFalse(report.ok)
        self.assertEqual(report.error, ErrorCode.CHUNK_AUTH)
        self.assertEqual(report.failed_chunk, 0)


def _metadata_entries(vector: dict[str, object]) -> list[MetadataEntry]:
    options = vector["options"]
    assert isinstance(options, dict)
    entries = options.get("metadata", [])
    assert isinstance(entries, list)
    return [
        MetadataEntry(tag=int(entry["tag"], 16), value=bytes.fromhex(entry["valueHex"]))
        for entry in entries
        if isinstance(entry, dict)
    ]
