"""UBC metadata TLV encoding and parsing."""

from __future__ import annotations

from dataclasses import dataclass
import struct
from typing import Iterable

from .errors import ErrorCode, UbcError


@dataclass(frozen=True, slots=True)
class MetadataEntry:
    tag: int
    value: bytes


def encode_metadata(entries: Iterable[MetadataEntry]) -> bytes:
    ordered = sorted(entries, key=lambda entry: entry.tag)
    if not ordered:
        return b""

    body = bytearray()
    previous_tag: int | None = None
    for entry in ordered:
        _validate_entry(entry)
        if previous_tag == entry.tag:
            raise UbcError(ErrorCode.META_MALFORMED)
        previous_tag = entry.tag
        if len(entry.value) > 0xFFFF_FFFF or len(body) + 6 + len(entry.value) > 0xFFFF_FFFF:
            raise UbcError(ErrorCode.META_MALFORMED)
        body.extend(struct.pack("<HI", entry.tag, len(entry.value)))
        body.extend(entry.value)
    return struct.pack("<I", len(body)) + bytes(body)


def parse_metadata(data: bytes | bytearray | memoryview) -> tuple[list[MetadataEntry], int]:
    view = memoryview(data)
    if len(view) < 4:
        raise UbcError(ErrorCode.META_MALFORMED)
    (metadata_length,) = struct.unpack("<I", view[:4])
    if metadata_length == 0 or metadata_length > len(view) - 4:
        raise UbcError(ErrorCode.META_MALFORMED)

    end = 4 + metadata_length
    entries: list[MetadataEntry] = []
    offset = 4
    previous_tag: int | None = None
    while offset < end:
        if end - offset < 6:
            raise UbcError(ErrorCode.META_MALFORMED)
        tag, value_length = struct.unpack("<HI", view[offset : offset + 6])
        offset += 6
        if value_length > end - offset or (previous_tag is not None and tag <= previous_tag):
            raise UbcError(ErrorCode.META_MALFORMED)
        value = bytes(view[offset : offset + value_length])
        entry = MetadataEntry(tag=tag, value=value)
        _validate_entry(entry)
        entries.append(entry)
        previous_tag = tag
        offset += value_length
    return entries, end


def _validate_entry(entry: MetadataEntry) -> None:
    if not 0 <= entry.tag <= 0xFFFF:
        raise UbcError(ErrorCode.META_MALFORMED)
    if not isinstance(entry.value, bytes):
        raise UbcError(ErrorCode.META_MALFORMED)
    if entry.tag == 0x0001:
        if entry.value.startswith(b"\xef\xbb\xbf") or b"\x00" in entry.value:
            raise UbcError(ErrorCode.META_MALFORMED)
        try:
            entry.value.decode("utf-8")
        except UnicodeDecodeError as error:
            raise UbcError(ErrorCode.META_MALFORMED) from error
    elif entry.tag == 0x0002 and any(value == 0 or value > 0x7F for value in entry.value):
        raise UbcError(ErrorCode.META_MALFORMED)
    elif entry.tag == 0x0003 and len(entry.value) != 8:
        raise UbcError(ErrorCode.META_MALFORMED)
