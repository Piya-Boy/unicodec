use std::{fs, path::PathBuf};

use ubc::{ErrorCode, MetadataEntry, decode_plain, encode_plain};

fn vector_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors")
}

fn read(relative_path: &str) -> Vec<u8> {
    fs::read(vector_root().join(relative_path)).expect("shared vector fixture must exist")
}

fn metadata() -> Vec<MetadataEntry> {
    vec![
        MetadataEntry {
            tag: 0x0001,
            value: "รายงาน-2026.txt".as_bytes().to_vec(),
        },
        MetadataEntry {
            tag: 0x0002,
            value: b"text/plain".to_vec(),
        },
        MetadataEntry {
            tag: 0x0003,
            value: vec![0, 0xa8, 0xda, 0x76, 0x9b, 1, 0, 0],
        },
        MetadataEntry {
            tag: 0x1000,
            value: vec![0, 0xff, 0x7f],
        },
    ]
}

#[test]
fn encodes_every_plain_shared_vector_byte_exactly() {
    for (input, expected, entries) in [
        ("inputs/empty.bin", "expected/plain-empty.ubc", Vec::new()),
        (
            "inputs/one-byte.bin",
            "expected/plain-one-byte.ubc",
            Vec::new(),
        ),
        (
            "inputs/chunk-1m.bin",
            "expected/plain-chunk-1m.ubc",
            Vec::new(),
        ),
        (
            "inputs/chunk-1m-plus-one.bin",
            "expected/plain-chunk-1m-plus-one.ubc",
            Vec::new(),
        ),
        (
            "inputs/multi-3m.bin",
            "expected/plain-multi-3m.ubc",
            Vec::new(),
        ),
        (
            "inputs/one-byte.bin",
            "expected/plain-metadata.ubc",
            metadata(),
        ),
    ] {
        assert_eq!(
            encode_plain(&read(input), entries, 1 << 20).expect(expected),
            read(expected),
            "{expected}"
        );
    }
}

#[test]
fn decodes_every_plain_shared_vector() {
    for (input, expected, entries) in [
        ("inputs/empty.bin", "expected/plain-empty.ubc", Vec::new()),
        (
            "inputs/one-byte.bin",
            "expected/plain-one-byte.ubc",
            Vec::new(),
        ),
        (
            "inputs/chunk-1m.bin",
            "expected/plain-chunk-1m.ubc",
            Vec::new(),
        ),
        (
            "inputs/chunk-1m-plus-one.bin",
            "expected/plain-chunk-1m-plus-one.ubc",
            Vec::new(),
        ),
        (
            "inputs/multi-3m.bin",
            "expected/plain-multi-3m.ubc",
            Vec::new(),
        ),
        (
            "inputs/one-byte.bin",
            "expected/plain-metadata.ubc",
            metadata(),
        ),
    ] {
        let (data, metadata) = decode_plain(&read(expected)).expect(expected);
        assert_eq!(data, read(input), "{expected}");
        assert_eq!(metadata, entries, "{expected}");
    }
}

#[test]
fn flipped_plain_payload_returns_root_mismatch() {
    let error = decode_plain(&read("expected/negative-root-mismatch.ubc"))
        .expect_err("tampered plain vector must fail");
    assert_eq!(error.code, ErrorCode::RootMismatch);
}
