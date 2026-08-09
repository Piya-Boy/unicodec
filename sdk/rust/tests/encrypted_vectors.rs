use std::{fs, path::PathBuf};

use ubc::{
    DEFAULT_MAX_CHUNK_COUNT, DEFAULT_MAX_CHUNK_LEN, DEFAULT_MAX_TOTAL_SIZE, DecodeOptions,
    ErrorCode, MetadataEntry, decode_encrypted, decode_encrypted_with_options,
    encode_encrypted_with_fixed_nonce,
};

const KEY: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31,
];
const BASE_NONCE: [u8; 12] = [
    0xf0, 0xe0, 0xd0, 0xc0, 0xb0, 0xa0, 0x90, 0x80, 0x70, 0x60, 0x50, 0x40,
];

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
fn encodes_every_encrypted_shared_vector_byte_exactly() {
    for (input, expected, entries) in [
        (
            "inputs/empty.bin",
            "expected/encrypted-empty.ubc",
            Vec::new(),
        ),
        (
            "inputs/one-byte.bin",
            "expected/encrypted-one-byte.ubc",
            Vec::new(),
        ),
        (
            "inputs/chunk-1m.bin",
            "expected/encrypted-chunk-1m.ubc",
            Vec::new(),
        ),
        (
            "inputs/chunk-1m-plus-one.bin",
            "expected/encrypted-chunk-1m-plus-one.ubc",
            Vec::new(),
        ),
        (
            "inputs/multi-3m.bin",
            "expected/encrypted-multi-3m.ubc",
            Vec::new(),
        ),
        (
            "inputs/one-byte.bin",
            "expected/encrypted-metadata.ubc",
            metadata(),
        ),
    ] {
        assert_eq!(
            encode_encrypted_with_fixed_nonce(&read(input), &KEY, BASE_NONCE, entries, 1 << 20)
                .expect(expected),
            read(expected),
            "{expected}"
        );
    }
}

#[test]
fn decodes_every_encrypted_shared_vector() {
    for (input, expected, entries) in [
        (
            "inputs/empty.bin",
            "expected/encrypted-empty.ubc",
            Vec::new(),
        ),
        (
            "inputs/one-byte.bin",
            "expected/encrypted-one-byte.ubc",
            Vec::new(),
        ),
        (
            "inputs/chunk-1m.bin",
            "expected/encrypted-chunk-1m.ubc",
            Vec::new(),
        ),
        (
            "inputs/chunk-1m-plus-one.bin",
            "expected/encrypted-chunk-1m-plus-one.ubc",
            Vec::new(),
        ),
        (
            "inputs/multi-3m.bin",
            "expected/encrypted-multi-3m.ubc",
            Vec::new(),
        ),
        (
            "inputs/one-byte.bin",
            "expected/encrypted-metadata.ubc",
            metadata(),
        ),
    ] {
        let (data, decoded_metadata) = decode_encrypted(&read(expected), &KEY).expect(expected);
        assert_eq!(data, read(input), "{expected}");
        assert_eq!(decoded_metadata, entries, "{expected}");
    }
}

#[test]
fn encrypted_negative_vectors_return_exact_error_codes() {
    for (name, key, code) in [
        (
            "negative-chunk-auth.ubc",
            KEY.as_slice(),
            ErrorCode::ChunkAuth,
        ),
        ("negative-missing-key.ubc", &[][..], ErrorCode::MissingKey),
        (
            "negative-encrypted-short-clen.ubc",
            KEY.as_slice(),
            ErrorCode::ChunkAuth,
        ),
        (
            "negative-encrypted-metadata-tamper.ubc",
            KEY.as_slice(),
            ErrorCode::ChunkAuth,
        ),
        (
            "negative-encrypted-reserved-metadata.ubc",
            &[][..],
            ErrorCode::MetadataMalformed,
        ),
        (
            "negative-encrypted-cap-missing-key.ubc",
            &[][..],
            ErrorCode::MissingKey,
        ),
        (
            "negative-encrypted-empty-wrong-key.ubc",
            &[0xff; 32],
            ErrorCode::RootMismatch,
        ),
    ] {
        let error = decode_encrypted(&read(&format!("expected/{name}")), key)
            .expect_err("negative vector must fail without exposing plaintext");
        assert_eq!(error.code, code, "{name}");
    }
}

#[test]
fn encrypted_decode_limits_are_enforced_after_key_validation() {
    let source = read("expected/encrypted-one-byte.ubc");

    let mut oversized_chunk_count = source.clone();
    oversized_chunk_count[12..20].copy_from_slice(&(DEFAULT_MAX_CHUNK_COUNT + 1).to_le_bytes());
    assert_eq!(
        decode_encrypted(&oversized_chunk_count, &KEY)
            .expect_err("chunk count above the default cap must fail")
            .code,
        ErrorCode::Truncated
    );
    assert_eq!(
        decode_encrypted(&oversized_chunk_count, &[])
            .expect_err("missing key must precede payload caps")
            .code,
        ErrorCode::MissingKey
    );

    let mut oversized_total_size = source.clone();
    oversized_total_size[20..28].copy_from_slice(&(DEFAULT_MAX_TOTAL_SIZE + 1).to_le_bytes());
    assert_eq!(
        decode_encrypted(&oversized_total_size, &KEY)
            .expect_err("total size above the default cap must fail")
            .code,
        ErrorCode::Truncated
    );

    let mut oversized_chunk_length = source;
    oversized_chunk_length[40..44].copy_from_slice(
        &u32::try_from(DEFAULT_MAX_CHUNK_LEN + 1)
            .expect("default chunk cap remains representable as u32")
            .to_le_bytes(),
    );
    assert_eq!(
        decode_encrypted(&oversized_chunk_length, &KEY)
            .expect_err("chunk body above the default cap must fail before decrypting")
            .code,
        ErrorCode::Truncated
    );
}

#[test]
fn encrypted_decode_options_override_default_caps() {
    let source = read("expected/encrypted-one-byte.ubc");
    let options = DecodeOptions {
        key: &KEY,
        max_metadata_bytes: ubc::DEFAULT_MAX_METADATA_BYTES,
        max_chunk_len: 16,
        max_chunk_count: 1,
        max_total_size: 1,
    };

    assert_eq!(
        decode_encrypted_with_options(&source, options)
            .expect_err("caller chunk cap must be enforced")
            .code,
        ErrorCode::Truncated
    );
}
