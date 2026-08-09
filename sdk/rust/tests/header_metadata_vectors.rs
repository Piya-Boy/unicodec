use std::{fs, path::PathBuf};

use ubc::{
    encode_metadata, parse_header, parse_metadata, parse_metadata_with_limit,
    ErrorCode, MetadataEntry, DEFAULT_MAX_METADATA_BYTES, HEADER_SIZE,
};

fn vector_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors")
}

fn vector(name: &str) -> Vec<u8> {
    fs::read(vector_root().join("expected").join(name)).expect("shared vector must exist")
}

#[test]
fn all_positive_vector_headers_round_trip_byte_exactly() {
    let expected_dir = vector_root().join("expected");
    for entry in fs::read_dir(expected_dir).expect("vector directory must exist") {
        let path = entry.expect("directory entry").path();
        let name = path
            .file_name()
            .and_then(|value| value.to_str())
            .expect("UTF-8 name");
        if name.starts_with("negative-")
            || path
                .extension()
                .is_none_or(|extension| extension != "ubc")
        {
            continue;
        }
        let container = fs::read(&path).expect("vector must be readable");
        let header =
            parse_header(&container).unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(
            header.to_bytes().expect("valid parsed header"),
            container[..HEADER_SIZE]
        );
    }
}

#[test]
fn vector_metadata_round_trips_byte_exactly() {
    let container = vector("plain-metadata.ubc");
    let header = parse_header(&container).expect("valid vector header");
    assert!(header.has_metadata());

    let (entries, consumed) =
        parse_metadata(&container[HEADER_SIZE..]).expect("valid vector metadata");
    assert_eq!(
        encode_metadata(entries).expect("valid vector entries"),
        container[HEADER_SIZE..HEADER_SIZE + consumed]
    );
}

#[test]
fn header_negative_vectors_use_stable_error_codes() {
    for (name, expected) in [
        ("negative-bad-magic.ubc", ErrorCode::BadMagic),
        ("negative-version-two.ubc", ErrorCode::UnsupportedVersion),
        ("negative-hash-algo.ubc", ErrorCode::UnsupportedAlgorithm),
        ("negative-aead-algo.ubc", ErrorCode::UnsupportedAlgorithm),
        ("negative-reserved-flag.ubc", ErrorCode::ReservedBits),
        ("negative-inconsistent-encryption.ubc", ErrorCode::ReservedBits),
        ("negative-zero-chunk-size.ubc", ErrorCode::ReservedBits),
        ("negative-encrypted-zero-chunk-size.ubc", ErrorCode::ReservedBits),
        ("negative-encrypted-oversized-chunk-size.ubc", ErrorCode::ReservedBits),
    ] {
        assert_eq!(parse_header(&vector(name)).expect_err(name).code, expected, "{name}");
    }
}

#[test]
fn metadata_negative_vectors_use_stable_error_codes() {
    for name in [
        "negative-meta-out-of-order.ubc",
        "negative-meta-duplicate.ubc",
        "negative-meta-overrun.ubc",
        "negative-empty-metadata.ubc",
        "negative-encrypted-reserved-metadata.ubc",
        "negative-reserved-metadata.ubc",
    ] {
        assert_eq!(
        parse_metadata(&vector(name)[HEADER_SIZE..])
            .expect_err(name)
            .code,
            ErrorCode::MetadataMalformed,
            "{name}"
        );
    }
}

#[test]
fn metadata_encoder_sorts_tags_and_rejects_duplicates() {
    let metadata = encode_metadata([
        MetadataEntry {
            tag: 0x1000,
            value: vec![1],
        },
        MetadataEntry {
            tag: 0x0001,
            value: b"example.txt".to_vec(),
        },
    ])
    .expect("sortable metadata");
    let (entries, _) = parse_metadata(&metadata).expect("encoded metadata parses");
    assert_eq!(entries[0].tag, 0x0001);
    assert_eq!(entries[1].tag, 0x1000);

    let duplicate = encode_metadata([
        MetadataEntry {
            tag: 1,
            value: Vec::new(),
        },
        MetadataEntry {
            tag: 1,
            value: Vec::new(),
        },
    ]);
    assert_eq!(
        duplicate.expect_err("duplicates must fail").code,
        ErrorCode::MetadataMalformed
    );
}

#[test]
fn metadata_length_cap_is_checked_before_copying_entries() {
    let oversized = (DEFAULT_MAX_METADATA_BYTES + 1).to_le_bytes();
    assert_eq!(
        parse_metadata(&oversized)
            .expect_err("default cap must reject the declared metadata length")
            .code,
        ErrorCode::MetadataMalformed
    );

    let metadata = encode_metadata([MetadataEntry {
        tag: 0x1000,
        value: vec![1],
    }])
    .expect("valid metadata");
    assert_eq!(
        parse_metadata_with_limit(&metadata, 6)
            .expect_err("caller cap must reject metadata before copying entries")
            .code,
        ErrorCode::MetadataMalformed
    );
}
