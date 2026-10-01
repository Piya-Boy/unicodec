use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

#[path = "support/mod.rs"]
mod support;

use support::{Manifest, decode_key, decode_vector, encode_vector, read_child};

fn vector_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors")
}

#[test]
fn every_shared_manifest_vector_conforms() {
    let root = vector_root();
    let manifest = Manifest::read(&root).expect("shared manifest must parse");
    let canonical_key = manifest
        .canonical_key()
        .expect("encrypted shared vectors must provide a canonical key")
        .to_vec();
    let mut positive_count = 0;
    let mut negative_count = 0;

    for vector in &manifest.vectors {
        let expected = read_child(&root, &vector.expected)
            .unwrap_or_else(|error| panic!("{}: {error}", vector.id));
        assert_eq!(
            Sha256::digest(&expected).as_slice(),
            vector.expected_sha256,
            "{}: expected artifact SHA-256 differs from vectors.json",
            vector.id
        );

        if let Some(expected_error) = &vector.expect_error {
            negative_count += 1;
            let key = decode_key(vector, &canonical_key);
            let error = decode_vector(&expected, &key)
                .expect_err("negative vector must not decode successfully");
            assert_eq!(
                error.code.as_str(),
                expected_error,
                "{}: stable error id differs from vectors.json",
                vector.id
            );
            continue;
        }

        positive_count += 1;
        let input_path = vector
            .input
            .as_deref()
            .unwrap_or_else(|| panic!("{}: positive vector has no input", vector.id));
        let input =
            read_child(&root, input_path).unwrap_or_else(|error| panic!("{}: {error}", vector.id));
        let encoded = encode_vector(&input, vector).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            encoded, expected,
            "{}: encoded container differs from vectors.json artifact",
            vector.id
        );

        let key = decode_key(vector, &canonical_key);
        let (decoded, metadata) = decode_vector(&expected, &key)
            .unwrap_or_else(|error| panic!("{}: decode failed with {}", vector.id, error.code));
        assert_eq!(decoded, input, "{}: decoded plaintext differs", vector.id);
        assert_eq!(
            metadata,
            vector
                .options
                .as_ref()
                .map(|options| options.metadata.as_slice())
                .unwrap_or_default(),
            "{}: decoded metadata differs",
            vector.id
        );
    }

    assert!(positive_count > 0, "manifest must contain positive vectors");
    assert!(negative_count > 0, "manifest must contain negative vectors");
}

#[test]
fn manifest_paths_stay_within_the_shared_vector_root() {
    let root = Path::new("vectors");
    assert!(support::safe_child(root, "expected/plain-empty.ubc").is_ok());
    assert!(support::safe_child(root, "../outside.ubc").is_err());
    assert!(support::safe_child(root, "/outside.ubc").is_err());
}
