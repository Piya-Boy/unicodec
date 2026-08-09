use std::{
    fs,
    io::{Cursor, Read, Write},
    path::PathBuf,
};

use ubc::{
    DecodeOptions, EncodeOptions, ErrorCode, MetadataEntry, inspect, new_decoder, new_encoder,
    verify,
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

#[test]
fn streamed_plain_output_is_byte_exact_and_fragmented_decode_round_trips() {
    let input = read("inputs/chunk-1m-plus-one.bin");
    let mut container = Vec::new();
    {
        let mut encoder = new_encoder(&mut container, Vec::new(), EncodeOptions::default())
            .expect("streaming encoder construction");
        for part in input.chunks(8_191) {
            encoder.write_all(part).expect("streaming input write");
        }
        encoder.finish().expect("streaming encoder finish");
    }
    assert_eq!(container, read("expected/plain-chunk-1m-plus-one.ubc"));

    let mut decoder = new_decoder(Fragmented::new(container, 127), DecodeOptions::default())
        .expect("streaming decoder construction");
    let mut decoded = Vec::new();
    decoder.read_to_end(&mut decoded).expect("streaming decode");
    assert_eq!(decoded, input);
}

#[test]
fn streamed_encrypted_output_is_byte_exact_and_authenticates_before_release() {
    let input = read("inputs/chunk-1m-plus-one.bin");
    let mut container = Vec::new();
    {
        let mut encoder = new_encoder(
            &mut container,
            Vec::new(),
            EncodeOptions {
                key: Some(&KEY),
                chunk_size: Some(1 << 20),
                base_nonce: Some(BASE_NONCE),
            },
        )
        .expect("streaming encrypted encoder construction");
        encoder.write_all(&input).expect("streaming input write");
        encoder
            .finish()
            .expect("streaming encrypted encoder finish");
    }
    assert_eq!(container, read("expected/encrypted-chunk-1m-plus-one.ubc"));

    let mut tampered = container;
    tampered[44] ^= 1;
    let mut decoder = new_decoder(Cursor::new(tampered), DecodeOptions::with_key(&KEY))
        .expect("metadata and key are valid");
    let mut output = [0; 32];
    let error = decoder
        .read(&mut output)
        .expect_err("tampered encrypted first chunk must not be released");
    let code = error
        .get_ref()
        .and_then(|cause| cause.downcast_ref::<ubc::UbcError>())
        .map(|error| error.code);
    assert_eq!(code, Some(ErrorCode::ChunkAuth));
}

#[test]
fn truncated_encrypted_footer_precedes_final_chunk_authentication() {
    let mut container = read("expected/encrypted-one-byte.ubc");
    container[44] ^= 1;
    container.pop();
    let mut decoder = new_decoder(Cursor::new(container), DecodeOptions::with_key(&KEY))
        .expect("header and key are valid");
    let mut output = Vec::new();

    let error = decoder
        .read_to_end(&mut output)
        .expect_err("truncated footer must precede final chunk authentication");
    let code = error
        .get_ref()
        .and_then(|cause| cause.downcast_ref::<ubc::UbcError>())
        .map(|error| error.code);

    assert_eq!(code, Some(ErrorCode::Truncated));
    assert!(output.is_empty());
}

#[test]
fn streamed_encoder_with_large_chunk_size_only_buffers_written_input() {
    let input = [0x5a];
    let mut container = Vec::new();
    {
        let mut encoder = new_encoder(
            &mut container,
            Vec::new(),
            EncodeOptions {
                key: None,
                chunk_size: Some(u32::MAX),
                base_nonce: None,
            },
        )
        .expect("large valid chunk size");
        encoder.write_all(&input).expect("streaming input write");
        encoder.finish().expect("streaming encoder finish");
    }

    assert_eq!(&container[8..12], &u32::MAX.to_le_bytes());
    let mut decoder = new_decoder(Cursor::new(container), DecodeOptions::default())
        .expect("encoded container header");
    let mut decoded = Vec::new();
    decoder.read_to_end(&mut decoded).expect("streaming decode");
    assert_eq!(decoded, input);
}

#[test]
fn verify_and_inspect_have_their_documented_read_scopes() {
    let container = read("expected/plain-metadata.ubc");
    let info = inspect(Cursor::new(&container)).expect("inspect prefix");
    assert!(info.flags.has_metadata);
    assert_eq!(info.chunk_count, 1);
    assert_eq!(
        info.metadata,
        vec![
            MetadataEntry {
                tag: 1,
                value: "รายงาน-2026.txt".as_bytes().to_vec()
            },
            MetadataEntry {
                tag: 2,
                value: b"text/plain".to_vec()
            },
            MetadataEntry {
                tag: 3,
                value: vec![0, 0xa8, 0xda, 0x76, 0x9b, 1, 0, 0]
            },
            MetadataEntry {
                tag: 0x1000,
                value: vec![0, 0xff, 0x7f]
            }
        ]
    );

    let report = verify(
        Cursor::new(read("expected/negative-root-mismatch.ubc")),
        DecodeOptions::default(),
    );
    assert!(!report.ok);
    assert_eq!(report.error, Some(ErrorCode::RootMismatch));
}

#[test]
fn streamed_plain_decoder_withholds_output_until_root_verifies() {
    let mut decoder = new_decoder(
        Cursor::new(read("expected/negative-root-mismatch.ubc")),
        DecodeOptions::default(),
    )
    .expect("header and metadata are valid");
    let mut output = [0; 32];
    let error = decoder
        .read(&mut output)
        .expect_err("root mismatch must not release plain output");
    let code = error
        .get_ref()
        .and_then(|cause| cause.downcast_ref::<ubc::UbcError>())
        .map(|error| error.code);
    assert_eq!(code, Some(ErrorCode::RootMismatch));
    assert_eq!(output, [0; 32]);
}

#[test]
fn streamed_plain_decoder_withholds_output_until_trailing_data_is_checked() {
    let mut container = read("expected/plain-one-byte.ubc");
    container.push(0);
    let mut decoder = new_decoder(Cursor::new(container), DecodeOptions::default())
        .expect("header and metadata are valid");
    let mut output = [0; 32];
    let error = decoder
        .read(&mut output)
        .expect_err("trailing data must not release plain output");
    let code = error
        .get_ref()
        .and_then(|cause| cause.downcast_ref::<ubc::UbcError>())
        .map(|error| error.code);
    assert_eq!(code, Some(ErrorCode::TrailingData));
    assert_eq!(output, [0; 32]);
}

#[test]
fn streamed_decoder_enforces_caps_before_allocating_chunk_data() {
    let mut container = read("expected/plain-one-byte.ubc");
    container[12..20].copy_from_slice(&2_u64.to_le_bytes());
    let options = DecodeOptions {
        key: &[],
        max_metadata_bytes: ubc::DEFAULT_MAX_METADATA_BYTES,
        max_chunk_len: ubc::DEFAULT_MAX_CHUNK_LEN,
        max_chunk_count: 1,
        max_total_size: ubc::DEFAULT_MAX_TOTAL_SIZE,
    };
    let error = match new_decoder(Cursor::new(container), options) {
        Ok(_) => panic!("chunk count cap must precede payload allocation"),
        Err(error) => error,
    };
    assert_eq!(error.code, ErrorCode::Truncated);
}

struct Fragmented {
    bytes: Cursor<Vec<u8>>,
    maximum: usize,
}

impl Fragmented {
    fn new(bytes: Vec<u8>, maximum: usize) -> Self {
        Self {
            bytes: Cursor::new(bytes),
            maximum,
        }
    }
}

impl Read for Fragmented {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        let count = output.len().min(self.maximum);
        self.bytes.read(&mut output[..count])
    }
}
