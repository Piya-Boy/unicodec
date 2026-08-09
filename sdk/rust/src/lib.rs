#![forbid(unsafe_code)]

mod crypto;
mod error;
mod header;
mod metadata;
mod payload;

pub use crypto::{
    DEFAULT_MAX_CHUNK_COUNT, DEFAULT_MAX_CHUNK_LEN, DEFAULT_MAX_TOTAL_SIZE, DecodeOptions,
    decode_encrypted, decode_encrypted_with_options, encode_encrypted,
    encode_encrypted_with_fixed_nonce,
};
pub use error::{ErrorCode, UbcError};
pub use header::{
    AEAD_AES_256_GCM, AEAD_NONE, AeadAlgorithm, FLAG_ENCRYPTED, FLAG_HAS_METADATA,
    HASH_HMAC_SHA256, HASH_SHA256, HEADER_SIZE, HashAlgorithm, Header, VERSION, parse_header,
};
pub use metadata::{
    DEFAULT_MAX_METADATA_BYTES, MetadataEntry, encode_metadata, parse_metadata,
    parse_metadata_with_limit,
};
pub use payload::{DEFAULT_CHUNK_SIZE, decode_plain, encode_plain};
