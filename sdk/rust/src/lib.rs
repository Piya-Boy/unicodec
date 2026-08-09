#![forbid(unsafe_code)]

mod error;
mod header;
mod metadata;

pub use error::{ErrorCode, UbcError};
pub use header::{
    parse_header, AeadAlgorithm, HashAlgorithm, Header, AEAD_AES_256_GCM, AEAD_NONE,
    FLAG_ENCRYPTED, FLAG_HAS_METADATA, HASH_HMAC_SHA256, HASH_SHA256, HEADER_SIZE, VERSION,
};
pub use metadata::{
    encode_metadata, parse_metadata, parse_metadata_with_limit, MetadataEntry,
    DEFAULT_MAX_METADATA_BYTES,
};
