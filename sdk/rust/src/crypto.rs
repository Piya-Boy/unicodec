use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload, consts::U12},
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::{
    AEAD_AES_256_GCM, ErrorCode, FLAG_ENCRYPTED, FLAG_HAS_METADATA, HASH_HMAC_SHA256, HEADER_SIZE,
    Header, MetadataEntry, UbcError, VERSION, encode_metadata, parse_header,
    parse_metadata_with_limit,
};

pub(crate) const FOOTER_MAGIC: [u8; 4] = *b"UBCE";
pub(crate) const FOOTER_SIZE: usize = 36;
pub(crate) const GCM_TAG_SIZE: usize = 16;
const ROOT_INFO: &[u8] = b"UBC1 root authentication";

/// Default upper bound for attacker-controlled encrypted chunk bodies during decoding.
pub const DEFAULT_MAX_CHUNK_LEN: u64 = 64 << 20;
/// Default upper bound for the number of encrypted chunks processed from one container.
pub const DEFAULT_MAX_CHUNK_COUNT: u64 = 1 << 20;
/// Default upper bound for plaintext produced from one encrypted container.
pub const DEFAULT_MAX_TOTAL_SIZE: u64 = 1 << 30;

/// Resource limits and key material for encrypted UBC decoding.
#[derive(Clone, Copy, Debug)]
pub struct DecodeOptions<'a> {
    pub key: &'a [u8],
    pub max_metadata_bytes: usize,
    pub max_chunk_len: u64,
    pub max_chunk_count: u64,
    pub max_total_size: u64,
}

impl<'a> DecodeOptions<'a> {
    pub const fn with_key(key: &'a [u8]) -> Self {
        Self {
            key,
            max_metadata_bytes: crate::DEFAULT_MAX_METADATA_BYTES,
            max_chunk_len: DEFAULT_MAX_CHUNK_LEN,
            max_chunk_count: DEFAULT_MAX_CHUNK_COUNT,
            max_total_size: DEFAULT_MAX_TOTAL_SIZE,
        }
    }
}

impl Default for DecodeOptions<'static> {
    fn default() -> Self {
        Self::with_key(&[])
    }
}

pub(crate) type HmacSha256 = Hmac<Sha256>;

/// Encodes with a freshly generated base nonce. Deterministic tests should use
/// [`encode_encrypted_with_fixed_nonce`] instead.
pub fn encode_encrypted(
    data: &[u8],
    key: &[u8],
    entries: impl IntoIterator<Item = MetadataEntry>,
    chunk_size: u32,
) -> Result<Vec<u8>, UbcError> {
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let mut base_nonce = [0_u8; 12];
    base_nonce.copy_from_slice(&nonce);
    encode_encrypted_with_fixed_nonce(data, key, base_nonce, entries, chunk_size)
}

/// Encodes with a caller-supplied base nonce for deterministic conformance tests.
pub fn encode_encrypted_with_fixed_nonce(
    data: &[u8],
    key: &[u8],
    base_nonce: [u8; 12],
    entries: impl IntoIterator<Item = MetadataEntry>,
    chunk_size: u32,
) -> Result<Vec<u8>, UbcError> {
    let cipher = cipher(key)?;
    let metadata = encode_metadata(entries)?;
    let chunk_count = chunk_count(data.len(), chunk_size)?;
    let header = Header {
        version: VERSION,
        flags: FLAG_ENCRYPTED
            | if metadata.is_empty() {
                0
            } else {
                FLAG_HAS_METADATA
            },
        hash_algo: HASH_HMAC_SHA256,
        aead_algo: AEAD_AES_256_GCM,
        chunk_size,
        chunk_count,
        total_size: u64::try_from(data.len())
            .map_err(|_| UbcError::new(ErrorCode::ReservedBits))?,
        base_nonce,
    }
    .to_bytes()?;

    let metadata_digest = Sha256::digest(&metadata);
    let mut root = root_mac(key, &base_nonce)?;
    root.update(&header);
    root.update(&metadata);
    let mut output = Vec::new();
    output.extend_from_slice(&header);
    output.extend_from_slice(&metadata);

    for (index, chunk) in data
        .chunks(usize::try_from(chunk_size).map_err(|_| UbcError::new(ErrorCode::ReservedBits))?)
        .enumerate()
    {
        let index = u64::try_from(index).map_err(|_| UbcError::new(ErrorCode::ReservedBits))?;
        let body = cipher
            .encrypt(
                &chunk_nonce(base_nonce, index),
                Payload {
                    msg: chunk,
                    aad: &chunk_aad(&header, &metadata_digest, index),
                },
            )
            .map_err(|_| UbcError::new(ErrorCode::ChunkAuth))?;
        let body_length =
            u32::try_from(body.len()).map_err(|_| UbcError::new(ErrorCode::ReservedBits))?;
        output.extend_from_slice(&body_length.to_le_bytes());
        output.extend_from_slice(&body);
        root.update(&Sha256::digest(&body));
    }

    output.extend_from_slice(&root.finalize().into_bytes());
    output.extend_from_slice(&FOOTER_MAGIC);
    Ok(output)
}

/// Fully verifies and decodes an encrypted UBC container without returning plaintext on failure.
pub fn decode_encrypted(
    container: &[u8],
    key: &[u8],
) -> Result<(Vec<u8>, Vec<MetadataEntry>), UbcError> {
    decode_encrypted_with_options(container, DecodeOptions::with_key(key))
}

/// Fully verifies and decodes an encrypted UBC container with caller-supplied resource limits.
pub fn decode_encrypted_with_options(
    container: &[u8],
    options: DecodeOptions<'_>,
) -> Result<(Vec<u8>, Vec<MetadataEntry>), UbcError> {
    let header = parse_header(container)?;
    let header_bytes = &container[..HEADER_SIZE];
    let mut offset = HEADER_SIZE;
    let (metadata, metadata_region) = if header.has_metadata() {
        let (metadata, consumed) =
            parse_metadata_with_limit(&container[offset..], options.max_metadata_bytes)?;
        let region = &container[offset..offset + consumed];
        offset += consumed;
        (metadata, region)
    } else {
        (Vec::new(), &[][..])
    };

    if !header.encrypted() || options.key.len() != 32 {
        return Err(UbcError::new(ErrorCode::MissingKey));
    }
    if header.chunk_count > options.max_chunk_count || header.total_size > options.max_total_size {
        return Err(UbcError::new(ErrorCode::Truncated));
    }
    let cipher = cipher(options.key)?;
    let metadata_digest = Sha256::digest(metadata_region);
    let mut root = root_mac(options.key, &header.base_nonce)?;
    root.update(header_bytes);
    root.update(metadata_region);
    let mut plaintext = Vec::new();
    let mut plain_size = 0_u64;

    for index in 0..header.chunk_count {
        let body_length = read_chunk_length(container, offset)?;
        offset += 4;
        if u64::try_from(body_length).map_err(|_| UbcError::new(ErrorCode::Truncated))?
            > options.max_chunk_len
        {
            return Err(UbcError::new(ErrorCode::Truncated));
        }
        let body_end = offset
            .checked_add(body_length)
            .ok_or(UbcError::new(ErrorCode::Truncated))?;
        if container.len().saturating_sub(body_end) < FOOTER_SIZE {
            return Err(UbcError::new(ErrorCode::Truncated));
        }
        let body = &container[offset..body_end];
        root.update(&Sha256::digest(body));
        if body.len() < GCM_TAG_SIZE {
            return Err(UbcError::new(ErrorCode::ChunkAuth));
        }
        let chunk = cipher
            .decrypt(
                &chunk_nonce(header.base_nonce, index),
                Payload {
                    msg: body,
                    aad: &chunk_aad(header_bytes, &metadata_digest, index),
                },
            )
            .map_err(|_| UbcError::new(ErrorCode::ChunkAuth))?;
        plain_size = plain_size
            .checked_add(
                u64::try_from(chunk.len()).map_err(|_| UbcError::new(ErrorCode::RootMismatch))?,
            )
            .ok_or(UbcError::new(ErrorCode::RootMismatch))?;
        if plain_size > header.total_size {
            return Err(UbcError::new(ErrorCode::RootMismatch));
        }
        plaintext.extend_from_slice(&chunk);
        offset = body_end;
    }

    let footer_end = offset
        .checked_add(FOOTER_SIZE)
        .ok_or(UbcError::new(ErrorCode::Truncated))?;
    if footer_end > container.len() || container[offset + 32..footer_end] != FOOTER_MAGIC {
        return Err(UbcError::new(ErrorCode::Truncated));
    }
    if plain_size != header.total_size
        || root.verify_slice(&container[offset..offset + 32]).is_err()
    {
        return Err(UbcError::new(ErrorCode::RootMismatch));
    }
    if footer_end != container.len() {
        return Err(UbcError::new(ErrorCode::TrailingData));
    }
    Ok((plaintext, metadata))
}

pub(crate) fn cipher(key: &[u8]) -> Result<Aes256Gcm, UbcError> {
    Aes256Gcm::new_from_slice(key).map_err(|_| UbcError::new(ErrorCode::MissingKey))
}

pub(crate) fn root_mac(key: &[u8], base_nonce: &[u8; 12]) -> Result<HmacSha256, UbcError> {
    let mut root_key = [0_u8; 32];
    Hkdf::<Sha256>::new(Some(base_nonce), key)
        .expand(ROOT_INFO, &mut root_key)
        .map_err(|_| UbcError::new(ErrorCode::RootMismatch))?;
    <HmacSha256 as Mac>::new_from_slice(&root_key)
        .map_err(|_| UbcError::new(ErrorCode::RootMismatch))
}

pub(crate) fn chunk_nonce(base_nonce: [u8; 12], index: u64) -> Nonce<U12> {
    let mut nonce = base_nonce;
    for (byte, index_byte) in nonce.iter_mut().zip(index.to_le_bytes().iter()) {
        *byte ^= index_byte;
    }
    *Nonce::<U12>::from_slice(&nonce)
}

pub(crate) fn chunk_aad(header: &[u8], metadata_digest: &[u8], index: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(header.len() + metadata_digest.len() + 8);
    aad.extend_from_slice(header);
    aad.extend_from_slice(metadata_digest);
    aad.extend_from_slice(&index.to_le_bytes());
    aad
}

fn chunk_count(data_len: usize, chunk_size: u32) -> Result<u64, UbcError> {
    if chunk_size == 0 {
        return Err(UbcError::new(ErrorCode::ReservedBits));
    }
    let data_len = u64::try_from(data_len).map_err(|_| UbcError::new(ErrorCode::ReservedBits))?;
    Ok(data_len.div_ceil(u64::from(chunk_size)))
}

fn read_chunk_length(container: &[u8], offset: usize) -> Result<usize, UbcError> {
    let length_end = offset
        .checked_add(4)
        .ok_or(UbcError::new(ErrorCode::Truncated))?;
    let bytes: [u8; 4] = container
        .get(offset..length_end)
        .ok_or(UbcError::new(ErrorCode::Truncated))?
        .try_into()
        .map_err(|_| UbcError::new(ErrorCode::Truncated))?;
    usize::try_from(u32::from_le_bytes(bytes)).map_err(|_| UbcError::new(ErrorCode::Truncated))
}
