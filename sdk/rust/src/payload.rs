use sha2::{Digest, Sha256};

use crate::{
    AEAD_NONE, ErrorCode, FLAG_HAS_METADATA, HASH_SHA256, HEADER_SIZE, Header, MetadataEntry,
    UbcError, VERSION, encode_metadata, parse_header, parse_metadata,
};

pub const DEFAULT_CHUNK_SIZE: u32 = 1 << 20;

const FOOTER_SIZE: usize = 36;
const FOOTER_MAGIC: [u8; 4] = *b"UBCE";

/// Encodes plaintext into a complete UBC v1 container using the plain SHA-256 root.
pub fn encode_plain(
    data: &[u8],
    entries: impl IntoIterator<Item = MetadataEntry>,
    chunk_size: u32,
) -> Result<Vec<u8>, UbcError> {
    let metadata = encode_metadata(entries)?;
    let chunk_count = chunk_count(data.len(), chunk_size)?;
    let header = Header {
        version: VERSION,
        flags: if metadata.is_empty() {
            0
        } else {
            FLAG_HAS_METADATA
        },
        hash_algo: HASH_SHA256,
        aead_algo: AEAD_NONE,
        chunk_size,
        chunk_count,
        total_size: u64::try_from(data.len())
            .map_err(|_| UbcError::new(ErrorCode::ReservedBits))?,
        base_nonce: [0; 12],
    }
    .to_bytes()?;

    let capacity = HEADER_SIZE
        .checked_add(metadata.len())
        .and_then(|size| size.checked_add(data.len()))
        .and_then(|size| size.checked_add(usize::try_from(chunk_count).ok()?.checked_mul(4)?))
        .and_then(|size| size.checked_add(FOOTER_SIZE))
        .ok_or(UbcError::new(ErrorCode::ReservedBits))?;
    let mut output = Vec::with_capacity(capacity);
    output.extend_from_slice(&header);
    output.extend_from_slice(&metadata);

    let mut root = Sha256::new();
    root.update(header);
    root.update(&metadata);
    for chunk in data
        .chunks(usize::try_from(chunk_size).map_err(|_| UbcError::new(ErrorCode::ReservedBits))?)
    {
        let chunk_len =
            u32::try_from(chunk.len()).map_err(|_| UbcError::new(ErrorCode::ReservedBits))?;
        output.extend_from_slice(&chunk_len.to_le_bytes());
        output.extend_from_slice(chunk);
        root.update(Sha256::digest(chunk));
    }
    output.extend_from_slice(&root.finalize());
    output.extend_from_slice(&FOOTER_MAGIC);
    Ok(output)
}

/// Fully verifies and decodes a non-encrypted UBC container held in memory.
pub fn decode_plain(container: &[u8]) -> Result<(Vec<u8>, Vec<MetadataEntry>), UbcError> {
    let header = parse_header(container)?;
    let header_bytes = &container[..HEADER_SIZE];
    let mut offset = HEADER_SIZE;
    let (metadata, metadata_region) = if header.has_metadata() {
        let (metadata, consumed) = parse_metadata(&container[offset..])?;
        let region = &container[offset..offset + consumed];
        offset += consumed;
        (metadata, region)
    } else {
        (Vec::new(), &[][..])
    };

    if header.encrypted() {
        return Err(UbcError::new(ErrorCode::MissingKey));
    }

    let mut root = Sha256::new();
    root.update(header_bytes);
    root.update(metadata_region);
    let mut plaintext = Vec::new();
    let mut plain_size = 0_u64;
    for _ in 0..header.chunk_count {
        let chunk_length = read_chunk_length(container, offset)?;
        offset += 4;
        let chunk_end = offset
            .checked_add(chunk_length)
            .ok_or(UbcError::new(ErrorCode::Truncated))?;
        if container.len().saturating_sub(chunk_end) < FOOTER_SIZE {
            return Err(UbcError::new(ErrorCode::Truncated));
        }
        let chunk = &container[offset..chunk_end];
        plain_size = plain_size
            .checked_add(
                u64::try_from(chunk.len()).map_err(|_| UbcError::new(ErrorCode::RootMismatch))?,
            )
            .ok_or(UbcError::new(ErrorCode::RootMismatch))?;
        if plain_size > header.total_size {
            return Err(UbcError::new(ErrorCode::RootMismatch));
        }
        root.update(Sha256::digest(chunk));
        plaintext.extend_from_slice(chunk);
        offset = chunk_end;
    }

    let footer_end = offset
        .checked_add(FOOTER_SIZE)
        .ok_or(UbcError::new(ErrorCode::Truncated))?;
    if footer_end > container.len() || container[offset + 32..footer_end] != FOOTER_MAGIC {
        return Err(UbcError::new(ErrorCode::Truncated));
    }
    if plain_size != header.total_size || container[offset..offset + 32] != root.finalize()[..] {
        return Err(UbcError::new(ErrorCode::RootMismatch));
    }
    if footer_end != container.len() {
        return Err(UbcError::new(ErrorCode::TrailingData));
    }
    Ok((plaintext, metadata))
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
