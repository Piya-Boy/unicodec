use crate::{ErrorCode, UbcError};

/// Default upper bound for attacker-controlled metadata blocks during decoding.
pub const DEFAULT_MAX_METADATA_BYTES: usize = 16 << 20;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetadataEntry {
    pub tag: u16,
    pub value: Vec<u8>,
}

pub fn encode_metadata<I>(entries: I) -> Result<Vec<u8>, UbcError>
where
    I: IntoIterator<Item = MetadataEntry>,
{
    let mut ordered: Vec<_> = entries.into_iter().collect();
    ordered.sort_unstable_by_key(|entry| entry.tag);
    if ordered.is_empty() {
        return Ok(Vec::new());
    }

    let mut body = Vec::new();
    let mut previous_tag = None;
    for entry in ordered {
        if previous_tag == Some(entry.tag) || !valid_reserved_metadata(&entry) {
            return Err(UbcError::new(ErrorCode::MetadataMalformed));
        }
        previous_tag = Some(entry.tag);

        let value_length = u32::try_from(entry.value.len())
            .map_err(|_| UbcError::new(ErrorCode::MetadataMalformed))?;
        let entry_length = 6_usize
            .checked_add(entry.value.len())
            .ok_or(UbcError::new(ErrorCode::MetadataMalformed))?;
        let next_length = body
            .len()
            .checked_add(entry_length)
            .ok_or(UbcError::new(ErrorCode::MetadataMalformed))?;
        if u32::try_from(next_length).is_err() {
            return Err(UbcError::new(ErrorCode::MetadataMalformed));
        }

        body.extend_from_slice(&entry.tag.to_le_bytes());
        body.extend_from_slice(&value_length.to_le_bytes());
        body.extend_from_slice(&entry.value);
    }

    let body_length =
        u32::try_from(body.len()).map_err(|_| UbcError::new(ErrorCode::MetadataMalformed))?;
    let mut encoded = Vec::with_capacity(4 + body.len());
    encoded.extend_from_slice(&body_length.to_le_bytes());
    encoded.extend_from_slice(&body);
    Ok(encoded)
}

/// Parses a serialized metadata region and returns its entries and byte length.
pub fn parse_metadata(data: &[u8]) -> Result<(Vec<MetadataEntry>, usize), UbcError> {
    parse_metadata_with_limit(data, DEFAULT_MAX_METADATA_BYTES)
}

/// Parses a serialized metadata region with a caller-supplied metadata size limit.
pub fn parse_metadata_with_limit(
    data: &[u8],
    max_metadata_bytes: usize,
) -> Result<(Vec<MetadataEntry>, usize), UbcError> {
    if data.len() < 4 {
        return Err(UbcError::new(ErrorCode::MetadataMalformed));
    }
    let body_length = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if body_length == 0 {
        return Err(UbcError::new(ErrorCode::MetadataMalformed));
    }
    let body_length =
        usize::try_from(body_length).map_err(|_| UbcError::new(ErrorCode::MetadataMalformed))?;
    if body_length > max_metadata_bytes {
        return Err(UbcError::new(ErrorCode::MetadataMalformed));
    }
    let end = 4_usize
        .checked_add(body_length)
        .ok_or(UbcError::new(ErrorCode::MetadataMalformed))?;
    if end > data.len() {
        return Err(UbcError::new(ErrorCode::MetadataMalformed));
    }

    let mut entries = Vec::new();
    let mut offset = 4;
    let mut previous_tag = None;
    while offset < end {
        if end - offset < 6 {
            return Err(UbcError::new(ErrorCode::MetadataMalformed));
        }
        let tag = u16::from_le_bytes([data[offset], data[offset + 1]]);
        let value_length = u32::from_le_bytes([
            data[offset + 2],
            data[offset + 3],
            data[offset + 4],
            data[offset + 5],
        ]);
        offset += 6;
        let value_length = usize::try_from(value_length)
            .map_err(|_| UbcError::new(ErrorCode::MetadataMalformed))?;
        let value_end = offset
            .checked_add(value_length)
            .ok_or(UbcError::new(ErrorCode::MetadataMalformed))?;
        if value_end > end || previous_tag.is_some_and(|previous| tag <= previous) {
            return Err(UbcError::new(ErrorCode::MetadataMalformed));
        }

        let entry = MetadataEntry {
            tag,
            value: data[offset..value_end].to_vec(),
        };
        if !valid_reserved_metadata(&entry) {
            return Err(UbcError::new(ErrorCode::MetadataMalformed));
        }
        entries.push(entry);
        previous_tag = Some(tag);
        offset = value_end;
    }
    Ok((entries, end))
}

fn valid_reserved_metadata(entry: &MetadataEntry) -> bool {
    match entry.tag {
        0x0001 => {
            !entry.value.starts_with(&[0xEF, 0xBB, 0xBF])
                && !entry.value.contains(&0)
                && std::str::from_utf8(&entry.value).is_ok()
        }
        0x0002 => entry.value.iter().all(|byte| (0x01..=0x7F).contains(byte)),
        0x0003 => entry.value.len() == 8,
        _ => true,
    }
}
