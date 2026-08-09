use crate::{ErrorCode, UbcError};

pub const HEADER_SIZE: usize = 40;
pub const VERSION: u8 = 1;
pub const HASH_SHA256: u8 = 0;
pub const HASH_HMAC_SHA256: u8 = 1;
pub const AEAD_NONE: u8 = 0;
pub const AEAD_AES_256_GCM: u8 = 1;
pub const FLAG_ENCRYPTED: u8 = 1 << 0;
pub const FLAG_HAS_METADATA: u8 = 1 << 1;

const MAGIC: [u8; 4] = *b"UBC1";
const ALLOWED_FLAGS: u8 = FLAG_ENCRYPTED | FLAG_HAS_METADATA;
const MAX_ENCRYPTED_CHUNK_SIZE: u32 = u32::MAX - 16;

pub type HashAlgorithm = u8;
pub type AeadAlgorithm = u8;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Header {
    pub version: u8,
    pub flags: u8,
    pub hash_algo: HashAlgorithm,
    pub aead_algo: AeadAlgorithm,
    pub chunk_size: u32,
    pub chunk_count: u64,
    pub total_size: u64,
    pub base_nonce: [u8; 12],
}

impl Header {
    pub const fn encrypted(&self) -> bool {
        self.flags & FLAG_ENCRYPTED != 0
    }

    pub const fn has_metadata(&self) -> bool {
        self.flags & FLAG_HAS_METADATA != 0
    }

    pub fn to_bytes(&self) -> Result<[u8; HEADER_SIZE], UbcError> {
        self.validate()?;

        let mut encoded = [0_u8; HEADER_SIZE];
        encoded[..4].copy_from_slice(&MAGIC);
        encoded[4] = self.version;
        encoded[5] = self.flags;
        encoded[6] = self.hash_algo;
        encoded[7] = self.aead_algo;
        encoded[8..12].copy_from_slice(&self.chunk_size.to_le_bytes());
        encoded[12..20].copy_from_slice(&self.chunk_count.to_le_bytes());
        encoded[20..28].copy_from_slice(&self.total_size.to_le_bytes());
        encoded[28..40].copy_from_slice(&self.base_nonce);
        Ok(encoded)
    }

    fn validate(&self) -> Result<(), UbcError> {
        if self.version != VERSION {
            return Err(UbcError::new(ErrorCode::UnsupportedVersion));
        }
        if !matches!(self.hash_algo, HASH_SHA256 | HASH_HMAC_SHA256)
            || !matches!(self.aead_algo, AEAD_NONE | AEAD_AES_256_GCM)
        {
            return Err(UbcError::new(ErrorCode::UnsupportedAlgorithm));
        }
        if self.flags & !ALLOWED_FLAGS != 0 {
            return Err(UbcError::new(ErrorCode::ReservedBits));
        }
        if self.encrypted() {
            if self.aead_algo != AEAD_AES_256_GCM
                || self.hash_algo != HASH_HMAC_SHA256
                || self.chunk_size == 0
                || self.chunk_size > MAX_ENCRYPTED_CHUNK_SIZE
            {
                return Err(UbcError::new(ErrorCode::ReservedBits));
            }
            return Ok(());
        }
        if self.aead_algo != AEAD_NONE
            || self.hash_algo != HASH_SHA256
            || self.chunk_size == 0
            || self.base_nonce != [0_u8; 12]
        {
            return Err(UbcError::new(ErrorCode::ReservedBits));
        }
        Ok(())
    }
}

pub fn parse_header(data: &[u8]) -> Result<Header, UbcError> {
    if data.len() < HEADER_SIZE {
        return Err(UbcError::new(ErrorCode::Truncated));
    }
    if data[..4] != MAGIC {
        return Err(UbcError::new(ErrorCode::BadMagic));
    }

    let mut base_nonce = [0_u8; 12];
    base_nonce.copy_from_slice(&data[28..40]);
    let header = Header {
        version: data[4],
        flags: data[5],
        hash_algo: data[6],
        aead_algo: data[7],
        chunk_size: u32::from_le_bytes([data[8], data[9], data[10], data[11]]),
        chunk_count: u64::from_le_bytes([
            data[12], data[13], data[14], data[15], data[16], data[17], data[18], data[19],
        ]),
        total_size: u64::from_le_bytes([
            data[20], data[21], data[22], data[23], data[24], data[25], data[26], data[27],
        ]),
        base_nonce,
    };
    header.validate()?;
    Ok(header)
}
