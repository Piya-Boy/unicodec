use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::PathBuf,
};

use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, AeadCore, OsRng, Payload, rand_core::RngCore},
};
use hmac::Mac;
use sha2::{Digest, Sha256};

use crate::crypto::{
    FOOTER_MAGIC, FOOTER_SIZE, GCM_TAG_SIZE, chunk_aad, chunk_nonce, cipher, root_mac,
};
use crate::{
    AEAD_AES_256_GCM, AEAD_NONE, DEFAULT_CHUNK_SIZE, DEFAULT_MAX_METADATA_BYTES, DecodeOptions,
    ErrorCode, FLAG_ENCRYPTED, FLAG_HAS_METADATA, HASH_HMAC_SHA256, HASH_SHA256, HEADER_SIZE,
    Header, MetadataEntry, UbcError, VERSION, encode_metadata, parse_header,
    parse_metadata_with_limit,
};

const READ_BLOCK_SIZE: usize = 32 << 10;

/// Options controlling streamed encoding. A supplied base nonce is intended only for
/// deterministic conformance tests.
#[derive(Clone, Copy, Debug, Default)]
pub struct EncodeOptions<'a> {
    pub key: Option<&'a [u8]>,
    pub chunk_size: Option<u32>,
    pub base_nonce: Option<[u8; 12]>,
}

/// A write-side UBC encoder. Plaintext is spooled until its final size is known,
/// because the v1 header precedes the payload and contains both size and chunk count.
pub struct Encoder<W: Write> {
    sink: W,
    metadata: Vec<u8>,
    options: EncodeOptions<'static>,
    key: Option<Vec<u8>>,
    spool: Option<TempSpool>,
    total_size: u64,
    finished: bool,
}

impl<W: Write> Encoder<W> {
    pub fn new(
        sink: W,
        entries: impl IntoIterator<Item = MetadataEntry>,
        options: EncodeOptions<'_>,
    ) -> Result<Self, UbcError> {
        let chunk_size = options.chunk_size.unwrap_or(DEFAULT_CHUNK_SIZE);
        if chunk_size == 0 || options.key.is_some_and(|key| key.len() != 32) {
            return Err(UbcError::new(ErrorCode::ReservedBits));
        }
        let metadata = encode_metadata(entries)?;
        Ok(Self {
            sink,
            metadata,
            options: EncodeOptions {
                key: None,
                chunk_size: Some(chunk_size),
                base_nonce: options.base_nonce,
            },
            key: options.key.map(ToOwned::to_owned),
            spool: Some(TempSpool::new().map_err(|_| UbcError::new(ErrorCode::Truncated))?),
            total_size: 0,
            finished: false,
        })
    }

    /// Writes the header, payload, authenticated root, and footer to the sink.
    pub fn finish(&mut self) -> io::Result<()> {
        if self.finished {
            return Err(io::Error::other("UBC encoder is already finished"));
        }
        self.finished = true;
        let chunk_size = self
            .options
            .chunk_size
            .expect("validated during construction");
        let chunk_count = self.total_size.div_ceil(u64::from(chunk_size));
        let encrypted = self.key.is_some();
        let base_nonce = if encrypted {
            self.options.base_nonce.unwrap_or_else(random_nonce)
        } else {
            [0; 12]
        };
        let header = Header {
            version: VERSION,
            flags: (if encrypted { FLAG_ENCRYPTED } else { 0 })
                | if self.metadata.is_empty() {
                    0
                } else {
                    FLAG_HAS_METADATA
                },
            hash_algo: if encrypted {
                HASH_HMAC_SHA256
            } else {
                HASH_SHA256
            },
            aead_algo: if encrypted {
                AEAD_AES_256_GCM
            } else {
                AEAD_NONE
            },
            chunk_size,
            chunk_count,
            total_size: self.total_size,
            base_nonce,
        }
        .to_bytes()
        .map_err(io_error)?;
        self.sink.write_all(&header)?;
        self.sink.write_all(&self.metadata)?;

        let metadata_digest = Sha256::digest(&self.metadata);
        let mut root = if let Some(key) = self.key.as_deref() {
            Root::Mac(root_mac(key, &base_nonce).map_err(io_error)?)
        } else {
            Root::Hash(Sha256::new())
        };
        root.update(&header);
        root.update(&self.metadata);
        self.spool
            .as_mut()
            .expect("spool exists until finalization succeeds")
            .file
            .as_mut()
            .expect("spool file exists until encoder drop")
            .seek(SeekFrom::Start(0))?;
        let buffer_length = usize::try_from(self.total_size.min(u64::from(chunk_size)))
            .map_err(|_| io::Error::other("chunk too large"))?;
        let mut buffer = vec![0; buffer_length];
        let cipher = self
            .key
            .as_deref()
            .map(cipher)
            .transpose()
            .map_err(io_error)?;
        for index in 0..chunk_count {
            let remaining = self.total_size - index * u64::from(chunk_size);
            let length = usize::try_from(remaining.min(u64::from(chunk_size)))
                .map_err(|_| io::Error::other("chunk too large"))?;
            self.spool
                .as_mut()
                .expect("spool exists until finalization succeeds")
                .file
                .as_mut()
                .expect("spool file exists until encoder drop")
                .read_exact(&mut buffer[..length])?;
            let body = if let Some(cipher) = &cipher {
                cipher
                    .encrypt(
                        &chunk_nonce(base_nonce, index),
                        Payload {
                            msg: &buffer[..length],
                            aad: &chunk_aad(&header, &metadata_digest, index),
                        },
                    )
                    .map_err(|_| io_error(UbcError::new(ErrorCode::ChunkAuth)))?
            } else {
                buffer[..length].to_vec()
            };
            let body_length = u32::try_from(body.len())
                .map_err(|_| io_error(UbcError::new(ErrorCode::ReservedBits)))?;
            self.sink.write_all(&body_length.to_le_bytes())?;
            self.sink.write_all(&body)?;
            root.update(&Sha256::digest(&body));
        }
        self.sink.write_all(&root.finish())?;
        self.sink.write_all(&FOOTER_MAGIC)?;
        let mut spool = self
            .spool
            .take()
            .expect("spool exists until finalization succeeds");
        spool.purge()?;
        Ok(())
    }
}

impl<W: Write> Write for Encoder<W> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if self.finished {
            return Err(io::Error::other("UBC encoder is already finished"));
        }
        let count = self
            .spool
            .as_mut()
            .expect("spool exists until finalization succeeds")
            .file
            .as_mut()
            .expect("spool file exists until encoder drop")
            .write(buffer)?;
        self.total_size = self
            .total_size
            .checked_add(u64::try_from(count).map_err(|_| io::Error::other("input too large"))?)
            .ok_or_else(|| io::Error::other("input too large"))?;
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.spool.as_mut() {
            Some(spool) => spool
                .file
                .as_mut()
                .expect("spool file exists until encoder drop")
                .flush(),
            None => self.sink.flush(),
        }
    }
}

pub fn new_encoder<W: Write>(
    sink: W,
    entries: impl IntoIterator<Item = MetadataEntry>,
    options: EncodeOptions<'_>,
) -> Result<Encoder<W>, UbcError> {
    Encoder::new(sink, entries, options)
}

/// A read-side UBC decoder. Encrypted chunks are authenticated before being returned.
pub struct Decoder<R: Read> {
    source: R,
    header: Header,
    header_bytes: [u8; HEADER_SIZE],
    metadata: Vec<MetadataEntry>,
    metadata_digest: [u8; 32],
    key: Option<Vec<u8>>,
    limits: Limits,
    root: Option<Root>,
    chunk_index: u64,
    plaintext_size: u64,
    pending: Vec<u8>,
    pending_offset: usize,
    spool: Option<TempSpool>,
    prefetched_footer: Option<[u8; FOOTER_SIZE]>,
    finished: bool,
    terminal_error: Option<UbcError>,
}

impl<R: Read> Decoder<R> {
    pub fn new(mut source: R, options: DecodeOptions<'_>) -> Result<Self, UbcError> {
        let mut header_bytes = [0; HEADER_SIZE];
        read_exact(&mut source, &mut header_bytes)?;
        let header = parse_header(&header_bytes)?;
        let limits = Limits::from(options);
        let (metadata, metadata_region) = if header.has_metadata() {
            read_metadata_region(&mut source, limits.max_metadata_bytes)?
        } else {
            (Vec::new(), Vec::new())
        };
        if header.encrypted() && options.key.len() != 32 {
            return Err(UbcError::new(ErrorCode::MissingKey));
        }
        if header.chunk_count > limits.max_chunk_count || header.total_size > limits.max_total_size
        {
            return Err(UbcError::new(ErrorCode::Truncated));
        }
        let mut root = if header.encrypted() {
            Root::Mac(root_mac(options.key, &header.base_nonce)?)
        } else {
            Root::Hash(Sha256::new())
        };
        root.update(&header_bytes);
        root.update(&metadata_region);
        let encrypted = header.encrypted();
        let spool = if encrypted {
            None
        } else {
            Some(TempSpool::new().map_err(|_| UbcError::new(ErrorCode::Truncated))?)
        };
        Ok(Self {
            source,
            header,
            header_bytes,
            metadata,
            metadata_digest: Sha256::digest(&metadata_region).into(),
            key: encrypted.then(|| options.key.to_vec()),
            limits,
            root: Some(root),
            chunk_index: 0,
            plaintext_size: 0,
            pending: Vec::new(),
            pending_offset: 0,
            spool,
            prefetched_footer: None,
            finished: false,
            terminal_error: None,
        })
    }

    pub fn metadata(&self) -> Vec<MetadataEntry> {
        self.metadata.to_vec()
    }

    fn load_chunk(&mut self) -> Result<(), UbcError> {
        if self.chunk_index == self.header.chunk_count {
            return self.verify_footer();
        }
        let mut length = [0; 4];
        read_exact(&mut self.source, &mut length)?;
        let body_length = u64::from(u32::from_le_bytes(length));
        if body_length > self.limits.max_chunk_len {
            return Err(UbcError::new(ErrorCode::Truncated));
        }
        let mut body = Vec::new();
        read_incrementally(&mut self.source, &mut body, body_length)?;
        self.root
            .as_mut()
            .expect("root remains until footer")
            .update(&Sha256::digest(&body));
        if self.key.is_some() && self.chunk_index + 1 == self.header.chunk_count {
            self.prefetched_footer = Some(read_footer(&mut self.source)?);
        }
        let plaintext = if let Some(key) = self.key.as_deref() {
            if body.len() < GCM_TAG_SIZE {
                return Err(UbcError::new(ErrorCode::ChunkAuth));
            }
            cipher(key)?
                .decrypt(
                    &chunk_nonce(self.header.base_nonce, self.chunk_index),
                    Payload {
                        msg: &body,
                        aad: &chunk_aad(
                            &self.header_bytes,
                            &self.metadata_digest,
                            self.chunk_index,
                        ),
                    },
                )
                .map_err(|_| UbcError::new(ErrorCode::ChunkAuth))?
        } else {
            body
        };
        self.plaintext_size = self
            .plaintext_size
            .checked_add(
                u64::try_from(plaintext.len())
                    .map_err(|_| UbcError::new(ErrorCode::RootMismatch))?,
            )
            .ok_or(UbcError::new(ErrorCode::RootMismatch))?;
        if self.plaintext_size > self.header.total_size {
            return Err(UbcError::new(ErrorCode::RootMismatch));
        }
        self.chunk_index += 1;
        if let Some(spool) = self.spool.as_mut() {
            spool
                .file
                .as_mut()
                .expect("spool file exists until decoder drop")
                .write_all(&plaintext)
                .map_err(|_| UbcError::new(ErrorCode::Truncated))?;
        } else {
            self.pending = plaintext;
            self.pending_offset = 0;
        }
        Ok(())
    }

    fn verify_footer(&mut self) -> Result<(), UbcError> {
        let footer = match self.prefetched_footer.take() {
            Some(footer) => footer,
            None => read_footer(&mut self.source)?,
        };
        if self.plaintext_size != self.header.total_size
            || !self
                .root
                .take()
                .expect("root exists before footer")
                .verify(&footer[..32])
        {
            return Err(UbcError::new(ErrorCode::RootMismatch));
        }
        let mut trailing = [0; 1];
        match self.source.read(&mut trailing) {
            Ok(0) => {}
            Ok(_) => return Err(UbcError::new(ErrorCode::TrailingData)),
            Err(_) => return Err(UbcError::new(ErrorCode::Truncated)),
        }
        if let Some(spool) = self.spool.as_mut() {
            spool
                .file
                .as_mut()
                .expect("spool file exists until decoder drop")
                .seek(SeekFrom::Start(0))
                .map_err(|_| UbcError::new(ErrorCode::Truncated))?;
        }
        self.finished = true;
        Ok(())
    }
}

impl<R: Read> Read for Decoder<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        if let Some(error) = self.terminal_error {
            return Err(io_error(error));
        }
        if self.spool.is_some() {
            while !self.finished {
                if let Err(error) = self.load_chunk() {
                    self.terminal_error = Some(error);
                    return Err(io_error(error));
                }
            }
            return self
                .spool
                .as_mut()
                .expect("plain decoder keeps its spool until drop")
                .file
                .as_mut()
                .expect("spool file exists until decoder drop")
                .read(output);
        }
        while self.pending_offset == self.pending.len() && !self.finished {
            if let Err(error) = self.load_chunk() {
                self.terminal_error = Some(error);
                return Err(io_error(error));
            }
        }
        if self.pending_offset == self.pending.len() {
            return Ok(0);
        }
        let count = output.len().min(self.pending.len() - self.pending_offset);
        output[..count]
            .copy_from_slice(&self.pending[self.pending_offset..self.pending_offset + count]);
        self.pending_offset += count;
        Ok(count)
    }
}

pub fn new_decoder<R: Read>(source: R, options: DecodeOptions<'_>) -> Result<Decoder<R>, UbcError> {
    Decoder::new(source, options)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifyReport {
    pub ok: bool,
    pub error: Option<ErrorCode>,
}

pub fn verify<R: Read>(source: R, options: DecodeOptions<'_>) -> VerifyReport {
    match Decoder::new(source, options) {
        Ok(mut decoder) => match io::copy(&mut decoder, &mut io::sink()) {
            Ok(_) => VerifyReport {
                ok: true,
                error: None,
            },
            Err(error) => VerifyReport {
                ok: false,
                error: error
                    .get_ref()
                    .and_then(|cause| cause.downcast_ref::<UbcError>())
                    .map(|error| error.code)
                    .or(Some(ErrorCode::Truncated)),
            },
        },
        Err(error) => VerifyReport {
            ok: false,
            error: Some(error.code),
        },
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContainerFlags {
    pub encrypted: bool,
    pub has_metadata: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContainerInfo {
    pub version: u8,
    pub flags: ContainerFlags,
    pub hash_algo: u8,
    pub aead_algo: u8,
    pub chunk_size: u32,
    pub chunk_count: u64,
    pub total_size: u64,
    pub metadata: Vec<MetadataEntry>,
}

pub fn inspect<R: Read>(source: R) -> Result<ContainerInfo, UbcError> {
    inspect_with_limit(source, DEFAULT_MAX_METADATA_BYTES)
}

pub fn inspect_with_limit<R: Read>(
    mut source: R,
    max_metadata_bytes: usize,
) -> Result<ContainerInfo, UbcError> {
    let mut header_bytes = [0; HEADER_SIZE];
    read_exact(&mut source, &mut header_bytes)?;
    let header = parse_header(&header_bytes)?;
    let metadata = if header.has_metadata() {
        read_metadata_region(&mut source, max_metadata_bytes)?.0
    } else {
        Vec::new()
    };
    Ok(ContainerInfo {
        version: header.version,
        flags: ContainerFlags {
            encrypted: header.encrypted(),
            has_metadata: header.has_metadata(),
        },
        hash_algo: header.hash_algo,
        aead_algo: header.aead_algo,
        chunk_size: header.chunk_size,
        chunk_count: header.chunk_count,
        total_size: header.total_size,
        metadata,
    })
}

#[derive(Clone, Copy)]
struct Limits {
    max_metadata_bytes: usize,
    max_chunk_len: u64,
    max_chunk_count: u64,
    max_total_size: u64,
}

impl From<DecodeOptions<'_>> for Limits {
    fn from(options: DecodeOptions<'_>) -> Self {
        Self {
            max_metadata_bytes: options.max_metadata_bytes,
            max_chunk_len: options.max_chunk_len,
            max_chunk_count: options.max_chunk_count,
            max_total_size: options.max_total_size,
        }
    }
}

enum Root {
    Hash(Sha256),
    Mac(crate::crypto::HmacSha256),
}

impl Root {
    fn update(&mut self, bytes: &[u8]) {
        match self {
            Self::Hash(hash) => hash.update(bytes),
            Self::Mac(mac) => mac.update(bytes),
        }
    }

    fn finish(self) -> [u8; 32] {
        match self {
            Self::Hash(hash) => hash.finalize().into(),
            Self::Mac(mac) => mac.finalize().into_bytes().into(),
        }
    }

    fn verify(self, expected: &[u8]) -> bool {
        match self {
            Self::Hash(hash) => hash.finalize().as_slice() == expected,
            Self::Mac(mac) => mac.verify_slice(expected).is_ok(),
        }
    }
}

struct TempSpool {
    path: PathBuf,
    file: Option<File>,
}

impl TempSpool {
    fn new() -> io::Result<Self> {
        let directory = std::env::temp_dir();
        for _ in 0..128 {
            let mut random_id = [0_u8; 16];
            OsRng.fill_bytes(&mut random_id);
            let path = directory.join(format!("ubc-{:032x}.tmp", u128::from_le_bytes(random_id)));
            let mut options = OpenOptions::new();
            options.read(true).write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;

                options.mode(0o600);
            }
            match options.open(&path) {
                Ok(file) => {
                    return Ok(Self {
                        path,
                        file: Some(file),
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not create UBC spool file",
        ))
    }

    fn purge(&mut self) -> io::Result<()> {
        if let Some(file) = self.file.as_mut() {
            file.set_len(0)?;
        }
        drop(self.file.take());
        std::fs::remove_file(&self.path)
    }
}

impl Drop for TempSpool {
    fn drop(&mut self) {
        drop(self.file.take());
        let _ = std::fs::remove_file(&self.path);
    }
}

fn random_nonce() -> [u8; 12] {
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    nonce.into()
}

fn read_exact(reader: &mut impl Read, bytes: &mut [u8]) -> Result<(), UbcError> {
    reader
        .read_exact(bytes)
        .map_err(|_| UbcError::new(ErrorCode::Truncated))
}

fn read_footer(reader: &mut impl Read) -> Result<[u8; FOOTER_SIZE], UbcError> {
    let mut footer = [0; FOOTER_SIZE];
    read_exact(reader, &mut footer)?;
    if footer[32..] != FOOTER_MAGIC {
        return Err(UbcError::new(ErrorCode::Truncated));
    }
    Ok(footer)
}

fn read_incrementally(
    reader: &mut impl Read,
    output: &mut Vec<u8>,
    mut length: u64,
) -> Result<(), UbcError> {
    let mut block = [0; READ_BLOCK_SIZE];
    while length != 0 {
        let count =
            usize::try_from(length.min(READ_BLOCK_SIZE as u64)).expect("bounded read block");
        read_exact(reader, &mut block[..count])?;
        output.extend_from_slice(&block[..count]);
        length -= count as u64;
    }
    Ok(())
}

fn read_metadata_region(
    reader: &mut impl Read,
    max_metadata_bytes: usize,
) -> Result<(Vec<MetadataEntry>, Vec<u8>), UbcError> {
    let mut prefix = [0; 4];
    read_exact(reader, &mut prefix).map_err(|_| UbcError::new(ErrorCode::MetadataMalformed))?;
    let length = usize::try_from(u32::from_le_bytes(prefix))
        .map_err(|_| UbcError::new(ErrorCode::MetadataMalformed))?;
    if length > max_metadata_bytes {
        return Err(UbcError::new(ErrorCode::MetadataMalformed));
    }
    let mut region = prefix.to_vec();
    read_incrementally(reader, &mut region, length as u64)
        .map_err(|_| UbcError::new(ErrorCode::MetadataMalformed))?;
    let (metadata, _) = parse_metadata_with_limit(&region, max_metadata_bytes)?;
    Ok((metadata, region))
}

fn io_error(error: UbcError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn successful_finish_removes_plaintext_spool() {
        let mut container = Vec::new();
        let mut encoder =
            Encoder::new(&mut container, Vec::new(), EncodeOptions::default()).unwrap();
        encoder.write_all(b"sensitive plaintext").unwrap();
        let spool_path = encoder.spool.as_ref().unwrap().path.clone();

        assert!(spool_path.exists());
        encoder.finish().unwrap();
        encoder.flush().unwrap();

        assert!(encoder.spool.is_none());
        assert!(!spool_path.exists());
    }
}
