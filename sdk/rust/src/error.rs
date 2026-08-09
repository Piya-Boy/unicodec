use core::fmt;

/// Stable UBC error identifiers defined by SPEC.md section 5.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ErrorCode {
    BadMagic,
    UnsupportedVersion,
    UnsupportedAlgorithm,
    ReservedBits,
    Truncated,
    RootMismatch,
    ChunkAuth,
    MissingKey,
    MetadataMalformed,
    TrailingData,
}

impl ErrorCode {
    pub const ALL: [Self; 10] = [
        Self::BadMagic,
        Self::UnsupportedVersion,
        Self::UnsupportedAlgorithm,
        Self::ReservedBits,
        Self::Truncated,
        Self::RootMismatch,
        Self::ChunkAuth,
        Self::MissingKey,
        Self::MetadataMalformed,
        Self::TrailingData,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BadMagic => "ERR_BAD_MAGIC",
            Self::UnsupportedVersion => "ERR_UNSUPPORTED_VER",
            Self::UnsupportedAlgorithm => "ERR_UNSUPPORTED_ALGO",
            Self::ReservedBits => "ERR_RESERVED_BITS",
            Self::Truncated => "ERR_TRUNCATED",
            Self::RootMismatch => "ERR_ROOT_MISMATCH",
            Self::ChunkAuth => "ERR_CHUNK_AUTH",
            Self::MissingKey => "ERR_MISSING_KEY",
            Self::MetadataMalformed => "ERR_META_MALFORMED",
            Self::TrailingData => "ERR_TRAILING_DATA",
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A UBC failure carrying a portable [`ErrorCode`].
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct UbcError {
    pub code: ErrorCode,
}

impl UbcError {
    pub const fn new(code: ErrorCode) -> Self {
        Self { code }
    }
}

impl fmt::Display for UbcError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.code.fmt(formatter)
    }
}

impl std::error::Error for UbcError {}
