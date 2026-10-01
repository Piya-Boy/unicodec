use std::{
    collections::BTreeMap,
    fs,
    path::{Component, Path, PathBuf},
};

use ubc::{
    MetadataEntry, UbcError, decode_encrypted, decode_plain, encode_encrypted_with_fixed_nonce,
    encode_plain, parse_header,
};

#[derive(Debug)]
pub struct Manifest {
    pub vectors: Vec<Vector>,
}

#[derive(Debug)]
pub struct Vector {
    pub id: String,
    pub input: Option<String>,
    pub options: Option<VectorOptions>,
    pub expected: String,
    pub expected_sha256: [u8; 32],
    pub expect_error: Option<String>,
}

#[derive(Debug)]
pub struct VectorOptions {
    pub chunk_size: Option<u32>,
    pub key: Option<Vec<u8>>,
    pub base_nonce: Option<[u8; 12]>,
    pub metadata: Vec<MetadataEntry>,
}

impl Manifest {
    pub fn read(vectors_root: &Path) -> Result<Self, String> {
        let bytes = read_child(vectors_root, "vectors.json")?;
        let root = JsonParser::new(&bytes).parse()?;
        let root = object(&root, "manifest")?;
        let vectors = array(required(root, "vectors")?, "vectors")?
            .iter()
            .map(parse_vector)
            .collect::<Result<Vec<_>, _>>()?;
        if vectors.is_empty() {
            return Err("manifest vectors must not be empty".to_owned());
        }
        Ok(Self { vectors })
    }

    pub fn canonical_key(&self) -> Result<&[u8], String> {
        self.vectors
            .iter()
            .filter(|vector| vector.expect_error.is_none())
            .filter_map(|vector| vector.options.as_ref()?.key.as_deref())
            .next()
            .ok_or_else(|| "manifest has no encrypted positive vector".to_owned())
    }
}

pub fn encode_vector(data: &[u8], vector: &Vector) -> Result<Vec<u8>, String> {
    let options = vector
        .options
        .as_ref()
        .ok_or_else(|| format!("{}: positive vector has no options", vector.id))?;
    let chunk_size = options
        .chunk_size
        .ok_or_else(|| format!("{}: positive vector has no chunkSize", vector.id))?;
    match (&options.key, options.base_nonce) {
        (None, None) => encode_plain(data, options.metadata.clone(), chunk_size),
        (Some(key), Some(nonce)) => encode_encrypted_with_fixed_nonce(
            data,
            key,
            nonce,
            options.metadata.clone(),
            chunk_size,
        ),
        _ => return Err(format!("{}: key and baseNonce must be paired", vector.id)),
    }
    .map_err(|error| format!("{}: encode failed with {}", vector.id, error.code))
}

pub fn decode_vector(
    container: &[u8],
    key: &[u8],
) -> Result<(Vec<u8>, Vec<MetadataEntry>), UbcError> {
    if parse_header(container)?.encrypted() {
        decode_encrypted(container, key)
    } else {
        decode_plain(container)
    }
}

pub fn decode_key(vector: &Vector, canonical_key: &[u8]) -> Vec<u8> {
    if let Some(key) = vector
        .options
        .as_ref()
        .and_then(|options| options.key.as_ref())
    {
        return key.clone();
    }
    if vector.expect_error.as_deref() == Some("ERR_CHUNK_AUTH") {
        return canonical_key.to_vec();
    }
    Vec::new()
}

pub fn read_child(root: &Path, relative: &str) -> Result<Vec<u8>, String> {
    let path = safe_child(root, relative)?;
    fs::read(&path).map_err(|error| format!("read {}: {error}", path.display()))
}

pub fn safe_child(root: &Path, relative: &str) -> Result<PathBuf, String> {
    let relative_path = Path::new(relative);
    if relative.is_empty()
        || relative_path.is_absolute()
        || relative_path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(format!("path must remain below its root: {relative}"));
    }
    Ok(root.join(relative_path))
}

pub fn safe_id(id: &str) -> bool {
    !id.is_empty()
        && id.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || (byte == b'-' && index != 0 && index + 1 != id.len())
        })
}

fn parse_vector(value: &JsonValue) -> Result<Vector, String> {
    let value = object(value, "vector")?;
    let id = string(required(value, "id")?, "id")?.to_owned();
    if !safe_id(&id) {
        return Err(format!("manifest contains unsafe vector id: {id}"));
    }
    let input = optional_string(value.get("input"), "input")?;
    let options = value.get("options").map(parse_options).transpose()?;
    let expected = string(required(value, "expected")?, "expected")?.to_owned();
    let expected_sha256 = parse_fixed_hex::<32>(string(
        required(value, "expectedSha256")?,
        "expectedSha256",
    )?)?;
    let expect_error = optional_string(value.get("expectError"), "expectError")?;
    Ok(Vector {
        id,
        input,
        options,
        expected,
        expected_sha256,
        expect_error,
    })
}

fn parse_options(value: &JsonValue) -> Result<VectorOptions, String> {
    let value = object(value, "options")?;
    let chunk_size = value
        .get("chunkSize")
        .map(|value| number(value, "chunkSize"))
        .transpose()?
        .map(|value| u32::try_from(value).map_err(|_| "chunkSize exceeds u32".to_owned()))
        .transpose()?;
    let key = optional_string(value.get("key"), "key")?
        .map(|value| parse_hex(&value))
        .transpose()?;
    let base_nonce = optional_string(value.get("baseNonce"), "baseNonce")?
        .map(|value| parse_fixed_hex::<12>(&value))
        .transpose()?;
    let metadata = match value.get("metadata") {
        None => Vec::new(),
        Some(entries) => array(entries, "metadata")?
            .iter()
            .map(parse_metadata)
            .collect::<Result<Vec<_>, _>>()?,
    };
    Ok(VectorOptions {
        chunk_size,
        key,
        base_nonce,
        metadata,
    })
}

fn parse_metadata(value: &JsonValue) -> Result<MetadataEntry, String> {
    let value = object(value, "metadata entry")?;
    let tag = string(required(value, "tag")?, "metadata tag")?;
    let tag = tag
        .strip_prefix("0x")
        .filter(|digits| digits.len() == 4)
        .ok_or_else(|| "metadata tag must be 0x followed by four digits".to_owned())?;
    let tag = u16::from_str_radix(tag, 16).map_err(|_| "invalid metadata tag".to_owned())?;
    let body = parse_hex(string(required(value, "valueHex")?, "metadata valueHex")?)?;
    Ok(MetadataEntry { tag, value: body })
}

fn parse_hex(value: &str) -> Result<Vec<u8>, String> {
    if value.len() % 2 != 0 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("value must be strict even-length hexadecimal".to_owned());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|digits| {
            let digits = std::str::from_utf8(digits).map_err(|_| "invalid hexadecimal")?;
            u8::from_str_radix(digits, 16).map_err(|_| "invalid hexadecimal")
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(str::to_owned)
}

fn parse_fixed_hex<const N: usize>(value: &str) -> Result<[u8; N], String> {
    parse_hex(value)?
        .try_into()
        .map_err(|_| format!("hex value must contain exactly {N} bytes"))
}

fn required<'a>(
    object: &'a BTreeMap<String, JsonValue>,
    key: &str,
) -> Result<&'a JsonValue, String> {
    object
        .get(key)
        .ok_or_else(|| format!("missing manifest field: {key}"))
}

fn object<'a>(
    value: &'a JsonValue,
    label: &str,
) -> Result<&'a BTreeMap<String, JsonValue>, String> {
    match value {
        JsonValue::Object(value) => Ok(value),
        _ => Err(format!("{label} must be an object")),
    }
}

fn array<'a>(value: &'a JsonValue, label: &str) -> Result<&'a [JsonValue], String> {
    match value {
        JsonValue::Array(value) => Ok(value),
        _ => Err(format!("{label} must be an array")),
    }
}

fn string<'a>(value: &'a JsonValue, label: &str) -> Result<&'a str, String> {
    match value {
        JsonValue::String(value) => Ok(value),
        _ => Err(format!("{label} must be a string")),
    }
}

fn number(value: &JsonValue, label: &str) -> Result<u64, String> {
    match value {
        JsonValue::Number(value) => Ok(*value),
        _ => Err(format!("{label} must be an unsigned integer")),
    }
}

fn optional_string(value: Option<&JsonValue>, label: &str) -> Result<Option<String>, String> {
    match value {
        None | Some(JsonValue::Null) => Ok(None),
        Some(value) => string(value, label).map(|value| Some(value.to_owned())),
    }
}

#[derive(Debug)]
enum JsonValue {
    Null,
    Bool,
    Number(u64),
    String(String),
    Array(Vec<Self>),
    Object(BTreeMap<String, Self>),
}

struct JsonParser<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> JsonParser<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn parse(mut self) -> Result<JsonValue, String> {
        let value = self.value()?;
        self.whitespace();
        if self.offset != self.input.len() {
            return Err(format!("unexpected JSON content at byte {}", self.offset));
        }
        Ok(value)
    }

    fn value(&mut self) -> Result<JsonValue, String> {
        self.whitespace();
        match self.peek() {
            Some(b'n') => self.literal(b"null", JsonValue::Null),
            Some(b't') => self.literal(b"true", JsonValue::Bool),
            Some(b'f') => self.literal(b"false", JsonValue::Bool),
            Some(b'"') => self.string().map(JsonValue::String),
            Some(b'[') => self.array(),
            Some(b'{') => self.object(),
            Some(b'0'..=b'9') => self.number().map(JsonValue::Number),
            _ => Err(format!("invalid JSON value at byte {}", self.offset)),
        }
    }

    fn literal(&mut self, expected: &[u8], value: JsonValue) -> Result<JsonValue, String> {
        if self.input.get(self.offset..self.offset + expected.len()) == Some(expected) {
            self.offset += expected.len();
            Ok(value)
        } else {
            Err(format!("invalid JSON literal at byte {}", self.offset))
        }
    }

    fn number(&mut self) -> Result<u64, String> {
        let start = self.offset;
        while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
            self.offset += 1;
        }
        let value = std::str::from_utf8(&self.input[start..self.offset])
            .map_err(|_| "invalid JSON number".to_owned())?;
        value
            .parse()
            .map_err(|_| format!("invalid JSON number at byte {start}"))
    }

    fn string(&mut self) -> Result<String, String> {
        self.expect(b'"')?;
        let mut output = Vec::new();
        loop {
            let byte = self
                .next()
                .ok_or_else(|| "unterminated JSON string".to_owned())?;
            match byte {
                b'"' => {
                    return String::from_utf8(output)
                        .map_err(|_| "invalid UTF-8 string".to_owned());
                }
                b'\\' => self.escape(&mut output)?,
                0..=0x1f => return Err("control byte in JSON string".to_owned()),
                _ => output.push(byte),
            }
        }
    }

    fn escape(&mut self, output: &mut Vec<u8>) -> Result<(), String> {
        match self.next() {
            Some(b'"') => output.push(b'"'),
            Some(b'\\') => output.push(b'\\'),
            Some(b'/') => output.push(b'/'),
            Some(b'b') => output.push(8),
            Some(b'f') => output.push(12),
            Some(b'n') => output.push(b'\n'),
            Some(b'r') => output.push(b'\r'),
            Some(b't') => output.push(b'\t'),
            Some(b'u') => {
                let end = self.offset + 4;
                let digits = self
                    .input
                    .get(self.offset..end)
                    .ok_or_else(|| "truncated JSON Unicode escape".to_owned())?;
                let digits = std::str::from_utf8(digits)
                    .map_err(|_| "invalid JSON Unicode escape".to_owned())?;
                let code = u32::from_str_radix(digits, 16)
                    .map_err(|_| "invalid JSON Unicode escape".to_owned())?;
                let character = char::from_u32(code)
                    .ok_or_else(|| "unsupported JSON surrogate escape".to_owned())?;
                let mut encoded = [0; 4];
                output.extend_from_slice(character.encode_utf8(&mut encoded).as_bytes());
                self.offset = end;
            }
            _ => return Err("invalid JSON escape".to_owned()),
        }
        Ok(())
    }

    fn array(&mut self) -> Result<JsonValue, String> {
        self.expect(b'[')?;
        let mut values = Vec::new();
        self.whitespace();
        if self.consume(b']') {
            return Ok(JsonValue::Array(values));
        }
        loop {
            values.push(self.value()?);
            self.whitespace();
            if self.consume(b']') {
                return Ok(JsonValue::Array(values));
            }
            self.expect(b',')?;
        }
    }

    fn object(&mut self) -> Result<JsonValue, String> {
        self.expect(b'{')?;
        let mut values = BTreeMap::new();
        self.whitespace();
        if self.consume(b'}') {
            return Ok(JsonValue::Object(values));
        }
        loop {
            self.whitespace();
            let key = self.string()?;
            self.whitespace();
            self.expect(b':')?;
            let value = self.value()?;
            if values.insert(key.clone(), value).is_some() {
                return Err(format!("duplicate JSON object key: {key}"));
            }
            self.whitespace();
            if self.consume(b'}') {
                return Ok(JsonValue::Object(values));
            }
            self.expect(b',')?;
        }
    }

    fn whitespace(&mut self) {
        while self.peek().is_some_and(|byte| byte.is_ascii_whitespace()) {
            self.offset += 1;
        }
    }

    fn expect(&mut self, expected: u8) -> Result<(), String> {
        if self.consume(expected) {
            Ok(())
        } else {
            Err(format!(
                "expected JSON byte {} at byte {}",
                char::from(expected),
                self.offset
            ))
        }
    }

    fn consume(&mut self, expected: u8) -> bool {
        if self.peek() == Some(expected) {
            self.offset += 1;
            true
        } else {
            false
        }
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.offset).copied()
    }

    fn next(&mut self) -> Option<u8> {
        let value = self.peek()?;
        self.offset += 1;
        Some(value)
    }
}
