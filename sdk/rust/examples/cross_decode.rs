use std::{collections::BTreeSet, env, fs, path::PathBuf};

use sha2::{Digest, Sha256};

#[path = "../tests/support/mod.rs"]
mod support;

use support::{
    Manifest, decode_key, decode_vector, encode_vector, read_child, safe_child, safe_id,
};

enum Mode {
    Write,
    Verify,
}

struct Arguments {
    vectors_root: PathBuf,
    work_dir: PathBuf,
    case_ids: Vec<String>,
    mode: Mode,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let arguments = arguments()?;
    let manifest = Manifest::read(&arguments.vectors_root)?;
    let canonical_key = manifest.canonical_key()?.to_vec();
    for id in &arguments.case_ids {
        let vector = manifest
            .vectors
            .iter()
            .find(|vector| vector.id == *id)
            .ok_or_else(|| format!("manifest vector is missing: {id}"))?;
        if vector.expect_error.is_some() {
            return Err(format!("negative cross-decode case is not allowed: {id}"));
        }
        let input_path = vector
            .input
            .as_deref()
            .ok_or_else(|| format!("{id}: positive vector has no input"))?;
        let input = read_child(&arguments.vectors_root, input_path)?;
        let expected = read_child(&arguments.vectors_root, &vector.expected)?;
        if Sha256::digest(&expected).as_slice() != vector.expected_sha256 {
            return Err(format!(
                "{id}: expected artifact SHA-256 differs from vectors.json"
            ));
        }
        match &arguments.mode {
            Mode::Write => {
                let container = encode_vector(&input, vector)?;
                if container != expected {
                    return Err(format!("{id}: Rust encode differs from shared artifact"));
                }
                let path = safe_child(&arguments.work_dir, &format!("{id}.rust.ubc"))?;
                fs::write(&path, container)
                    .map_err(|error| format!("write {}: {error}", path.display()))?;
            }
            Mode::Verify => {
                let key = decode_key(vector, &canonical_key);
                for producer in ["go", "node", "python", "rust"] {
                    let path = format!("{id}.{producer}.ubc");
                    let container = read_child(&arguments.work_dir, &path)?;
                    let (decoded, metadata) = decode_vector(&container, &key).map_err(|error| {
                        format!(
                            "{id}: Rust rejected {producer} container with {}",
                            error.code
                        )
                    })?;
                    if decoded != input {
                        return Err(format!(
                            "{id}: Rust-decoded {producer} plaintext differs from manifest input"
                        ));
                    }
                    let expected_metadata = vector
                        .options
                        .as_ref()
                        .map(|options| options.metadata.as_slice())
                        .unwrap_or_default();
                    if metadata != expected_metadata {
                        return Err(format!(
                            "{id}: Rust-decoded {producer} metadata differs from manifest"
                        ));
                    }
                    if encode_vector(&decoded, vector)? != expected {
                        return Err(format!(
                            "{id}: {producer}-to-Rust re-encode is not byte-identical"
                        ));
                    }
                    if container != expected {
                        return Err(format!(
                            "{id}: fresh {producer} container differs from shared artifact"
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}

fn arguments() -> Result<Arguments, String> {
    let mut values = env::args().skip(1);
    let mut vectors_root = None;
    let mut work_dir = None;
    let mut cases = None;
    let mut mode = None;
    while let Some(argument) = values.next() {
        match argument.as_str() {
            "--vectors" => vectors_root = values.next().map(PathBuf::from),
            "--work" => work_dir = values.next().map(PathBuf::from),
            "--cases" => cases = values.next(),
            "--write" if mode.is_none() => mode = Some(Mode::Write),
            "--verify" if mode.is_none() => mode = Some(Mode::Verify),
            _ => return Err(format!("unexpected argument: {argument}")),
        }
    }
    let vectors_root = existing_directory(vectors_root, "vectors")?;
    let work_dir = existing_directory(work_dir, "work")?;
    let cases = cases.ok_or_else(|| "--cases is required".to_owned())?;
    let mut seen = BTreeSet::new();
    let case_ids = cases
        .split(',')
        .map(|id| {
            if !safe_id(id) || !seen.insert(id.to_owned()) {
                return Err(format!("unsafe or duplicate case id: {id}"));
            }
            Ok(id.to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    if case_ids.is_empty() {
        return Err("--cases must not be empty".to_owned());
    }
    Ok(Arguments {
        vectors_root,
        work_dir,
        case_ids,
        mode: mode.ok_or_else(|| "exactly one of --write or --verify is required".to_owned())?,
    })
}

fn existing_directory(path: Option<PathBuf>, label: &str) -> Result<PathBuf, String> {
    let path = path.ok_or_else(|| format!("--{label} is required"))?;
    let path = path
        .canonicalize()
        .map_err(|error| format!("resolve {label} directory: {error}"))?;
    if !path.is_dir() {
        return Err(format!("{label} path is not a directory"));
    }
    Ok(path)
}
