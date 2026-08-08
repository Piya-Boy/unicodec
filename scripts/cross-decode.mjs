import assert from "node:assert/strict";
import { execFile as execFileCallback } from "node:child_process";
import { access, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, relative, resolve, sep } from "node:path";
import { promisify } from "node:util";
import { fileURLToPath, pathToFileURL } from "node:url";

const execFile = promisify(execFileCallback);
const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const vectorsRoot = resolve(repoRoot, "spec", "vectors");
const caseIDs = ["plain-one-byte", "plain-chunk-1m-plus-one", "plain-metadata", "encrypted-one-byte", "encrypted-chunk-1m-plus-one", "encrypted-metadata"];
const nodeModule = resolve(repoRoot, "sdk", "node", "dist", "src", "index.js");

function safeId(value) {
  return typeof value === "string" && /^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(value);
}

function safeChild(root, child) {
  if (typeof child !== "string" || child.length === 0 || isAbsolute(child)) throw new Error("manifest path must be a non-empty relative path");
  const target = resolve(root, child);
  const pathFromRoot = relative(root, target);
  if (pathFromRoot === ".." || pathFromRoot.startsWith(`..${sep}`) || isAbsolute(pathFromRoot)) throw new Error(`manifest path escapes vectors root: ${child}`);
  return target;
}

function parseHex(value, label) {
  if (typeof value !== "string" || value.length % 2 !== 0 || !/^[0-9a-f]*$/i.test(value)) throw new Error(`${label} must be strict hexadecimal`);
  return Buffer.from(value, "hex");
}

function metadataEntries(metadata) {
  if (metadata === undefined) return [];
  if (!Array.isArray(metadata)) throw new Error("metadata must be an array");
  return metadata.map((entry, index) => {
    if (entry === null || typeof entry !== "object" || typeof entry.tag !== "string" || !/^0x[0-9a-f]{4}$/i.test(entry.tag)) {
      throw new Error(`metadata entry ${index} has an invalid tag`);
    }
    return { tag: Number.parseInt(entry.tag.slice(2), 16), value: parseHex(entry.valueHex, `metadata entry ${index} value`) };
  });
}

function encodeOptions(options) {
  if (options === null || typeof options !== "object" || !Number.isInteger(options.chunkSize) || options.chunkSize <= 0 || options.chunkSize > 0xffffffff) {
    throw new Error("vector has an invalid chunkSize");
  }
  const hasKey = options.key !== undefined;
  const hasNonce = options.baseNonce !== undefined;
  if (hasKey !== hasNonce) throw new Error("encrypted vector must provide both key and baseNonce");
  if (!hasKey) return { chunkSize: options.chunkSize };
  const key = parseHex(options.key, "key");
  const baseNonce = parseHex(options.baseNonce, "baseNonce");
  if (key.byteLength !== 32 || baseNonce.byteLength !== 12) throw new Error("vector encryption option has an invalid length");
  return { chunkSize: options.chunkSize, key, baseNonce };
}

function assertMetadata(actual, expected) {
  assert.equal(actual.entries.length, expected.length, "metadata entry count");
  for (let index = 0; index < expected.length; index++) {
    assert.equal(actual.entries[index].tag, expected[index].tag, `metadata tag ${index}`);
    assert.deepEqual(actual.entries[index].value, expected[index].value, `metadata value ${index}`);
  }
}

async function main() {
  try {
    await access(nodeModule);
  } catch {
    throw new Error("Node SDK build is missing; run npm run build --prefix sdk/node before cross-decode.");
  }
  const { decodeBytes, encodeBytes } = await import(pathToFileURL(nodeModule).href);
  const manifest = JSON.parse(await readFile(safeChild(vectorsRoot, "vectors.json"), "utf8"));
  if (!Array.isArray(manifest.vectors)) throw new Error("manifest vectors must be an array");
  const byID = new Map(manifest.vectors.map((vector) => [vector.id, vector]));
  const workDir = await mkdtemp(resolve(tmpdir(), "ubc-crossdecode-"));

  try {
    for (const id of caseIDs) {
      if (!safeId(id)) throw new Error(`unsafe case ID: ${id}`);
      const vector = byID.get(id);
      if (vector === undefined) throw new Error(`shared vector is missing: ${id}`);
      if (vector.expectError !== null) throw new Error(`negative vector is not allowed: ${id}`);
      const input = await readFile(safeChild(vectorsRoot, vector.input));
      const entries = metadataEntries(vector.options?.metadata);
      const options = encodeOptions(vector.options);
      const nodeFresh = encodeBytes(input, entries, options);
      await writeFile(safeChild(workDir, `${id}.node.ubc`), nodeFresh, { mode: 0o600 });
    }

    await execFile("go", ["run", "./tools/crossdecode", "--vectors", vectorsRoot, "--work", workDir, "--cases", caseIDs.join(",")], { cwd: repoRoot });

    for (const id of caseIDs) {
      const vector = byID.get(id);
      const input = await readFile(safeChild(vectorsRoot, vector.input));
      const entries = metadataEntries(vector.options?.metadata);
      const options = encodeOptions(vector.options);
      const goFresh = await readFile(safeChild(workDir, `${id}.go.ubc`));
      const nodeFresh = await readFile(safeChild(workDir, `${id}.node.ubc`));
      const decoded = decodeBytes(goFresh, options.key === undefined ? {} : { key: options.key });

      assert.ok(decoded.data.equals(input), `${id}: Go-decoded plaintext differs from manifest input`);
      assertMetadata(decoded.meta, entries);
      assert.ok(encodeBytes(decoded.data, decoded.meta, options).equals(nodeFresh), `${id}: Node re-encode is not byte-identical`);
      assert.ok(goFresh.equals(nodeFresh), `${id}: fresh Go and Node containers differ`);
    }
    process.stdout.write(`Cross-decode passed: ${caseIDs.join(", ")}\n`);
  } finally {
    await rm(workDir, { recursive: true, force: true });
  }
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
