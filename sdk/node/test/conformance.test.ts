import assert from "node:assert/strict";
import { readFile, stat } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { Readable, Writable } from "node:stream";
import { finished } from "node:stream/promises";
import { Decoder, decodeBytes, encodeBytes, inspectStream, newDecoder, newEncoder, type EncodeOptions, UbcError, verify, verifyStream } from "../src/index.js";

interface VectorMetadata { tag: string; valueHex: string }
interface VectorOptions { chunkSize?: number; key?: string; baseNonce?: string; metadata?: VectorMetadata[] }
interface Vector { id: string; input?: string; options?: VectorOptions; expected: string; expectError: string | null }
interface Manifest { vectors: Vector[] }

const vectorsRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../../../spec/vectors");
const manifest = JSON.parse(await readFile(resolve(vectorsRoot, "vectors.json"), "utf8")) as Manifest;
const fixedVectorKey = manifest.vectors.find((vector) => vector.options?.key)?.options?.key;

function encodeOptions(options: VectorOptions = {}): EncodeOptions {
  return {
    chunkSize: options.chunkSize,
    key: options.key ? Buffer.from(options.key, "hex") : undefined,
    baseNonce: options.baseNonce ? Buffer.from(options.baseNonce, "hex") : undefined,
  };
}

function metadata(options: VectorOptions = {}) {
  return (options.metadata ?? []).map(({ tag, valueHex }) => ({ tag: Number.parseInt(tag, 16), value: Buffer.from(valueHex, "hex") }));
}

function seededRandom(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return state >>> 0;
  };
}

function seededBytes(random: () => number, length: number): Buffer {
  const result = Buffer.alloc(length);
  for (let index = 0; index < length; index++) result[index] = random() & 0xff;
  return result;
}

for (const vector of manifest.vectors) {
  test(vector.id, async () => {
    const expected = await readFile(resolve(vectorsRoot, vector.expected));
    const options = encodeOptions(vector.options);
    if (vector.expectError !== null) {
      if (vector.expectError === "ERR_CHUNK_AUTH" && fixedVectorKey !== undefined) options.key = Buffer.from(fixedVectorKey, "hex");
      assert.throws(() => decodeBytes(expected, options), (error: unknown) => error instanceof UbcError && error.code === vector.expectError);
      assert.deepEqual(verify(expected, options), vector.expectError === "ERR_CHUNK_AUTH" ? { ok: false, error: vector.expectError, failedChunk: 0n } : { ok: false, error: vector.expectError });
      return;
    }
    const input = await readFile(resolve(vectorsRoot, vector.input!));
    assert.deepEqual(encodeBytes(input, metadata(vector.options), options), expected);
    const decoded = decodeBytes(expected, options);
    assert.deepEqual(decoded.data, input);
    assert.deepEqual(verify(expected, options), { ok: true });
  });
}

test("streaming encoder and decoder match a shared vector", async () => {
  const input = await readFile(resolve(vectorsRoot, "inputs/one-byte.bin"));
  const expected = await readFile(resolve(vectorsRoot, "expected/encrypted-one-byte.ubc"));
  const chunks: Buffer[] = [];
  const sink = new Writable({ write(chunk, _encoding, callback) { chunks.push(Buffer.from(chunk)); callback(); } });
  const encoder = newEncoder(sink, [], { chunkSize: 1 << 20, key: Buffer.from("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "hex"), baseNonce: Buffer.from("f0e0d0c0b0a0908070605040", "hex") });
  encoder.write(input.subarray(0, 1));
  encoder.end();
  await finished(encoder);
  assert.deepEqual(Buffer.concat(chunks), expected);

  const decoder = newDecoder(Readable.from([expected.subarray(0, 17), expected.subarray(17)]), { key: Buffer.from("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "hex") });
  const output: Buffer[] = [];
  for await (const chunk of decoder) output.push(Buffer.from(chunk));
  assert.deepEqual(Buffer.concat(output), input);
});

async function assertEncoderSpoolRemoved(encoder: ReturnType<typeof newEncoder>): Promise<void> {
  const internal = encoder as unknown as { spoolPathPromise: Promise<string> };
  const spoolPath = await internal.spoolPathPromise;
  await assert.rejects(stat(spoolPath));
}

test("streaming encoder removes its spool on validation failure", async () => {
  const encoder = newEncoder(new Writable({ write(_chunk, _encoding, callback) { callback(); } }), [], { chunkSize: 0 });
  const completion = finished(encoder);
  encoder.end(Buffer.from("x"));
  await assert.rejects(completion, (error: unknown) => error instanceof UbcError && error.code === "ERR_RESERVED_BITS");
  await assertEncoderSpoolRemoved(encoder);
});

test("streaming encoder removes its spool after a sink write failure", async () => {
  const sink = new Writable({ write(_chunk, _encoding, callback) { callback(new Error("sink failed")); } });
  sink.on("error", () => undefined);
  const encoder = newEncoder(sink);
  const completion = finished(encoder);
  encoder.end(Buffer.from("x"));
  await assert.rejects(completion, /sink failed/);
  await assertEncoderSpoolRemoved(encoder);
});

test("streaming encoder removes its spool when opening the reader fails", async () => {
  const encoder = newEncoder(new Writable({ write(_chunk, _encoding, callback) { callback(); } }));
  const internal = encoder as unknown as { openSpoolReader: (path: string) => Promise<never> };
  internal.openSpoolReader = async () => { throw new Error("reader failed"); };
  const completion = finished(encoder);
  encoder.end(Buffer.from("x"));
  await assert.rejects(completion, /reader failed/);
  await assertEncoderSpoolRemoved(encoder);
});

test("streaming encoder removes its spool when destroyed early", async () => {
  const encoder = newEncoder(new Writable({ write(_chunk, _encoding, callback) { callback(); } }));
  const internal = encoder as unknown as { spoolPathPromise: Promise<string> };
  await internal.spoolPathPromise;
  const completion = finished(encoder);
  encoder.destroy(new Error("cancelled"));
  await assert.rejects(completion, /cancelled/);
  await assertEncoderSpoolRemoved(encoder);
});

test("streaming decoder accepts heavily fragmented input", async () => {
  const input = Buffer.alloc(16 << 10, 0xa5);
  const container = encodeBytes(input, [], { chunkSize: 1024 });
  const decoder = newDecoder(Readable.from([...container].map((byte) => Buffer.from([byte]))));
  const output: Buffer[] = [];
  for await (const chunk of decoder) output.push(Buffer.from(chunk));
  assert.deepEqual(Buffer.concat(output), input);
});

test("streaming decoder bounds queued segments under one-byte fragmentation", async () => {
  const input = Buffer.alloc(64 << 10, 0xa5);
  const container = encodeBytes(input, [], { chunkSize: 1024 });
  const decoder = new Decoder();
  const internal = decoder as unknown as { pendingSegmentCount(): number };
  let maximumSegments = 0;
  for (const byte of container) {
    decoder.write(Buffer.from([byte]));
    maximumSegments = Math.max(maximumSegments, internal.pendingSegmentCount());
  }
  decoder.end();
  const output: Buffer[] = [];
  for await (const chunk of decoder) output.push(Buffer.from(chunk));
  assert.equal(maximumSegments, 1);
  assert.deepEqual(Buffer.concat(output), input);
});

test("streaming decoder bounds plaintext when its consumer is initially absent", async () => {
  const input = Buffer.alloc(512 << 10, 0xa5);
  const container = encodeBytes(input, [], { chunkSize: 1024 });
  const records = Array.from({ length: Math.ceil(container.byteLength / 1028) }, (_, index) => container.subarray(index * 1028, (index + 1) * 1028));
  const source = Readable.from(records);
  const decoder = new Decoder();
  source.pipe(decoder);

  await new Promise<void>((resolve) => setImmediate(resolve));
  assert.ok(!source.readableEnded, "source should be paused by decoder backpressure");
  assert.ok(
    decoder.readableLength <= decoder.readableHighWaterMark + 1024,
    `buffered ${decoder.readableLength} plaintext bytes beyond the readable high-water mark`,
  );

  const output: Buffer[] = [];
  for await (const chunk of decoder) {
    output.push(Buffer.from(chunk));
    await new Promise<void>((resolve) => setImmediate(resolve));
  }
  assert.deepEqual(Buffer.concat(output), input);
});

test("streamed inspect and verify honor the container contract", async () => {
  const plain = await readFile(resolve(vectorsRoot, "expected/plain-metadata.ubc"));
  const info = await inspectStream(Readable.from([plain.subarray(0, 9), plain.subarray(9)]));
  assert.equal(info.chunkCount, 1n);
  assert.equal(info.metadata.entries.length, 4);
  assert.deepEqual(await verifyStream(Readable.from([plain])), { ok: true });

  const encrypted = await readFile(resolve(vectorsRoot, "expected/negative-chunk-auth.ubc"));
  const key = Buffer.from(fixedVectorKey!, "hex");
  assert.deepEqual(await verifyStream(Readable.from([encrypted]), { key }), { ok: false, error: "ERR_CHUNK_AUTH", failedChunk: 0n });
});

test("inspectStream restores bytes beyond the inspected prefix", async () => {
  const container = await readFile(resolve(vectorsRoot, "expected/plain-metadata.ubc"));
  const source = Readable.from([container]);
  const info = await inspectStream(source);
  const metadataLength = container.readUInt32LE(40);
  const remaining: Buffer[] = [];
  for await (const chunk of source) remaining.push(Buffer.from(chunk));

  assert.equal(info.metadata.filename, "รายงาน-2026.txt");
  assert.deepEqual(Buffer.concat(remaining), container.subarray(44 + metadataLength));
});

test("verifyStream rethrows source failures that are not UBC errors", async () => {
  const source = Readable.from((async function* () {
    yield Buffer.alloc(0);
    throw new Error("source I/O failed");
  })());
  await assert.rejects(verifyStream(source), /source I\/O failed/);
});

test("metadata object input exposes typed fields and ordered raw entries", () => {
  const container = encodeBytes(Buffer.from("x"), {
    filename: "report.pdf",
    mimeType: "application/pdf",
    createdAt: 1_725_000_000_000n,
    raw: new Map([[0x1000, Buffer.from([0, 0xff])]]),
  });
  const { data, meta } = decodeBytes(container);

  assert.equal(meta.filename, "report.pdf");
  assert.equal(meta.mimeType, "application/pdf");
  assert.equal(meta.createdAt, 1_725_000_000_000n);
  assert.deepEqual(meta.entries.map(({ tag }) => tag), [0x0001, 0x0002, 0x0003, 0x1000]);
  assert.deepEqual(meta.raw.get(0x1000), Buffer.from([0, 0xff]));
  assert.deepEqual(encodeBytes(data, meta), container);
});

test("metadata object rejects non-ASCII MIME input before ASCII encoding", () => {
  for (const metadata of [{ mimeType: "audio/\u{1d11e}" }, { mime_type: "text/\u{1d11e}" }]) {
    assert.throws(
      () => encodeBytes(Buffer.from("x"), metadata),
      (error: unknown) => error instanceof UbcError && error.code === "ERR_META_MALFORMED",
    );
  }
});

test("complete encrypted chunk bodies shorter than a GCM tag fail authentication", () => {
  const key = Buffer.from("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "hex");
  const valid = encodeBytes(Buffer.from("x"), [], { key, chunkSize: 1, baseNonce: Buffer.alloc(12, 0x42) });
  const length = Buffer.alloc(4);
  length.writeUInt32LE(15, 0);
  const malformed = Buffer.concat([
    valid.subarray(0, 40),
    length,
    valid.subarray(44, 59),
    valid.subarray(61),
  ]);

  assert.throws(
    () => decodeBytes(malformed, { key }),
    (error: unknown) => error instanceof UbcError && error.code === "ERR_CHUNK_AUTH" && error.failedChunk === 0n,
  );
  assert.deepEqual(verify(malformed, { key }), { ok: false, error: "ERR_CHUNK_AUTH", failedChunk: 0n });
});

test("seeded round trips cover randomized sizes, metadata, encryption, and fragmented streams", async () => {
  const random = seededRandom(0x5eedc0de);
  const chunkSize = 257;
  const key = seededBytes(random, 32);
  const baseNonce = seededBytes(random, 12);
  const sizes = [0, chunkSize, chunkSize + 1, chunkSize * 3 + 2 + (random() % chunkSize)];

  for (const encrypted of [false, true]) {
    for (const size of sizes) {
      const input = seededBytes(random, size);
      const meta = {
        filename: `sample-${size}-\u0e44\u0e17\u0e22.bin`,
        mimeType: "application/octet-stream",
        createdAt: BigInt(random()),
        raw: new Map([[0x1000, seededBytes(random, 4)]]),
      };
      const options = encrypted ? { chunkSize, key, baseNonce } : { chunkSize };
      const decoded = decodeBytes(encodeBytes(input, meta, options), encrypted ? { key } : {});

      assert.deepEqual(decoded.data, input);
      assert.equal(decoded.meta.filename, meta.filename);
      assert.equal(decoded.meta.mimeType, meta.mimeType);
      assert.equal(decoded.meta.createdAt, meta.createdAt);
      assert.deepEqual(decoded.meta.raw.get(0x1000), meta.raw.get(0x1000));
    }
  }

  const input = seededBytes(random, chunkSize * 3 + 17);
  const meta = { filename: "fragmented.bin", mimeType: "application/octet-stream" };
  const container = encodeBytes(input, meta, { chunkSize, key, baseNonce });
  const fragments: Buffer[] = [];
  for (let offset = 0; offset < container.byteLength;) {
    const length = Math.min(container.byteLength - offset, 1 + (random() % 31));
    fragments.push(container.subarray(offset, offset + length));
    offset += length;
  }
  const decoder = newDecoder(Readable.from(fragments), { key });
  const output: Buffer[] = [];
  for await (const chunk of decoder) output.push(Buffer.from(chunk));

  assert.deepEqual(Buffer.concat(output), input);
  assert.equal(decoder.meta().filename, meta.filename);
});
