import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";
import { open as openFile, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Readable, Transform, Writable } from "node:stream";

export type ErrorCode =
  | "ERR_BAD_MAGIC"
  | "ERR_UNSUPPORTED_VER"
  | "ERR_UNSUPPORTED_ALGO"
  | "ERR_RESERVED_BITS"
  | "ERR_TRUNCATED"
  | "ERR_ROOT_MISMATCH"
  | "ERR_CHUNK_AUTH"
  | "ERR_MISSING_KEY"
  | "ERR_META_MALFORMED";

export class UbcError extends Error {
  constructor(public readonly code: ErrorCode, public readonly failedChunk?: bigint) {
    super(code);
    this.name = "UbcError";
  }
}

export interface MetadataEntry {
  tag: number;
  value: Uint8Array;
}

/**
 * The decoded representation keeps the wire entries in their original order,
 * while offering convenient access to the three reserved tags.
 */
export interface Metadata {
  filename?: string;
  mimeType?: string;
  createdAt?: bigint;
  entries: readonly MetadataEntry[];
  raw: ReadonlyMap<number, Uint8Array>;
}

/** Input accepted by the public encode APIs. */
export interface MetadataObject {
  filename?: string;
  mimeType?: string;
  /** Alias for callers that use the wire-name spelling. */
  mime_type?: string;
  createdAt?: bigint;
  /** Alias for callers that use the wire-name spelling. */
  created_at?: bigint;
  /** Ordered wire entries. When present, these are the source of truth. */
  entries?: readonly MetadataEntry[];
  /** Opaque user-defined entries, usually tags >= 0x1000. */
  raw?: ReadonlyMap<number, Uint8Array>;
}

export type MetadataInput = readonly MetadataEntry[] | MetadataObject;

export interface EncodeOptions {
  key?: Uint8Array;
  chunkSize?: number;
  baseNonce?: Uint8Array;
}

export interface DecodeOptions {
  key?: Uint8Array;
  maxMetaBytes?: number;
  maxChunkLen?: number;
  maxChunkCount?: bigint;
  maxTotalSize?: bigint;
}

export interface ContainerInfo {
  version: number;
  flags: { encrypted: boolean; hasMetadata: boolean };
  hashAlgo: number;
  aeadAlgo: number;
  chunkSize: number;
  chunkCount: bigint;
  totalSize: bigint;
  metadata: Metadata;
}

export interface VerifyReport {
  ok: boolean;
  error?: ErrorCode;
  failedChunk?: bigint;
}

async function writeTo(stream: Writable, data: Buffer): Promise<void> {
  await new Promise<void>((resolve, reject) => stream.write(data, (error) => error ? reject(error) : resolve()));
}

const HEADER_SIZE = 40;
const FOOTER_SIZE = 36;
const FLAG_ENCRYPTED = 1;
const FLAG_METADATA = 2;
const DEFAULT_CHUNK_SIZE = 1 << 20;
const DEFAULT_MAX_META_BYTES = 16 << 20;
const DEFAULT_MAX_CHUNK_LEN = 64 << 20;
const DEFAULT_MAX_CHUNK_COUNT = 1n << 20n;
const DEFAULT_MAX_TOTAL_SIZE = 1n << 30n;

interface Header {
  version: number;
  flags: number;
  hashAlgo: number;
  aeadAlgo: number;
  chunkSize: number;
  chunkCount: bigint;
  totalSize: bigint;
  baseNonce: Buffer;
}

function fail(code: ErrorCode, failedChunk?: bigint): never {
  throw new UbcError(code, failedChunk);
}

function asBuffer(bytes: Uint8Array): Buffer {
  return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
}

function checkedKey(key: Uint8Array | undefined): Buffer | undefined {
  if (key === undefined) return undefined;
  if (key.byteLength !== 32) fail("ERR_RESERVED_BITS");
  return asBuffer(key);
}

function decodeKey(key: Uint8Array | undefined): Buffer {
  if (key === undefined || key.byteLength !== 32) fail("ERR_MISSING_KEY");
  return asBuffer(key);
}

function marshalHeader(header: Header): Buffer {
  validateHeader(header);
  const result = Buffer.alloc(HEADER_SIZE);
  result.write("UBC1", 0, "ascii");
  result[4] = header.version;
  result[5] = header.flags;
  result[6] = header.hashAlgo;
  result[7] = header.aeadAlgo;
  result.writeUInt32LE(header.chunkSize, 8);
  result.writeBigUInt64LE(header.chunkCount, 12);
  result.writeBigUInt64LE(header.totalSize, 20);
  header.baseNonce.copy(result, 28);
  return result;
}

function parseHeader(data: Buffer): Header {
  if (data.byteLength < HEADER_SIZE) fail("ERR_TRUNCATED");
  if (!data.subarray(0, 4).equals(Buffer.from("UBC1"))) fail("ERR_BAD_MAGIC");
  const header: Header = {
    version: data[4], flags: data[5], hashAlgo: data[6], aeadAlgo: data[7],
    chunkSize: data.readUInt32LE(8), chunkCount: data.readBigUInt64LE(12),
    totalSize: data.readBigUInt64LE(20), baseNonce: Buffer.from(data.subarray(28, 40)),
  };
  validateHeader(header);
  return header;
}

function validateHeader(header: Header): void {
  if (header.version !== 1) fail("ERR_UNSUPPORTED_VER");
  if (header.hashAlgo !== 0 || (header.aeadAlgo !== 0 && header.aeadAlgo !== 1)) fail("ERR_UNSUPPORTED_ALGO");
  if ((header.flags & ~(FLAG_ENCRYPTED | FLAG_METADATA)) !== 0) fail("ERR_RESERVED_BITS");
  const encrypted = (header.flags & FLAG_ENCRYPTED) !== 0;
  if ((encrypted && header.aeadAlgo !== 1) || (!encrypted && (header.aeadAlgo !== 0 || !header.baseNonce.equals(Buffer.alloc(12))))) {
    fail("ERR_RESERVED_BITS");
  }
}

function utf8(value: string): Buffer {
  const encoded = Buffer.from(value, "utf8");
  if (encoded.includes(0)) fail("ERR_META_MALFORMED");
  return encoded;
}

function metadataEntries(metadata: MetadataInput | undefined): MetadataEntry[] {
  if (metadata === undefined) return [];
  if (Array.isArray(metadata)) {
    return (metadata as readonly MetadataEntry[]).map(({ tag, value }) => ({ tag, value: Buffer.from(value) }));
  }
  const object = metadata as MetadataObject;
  if (object.entries !== undefined) return object.entries.map(({ tag, value }) => ({ tag, value: Buffer.from(value) }));

  const entries: MetadataEntry[] = [];
  if (object.filename !== undefined) entries.push({ tag: 0x0001, value: utf8(object.filename) });
  const mimeType = object.mimeType ?? object.mime_type;
  if (mimeType !== undefined) {
    for (let index = 0; index < mimeType.length; index++) {
      if (mimeType.charCodeAt(index) > 0x7f) fail("ERR_META_MALFORMED");
    }
    const value = Buffer.from(mimeType, "ascii");
    entries.push({ tag: 0x0002, value });
  }
  const createdAt = object.createdAt ?? object.created_at;
  if (createdAt !== undefined) {
    const value = Buffer.alloc(8);
    value.writeBigInt64LE(createdAt);
    entries.push({ tag: 0x0003, value });
  }
  if (object.raw !== undefined) {
    for (const [tag, value] of object.raw) entries.push({ tag, value: Buffer.from(value) });
  }
  return entries;
}

function metadataView(entries: MetadataEntry[]): Metadata {
  const ordered = entries.map(({ tag, value }) => ({ tag, value: Buffer.from(value) }));
  const raw = new Map<number, Uint8Array>(ordered.map(({ tag, value }) => [tag, Buffer.from(value)]));
  const filename = raw.get(0x0001);
  const mimeType = raw.get(0x0002);
  const createdAt = raw.get(0x0003);
  return {
    ...(filename === undefined ? {} : { filename: Buffer.from(filename).toString("utf8") }),
    ...(mimeType === undefined ? {} : { mimeType: Buffer.from(mimeType).toString("ascii") }),
    ...(createdAt?.byteLength === 8 ? { createdAt: Buffer.from(createdAt).readBigInt64LE(0) } : {}),
    entries: ordered,
    raw,
  };
}

function encodeMetadata(entries: MetadataEntry[]): Buffer {
  if (entries.length === 0) return Buffer.alloc(0);
  const sorted = [...entries].sort((a, b) => a.tag - b.tag);
  const fields: Buffer[] = [];
  let previous = -1;
  for (const entry of sorted) {
    if (!Number.isInteger(entry.tag) || entry.tag < 0 || entry.tag > 0xffff || entry.tag === previous) fail("ERR_META_MALFORMED");
    const value = asBuffer(entry.value);
    const field = Buffer.alloc(6);
    field.writeUInt16LE(entry.tag, 0);
    field.writeUInt32LE(value.byteLength, 2);
    fields.push(field, value);
    previous = entry.tag;
  }
  const body = Buffer.concat(fields);
  const region = Buffer.alloc(4);
  region.writeUInt32LE(body.byteLength, 0);
  return Buffer.concat([region, body]);
}

function parseMetadata(container: Buffer, offset: number, maxBytes: number): { metadata: MetadataEntry[]; region: Buffer; offset: number } {
  if (offset + 4 > container.byteLength) fail("ERR_META_MALFORMED");
  const length = container.readUInt32LE(offset);
  if (length > maxBytes || offset + 4 + length > container.byteLength) fail("ERR_META_MALFORMED");
  const end = offset + 4 + length;
  const metadata: MetadataEntry[] = [];
  let cursor = offset + 4;
  let previous = -1;
  while (cursor < end) {
    if (cursor + 6 > end) fail("ERR_META_MALFORMED");
    const tag = container.readUInt16LE(cursor);
    const valueLength = container.readUInt32LE(cursor + 2);
    cursor += 6;
    if (tag <= previous || valueLength > end - cursor) fail("ERR_META_MALFORMED");
    metadata.push({ tag, value: Buffer.from(container.subarray(cursor, cursor + valueLength)) });
    previous = tag;
    cursor += valueLength;
  }
  return { metadata, region: Buffer.from(container.subarray(offset, end)), offset: end };
}

function nonce(baseNonce: Buffer, index: bigint): Buffer {
  const result = Buffer.from(baseNonce);
  for (let position = 0; position < 12; position++) result[position] ^= Number((index >> (8n * BigInt(position))) & 0xffn);
  return result;
}

function aad(header: Buffer, index: bigint): Buffer {
  const suffix = Buffer.alloc(8);
  suffix.writeBigUInt64LE(index);
  return Buffer.concat([header, suffix]);
}

function seal(key: Buffer, baseNonce: Buffer, header: Buffer, index: bigint, plaintext: Buffer): Buffer {
  const cipher = createCipheriv("aes-256-gcm", key, nonce(baseNonce, index));
  cipher.setAAD(aad(header, index));
  return Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
}

function open(key: Buffer, baseNonce: Buffer, header: Buffer, index: bigint, body: Buffer): Buffer {
  try {
    const decipher = createDecipheriv("aes-256-gcm", key, nonce(baseNonce, index));
    decipher.setAAD(aad(header, index));
    decipher.setAuthTag(body.subarray(body.byteLength - 16));
    return Buffer.concat([decipher.update(body.subarray(0, -16)), decipher.final()]);
  } catch {
    return fail("ERR_CHUNK_AUTH", index);
  }
}

export function encodeBytes(data: Uint8Array, metadata: MetadataInput = [], options: EncodeOptions = {}): Buffer {
  const plain = asBuffer(data);
  const key = checkedKey(options.key);
  const chunkSize = options.chunkSize ?? DEFAULT_CHUNK_SIZE;
  if (!Number.isInteger(chunkSize) || chunkSize <= 0 || chunkSize > 0xffffffff) fail("ERR_RESERVED_BITS");
  const metaRegion = encodeMetadata(metadataEntries(metadata));
  const baseNonce = key === undefined ? Buffer.alloc(12) : options.baseNonce === undefined ? randomBytes(12) : asBuffer(options.baseNonce);
  if (baseNonce.byteLength !== 12) fail("ERR_RESERVED_BITS");
  const chunkCount = BigInt(Math.ceil(plain.byteLength / chunkSize));
  const header = marshalHeader({ version: 1, flags: (key ? FLAG_ENCRYPTED : 0) | (metaRegion.byteLength ? FLAG_METADATA : 0), hashAlgo: 0, aeadAlgo: key ? 1 : 0, chunkSize, chunkCount, totalSize: BigInt(plain.byteLength), baseNonce });
  const parts: Buffer[] = [header, metaRegion];
  const root = createHash("sha256");
  root.update(header); root.update(metaRegion);
  for (let index = 0n; index < chunkCount; index++) {
    const start = Number(index) * chunkSize;
    const body = key ? seal(key, baseNonce, header, index, plain.subarray(start, start + chunkSize)) : plain.subarray(start, start + chunkSize);
    const length = Buffer.alloc(4); length.writeUInt32LE(body.byteLength);
    parts.push(length, body); root.update(createHash("sha256").update(body).digest());
  }
  parts.push(root.digest(), Buffer.from("UBCE"));
  return Buffer.concat(parts);
}

export function decodeBytes(containerBytes: Uint8Array, options: DecodeOptions = {}): { data: Buffer; meta: Metadata } {
  const container = asBuffer(containerBytes);
  const headerBytes = Buffer.from(container.subarray(0, HEADER_SIZE));
  const header = parseHeader(headerBytes);
  const maxMetaBytes = options.maxMetaBytes ?? DEFAULT_MAX_META_BYTES;
  const maxChunkLen = options.maxChunkLen ?? DEFAULT_MAX_CHUNK_LEN;
  const maxChunkCount = options.maxChunkCount ?? DEFAULT_MAX_CHUNK_COUNT;
  const maxTotalSize = options.maxTotalSize ?? DEFAULT_MAX_TOTAL_SIZE;
  if (header.chunkCount > maxChunkCount || header.totalSize > maxTotalSize) fail("ERR_TRUNCATED");
  const key = header.flags & FLAG_ENCRYPTED ? decodeKey(options.key) : undefined;
  let offset = HEADER_SIZE;
  let metadata: MetadataEntry[] = [];
  let metaRegion: Uint8Array = Buffer.alloc(0);
  if (header.flags & FLAG_METADATA) ({ metadata, region: metaRegion, offset } = parseMetadata(container, offset, maxMetaBytes));
  const root = createHash("sha256"); root.update(headerBytes); root.update(metaRegion);
  const chunks: Buffer[] = []; let totalSize = 0n;
  for (let index = 0n; index < header.chunkCount; index++) {
    if (offset + 4 > container.byteLength) fail("ERR_TRUNCATED");
    const length = container.readUInt32LE(offset); offset += 4;
    if (length > maxChunkLen || offset + length > container.byteLength) fail("ERR_TRUNCATED");
    const body = Buffer.from(container.subarray(offset, offset + length)); offset += length;
    root.update(createHash("sha256").update(body).digest());
    const plain = key ? open(key, header.baseNonce, headerBytes, index, body) : body;
    totalSize += BigInt(plain.byteLength);
    if (totalSize > header.totalSize) fail("ERR_ROOT_MISMATCH");
    chunks.push(plain);
  }
  if (offset + FOOTER_SIZE > container.byteLength || !container.subarray(offset + 32, offset + 36).equals(Buffer.from("UBCE"))) fail("ERR_TRUNCATED");
  if (totalSize !== header.totalSize || !timingSafeEqual(root.digest(), container.subarray(offset, offset + 32))) fail("ERR_ROOT_MISMATCH");
  return { data: Buffer.concat(chunks), meta: metadataView(metadata) };
}

export function inspect(containerBytes: Uint8Array, options: Pick<DecodeOptions, "maxMetaBytes"> = {}): ContainerInfo {
  const container = asBuffer(containerBytes);
  const header = parseHeader(container.subarray(0, HEADER_SIZE));
  let metadata: MetadataEntry[] = [];
  if (header.flags & FLAG_METADATA) ({ metadata } = parseMetadata(container, HEADER_SIZE, options.maxMetaBytes ?? DEFAULT_MAX_META_BYTES));
  return { version: header.version, flags: { encrypted: Boolean(header.flags & FLAG_ENCRYPTED), hasMetadata: Boolean(header.flags & FLAG_METADATA) }, hashAlgo: header.hashAlgo, aeadAlgo: header.aeadAlgo, chunkSize: header.chunkSize, chunkCount: header.chunkCount, totalSize: header.totalSize, metadata: metadataView(metadata) };
}

export function verify(container: Uint8Array, options: DecodeOptions = {}): VerifyReport {
  try { decodeBytes(container, options); return { ok: true }; }
  catch (error) { return error instanceof UbcError ? { ok: false, error: error.code, ...(error.failedChunk === undefined ? {} : { failedChunk: error.failedChunk }) } : { ok: false, error: "ERR_TRUNCATED" }; }
}

function failedReport(error: UbcError): VerifyReport {
  return { ok: false, error: error.code, ...(error.failedChunk === undefined ? {} : { failedChunk: error.failedChunk }) };
}

class PrefixReader {
  private remainder = Buffer.alloc(0);
  private readonly iterator: AsyncIterator<Buffer>;

  constructor(private readonly source: Readable) { this.iterator = source.iterator({ destroyOnReturn: false }) as AsyncIterator<Buffer>; }

  async read(length: number): Promise<Buffer> {
    const chunks: Buffer[] = [];
    let total = 0;
    while (total < length) {
      const available = this.remainder;
      if (available.byteLength !== 0) {
        const needed = length - total;
        const taken = available.subarray(0, needed);
        chunks.push(taken); total += taken.byteLength; this.remainder = available.subarray(taken.byteLength);
        continue;
      }
      const next = await this.iterator.next();
      if (next.done) fail("ERR_TRUNCATED");
      this.remainder = Buffer.from(next.value);
    }
    return Buffer.concat(chunks, length);
  }

  restore(): void {
    if (this.remainder.byteLength !== 0) {
      this.source.unshift(this.remainder);
      this.remainder = Buffer.alloc(0);
    }
  }
}

export async function inspectStream(source: Readable, options: Pick<DecodeOptions, "maxMetaBytes"> = {}): Promise<ContainerInfo> {
  const reader = new PrefixReader(source);
  try {
    const headerBytes = await reader.read(HEADER_SIZE);
    const header = parseHeader(headerBytes);
    let metadata: MetadataEntry[] = [];
    if (header.flags & FLAG_METADATA) {
      const prefix = await reader.read(4);
      const length = prefix.readUInt32LE(0);
      if (length > (options.maxMetaBytes ?? DEFAULT_MAX_META_BYTES)) fail("ERR_META_MALFORMED");
      const region = Buffer.concat([prefix, await reader.read(length)]);
      ({ metadata } = parseMetadata(region, 0, options.maxMetaBytes ?? DEFAULT_MAX_META_BYTES));
    }
    return { version: header.version, flags: { encrypted: Boolean(header.flags & FLAG_ENCRYPTED), hasMetadata: Boolean(header.flags & FLAG_METADATA) }, hashAlgo: header.hashAlgo, aeadAlgo: header.aeadAlgo, chunkSize: header.chunkSize, chunkCount: header.chunkCount, totalSize: header.totalSize, metadata: metadataView(metadata) };
  } finally {
    // Inspect intentionally consumes only the prefix. Put any over-read tail
    // back so callers can continue reading the payload from the same stream.
    reader.restore();
  }
}

export async function verifyStream(source: Readable, options: DecodeOptions = {}): Promise<VerifyReport> {
  try { for await (const _chunk of newDecoder(source, options)) { } return { ok: true }; }
  catch (error) {
    if (error instanceof UbcError) return failedReport(error);
    throw error;
  }
}

export class Encoder extends Writable {
  private readonly metadata: MetadataInput;
  private readonly options: EncodeOptions;
  private readonly spoolPathPromise = mkdtemp(join(tmpdir(), "ubc-"));
  private readonly handlePromise = this.spoolPathPromise.then(async (directory) => openFile(join(directory, "plaintext"), "w"));
  private cleanupPromise?: Promise<void>;
  private totalSize = 0n;

  constructor(private readonly sink: Writable, metadata: MetadataInput = [], options: EncodeOptions = {}) {
    super();
    this.metadata = metadata;
    this.options = options;
  }

  override _write(chunk: Buffer, _encoding: BufferEncoding, callback: (error?: Error | null) => void): void {
    this.writeChunk(chunk).then(() => callback(), (error: unknown) => callback(error instanceof Error ? error : new Error(String(error))));
  }

  override _final(callback: (error?: Error | null) => void): void {
    this.finish().then(() => callback(), (error: unknown) => callback(error instanceof Error ? error : new Error(String(error))));
  }

  override _destroy(error: Error | null, callback: (error?: Error | null) => void): void {
    this.cleanup().then(
      () => callback(error),
      (cleanupError: unknown) => callback(error ?? (cleanupError instanceof Error ? cleanupError : new Error(String(cleanupError)))),
    );
  }

  private async writeChunk(chunk: Buffer): Promise<void> {
    try {
      const handle = await this.handlePromise;
      await handle.write(chunk);
      this.totalSize += BigInt(chunk.byteLength);
    } catch (error) {
      await this.cleanup();
      throw error;
    }
  }

  private cleanup(): Promise<void> {
    if (this.cleanupPromise === undefined) this.cleanupPromise = this.cleanupSpool();
    return this.cleanupPromise;
  }

  private async cleanupSpool(): Promise<void> {
    const handle = await this.handlePromise.catch(() => undefined);
    await handle?.close().catch(() => undefined);
    const path = await this.spoolPathPromise.catch(() => undefined);
    if (path !== undefined) await rm(path, { recursive: true, force: true });
  }

  private openSpoolReader(path: string): ReturnType<typeof openFile> {
    return openFile(join(path, "plaintext"), "r");
  }

  private async finish(): Promise<void> {
    let reader: Awaited<ReturnType<typeof openFile>> | undefined;
    try {
      const key = checkedKey(this.options.key);
      const chunkSize = this.options.chunkSize ?? DEFAULT_CHUNK_SIZE;
      if (!Number.isInteger(chunkSize) || chunkSize <= 0 || chunkSize > 0xffffffff) fail("ERR_RESERVED_BITS");
      const metadata = encodeMetadata(metadataEntries(this.metadata));
      const baseNonce = key === undefined ? Buffer.alloc(12) : this.options.baseNonce === undefined ? randomBytes(12) : asBuffer(this.options.baseNonce);
      if (baseNonce.byteLength !== 12) fail("ERR_RESERVED_BITS");
      const chunkCount = (this.totalSize + BigInt(chunkSize) - 1n) / BigInt(chunkSize);
      const header = marshalHeader({ version: 1, flags: (key ? FLAG_ENCRYPTED : 0) | (metadata.byteLength ? FLAG_METADATA : 0), hashAlgo: 0, aeadAlgo: key ? 1 : 0, chunkSize, chunkCount, totalSize: this.totalSize, baseNonce });
      const root = createHash("sha256"); root.update(header); root.update(metadata);
      const path = await this.spoolPathPromise;
      const handle = await this.handlePromise;
      await handle.close();
      reader = await this.openSpoolReader(path);
      await writeTo(this.sink, header); await writeTo(this.sink, metadata);
      for (let index = 0n; index < chunkCount; index++) {
        const remaining = this.totalSize - index * BigInt(chunkSize);
        const length = Number(remaining < BigInt(chunkSize) ? remaining : BigInt(chunkSize));
        const plain = Buffer.alloc(length);
        const { bytesRead } = await reader.read(plain, 0, length, null);
        if (bytesRead !== length) throw new Error("UBC plaintext spool was truncated");
        const body = key ? seal(key, baseNonce, header, index, plain) : plain;
        const prefix = Buffer.alloc(4); prefix.writeUInt32LE(body.byteLength);
        await writeTo(this.sink, prefix); await writeTo(this.sink, body); root.update(createHash("sha256").update(body).digest());
      }
      await writeTo(this.sink, Buffer.concat([root.digest(), Buffer.from("UBCE")]));
    } finally {
      try { await reader?.close(); }
      finally { await this.cleanup(); }
    }
  }
}

export function newEncoder(sink: Writable, metadata: MetadataInput = [], options: EncodeOptions = {}): Encoder {
  return new Encoder(sink, metadata, options);
}

export class Decoder extends Transform {
  // Keep at most one owned slab. Retaining every incoming Buffer lets a
  // byte-fragmented stream turn a valid chunk into millions of JS objects.
  private slab = Buffer.alloc(0);
  private slabStart = 0;
  private slabEnd = 0;
  private bufferedBytes = 0;
  private header?: Header;
  private headerBytes?: Buffer;
  private metadata: MetadataEntry[] = [];
  private key?: Buffer;
  private offsetState: "header" | "metadata" | "payload" | "footer" | "done" = "header";
  private chunkIndex = 0n;
  private plainTotal = 0n;
  private readonly root = createHash("sha256");
  private readonly maxMetaBytes: number;
  private readonly maxChunkLen: number;
  private readonly maxChunkCount: bigint;
  private readonly maxTotalSize: bigint;
  // A Transform must hold its write callback once `push()` reports that its
  // readable side is full.  Otherwise an upstream source can keep feeding us
  // while decoded plaintext accumulates without a consumer.
  private outputBackpressured = false;
  private deferredCallback?: (error?: Error | null) => void;
  private deferredFlush = false;

  constructor(private readonly options: DecodeOptions = {}) {
    super();
    this.maxMetaBytes = options.maxMetaBytes ?? DEFAULT_MAX_META_BYTES;
    this.maxChunkLen = options.maxChunkLen ?? DEFAULT_MAX_CHUNK_LEN;
    this.maxChunkCount = options.maxChunkCount ?? DEFAULT_MAX_CHUNK_COUNT;
    this.maxTotalSize = options.maxTotalSize ?? DEFAULT_MAX_TOTAL_SIZE;
  }

  meta(): Metadata { return metadataView(this.metadata); }

  override _transform(chunk: Buffer, _encoding: BufferEncoding, callback: (error?: Error | null) => void): void {
    try {
      if (this.offsetState !== "done" && chunk.byteLength > 0) this.enqueue(chunk);
      this.process();
      this.finishOrDefer(callback, false);
    }
    catch (error) { callback(error instanceof Error ? error : new Error(String(error))); }
  }

  override _flush(callback: (error?: Error | null) => void): void {
    try {
      this.process();
      this.finishOrDefer(callback, true);
    }
    catch (error) { callback(error instanceof Error ? error : new Error(String(error))); }
  }

  override _read(size: number): void {
    if (this.outputBackpressured) {
      this.outputBackpressured = false;
      try {
        this.process();
        if (this.outputBackpressured) return;
        this.releaseDeferredCallback();
      } catch (error) {
        const callback = this.takeDeferredCallback();
        callback?.(error instanceof Error ? error : new Error(String(error)));
        return;
      }
    }
    // Transform's implementation starts the next pending writable chunk. This
    // must happen after releasing our deferred callback, otherwise it observes
    // the old transform as still active and no further source reads occur.
    super._read(size);
  }

  private finishOrDefer(callback: (error?: Error | null) => void, flush: boolean): void {
    if (!this.outputBackpressured) {
      if (flush && this.offsetState !== "done") fail("ERR_TRUNCATED");
      callback();
      return;
    }
    if (this.deferredCallback !== undefined) throw new Error("Decoder already has a deferred write");
    this.deferredCallback = callback;
    this.deferredFlush = flush;
  }

  private takeDeferredCallback(): ((error?: Error | null) => void) | undefined {
    const callback = this.deferredCallback;
    this.deferredCallback = undefined;
    this.deferredFlush = false;
    return callback;
  }

  private releaseDeferredCallback(): void {
    const flush = this.deferredFlush;
    const callback = this.takeDeferredCallback();
    if (callback === undefined) return;
    if (flush && this.offsetState !== "done") {
      callback(new UbcError("ERR_TRUNCATED"));
      return;
    }
    callback();
  }

  private consume(length: number): Buffer {
    if (length > this.bufferedBytes) throw new RangeError("consume exceeds buffered data");
    const available = this.slabEnd - this.slabStart;
    if (length <= available) {
      const result = this.slab.subarray(this.slabStart, this.slabStart + length);
      this.advance(length);
      return result;
    }
    throw new RangeError("slab does not contain buffered data");
  }

  private peek(length: number): Buffer {
    if (length > this.bufferedBytes) throw new RangeError("peek exceeds buffered data");
    return this.slab.subarray(this.slabStart, this.slabStart + length);
  }

  private advance(length: number): void {
    this.bufferedBytes -= length;
    this.slabStart += length;
    if (this.bufferedBytes === 0) this.slabStart = this.slabEnd = 0;
  }

  private discardBuffered(): void {
    this.slabStart = 0;
    this.slabEnd = 0;
    this.bufferedBytes = 0;
  }

  private enqueue(chunk: Buffer): void {
    const required = this.bufferedBytes + chunk.byteLength;
    if (this.slabEnd + chunk.byteLength > this.slab.byteLength) this.makeRoom(required);
    chunk.copy(this.slab, this.slabEnd);
    this.slabEnd += chunk.byteLength;
    this.bufferedBytes += chunk.byteLength;
  }

  private makeRoom(required: number): void {
    if (required <= this.slab.byteLength) {
      this.slab.copy(this.slab, 0, this.slabStart, this.slabEnd);
      this.slabStart = 0;
      this.slabEnd = this.bufferedBytes;
      return;
    }
    let capacity = Math.max(4096, this.slab.byteLength);
    while (capacity < required) capacity *= 2;
    const next = Buffer.allocUnsafe(capacity);
    this.slab.copy(next, 0, this.slabStart, this.slabEnd);
    this.slab = next;
    this.slabStart = 0;
    this.slabEnd = this.bufferedBytes;
  }

  // Test-only invariant: fragmented input is represented by zero or one slab.
  private pendingSegmentCount(): number { return this.bufferedBytes === 0 ? 0 : 1; }

  private process(): void {
    while (true) {
      if (this.offsetState === "header") {
        if (this.bufferedBytes < HEADER_SIZE) return;
        this.headerBytes = Buffer.from(this.consume(HEADER_SIZE)); this.header = parseHeader(this.headerBytes);
        if (this.header.chunkCount > this.maxChunkCount || this.header.totalSize > this.maxTotalSize) fail("ERR_TRUNCATED");
        if (this.header.flags & FLAG_ENCRYPTED) this.key = decodeKey(this.options.key);
        this.root.update(this.headerBytes);
        this.offsetState = this.header.flags & FLAG_METADATA ? "metadata" : "payload";
      }
      if (this.offsetState === "metadata") {
        if (this.bufferedBytes < 4) return;
        const length = this.peek(4).readUInt32LE(0);
        if (length > this.maxMetaBytes) fail("ERR_META_MALFORMED");
        if (this.bufferedBytes < length + 4) return;
        const parsed = parseMetadata(this.peek(length + 4), 0, this.maxMetaBytes);
        this.consume(length + 4); this.metadata = parsed.metadata; this.root.update(parsed.region); this.offsetState = "payload";
      }
      if (this.offsetState === "payload") {
        if (this.chunkIndex === this.header!.chunkCount) { this.offsetState = "footer"; continue; }
        if (this.bufferedBytes < 4) return;
        const length = this.peek(4).readUInt32LE(0);
        if (length > this.maxChunkLen) fail("ERR_TRUNCATED");
        if (this.bufferedBytes < length + 4) return;
        this.consume(4); const body = Buffer.from(this.consume(length));
        this.root.update(createHash("sha256").update(body).digest());
        const plain = this.key ? open(this.key, this.header!.baseNonce, this.headerBytes!, this.chunkIndex, body) : body;
        this.plainTotal += BigInt(plain.byteLength);
        if (this.plainTotal > this.header!.totalSize) fail("ERR_ROOT_MISMATCH");
        this.chunkIndex++;
        if (!this.push(plain)) {
          this.outputBackpressured = true;
          return;
        }
        continue;
      }
      if (this.offsetState === "footer") {
        if (this.bufferedBytes < FOOTER_SIZE) return;
        const footer = this.consume(FOOTER_SIZE);
        if (!footer.subarray(32).equals(Buffer.from("UBCE"))) fail("ERR_TRUNCATED");
        if (this.plainTotal !== this.header!.totalSize || !timingSafeEqual(this.root.digest(), footer.subarray(0, 32))) fail("ERR_ROOT_MISMATCH");
        this.offsetState = "done";
        this.discardBuffered();
        return;
      }
      return;
    }
  }
}

export function newDecoder(source: Readable, options: DecodeOptions = {}): Decoder {
  const decoder = new Decoder(options);
  source.once("error", (error) => decoder.destroy(error));
  decoder.once("close", () => source.unpipe(decoder));
  source.pipe(decoder);
  return decoder;
}
