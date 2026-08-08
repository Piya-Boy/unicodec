package ubc

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"math"
)

type DecodeOptions struct {
	Key           []byte
	MaxMetaBytes  uint64
	MaxChunkLen   uint64
	MaxChunkCount uint64
	MaxTotalSize  uint64
}

const (
	// DefaultMaxMetaBytes bounds attacker-controlled metadata allocations.
	DefaultMaxMetaBytes uint64 = 16 << 20
	// DefaultMaxChunkLen bounds attacker-controlled chunk allocations.
	DefaultMaxChunkLen uint64 = 64 << 20
	// DefaultMaxChunkCount bounds per-container processing work.
	DefaultMaxChunkCount uint64 = 1 << 20
	// DefaultMaxTotalSize bounds plaintext released from one container.
	DefaultMaxTotalSize uint64 = 1 << 30
	// incrementalReadBlockSize limits each read/allocation step for length-prefixed data.
	incrementalReadBlockSize = 32 << 10
)

type decodeLimits struct {
	maxMetaBytes  uint64
	maxChunkLen   uint64
	maxChunkCount uint64
	maxTotalSize  uint64
}

func limitsFor(options DecodeOptions) decodeLimits {
	limits := decodeLimits{
		maxMetaBytes:  DefaultMaxMetaBytes,
		maxChunkLen:   DefaultMaxChunkLen,
		maxChunkCount: DefaultMaxChunkCount,
		maxTotalSize:  DefaultMaxTotalSize,
	}
	if options.MaxMetaBytes != 0 {
		limits.maxMetaBytes = options.MaxMetaBytes
	}
	if options.MaxChunkLen != 0 {
		limits.maxChunkLen = options.MaxChunkLen
	}
	if options.MaxChunkCount != 0 {
		limits.maxChunkCount = options.MaxChunkCount
	}
	if options.MaxTotalSize != 0 {
		limits.maxTotalSize = options.MaxTotalSize
	}
	return limits
}

type Decoder struct {
	source         io.Reader
	header         Header
	headerBytes    []byte
	metadataDigest [sha256.Size]byte
	metadata       []MetadataEntry
	metadataRaw    []byte
	key            []byte
	root           hashWriter
	limits         decodeLimits
	chunkIndex     uint64
	plainTotal     uint64
	pending        []byte
	terminalErr    error
	finalized      bool
}

type hashWriter interface {
	Write([]byte) (int, error)
	Sum([]byte) []byte
}

func NewDecoder(source io.Reader, options DecodeOptions) (*Decoder, error) {
	if source == nil {
		return nil, errors.New("ubc: nil decoder source")
	}
	headerBytes := make([]byte, HeaderSize)
	if err := readExact(source, headerBytes); err != nil {
		return nil, err
	}
	header, err := ParseHeader(headerBytes)
	if err != nil {
		return nil, err
	}
	limits := limitsFor(options)
	decoder := &Decoder{source: source, header: header, headerBytes: headerBytes, metadataDigest: sha256.Sum256(nil), root: sha256.New(), limits: limits}
	_, _ = decoder.root.Write(headerBytes)
	if header.HasMetadata() {
		region, err := readMetadataRegion(source, limits.maxMetaBytes)
		if err != nil {
			return nil, err
		}
		metadata, _, err := ParseMetadata(region)
		if err != nil {
			return nil, err
		}
		decoder.metadata = metadata
		decoder.metadataRaw = region
		decoder.metadataDigest = sha256.Sum256(region)
		_, _ = decoder.root.Write(region)
	}
	if header.Encrypted() && len(options.Key) != 32 {
		return nil, ErrMissingKey
	}
	if header.ChunkCount > limits.maxChunkCount || header.TotalSize > limits.maxTotalSize {
		return nil, ErrTruncated
	}
	decoder.key = append([]byte(nil), options.Key...)
	if header.Encrypted() {
		decoder.root = hmac.New(sha256.New, rootKey(decoder.key, header.BaseNonce))
		_, _ = decoder.root.Write(headerBytes)
		_, _ = decoder.root.Write(decoder.metadataRaw)
	}
	return decoder, nil
}

func (d *Decoder) Metadata() []MetadataEntry {
	metadata := make([]MetadataEntry, len(d.metadata))
	for i, entry := range d.metadata {
		metadata[i] = MetadataEntry{Tag: entry.Tag, Value: append([]byte(nil), entry.Value...)}
	}
	return metadata
}

func (d *Decoder) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if d.terminalErr != nil {
		return 0, d.terminalErr
	}
	for len(d.pending) == 0 && !d.finalized {
		if err := d.loadChunk(); err != nil {
			d.terminalErr = err
			return 0, err
		}
	}
	if len(d.pending) == 0 {
		return 0, io.EOF
	}
	n := copy(p, d.pending)
	d.pending = d.pending[n:]
	return n, nil
}

func (d *Decoder) loadChunk() error {
	if d.chunkIndex == d.header.ChunkCount {
		return d.verifyFooter()
	}
	var length [4]byte
	if err := readExact(d.source, length[:]); err != nil {
		return err
	}
	chunkLength := binary.LittleEndian.Uint32(length[:])
	if uint64(chunkLength) > d.limits.maxChunkLen || uint64(chunkLength) > uint64(maxInt()) {
		return ErrTruncated
	}
	body, err := readIncrementally(d.source, nil, uint64(chunkLength))
	if err != nil {
		return err
	}
	leaf := sha256.Sum256(body)
	_, _ = d.root.Write(leaf[:])
	plain := body
	if d.header.Encrypted() {
		var err error
		if len(body) < 16 {
			return ErrChunkAuth
		}
		plain, err = openChunk(d.key, d.header.BaseNonce, d.headerBytes, d.metadataDigest[:], d.chunkIndex, body)
		if err != nil {
			return err
		}
	}
	if uint64(len(plain)) > math.MaxUint64-d.plainTotal {
		return ErrRootMismatch
	}
	d.plainTotal += uint64(len(plain))
	if d.plainTotal > d.header.TotalSize {
		return ErrRootMismatch
	}
	d.chunkIndex++
	d.pending = plain
	return nil
}

func (d *Decoder) verifyFooter() error {
	footer := make([]byte, 36)
	if err := readExact(d.source, footer); err != nil {
		return err
	}
	if !bytes.Equal(footer[32:], []byte("UBCE")) {
		return ErrTruncated
	}
	if d.plainTotal != d.header.TotalSize || !rootMatches(d.header.Encrypted(), footer[:32], d.root.Sum(nil)) {
		return ErrRootMismatch
	}
	var extra [1]byte
	for {
		n, err := d.source.Read(extra[:])
		if n > 0 {
			return ErrTrailingData
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return ErrTruncated
		}
	}
	d.finalized = true
	return nil
}

func rootMatches(encrypted bool, got, want []byte) bool {
	if encrypted {
		return hmac.Equal(got, want)
	}
	return bytes.Equal(got, want)
}

func readMetadataRegion(reader io.Reader, maxMetaBytes uint64) ([]byte, error) {
	prefix := make([]byte, 4)
	if err := readExact(reader, prefix); err != nil {
		return nil, ErrMetaMalformed
	}
	length := binary.LittleEndian.Uint32(prefix)
	if uint64(length) > maxMetaBytes || uint64(length) > uint64(maxInt()-4) {
		return nil, ErrMetaMalformed
	}
	region, err := readIncrementally(reader, prefix, uint64(length))
	if err != nil {
		return nil, ErrMetaMalformed
	}
	return region, nil
}

func readIncrementally(reader io.Reader, data []byte, length uint64) ([]byte, error) {
	var block [incrementalReadBlockSize]byte
	for length > 0 {
		readSize := len(block)
		if length < uint64(readSize) {
			readSize = int(length)
		}
		n, err := io.ReadFull(reader, block[:readSize])
		if n > 0 {
			data = append(data, block[:n]...)
		}
		if err != nil {
			return nil, err
		}
		length -= uint64(n)
	}
	return data, nil
}

func readExact(reader io.Reader, data []byte) error {
	if _, err := io.ReadFull(reader, data); err != nil {
		return ErrTruncated
	}
	return nil
}

func maxInt() int { return int(^uint(0) >> 1) }
