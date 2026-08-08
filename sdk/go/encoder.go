package ubc

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"os"
)

const defaultChunkSize uint32 = 1 << 20

var errEncoderClosed = errors.New("ubc: encoder is closed")

type EncodeOptions struct {
	Key       []byte
	ChunkSize uint32
	BaseNonce *[12]byte
}

type Encoder struct {
	sink      io.Writer
	metadata  []byte
	options   EncodeOptions
	spool     *os.File
	totalSize uint64
	closed    bool
}

func NewEncoder(sink io.Writer, entries []MetadataEntry, options EncodeOptions) (*Encoder, error) {
	if sink == nil {
		return nil, errors.New("ubc: nil encoder sink")
	}
	if options.ChunkSize == 0 {
		options.ChunkSize = defaultChunkSize
	}
	if len(options.Key) != 0 && len(options.Key) != 32 {
		return nil, ErrReservedBits
	}
	metadata, err := EncodeMetadata(entries)
	if err != nil {
		return nil, err
	}
	spool, err := os.CreateTemp("", "ubc-plaintext-*")
	if err != nil {
		return nil, err
	}
	return &Encoder{sink: sink, metadata: metadata, options: options, spool: spool}, nil
}

func (e *Encoder) Write(p []byte) (int, error) {
	if e.closed {
		return 0, errEncoderClosed
	}
	if uint64(len(p)) > math.MaxUint64-e.totalSize {
		return 0, ErrReservedBits
	}
	n, err := e.spool.Write(p)
	e.totalSize += uint64(n)
	return n, err
}

func (e *Encoder) Close() (err error) {
	if e.closed {
		return errEncoderClosed
	}
	e.closed = true
	defer func() {
		closeErr := e.spool.Close()
		removeErr := os.Remove(e.spool.Name())
		if err == nil && closeErr != nil {
			err = closeErr
		}
		if err == nil && removeErr != nil {
			err = removeErr
		}
	}()

	chunkCount := e.totalSize / uint64(e.options.ChunkSize)
	if e.totalSize%uint64(e.options.ChunkSize) != 0 {
		chunkCount++
	}
	header := Header{
		Version:    Version,
		HashAlgo:   HashSHA256,
		ChunkSize:  e.options.ChunkSize,
		ChunkCount: chunkCount,
		TotalSize:  e.totalSize,
	}
	if len(e.metadata) != 0 {
		header.Flags |= FlagHasMetadata
	}
	if len(e.options.Key) != 0 {
		header.Flags |= FlagEncrypted
		header.HashAlgo = HashHMACSHA256
		header.AEADAlgo = AEADAESGCM
		if e.options.BaseNonce != nil {
			header.BaseNonce = *e.options.BaseNonce
		} else if _, err := rand.Read(header.BaseNonce[:]); err != nil {
			return err
		}
	}
	headerBytes, err := header.MarshalBinary()
	if err != nil {
		return err
	}
	if err := writeAll(e.sink, headerBytes); err != nil {
		return err
	}
	if err := writeAll(e.sink, e.metadata); err != nil {
		return err
	}
	metadataDigest := sha256.Sum256(e.metadata)
	var rootWriter hashWriter = sha256.New()
	if header.Encrypted() {
		rootWriter = hmac.New(sha256.New, rootKey(e.options.Key, header.BaseNonce))
	}
	_, _ = rootWriter.Write(headerBytes)
	_, _ = rootWriter.Write(e.metadata)
	if _, err := e.spool.Seek(0, io.SeekStart); err != nil {
		return err
	}
	buffer := make([]byte, e.options.ChunkSize)
	for index := uint64(0); index < chunkCount; index++ {
		plainLength := int(e.options.ChunkSize)
		remaining := e.totalSize - index*uint64(e.options.ChunkSize)
		if remaining < uint64(plainLength) {
			plainLength = int(remaining)
		}
		if _, err := io.ReadFull(e.spool, buffer[:plainLength]); err != nil {
			return err
		}
		body := buffer[:plainLength]
		if header.Encrypted() {
			body, err = sealChunk(e.options.Key, header.BaseNonce, headerBytes, metadataDigest[:], index, body)
			if err != nil {
				return err
			}
		}
		var length [4]byte
		binary.LittleEndian.PutUint32(length[:], uint32(len(body)))
		if err := writeAll(e.sink, length[:]); err != nil {
			return err
		}
		if err := writeAll(e.sink, body); err != nil {
			return err
		}
		leaf := sha256.Sum256(body)
		_, _ = rootWriter.Write(leaf[:])
	}
	if err := writeAll(e.sink, rootWriter.Sum(nil)); err != nil {
		return err
	}
	return writeAll(e.sink, []byte("UBCE"))
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) != 0 {
		n, err := writer.Write(data)
		if n > 0 {
			data = data[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
