package ubc

import (
	"bytes"
	"encoding/binary"
)

const (
	HeaderSize = 40
	Version    = 1

	HashSHA256 = 0
	AEADNone   = 0
	AEADAESGCM = 1

	FlagEncrypted   = 1 << 0
	FlagHasMetadata = 1 << 1
)

var magic = [4]byte{'U', 'B', 'C', '1'}

type Header struct {
	Version    uint8
	Flags      uint8
	HashAlgo   uint8
	AEADAlgo   uint8
	ChunkSize  uint32
	ChunkCount uint64
	TotalSize  uint64
	BaseNonce  [12]byte
}

func (h Header) Encrypted() bool { return h.Flags&FlagEncrypted != 0 }

func (h Header) HasMetadata() bool { return h.Flags&FlagHasMetadata != 0 }

func (h Header) MarshalBinary() ([]byte, error) {
	if err := h.validate(); err != nil {
		return nil, err
	}
	data := make([]byte, HeaderSize)
	copy(data[:4], magic[:])
	data[4] = h.Version
	data[5] = h.Flags
	data[6] = h.HashAlgo
	data[7] = h.AEADAlgo
	binary.LittleEndian.PutUint32(data[8:12], h.ChunkSize)
	binary.LittleEndian.PutUint64(data[12:20], h.ChunkCount)
	binary.LittleEndian.PutUint64(data[20:28], h.TotalSize)
	copy(data[28:40], h.BaseNonce[:])
	return data, nil
}

func ParseHeader(data []byte) (Header, error) {
	if len(data) < HeaderSize {
		return Header{}, ErrTruncated
	}
	if !bytes.Equal(data[:4], magic[:]) {
		return Header{}, ErrBadMagic
	}
	header := Header{
		Version:    data[4],
		Flags:      data[5],
		HashAlgo:   data[6],
		AEADAlgo:   data[7],
		ChunkSize:  binary.LittleEndian.Uint32(data[8:12]),
		ChunkCount: binary.LittleEndian.Uint64(data[12:20]),
		TotalSize:  binary.LittleEndian.Uint64(data[20:28]),
	}
	copy(header.BaseNonce[:], data[28:40])
	if err := header.validate(); err != nil {
		return Header{}, err
	}
	return header, nil
}

func (h Header) validate() error {
	if h.Version != Version {
		return ErrUnsupportedVer
	}
	if h.HashAlgo != HashSHA256 || (h.AEADAlgo != AEADNone && h.AEADAlgo != AEADAESGCM) {
		return ErrUnsupportedAlgo
	}
	if h.Flags&^uint8(FlagEncrypted|FlagHasMetadata) != 0 {
		return ErrReservedBits
	}
	if h.Encrypted() {
		if h.AEADAlgo != AEADAESGCM {
			return ErrReservedBits
		}
		return nil
	}
	if h.AEADAlgo != AEADNone || h.BaseNonce != [12]byte{} {
		return ErrReservedBits
	}
	return nil
}
