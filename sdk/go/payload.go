package ubc

import (
	"crypto/sha256"
	"encoding/binary"
)

func EncodePlain(data []byte, entries []MetadataEntry, chunkSize uint32) ([]byte, error) {
	if chunkSize == 0 {
		return nil, ErrReservedBits
	}
	meta, err := EncodeMetadata(entries)
	if err != nil {
		return nil, err
	}
	count := uint64((len(data) + int(chunkSize) - 1) / int(chunkSize))
	h := Header{Version: Version, HashAlgo: HashSHA256, ChunkSize: chunkSize, ChunkCount: count, TotalSize: uint64(len(data))}
	if len(meta) > 0 {
		h.Flags = FlagHasMetadata
	}
	header, err := h.MarshalBinary()
	if err != nil {
		return nil, err
	}
	out, leaves := append([]byte(nil), header...), make([]byte, 0, count*sha256.Size)
	out = append(out, meta...)
	for offset := 0; offset < len(data); offset += int(chunkSize) {
		end := offset + int(chunkSize)
		if end > len(data) {
			end = len(data)
		}
		c := data[offset:end]
		l := make([]byte, 4)
		binary.LittleEndian.PutUint32(l, uint32(len(c)))
		out = append(out, l...)
		out = append(out, c...)
		x := sha256.Sum256(c)
		leaves = append(leaves, x[:]...)
	}
	root := sha256.Sum256(append(append(append([]byte(nil), header...), meta...), leaves...))
	out = append(out, root[:]...)
	return append(out, "UBCE"...), nil
}
