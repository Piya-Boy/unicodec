package ubc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
)

func chunkNonce(base [12]byte, index uint64) [12]byte {
	n := base
	for i := 0; i < 8; i++ {
		n[i] ^= byte(index >> (8 * i))
	}
	return n
}

var rootInfo = []byte("UBC1 root authentication")

func rootKey(key []byte, base [12]byte) []byte {
	prk := hmac.New(sha256.New, base[:])
	_, _ = prk.Write(key)
	expand := hmac.New(sha256.New, prk.Sum(nil))
	_, _ = expand.Write(rootInfo)
	_, _ = expand.Write([]byte{1})
	return expand.Sum(nil)
}

func chunkAAD(header, metadataDigest []byte, index uint64) []byte {
	aad := append([]byte(nil), header...)
	aad = append(aad, metadataDigest...)
	i := make([]byte, 8)
	binary.LittleEndian.PutUint64(i, index)
	return append(aad, i...)
}
func sealChunk(key []byte, base [12]byte, header, metadataDigest []byte, index uint64, plain []byte) ([]byte, error) {
	b, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	a, e := cipher.NewGCM(b)
	if e != nil {
		return nil, e
	}
	n := chunkNonce(base, index)
	return a.Seal(nil, n[:], plain, chunkAAD(header, metadataDigest, index)), nil
}

func openChunk(key []byte, base [12]byte, header, metadataDigest []byte, index uint64, data []byte) ([]byte, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	a, err := cipher.NewGCM(b)
	if err != nil {
		return nil, err
	}
	n := chunkNonce(base, index)
	plain, err := a.Open(nil, n[:], data, chunkAAD(header, metadataDigest, index))
	if err != nil {
		return nil, ErrChunkAuth
	}
	return plain, nil
}

func EncodeEncrypted(data, key []byte, entries []MetadataEntry, size uint32) ([]byte, error) {
	var base [12]byte
	if _, err := rand.Read(base[:]); err != nil {
		return nil, err
	}
	return EncodeEncryptedWithFixedNonce(data, key, base, entries, size)
}

// EncodeEncryptedWithFixedNonce is for deterministic conformance tests only.
func EncodeEncryptedWithFixedNonce(data, key []byte, base [12]byte, entries []MetadataEntry, size uint32) ([]byte, error) {
	if len(key) != 32 || size == 0 {
		return nil, ErrReservedBits
	}
	meta, e := EncodeMetadata(entries)
	if e != nil {
		return nil, e
	}
	count := uint64((len(data) + int(size) - 1) / int(size))
	h := Header{Version: Version, Flags: FlagEncrypted, HashAlgo: HashHMACSHA256, AEADAlgo: AEADAESGCM, ChunkSize: size, ChunkCount: count, TotalSize: uint64(len(data)), BaseNonce: base}
	if len(meta) > 0 {
		h.Flags |= FlagHasMetadata
	}
	head, e := h.MarshalBinary()
	if e != nil {
		return nil, e
	}
	out := append([]byte(nil), head...)
	out = append(out, meta...)
	leaves := []byte{}
	metadataDigest := sha256.Sum256(meta)
	for i, off := uint64(0), 0; off < len(data); i, off = i+1, off+int(size) {
		end := off + int(size)
		if end > len(data) {
			end = len(data)
		}
		c, e := sealChunk(key, base, head, metadataDigest[:], i, data[off:end])
		if e != nil {
			return nil, e
		}
		l := make([]byte, 4)
		binary.LittleEndian.PutUint32(l, uint32(len(c)))
		out = append(out, l...)
		out = append(out, c...)
		x := sha256.Sum256(c)
		leaves = append(leaves, x[:]...)
	}
	root := hmac.New(sha256.New, rootKey(key, base))
	_, _ = root.Write(head)
	_, _ = root.Write(meta)
	_, _ = root.Write(leaves)
	out = append(out, root.Sum(nil)...)
	return append(out, "UBCE"...), nil
}
