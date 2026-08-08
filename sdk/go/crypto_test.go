package ubc

import (
	"bytes"
	"errors"
	"os"
	"testing"
)

func TestEncryptedVector(t *testing.T) {
	key := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31}
	base := [12]byte{0xf0, 0xe0, 0xd0, 0xc0, 0xb0, 0xa0, 0x90, 0x80, 0x70, 0x60, 0x50, 0x40}
	for _, name := range []string{"empty", "one-byte", "chunk-1m", "chunk-1m-plus-one", "multi-3m"} {
		in, _ := os.ReadFile("../../spec/vectors/inputs/" + name + ".bin")
		want, _ := os.ReadFile("../../spec/vectors/expected/encrypted-" + name + ".ubc")
		got, e := EncodeEncryptedWithFixedNonce(in, key, base, nil, 1<<20)
		if e != nil || !bytes.Equal(got, want) {
			t.Fatalf("%s: %v", name, e)
		}
	}
	in, _ := os.ReadFile("../../spec/vectors/inputs/one-byte.bin")
	want, _ := os.ReadFile("../../spec/vectors/expected/encrypted-metadata.ubc")
	meta := []MetadataEntry{{Tag: 1, Value: []byte("รายงาน-2026.txt")}, {Tag: 2, Value: []byte("text/plain")}, {Tag: 3, Value: []byte{0, 0xa8, 0xda, 0x76, 0x9b, 1, 0, 0}}, {Tag: 0x1000, Value: []byte{0, 0xff, 0x7f}}}
	got, e := EncodeEncryptedWithFixedNonce(in, key, base, meta, 1<<20)
	if e != nil || !bytes.Equal(got, want) {
		t.Fatalf("metadata: %v", e)
	}
}

func TestOpenChunkVerifiesBeforeRelease(t *testing.T) {
	key := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31}
	base := [12]byte{1}
	header := make([]byte, HeaderSize)
	ciphertext, err := sealChunk(key, base, header, 0, []byte("test"))
	if err != nil {
		t.Fatal(err)
	}
	ciphertext[0] ^= 1
	plain, err := openChunk(key, base, header, 0, ciphertext)
	if !errors.Is(err, ErrChunkAuth) || plain != nil {
		t.Fatalf("plain=%x err=%v", plain, err)
	}
}
