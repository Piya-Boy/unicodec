package ubc

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
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

func TestRootKeyKnownAnswer(t *testing.T) {
	key := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31}
	base := [12]byte{0xf0, 0xe0, 0xd0, 0xc0, 0xb0, 0xa0, 0x90, 0x80, 0x70, 0x60, 0x50, 0x40}
	if got := hex.EncodeToString(rootKey(key, base)); got != "52c04b400d73df15d8a0db6ba58919f46fe822fff200fb50d8dee097af3c688c" {
		t.Fatalf("root key = %s", got)
	}
}

func TestEncryptedEmptyRejectsWrongKey(t *testing.T) {
	key := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31}
	container, err := EncodeEncryptedWithFixedNonce(nil, key, [12]byte{1}, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	wrong := append([]byte(nil), key...)
	wrong[0] ^= 1
	decoder, err := NewDecoder(bytes.NewReader(container), DecodeOptions{Key: wrong})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = io.ReadAll(decoder); !errors.Is(err, ErrRootMismatch) {
		t.Fatalf("wrong key error = %v", err)
	}
}

func TestEncryptedMetadataIsChunkAAD(t *testing.T) {
	key := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31}
	container, err := EncodeEncryptedWithFixedNonce([]byte("x"), key, [12]byte{1}, []MetadataEntry{{Tag: 2, Value: []byte("text/plain")}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	position := bytes.Index(container, []byte("text/plain"))
	if position < 0 {
		t.Fatal("metadata not found")
	}
	container[position] = 'q'
	decoder, err := NewDecoder(bytes.NewReader(container), DecodeOptions{Key: key})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = io.ReadAll(decoder); !errors.Is(err, ErrChunkAuth) {
		t.Fatalf("metadata tamper error = %v", err)
	}
}

func TestOpenChunkVerifiesBeforeRelease(t *testing.T) {
	key := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31}
	base := [12]byte{1}
	header := make([]byte, HeaderSize)
	ciphertext, err := sealChunk(key, base, header, make([]byte, 32), 0, []byte("test"))
	if err != nil {
		t.Fatal(err)
	}
	ciphertext[0] ^= 1
	plain, err := openChunk(key, base, header, make([]byte, 32), 0, ciphertext)
	if !errors.Is(err, ErrChunkAuth) || plain != nil {
		t.Fatalf("plain=%x err=%v", plain, err)
	}
}
