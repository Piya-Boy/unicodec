package ubc

import (
	"bytes"
	"testing"
)

func TestVerifyAcceptsValidPlain(t *testing.T) {
	container, err := EncodePlain([]byte("hello world"), nil, 4)
	if err != nil {
		t.Fatal(err)
	}
	if got := Verify(bytes.NewReader(container), DecodeOptions{}); !got.OK {
		t.Fatalf("want OK, got %+v", got)
	}
}

func TestVerifyRejectsTamperedPlainWithoutReleasingPlaintext(t *testing.T) {
	container, err := EncodePlain([]byte("hello world"), nil, 4)
	if err != nil {
		t.Fatal(err)
	}
	container[HeaderSize+4] ^= 0xff // flip a payload byte
	got := Verify(bytes.NewReader(container), DecodeOptions{})
	if got.OK || got.Error != CodeRootMismatch {
		t.Fatalf("want ERR_ROOT_MISMATCH, got %+v", got)
	}
}

func TestVerifyEncryptedTagFailure(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	var base [12]byte
	container, err := EncodeEncryptedWithFixedNonce([]byte("secret payload"), key, base, nil, 8)
	if err != nil {
		t.Fatal(err)
	}
	container[HeaderSize+4] ^= 0x01 // corrupt ciphertext
	got := Verify(bytes.NewReader(container), DecodeOptions{Key: key})
	if got.OK || got.Error != CodeChunkAuth {
		t.Fatalf("want ERR_CHUNK_AUTH, got %+v", got)
	}
}

func TestVerifyEncryptedMissingKey(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	var base [12]byte
	container, err := EncodeEncryptedWithFixedNonce([]byte("x"), key, base, nil, 8)
	if err != nil {
		t.Fatal(err)
	}
	got := Verify(bytes.NewReader(container), DecodeOptions{})
	if got.OK || got.Error != CodeMissingKey {
		t.Fatalf("want ERR_MISSING_KEY, got %+v", got)
	}
}
