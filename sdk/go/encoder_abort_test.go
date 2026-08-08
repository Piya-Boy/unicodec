package ubc

import (
	"bytes"
	"errors"
	"os"
	"testing"
)

func TestEncoderAbortDiscardsBufferedPlaintext(t *testing.T) {
	var sink bytes.Buffer
	encoder, err := NewEncoder(&sink, nil, EncodeOptions{ChunkSize: 4})
	if err != nil {
		t.Fatal(err)
	}
	spoolName := encoder.spool.Name()
	if _, err := encoder.Write([]byte("secret")); err != nil {
		t.Fatal(err)
	}
	if err := encoder.Abort(); err != nil {
		t.Fatal(err)
	}
	if sink.Len() != 0 {
		t.Fatalf("sink received %d bytes", sink.Len())
	}
	if _, err := os.Stat(spoolName); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("spool still exists: %v", err)
	}
}
