package ubc

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

type inspectVectors struct {
	Vectors []inspectVector `json:"vectors"`
}

type inspectVector struct {
	ID       string `json:"id"`
	Expected string `json:"expected"`
	Options  struct {
		Metadata []struct {
			Tag      string `json:"tag"`
			ValueHex string `json:"valueHex"`
		} `json:"metadata"`
	} `json:"options"`
}

func TestInspectSharedMetadataVectors(t *testing.T) {
	vectors := loadInspectVectors(t)
	for _, id := range []string{"plain-metadata", "encrypted-metadata"} {
		vector := vectorByID(t, vectors, id)
		container := readInspectVectorFile(t, vector.Expected)
		info, err := Inspect(bytes.NewReader(container))
		if err != nil {
			t.Fatalf("%s: Inspect: %v", id, err)
		}
		if info.Flags.Encrypted != (id == "encrypted-metadata") || !info.Flags.HasMetadata {
			t.Fatalf("%s: flags = %+v", id, info.Flags)
		}
		if got, want := info.Metadata, inspectVectorMetadata(t, vector); !inspectMetadataEqual(got, want) {
			t.Fatalf("%s: metadata = %#v, want %#v", id, got, want)
		}
	}
}

func TestInspectReadsOnlyHeaderAndMetadata(t *testing.T) {
	container := readInspectVectorFile(t, "expected/encrypted-metadata.ubc")
	metadataEnd := HeaderSize + int(uint32(container[HeaderSize])|uint32(container[HeaderSize+1])<<8|uint32(container[HeaderSize+2])<<16|uint32(container[HeaderSize+3])<<24) + 4
	reader := &guardedReader{data: container, limit: metadataEnd}
	info, err := Inspect(reader)
	if err != nil {
		t.Fatal(err)
	}
	if reader.read != metadataEnd || !info.Flags.Encrypted {
		t.Fatalf("read %d bytes, want %d; info=%+v", reader.read, metadataEnd, info)
	}

	first := info.Metadata[0].Value[0]
	container[HeaderSize+10] ^= 0xff
	if info.Metadata[0].Value[0] != first {
		t.Fatal("metadata aliases source bytes")
	}
}

func TestInspectMetadataErrors(t *testing.T) {
	for _, name := range []string{"negative-meta-out-of-order", "negative-meta-duplicate", "negative-meta-overrun", "negative-empty-metadata", "negative-encrypted-reserved-metadata"} {
		container := readInspectVectorFile(t, "expected/"+name+".ubc")
		if _, err := Inspect(bytes.NewReader(container)); !errors.Is(err, ErrMetaMalformed) {
			t.Fatalf("%s: error = %v, want %v", name, err, ErrMetaMalformed)
		}
	}

	container := readInspectVectorFile(t, "expected/plain-metadata.ubc")
	if _, err := Inspect(bytes.NewReader(container[:HeaderSize+2])); !errors.Is(err, ErrMetaMalformed) {
		t.Fatalf("truncated metadata: error = %v, want %v", err, ErrMetaMalformed)
	}
}

type guardedReader struct {
	data        []byte
	limit, read int
}

func (r *guardedReader) Read(p []byte) (int, error) {
	if r.read >= r.limit {
		return 0, errors.New("payload read")
	}
	remaining := r.limit - r.read
	if len(p) > remaining {
		p = p[:remaining]
	}
	n := copy(p, r.data[r.read:r.read+len(p)])
	r.read += n
	return n, nil
}

func loadInspectVectors(t *testing.T) []inspectVector {
	t.Helper()
	data := readInspectVectorFile(t, "vectors.json")
	var vectors inspectVectors
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	return vectors.Vectors
}

func vectorByID(t *testing.T, vectors []inspectVector, id string) inspectVector {
	t.Helper()
	for _, vector := range vectors {
		if vector.ID == id {
			return vector
		}
	}
	t.Fatalf("missing shared vector %q", id)
	return inspectVector{}
}

func inspectVectorMetadata(t *testing.T, vector inspectVector) []MetadataEntry {
	t.Helper()
	metadata := make([]MetadataEntry, len(vector.Options.Metadata))
	for i, entry := range vector.Options.Metadata {
		var tag uint16
		if _, err := fmt.Sscanf(entry.Tag, "0x%x", &tag); err != nil {
			t.Fatal(err)
		}
		value, err := hex.DecodeString(entry.ValueHex)
		if err != nil {
			t.Fatal(err)
		}
		metadata[i] = MetadataEntry{Tag: tag, Value: value}
	}
	return metadata
}

func readInspectVectorFile(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "spec", "vectors", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func inspectMetadataEqual(left, right []MetadataEntry) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i].Tag != right[i].Tag || !bytes.Equal(left[i].Value, right[i].Value) {
			return false
		}
	}
	return true
}
