package ubc

import (
	"bytes"
	"os"
	"testing"
)

func TestEncodePlainMatchesVectors(t *testing.T) {
	cases := []string{"empty", "one-byte", "chunk-1m", "chunk-1m-plus-one", "multi-3m"}
	for _, n := range cases {
		in, _ := os.ReadFile("../../spec/vectors/inputs/" + n + ".bin")
		want, _ := os.ReadFile("../../spec/vectors/expected/plain-" + n + ".ubc")
		got, e := EncodePlain(in, nil, 1<<20)
		if e != nil || !bytes.Equal(got, want) {
			t.Fatalf("%s: %v", n, e)
		}
	}
	in, _ := os.ReadFile("../../spec/vectors/inputs/one-byte.bin")
	want, _ := os.ReadFile("../../spec/vectors/expected/plain-metadata.ubc")
	meta := []MetadataEntry{{Tag: 1, Value: []byte("รายงาน-2026.txt")}, {Tag: 2, Value: []byte("text/plain")}, {Tag: 3, Value: []byte{0, 0xa8, 0xda, 0x76, 0x9b, 1, 0, 0}}, {Tag: 0x1000, Value: []byte{0, 0xff, 0x7f}}}
	got, err := EncodePlain(in, meta, 1<<20)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("metadata: %v", err)
	}
}
