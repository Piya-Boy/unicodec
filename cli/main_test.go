package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	ubc "github.com/ubc/vectors/sdk/go"
)

type cliVector struct {
	ID          string `json:"id"`
	Input       string `json:"input"`
	Expected    string `json:"expected"`
	ExpectError string `json:"expectError"`
	Options     struct {
		ChunkSize uint32              `json:"chunkSize"`
		Key       string              `json:"key"`
		BaseNonce string              `json:"baseNonce"`
		Metadata  []cliMetadataVector `json:"metadata"`
	} `json:"options"`
}

type cliMetadataVector struct {
	Tag      string `json:"tag"`
	ValueHex string `json:"valueHex"`
}

type cliVectorManifest struct {
	CryptoKnownAnswers []struct {
		Key string `json:"key"`
	} `json:"cryptoKnownAnswers"`
	Vectors []cliVector `json:"vectors"`
}

func loadCLIManifest(t *testing.T) cliVectorManifest {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "spec", "vectors", "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest cliVectorManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	return manifest
}

func loadCLIVectors(t *testing.T) []cliVector {
	return loadCLIManifest(t).Vectors
}

func fixedVectorKey(t *testing.T) []byte {
	t.Helper()
	knownAnswers := loadCLIManifest(t).CryptoKnownAnswers
	if len(knownAnswers) == 0 {
		t.Fatal("vectors manifest has no crypto known-answer key")
	}
	return decodeVectorKey(t, knownAnswers[0].Key)
}

func vectorKey(t *testing.T, vector cliVector) []byte {
	t.Helper()
	if vector.Options.Key != "" {
		return decodeVectorKey(t, vector.Options.Key)
	}
	return fixedVectorKey(t)
}

func decodeVectorKey(t *testing.T, value string) []byte {
	t.Helper()
	key, err := hex.DecodeString(value)
	if err != nil || len(key) != 32 {
		t.Fatalf("invalid vector key %q: %v", value, err)
	}
	return key
}

func vectorIsEncrypted(t *testing.T, path string) bool {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return len(data) > 5 && data[5]&1 != 0
}

func TestRootHelpAndVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--help"}, &stdout, &stderr); code != 0 {
		t.Fatalf("help exit code = %d", code)
	}
	if !strings.Contains(stdout.String(), "Usage: ubc <command> [flags]") || stderr.Len() != 0 {
		t.Fatalf("help output = %q, stderr = %q", stdout.String(), stderr.String())
	}

	stdout.Reset()
	if code := run([]string{"version"}, &stdout, &stderr); code != 0 || stdout.String() != "ubc "+version+"\n" {
		t.Fatalf("version exit code = %d, output = %q", code, stdout.String())
	}
}

func TestSubcommandHelpRenders(t *testing.T) {
	for _, command := range []string{"encode", "decode", "verify", "inspect"} {
		t.Run(command, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run([]string{command, "--help"}, &stdout, &stderr); code != 0 {
				t.Fatalf("help exit code = %d", code)
			}
			for _, flag := range []string{"-in <path|->", "-out <path|->", "-key-file <path>", "-chunk-size <bytes>"} {
				if !strings.Contains(stdout.String(), flag) {
					t.Fatalf("missing %q in %q", flag, stdout.String())
				}
			}
			if stderr.Len() != 0 {
				t.Fatalf("stderr = %q", stderr.String())
			}
			if command == "inspect" && !strings.Contains(stdout.String(), "-json") {
				t.Fatalf("inspect help does not describe -json: %q", stdout.String())
			}
		})
	}
}

func TestUsageErrorsExitTwo(t *testing.T) {
	tests := [][]string{
		{},
		{"nope"},
		{"help", "encode", "extra"},
		{"help", "--help"},
		{"-h", "-h"},
		{"encode", "-chunk-size", "0"},
		{"decode", "-key", "secret"},
	}
	for _, args := range tests {
		var stdout, stderr bytes.Buffer
		if code := run(args, &stdout, &stderr); code != 2 {
			t.Fatalf("run(%q) exit code = %d", args, code)
		}
		if stderr.Len() == 0 {
			t.Fatalf("run(%q) did not report a usage error", args)
		}
	}
}

func TestCommandOptionsAcceptGlobalFlags(t *testing.T) {
	options, help, err := parseCommandOptions("encode", []string{"-in", "input", "-out", "output", "-key-file", "key.bin", "-chunk-size", "4096", "-metadata", "0x1000:00ff"})
	if err != nil || help {
		t.Fatalf("parseCommandOptions() = %#v, %v, %v", options, help, err)
	}
	if options.inputPath != "input" || options.outputPath != "output" || options.keyFile != "key.bin" || options.chunkSize != 4096 {
		t.Fatalf("options = %#v", options)
	}
	if len(options.metadata) != 1 || options.metadata[0] != "0x1000:00ff" {
		t.Fatalf("metadata = %#v", options.metadata)
	}
}

func TestEncodeMatchesSharedVectors(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expected  string
		encrypted bool
		envKey    bool
		rawKey    bool
	}{
		{name: "plain-empty", input: "empty", expected: "plain-empty"},
		{name: "plain-one-byte", input: "one-byte", expected: "plain-one-byte"},
		{name: "plain-chunk", input: "chunk-1m", expected: "plain-chunk-1m"},
		{name: "plain-boundary", input: "chunk-1m-plus-one", expected: "plain-chunk-1m-plus-one"},
		{name: "plain-multi", input: "multi-3m", expected: "plain-multi-3m"},
		{name: "encrypted-empty", input: "empty", expected: "encrypted-empty", encrypted: true, rawKey: true},
		{name: "encrypted-one-byte", input: "one-byte", expected: "encrypted-one-byte", encrypted: true, envKey: true},
		{name: "encrypted-chunk", input: "chunk-1m", expected: "encrypted-chunk-1m", encrypted: true},
		{name: "encrypted-boundary", input: "chunk-1m-plus-one", expected: "encrypted-chunk-1m-plus-one", encrypted: true},
		{name: "encrypted-multi", input: "multi-3m", expected: "encrypted-multi-3m", encrypted: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("UBC_KEY", "")
			directory := t.TempDir()
			output := filepath.Join(directory, "output.ubc")
			args := []string{
				"encode",
				"-in", filepath.Join("..", "spec", "vectors", "inputs", test.input+".bin"),
				"-out", output,
			}
			if test.encrypted {
				if test.envKey {
					t.Setenv("UBC_KEY", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
				} else {
					keyPath := filepath.Join(directory, "key.hex")
					key := []byte("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n")
					if test.rawKey {
						key = make([]byte, 32)
						for i := range key {
							key[i] = byte(i)
						}
					}
					if err := os.WriteFile(keyPath, key, 0o600); err != nil {
						t.Fatal(err)
					}
					args = append(args, "-key-file", keyPath)
				}
				args = append(args, "-base-nonce", "f0e0d0c0b0a0908070605040")
			}

			var stdout, stderr bytes.Buffer
			if code := run(args, &stdout, &stderr); code != 0 {
				t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
			}
			if stdout.Len() != 0 || stderr.Len() != 0 {
				t.Fatalf("stdout = %q, stderr = %q", stdout.String(), stderr.String())
			}
			got, err := os.ReadFile(output)
			if err != nil {
				t.Fatal(err)
			}
			want, err := os.ReadFile(filepath.Join("..", "spec", "vectors", "expected", test.expected+".ubc"))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatal("output differs from shared vector")
			}
		})
	}
}

func TestEncodeStdinStdoutAndMetadataMatchSDK(t *testing.T) {
	input := []byte("streamed input")
	args := []string{"encode", "-in", "-", "-out", "-", "-chunk-size", "2", "-name", "report.txt", "-mime", "text/plain"}
	var stdout, stderr bytes.Buffer
	if code := runWithInput(args, bytes.NewReader(input), &stdout, &stderr); code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}

	var want bytes.Buffer
	encoder, err := ubc.NewEncoder(&want, []ubc.MetadataEntry{
		{Tag: 0x0001, Value: []byte("report.txt")},
		{Tag: 0x0002, Value: []byte("text/plain")},
	}, ubc.EncodeOptions{ChunkSize: 2})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := encoder.Write(input); err != nil {
		t.Fatal(err)
	}
	if err := encoder.Close(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stdout.Bytes(), want.Bytes()) || stderr.Len() != 0 {
		t.Fatalf("output differs from SDK; stderr = %q", stderr.String())
	}
}

func TestEncodeInvalidConfigurationIsUsageError(t *testing.T) {
	tests := [][]string{
		{"encode", "-base-nonce", "f0e0d0c0b0a0908070605040"},
		{"encode", "-base-nonce", "nope", "-key-file", "key.hex"},
		{"encode", "-metadata", "bad"},
		{"encode", "-metadata", "0x10000:00"},
		{"encode", "-metadata", "0x1000:not-hex"},
	}
	for _, args := range tests {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			if strings.Contains(strings.Join(args, " "), "key.hex") {
				keyPath := filepath.Join(t.TempDir(), "key.hex")
				if err := os.WriteFile(keyPath, []byte("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"), 0o600); err != nil {
					t.Fatal(err)
				}
				args = append([]string(nil), args...)
				args[len(args)-1] = keyPath
			}
			var stdout, stderr bytes.Buffer
			if code := run(args, &stdout, &stderr); code != 2 {
				t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
			}
		})
	}
}

func TestParseMetadataEntryUsesHexadecimalTags(t *testing.T) {
	for _, value := range []string{"1000:00", "0x1000:00", "0X1000:00"} {
		entry, err := parseMetadataEntry(value)
		if err != nil {
			t.Fatalf("parseMetadataEntry(%q): %v", value, err)
		}
		if entry.Tag != 0x1000 || !bytes.Equal(entry.Value, []byte{0}) {
			t.Fatalf("parseMetadataEntry(%q) = %#v", value, entry)
		}
	}
	if _, err := parseMetadataEntry("0x0X1000:00"); err == nil {
		t.Fatal("parseMetadataEntry accepted a double hexadecimal prefix")
	}
}

func TestEncodeDoesNotOverwriteItsInput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input.bin")
	input := []byte("must survive")
	if err := os.WriteFile(path, input, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"encode", "-in", path, "-out", path}, &stdout, &stderr); code != 2 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, input) {
		t.Fatal("input file was modified")
	}
}

func TestEncodeInvalidMetadataPreservesOutput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "output.ubc")
	original := []byte("existing output")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := runWithInput([]string{"encode", "-in", "-", "-out", path, "-mime", "\x80"}, bytes.NewReader([]byte("input")), &stdout, &stderr); code != 2 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) {
		t.Fatal("invalid metadata modified output")
	}
}

type failingReader struct {
	data []byte
	done bool
}

func (reader *failingReader) Read(p []byte) (int, error) {
	if reader.done {
		return 0, os.ErrInvalid
	}
	reader.done = true
	n := copy(p, reader.data)
	return n, os.ErrInvalid
}

func TestEncodeInputFailureDoesNotPublishPartialContainer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "output.ubc")
	original := []byte("existing output")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := runWithInput([]string{"encode", "-in", "-", "-out", path}, &failingReader{data: []byte("prefix")}, &stdout, &stderr); code != 1 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) {
		t.Fatal("input failure published a partial container")
	}
}

func TestEncodeStdinCanPublishToItsSourcePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input.bin")
	input := []byte("redirected stdin")
	if err := os.WriteFile(path, input, 0o600); err != nil {
		t.Fatal(err)
	}
	stdin, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stdin.Close() }()
	var stdout, stderr bytes.Buffer
	if code := runWithInput([]string{"encode", "-in", "-", "-out", path}, stdin, &stdout, &stderr); code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want, err := ubc.EncodePlain(input, nil, defaultChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("redirected stdin output differs from SDK")
	}
}

func TestDecodeSharedPositiveVectors(t *testing.T) {
	for _, vector := range loadCLIVectors(t) {
		if vector.ExpectError != "" {
			continue
		}
		t.Run(vector.ID, func(t *testing.T) {
			t.Setenv("UBC_KEY", "")
			directory := t.TempDir()
			output := filepath.Join(directory, "output.bin")
			container := filepath.Join("..", "spec", "vectors", vector.Expected)
			args := []string{
				"decode",
				"-in", container,
				"-out", output,
			}
			if vectorIsEncrypted(t, container) {
				keyPath := filepath.Join(directory, "key.bin")
				if err := os.WriteFile(keyPath, vectorKey(t, vector), 0o600); err != nil {
					t.Fatal(err)
				}
				args = append(args, "-key-file", keyPath)
			}
			var stdout, stderr bytes.Buffer
			if code := run(args, &stdout, &stderr); code != 0 {
				t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
			}
			got, err := os.ReadFile(output)
			if err != nil {
				t.Fatal(err)
			}
			want, err := os.ReadFile(filepath.Join("..", "spec", "vectors", vector.Input))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) || stdout.Len() != 0 || stderr.Len() != 0 {
				t.Fatalf("output differs from shared input; stdout = %q, stderr = %q", stdout.String(), stderr.String())
			}
		})
	}
}

func TestDecodeNegativeVectorsFailClosed(t *testing.T) {
	for _, vector := range loadCLIVectors(t) {
		if vector.ExpectError == "" {
			continue
		}
		t.Run(vector.ID, func(t *testing.T) {
			t.Setenv("UBC_KEY", "")
			directory := t.TempDir()
			container := filepath.Join("..", "spec", "vectors", vector.Expected)
			args := []string{
				"decode",
				"-in", container,
				"-out", "-",
			}
			if vector.ExpectError != "ERR_MISSING_KEY" && vectorIsEncrypted(t, container) {
				key := vectorKey(t, vector)
				keyPath := filepath.Join(directory, "key.bin")
				if err := os.WriteFile(keyPath, key, 0o600); err != nil {
					t.Fatal(err)
				}
				args = append(args, "-key-file", keyPath)
			}
			var stdout, stderr bytes.Buffer
			if code := run(args, &stdout, &stderr); code != 1 {
				t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
			}
			if stdout.Len() != 0 || stderr.String() != vector.ExpectError+"\n" {
				t.Fatalf("stdout = %q, stderr = %q", stdout.String(), stderr.String())
			}
		})
	}
}

func TestDecodeDoesNotOverwriteKeyFile(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "key.bin")
	key := fixedVectorKey(t)
	if err := os.WriteFile(keyPath, key, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{
		"decode",
		"-in", filepath.Join("..", "spec", "vectors", "expected", "encrypted-one-byte.ubc"),
		"-key-file", keyPath,
		"-out", keyPath,
	}, &stdout, &stderr); code != 2 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	got, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, key) {
		t.Fatal("decode modified the key file")
	}
}

func TestDecodeLateFailurePreservesExistingFileOutput(t *testing.T) {
	directory := t.TempDir()
	output := filepath.Join(directory, "output.bin")
	original := []byte("preserve this output")
	if err := os.WriteFile(output, original, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{
		"decode",
		"-in", filepath.Join("..", "spec", "vectors", "expected", "negative-root-mismatch.ubc"),
		"-out", output,
	}, &stdout, &stderr); code != 1 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	got, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) || stdout.Len() != 0 || stderr.String() != "ERR_ROOT_MISMATCH\n" {
		t.Fatalf("output = %q, stdout = %q, stderr = %q", got, stdout.String(), stderr.String())
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "output.bin" {
		t.Fatalf("staged output was not cleaned up: %#v", entries)
	}
}

func TestVerifySharedVectors(t *testing.T) {
	for _, vector := range loadCLIVectors(t) {
		t.Run(vector.ID, func(t *testing.T) {
			t.Setenv("UBC_KEY", "")
			directory := t.TempDir()
			container := filepath.Join("..", "spec", "vectors", vector.Expected)
			args := []string{"verify", "-in", container}
			if vector.ExpectError != "ERR_MISSING_KEY" && vectorIsEncrypted(t, container) {
				keyPath := filepath.Join(directory, "key.bin")
				if err := os.WriteFile(keyPath, vectorKey(t, vector), 0o600); err != nil {
					t.Fatal(err)
				}
				args = append(args, "-key-file", keyPath)
			}
			var stdout, stderr bytes.Buffer
			code := run(args, &stdout, &stderr)
			if vector.ExpectError == "" {
				if code != 0 || stdout.String() != "ok\n" || stderr.Len() != 0 {
					t.Fatalf("code = %d, stdout = %q, stderr = %q", code, stdout.String(), stderr.String())
				}
				return
			}
			if code != 1 || stdout.String() != "fail\n" || stderr.String() != vector.ExpectError+"\n" {
				t.Fatalf("code = %d, stdout = %q, stderr = %q", code, stdout.String(), stderr.String())
			}
		})
	}
}

func TestVerifyRejectsPlaintextOutputPath(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"verify", "-out", "output.bin"}, &stdout, &stderr); code != 2 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
}

func TestInspectSharedPositiveVectors(t *testing.T) {
	for _, vector := range loadCLIVectors(t) {
		if vector.ExpectError != "" {
			continue
		}
		t.Run(vector.ID, func(t *testing.T) {
			container, err := os.ReadFile(filepath.Join("..", "spec", "vectors", vector.Expected))
			if err != nil {
				t.Fatal(err)
			}
			want, err := ubc.Inspect(bytes.NewReader(container))
			if err != nil {
				t.Fatal(err)
			}

			var stdout, stderr bytes.Buffer
			if code := runWithInput([]string{"inspect", "-json"}, bytes.NewReader(container), &stdout, &stderr); code != 0 {
				t.Fatalf("exit code = %d, stdout = %q, stderr = %q", code, stdout.String(), stderr.String())
			}
			var got inspectOutput
			if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, newInspectOutput(want)) {
				t.Fatalf("JSON output = %#v, want %#v", got, newInspectOutput(want))
			}

			stdout.Reset()
			stderr.Reset()
			if code := runWithInput([]string{"inspect"}, bytes.NewReader(container), &stdout, &stderr); code != 0 {
				t.Fatalf("text exit code = %d, stdout = %q, stderr = %q", code, stdout.String(), stderr.String())
			}
			var wantText strings.Builder
			wantText.WriteString("version: " + strconv.Itoa(int(want.Version)) + "\n")
			wantText.WriteString("encrypted: " + strconv.FormatBool(want.Flags.Encrypted) + "\n")
			wantText.WriteString("has_metadata: " + strconv.FormatBool(want.Flags.HasMetadata) + "\n")
			wantText.WriteString("hash_algo: " + strconv.Itoa(int(want.HashAlgo)) + "\n")
			wantText.WriteString("aead_algo: " + strconv.Itoa(int(want.AEADAlgo)) + "\n")
			wantText.WriteString("chunk_size: " + strconv.FormatUint(uint64(want.ChunkSize), 10) + "\n")
			wantText.WriteString("chunk_count: " + strconv.FormatUint(want.ChunkCount, 10) + "\n")
			wantText.WriteString("total_size: " + strconv.FormatUint(want.TotalSize, 10) + "\n")
			for _, entry := range want.Metadata {
				wantText.WriteString("metadata 0x" + hex.EncodeToString([]byte{byte(entry.Tag >> 8), byte(entry.Tag)}) + ": " + hex.EncodeToString(entry.Value) + "\n")
			}
			if stdout.String() != wantText.String() {
				t.Fatalf("text output = %q, want %q", stdout.String(), wantText.String())
			}
		})
	}
}

func TestInspectRejectsInvalidPrefixes(t *testing.T) {
	invalidPrefixes := map[string]bool{
		"negative-bad-magic":                      true,
		"negative-version-two":                    true,
		"negative-hash-algo":                      true,
		"negative-aead-algo":                      true,
		"negative-reserved-flag":                  true,
		"negative-inconsistent-encryption":        true,
		"negative-meta-out-of-order":              true,
		"negative-meta-duplicate":                 true,
		"negative-meta-overrun":                   true,
		"negative-zero-chunk-size":                true,
		"negative-empty-metadata":                 true,
		"negative-encrypted-zero-chunk-size":      true,
		"negative-encrypted-oversized-chunk-size": true,
		"negative-encrypted-reserved-metadata":    true,
		"negative-reserved-metadata":              true,
	}
	for _, vector := range loadCLIVectors(t) {
		if !invalidPrefixes[vector.ID] {
			continue
		}
		t.Run(vector.ID, func(t *testing.T) {
			container, err := os.ReadFile(filepath.Join("..", "spec", "vectors", vector.Expected))
			if err != nil {
				t.Fatal(err)
			}
			var stdout, stderr bytes.Buffer
			if code := runWithInput([]string{"inspect"}, bytes.NewReader(container), &stdout, &stderr); code != 1 || stdout.Len() != 0 || stderr.String() != vector.ExpectError+"\n" {
				t.Fatalf("code = %d, stdout = %q, stderr = %q", code, stdout.String(), stderr.String())
			}
		})
	}
}

func TestInspectDoesNotReadPayload(t *testing.T) {
	container, err := os.ReadFile(filepath.Join("..", "spec", "vectors", "expected", "encrypted-metadata.ubc"))
	if err != nil {
		t.Fatal(err)
	}
	metadataLength := int(uint32(container[ubc.HeaderSize]) | uint32(container[ubc.HeaderSize+1])<<8 | uint32(container[ubc.HeaderSize+2])<<16 | uint32(container[ubc.HeaderSize+3])<<24)
	reader := &prefixOnlyReader{data: container, limit: ubc.HeaderSize + 4 + metadataLength}
	var stdout, stderr bytes.Buffer
	if code := runWithInput([]string{"inspect", "-json"}, reader, &stdout, &stderr); code != 0 {
		t.Fatalf("exit code = %d, stdout = %q, stderr = %q", code, stdout.String(), stderr.String())
	}
	if reader.read != reader.limit {
		t.Fatalf("read %d bytes, want %d", reader.read, reader.limit)
	}
}

func TestInspectRejectsOutputPath(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"inspect", "-out", "output.txt"}, &stdout, &stderr); code != 2 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
}

type prefixOnlyReader struct {
	data        []byte
	limit, read int
}

func (reader *prefixOnlyReader) Read(buffer []byte) (int, error) {
	if reader.read >= reader.limit {
		return 0, errors.New("inspect attempted to read payload")
	}
	remaining := reader.limit - reader.read
	if len(buffer) > remaining {
		buffer = buffer[:remaining]
	}
	n := copy(buffer, reader.data[reader.read:reader.read+len(buffer)])
	reader.read += n
	return n, nil
}
