package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
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
		Key string `json:"key"`
	} `json:"options"`
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
	options, help, err := parseCommandOptions("encode", []string{"-in", "input", "-out", "output", "-key-file", "key.bin", "-chunk-size", "4096"})
	if err != nil || help {
		t.Fatalf("parseCommandOptions() = %#v, %v, %v", options, help, err)
	}
	if options.inputPath != "input" || options.outputPath != "output" || options.keyFile != "key.bin" || options.chunkSize != 4096 {
		t.Fatalf("options = %#v", options)
	}
}

func TestUnimplementedCommandDoesNotReportSuccess(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"inspect", "-in", "input"}, &stdout, &stderr); code != 2 {
		t.Fatalf("inspect exit code = %d", code)
	}
	if stdout.Len() != 0 || stderr.String() != "ubc inspect: not implemented\n" {
		t.Fatalf("stdout = %q, stderr = %q", stdout.String(), stderr.String())
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
