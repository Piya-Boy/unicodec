package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ubc "github.com/ubc/vectors/sdk/go"
)

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
	var stdout, stderr bytes.Buffer
	if code := run([]string{"encode", "--help"}, &stdout, &stderr); code != 0 {
		t.Fatalf("encode help exit code = %d", code)
	}
	for _, flag := range []string{"-name <filename>", "-mime <type>", "-base-nonce <hex>", "-unsafe-deterministic"} {
		if !strings.Contains(stdout.String(), flag) {
			t.Fatalf("encode help missing %q", flag)
		}
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
	if code := run([]string{"decode", "-in", "input"}, &stdout, &stderr); code != 2 {
		t.Fatalf("decode exit code = %d", code)
	}
	if stdout.Len() != 0 || stderr.String() != "ubc decode: not implemented\n" {
		t.Fatalf("stdout = %q, stderr = %q", stdout.String(), stderr.String())
	}
}

func TestEncodeMatchesPlainVectorFromStandardInput(t *testing.T) {
	input := readVector(t, "inputs/one-byte.bin")
	want := readVector(t, "expected/plain-one-byte.ubc")
	var stdout, stderr bytes.Buffer
	if code := runWithIO([]string{"encode"}, bytes.NewReader(input), &stdout, &stderr); code != 0 {
		t.Fatalf("encode exit code = %d, stderr = %q", code, stderr.String())
	}
	if !bytes.Equal(stdout.Bytes(), want) {
		t.Fatal("plain output differs from vector")
	}
}

func TestEncodeMatchesEncryptedVectorWithKeyFileAndFixedNonce(t *testing.T) {
	input := readVector(t, "inputs/one-byte.bin")
	want := readVector(t, "expected/encrypted-one-byte.ubc")
	keyFile := filepath.Join(t.TempDir(), "key.bin")
	key := bytes.Repeat([]byte{0}, 32)
	for i := range key {
		key[i] = byte(i)
	}
	if err := os.WriteFile(keyFile, key, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	args := []string{"encode", "-key-file", keyFile, "-base-nonce", "f0e0d0c0b0a0908070605040", "-unsafe-deterministic"}
	if code := runWithIO(args, bytes.NewReader(input), &stdout, &stderr); code != 0 {
		t.Fatalf("encode exit code = %d, stderr = %q", code, stderr.String())
	}
	if !bytes.Equal(stdout.Bytes(), want) {
		t.Fatal("encrypted output differs from vector")
	}
}

func TestEncodeUsesKeyFromEnvironment(t *testing.T) {
	input := readVector(t, "inputs/one-byte.bin")
	want := readVector(t, "expected/encrypted-one-byte.ubc")
	t.Setenv("UBC_KEY", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	var stdout, stderr bytes.Buffer
	args := []string{"encode", "-base-nonce", "f0e0d0c0b0a0908070605040", "-unsafe-deterministic"}
	if code := runWithIO(args, bytes.NewReader(input), &stdout, &stderr); code != 0 {
		t.Fatalf("encode exit code = %d, stderr = %q", code, stderr.String())
	}
	if !bytes.Equal(stdout.Bytes(), want) {
		t.Fatal("environment-key output differs from vector")
	}
}

func TestEncodeRejectsFixedNonceWithoutUnsafeOptIn(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), "key.bin")
	if err := os.WriteFile(keyFile, bytes.Repeat([]byte{1}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	args := []string{"encode", "-key-file", keyFile, "-base-nonce", "f0e0d0c0b0a0908070605040"}
	if code := runWithIO(args, bytes.NewReader([]byte("data")), &stdout, &stderr); code != 2 {
		t.Fatalf("encode exit code = %d", code)
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "-unsafe-deterministic") {
		t.Fatalf("stdout = %q, stderr = %q", stdout.String(), stderr.String())
	}
}

func TestEncodeMetadataMatchesGoSDK(t *testing.T) {
	input := []byte("metadata payload")
	var stdout, stderr, want bytes.Buffer
	if code := runWithIO([]string{"encode", "-name", "report.txt", "-mime", "text/plain", "-chunk-size", "4"}, bytes.NewReader(input), &stdout, &stderr); code != 0 {
		t.Fatalf("encode exit code = %d, stderr = %q", code, stderr.String())
	}
	encoder, err := ubc.NewEncoder(&want, []ubc.MetadataEntry{{Tag: 1, Value: []byte("report.txt")}, {Tag: 2, Value: []byte("text/plain")}}, ubc.EncodeOptions{ChunkSize: 4})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := encoder.Write(input); err != nil {
		t.Fatal(err)
	}
	if err := encoder.Close(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stdout.Bytes(), want.Bytes()) {
		t.Fatal("metadata output differs from Go SDK")
	}
}

func TestEncodeRejectsSourceFailureWithoutWritingContainer(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := runWithIO([]string{"encode"}, failingReader{}, &stdout, &stderr); code != 1 {
		t.Fatalf("encode exit code = %d", code)
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "source failed") {
		t.Fatalf("stdout = %q, stderr = %q", stdout.String(), stderr.String())
	}
}

func TestEncodeOnlyPublishesFileAfterSuccess(t *testing.T) {
	directory := t.TempDir()
	outputPath := filepath.Join(directory, "output.ubc")
	if err := os.WriteFile(outputPath, []byte("previous output"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := runWithIO([]string{"encode", "-out", outputPath}, failingReader{}, &stdout, &stderr); code != 1 {
		t.Fatalf("failed encode exit code = %d", code)
	}
	got, err := os.ReadFile(outputPath)
	if err != nil || string(got) != "previous output" {
		t.Fatalf("failed encode changed output: %q, %v", got, err)
	}

	input := readVector(t, "inputs/one-byte.bin")
	want := readVector(t, "expected/plain-one-byte.ubc")
	stdout.Reset()
	stderr.Reset()
	if code := runWithIO([]string{"encode", "-out", outputPath}, bytes.NewReader(input), &stdout, &stderr); code != 0 {
		t.Fatalf("successful encode exit code = %d, stderr = %q", code, stderr.String())
	}
	got, err = os.ReadFile(outputPath)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("output = %x, err = %v", got, err)
	}
}

func TestEncodeValidatesMetadataBeforeReplacingOutput(t *testing.T) {
	outputPath := filepath.Join(t.TempDir(), "output.ubc")
	if err := os.WriteFile(outputPath, []byte("previous output"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := runWithIO([]string{"encode", "-mime", "text/plain\x00", "-out", outputPath}, bytes.NewReader([]byte("data")), &stdout, &stderr); code != 2 {
		t.Fatalf("encode exit code = %d", code)
	}
	got, err := os.ReadFile(outputPath)
	if err != nil || string(got) != "previous output" {
		t.Fatalf("invalid metadata changed output: %q, %v", got, err)
	}
}

func TestEncodeRefusesToOverwriteInput(t *testing.T) {
	inputPath := filepath.Join(t.TempDir(), "input.bin")
	input := []byte("keep me")
	if err := os.WriteFile(inputPath, input, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := runWithIO([]string{"encode", "-in", inputPath, "-out", inputPath}, bytes.NewReader(nil), &stdout, &stderr); code != 2 {
		t.Fatalf("encode exit code = %d", code)
	}
	got, err := os.ReadFile(inputPath)
	if err != nil || !bytes.Equal(got, input) {
		t.Fatalf("input was changed: %q, %v", got, err)
	}
}

func readVector(t *testing.T, relativePath string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "spec", "vectors", relativePath))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("source failed") }
