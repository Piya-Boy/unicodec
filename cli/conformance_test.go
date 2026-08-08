package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"

	ubc "github.com/ubc/vectors/sdk/go"
)

func TestBinaryConformanceAgainstSharedVectors(t *testing.T) {
	t.Setenv("UBC_KEY", strings.Repeat("00", 32))
	binary := buildCLIBinary(t)
	vectors := loadCLIVectors(t)

	t.Run("encode", func(t *testing.T) {
		for _, vector := range vectors {
			if vector.ExpectError != "" {
				continue
			}
			t.Run(vector.ID, func(t *testing.T) {
				directory := t.TempDir()
				outputPath := filepath.Join(directory, "container.ubc")
				args := []string{
					"encode",
					"-in", filepath.Join("..", "spec", "vectors", vector.Input),
					"-out", outputPath,
					"-chunk-size", strconv.FormatUint(uint64(vector.Options.ChunkSize), 10),
				}
				args = append(args, binaryMetadataArgs(vector)...)
				if vector.Options.Key != "" {
					args = append(args, binaryKeyArgs(t, vector, directory)...)
					args = append(args, "-base-nonce", vector.Options.BaseNonce)
				}
				code, stdout, stderr := runCLIBinary(t, binary, args...)
				if code != 0 || stdout != "" || stderr != "" {
					t.Fatalf("code = %d, stdout = %q, stderr = %q", code, stdout, stderr)
				}
				got, err := os.ReadFile(outputPath)
				if err != nil {
					t.Fatal(err)
				}
				want := readBinaryVectorFile(t, vector.Expected)
				if !bytes.Equal(got, want) {
					t.Fatal("container differs from shared expected vector")
				}
			})
		}
	})

	t.Run("decode", func(t *testing.T) {
		for _, vector := range vectors {
			t.Run(vector.ID, func(t *testing.T) {
				directory := t.TempDir()
				containerPath := filepath.Join("..", "spec", "vectors", vector.Expected)
				outputPath := filepath.Join(directory, "plaintext.bin")
				args := []string{"decode", "-in", containerPath, "-out", outputPath}
				usesKey := binaryVectorEncrypted(t, containerPath) && vector.ExpectError != "ERR_MISSING_KEY"
				if usesKey {
					args = append(args, binaryKeyArgs(t, vector, directory)...)
				}
				code, stdout, stderr := runCLIBinary(t, binary, args...)
				if vector.ExpectError != "" {
					if code != 1 || stdout != "" || stderr != vector.ExpectError+"\n" {
						t.Fatalf("code = %d, stdout = %q, stderr = %q", code, stdout, stderr)
					}
					if _, err := os.Stat(outputPath); !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("failed decode left plaintext output: %v", err)
					}
					assertNoDecodeResidue(t, directory, usesKey)
					return
				}
				if code != 0 || stdout != "" || stderr != "" {
					t.Fatalf("code = %d, stdout = %q, stderr = %q", code, stdout, stderr)
				}
				got, err := os.ReadFile(outputPath)
				if err != nil {
					t.Fatal(err)
				}
				want := readBinaryVectorFile(t, vector.Input)
				if !bytes.Equal(got, want) {
					t.Fatal("plaintext differs from shared input vector")
				}
			})
		}
	})

	t.Run("verify", func(t *testing.T) {
		for _, vector := range vectors {
			t.Run(vector.ID, func(t *testing.T) {
				directory := t.TempDir()
				containerPath := filepath.Join("..", "spec", "vectors", vector.Expected)
				args := []string{"verify", "-in", containerPath}
				if binaryVectorEncrypted(t, containerPath) && vector.ExpectError != "ERR_MISSING_KEY" {
					args = append(args, binaryKeyArgs(t, vector, directory)...)
				}
				code, stdout, stderr := runCLIBinary(t, binary, args...)
				if vector.ExpectError == "" {
					if code != 0 || stdout != "ok\n" || stderr != "" {
						t.Fatalf("code = %d, stdout = %q, stderr = %q", code, stdout, stderr)
					}
					return
				}
				if code != 1 || stdout != "fail\n" || stderr != vector.ExpectError+"\n" {
					t.Fatalf("code = %d, stdout = %q, stderr = %q", code, stdout, stderr)
				}
			})
		}
	})

	t.Run("inspect", func(t *testing.T) {
		for _, vector := range vectors {
			t.Run(vector.ID, func(t *testing.T) {
				container := readBinaryVectorFile(t, vector.Expected)
				want, wantErr := ubc.Inspect(bytes.NewReader(container))
				code, stdout, stderr := runCLIBinary(t, binary, "inspect", "-json", "-in", filepath.Join("..", "spec", "vectors", vector.Expected))
				if wantErr != nil {
					if code != 1 || stdout != "" || stderr != string(ubc.ErrorCodeOf(wantErr))+"\n" {
						t.Fatalf("code = %d, stdout = %q, stderr = %q", code, stdout, stderr)
					}
					return
				}
				if code != 0 || stderr != "" {
					t.Fatalf("code = %d, stdout = %q, stderr = %q", code, stdout, stderr)
				}
				var got inspectOutput
				if err := json.Unmarshal([]byte(stdout), &got); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(got, newInspectOutput(want)) {
					t.Fatalf("JSON output = %#v, want %#v", got, newInspectOutput(want))
				}
			})
		}
	})
}

func buildCLIBinary(t *testing.T) string {
	t.Helper()
	name := "ubc"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	binary := filepath.Join(t.TempDir(), name)
	command := exec.Command("go", "build", "-o", binary, ".")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("build CLI: %v\n%s", err, output)
	}
	return binary
}

func runCLIBinary(t *testing.T, binary string, args ...string) (int, string, string) {
	t.Helper()
	command := exec.Command(binary, args...)
	command.Env = withoutUBCKey(os.Environ())
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	if err == nil {
		return 0, stdout.String(), stderr.String()
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		return exitError.ExitCode(), stdout.String(), stderr.String()
	}
	t.Fatalf("run CLI: %v", err)
	return 0, "", ""
}

func withoutUBCKey(environment []string) []string {
	clean := make([]string, 0, len(environment))
	for _, entry := range environment {
		name, _, found := strings.Cut(entry, "=")
		if found && strings.EqualFold(name, "UBC_KEY") {
			continue
		}
		clean = append(clean, entry)
	}
	return clean
}

func assertNoDecodeResidue(t *testing.T, directory string, usesKey bool) {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if usesKey && entry.Name() == "key.hex" {
			continue
		}
		t.Fatalf("failed decode left unexpected file %q", entry.Name())
	}
}

func binaryKeyArgs(t *testing.T, vector cliVector, directory string) []string {
	t.Helper()
	keyPath := filepath.Join(directory, "key.hex")
	if err := os.WriteFile(keyPath, []byte(hex.EncodeToString(vectorKey(t, vector))+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return []string{"-key-file", keyPath}
}

func binaryMetadataArgs(vector cliVector) []string {
	args := make([]string, 0, len(vector.Options.Metadata)*2)
	for _, entry := range vector.Options.Metadata {
		args = append(args, "-metadata", entry.Tag+":"+entry.ValueHex)
	}
	return args
}

func binaryVectorEncrypted(t *testing.T, containerPath string) bool {
	t.Helper()
	data, err := os.ReadFile(containerPath)
	if err != nil {
		t.Fatal(err)
	}
	return len(data) > 5 && data[5]&1 != 0
}

func readBinaryVectorFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "spec", "vectors", path))
	if err != nil {
		t.Fatal(err)
	}
	return data
}
