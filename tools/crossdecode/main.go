package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	ubc "github.com/ubc/vectors/sdk/go"
)

var sharedCaseIDs = map[string]struct{}{
	"plain-one-byte":              {},
	"plain-chunk-1m-plus-one":     {},
	"plain-metadata":              {},
	"encrypted-one-byte":          {},
	"encrypted-chunk-1m-plus-one": {},
	"encrypted-metadata":          {},
}

type manifest struct {
	Vectors []vector `json:"vectors"`
}

type vector struct {
	ID          string        `json:"id"`
	Input       string        `json:"input"`
	Options     vectorOptions `json:"options"`
	ExpectError *string       `json:"expectError"`
}

type vectorOptions struct {
	ChunkSize uint32           `json:"chunkSize"`
	Key       string           `json:"key"`
	BaseNonce string           `json:"baseNonce"`
	Metadata  []vectorMetadata `json:"metadata"`
}

type vectorMetadata struct {
	Tag      string `json:"tag"`
	ValueHex string `json:"valueHex"`
}

func main() {
	vectorsRoot := flag.String("vectors", "", "path to spec/vectors")
	workDir := flag.String("work", "", "isolated cross-decode work directory")
	casesValue := flag.String("cases", "", "comma-separated approved vector IDs")
	flag.Parse()

	if flag.NArg() != 0 {
		die("unexpected positional arguments")
	}
	if err := run(*vectorsRoot, *workDir, *casesValue); err != nil {
		die("cross-decode: %v", err)
	}
}

func run(vectorsRoot, workDir, casesValue string) error {
	root, err := existingDirectory(vectorsRoot, "vectors")
	if err != nil {
		return err
	}
	work, err := existingDirectory(workDir, "work")
	if err != nil {
		return err
	}
	caseIDs, err := parseCaseIDs(casesValue)
	if err != nil {
		return err
	}
	vectors, err := readManifest(root)
	if err != nil {
		return err
	}

	for _, id := range caseIDs {
		vector, ok := vectors[id]
		if !ok {
			return fmt.Errorf("unknown vector case %q", id)
		}
		if vector.ExpectError != nil {
			return fmt.Errorf("negative vector case %q is not allowed", id)
		}
		if err := crossDecodeCase(root, work, vector); err != nil {
			return fmt.Errorf("%s: %w", id, err)
		}
	}
	return nil
}

func existingDirectory(path, label string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("--%s is required", label)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve %s path: %w", label, err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("stat %s path: %w", label, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%s path is not a directory", label)
	}
	return abs, nil
}

func parseCaseIDs(value string) ([]string, error) {
	if value == "" {
		return nil, fmt.Errorf("--cases is required")
	}
	seen := make(map[string]struct{})
	ids := strings.Split(value, ",")
	for _, id := range ids {
		if !safeID(id) {
			return nil, fmt.Errorf("unsafe case ID %q", id)
		}
		if _, ok := sharedCaseIDs[id]; !ok {
			return nil, fmt.Errorf("case %q is not an approved shared cross-decode case", id)
		}
		if _, ok := seen[id]; ok {
			return nil, fmt.Errorf("duplicate case ID %q", id)
		}
		seen[id] = struct{}{}
	}
	return ids, nil
}

func safeID(id string) bool {
	if id == "" {
		return false
	}
	for index, character := range id {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || (character == '-' && index > 0 && index < len(id)-1) {
			continue
		}
		return false
	}
	return true
}

func readManifest(root string) (map[string]vector, error) {
	manifestPath, err := safeChild(root, "vectors.json")
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	var decoded manifest
	if err := json.Unmarshal(data, &decoded); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	vectors := make(map[string]vector, len(decoded.Vectors))
	for _, vector := range decoded.Vectors {
		if !safeID(vector.ID) {
			return nil, fmt.Errorf("manifest contains unsafe vector ID %q", vector.ID)
		}
		if _, exists := vectors[vector.ID]; exists {
			return nil, fmt.Errorf("manifest contains duplicate vector ID %q", vector.ID)
		}
		vectors[vector.ID] = vector
	}
	return vectors, nil
}

func crossDecodeCase(vectorsRoot, workDir string, vector vector) error {
	if vector.Input == "" {
		return fmt.Errorf("positive vector has no input")
	}
	inputPath, err := safeChild(vectorsRoot, vector.Input)
	if err != nil {
		return fmt.Errorf("unsafe input path: %w", err)
	}
	input, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("read input: %w", err)
	}
	entries, err := parseMetadata(vector.Options.Metadata)
	if err != nil {
		return err
	}
	key, nonce, encrypted, err := parseEncryption(vector.Options)
	if err != nil {
		return err
	}
	goFresh, err := encodeFresh(input, entries, vector.Options.ChunkSize, key, nonce, encrypted)
	if err != nil {
		return fmt.Errorf("fresh Go encode: %w", err)
	}
	goPath, err := safeChild(workDir, vector.ID+".go.ubc")
	if err != nil {
		return err
	}
	if err := os.WriteFile(goPath, goFresh, 0o600); err != nil {
		return fmt.Errorf("write Go container: %w", err)
	}

	nodePath, err := safeChild(workDir, vector.ID+".node.ubc")
	if err != nil {
		return err
	}
	nodeFresh, err := os.ReadFile(nodePath)
	if err != nil {
		return fmt.Errorf("read Node container: %w", err)
	}
	decoder, err := ubc.NewDecoder(bytes.NewReader(nodeFresh), ubc.DecodeOptions{Key: key})
	if err != nil {
		return fmt.Errorf("decode Node container: %w", err)
	}
	decoded, err := io.ReadAll(decoder)
	if err != nil {
		return fmt.Errorf("read Node container: %w", err)
	}
	if !bytes.Equal(decoded, input) {
		return fmt.Errorf("Node-decoded plaintext differs from manifest input")
	}
	if !equalMetadata(decoder.Metadata(), entries) {
		return fmt.Errorf("Node-decoded metadata differs from manifest metadata")
	}
	goReencoded, err := encodeFresh(decoded, decoder.Metadata(), vector.Options.ChunkSize, key, nonce, encrypted)
	if err != nil {
		return fmt.Errorf("Go re-encode: %w", err)
	}
	if !bytes.Equal(goReencoded, goFresh) {
		return fmt.Errorf("Go re-encode is not byte-identical")
	}
	if !bytes.Equal(goFresh, nodeFresh) {
		return fmt.Errorf("fresh Go and Node containers differ")
	}
	return nil
}

func safeChild(root, child string) (string, error) {
	if child == "" || filepath.IsAbs(child) {
		return "", fmt.Errorf("path must be a non-empty relative path")
	}
	joined := filepath.Join(root, child)
	relative, err := filepath.Rel(root, joined)
	if err != nil {
		return "", fmt.Errorf("validate path: %w", err)
	}
	if relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return "", fmt.Errorf("path escapes its root")
	}
	return joined, nil
}

func parseMetadata(values []vectorMetadata) ([]ubc.MetadataEntry, error) {
	entries := make([]ubc.MetadataEntry, len(values))
	for index, value := range values {
		tag, err := parseTag(value.Tag)
		if err != nil {
			return nil, fmt.Errorf("metadata entry %d: %w", index, err)
		}
		body, err := parseHex(value.ValueHex, "metadata value")
		if err != nil {
			return nil, fmt.Errorf("metadata entry %d: %w", index, err)
		}
		entries[index] = ubc.MetadataEntry{Tag: tag, Value: body}
	}
	return entries, nil
}

func parseTag(value string) (uint16, error) {
	if len(value) != 6 || !strings.HasPrefix(value, "0x") {
		return 0, fmt.Errorf("metadata tag must be a four-digit 0x hexadecimal value")
	}
	parsed, err := strconv.ParseUint(value[2:], 16, 16)
	if err != nil {
		return 0, fmt.Errorf("invalid metadata tag")
	}
	return uint16(parsed), nil
}

func parseEncryption(options vectorOptions) ([]byte, [12]byte, bool, error) {
	var nonce [12]byte
	if options.Key == "" && options.BaseNonce == "" {
		return nil, nonce, false, nil
	}
	if options.Key == "" || options.BaseNonce == "" {
		return nil, nonce, false, fmt.Errorf("encrypted vector must supply both key and baseNonce")
	}
	key, err := parseHex(options.Key, "key")
	if err != nil {
		return nil, nonce, false, err
	}
	if len(key) != 32 {
		return nil, nonce, false, fmt.Errorf("key must be 32 bytes")
	}
	nonceBytes, err := parseHex(options.BaseNonce, "baseNonce")
	if err != nil {
		return nil, nonce, false, err
	}
	if len(nonceBytes) != len(nonce) {
		return nil, nonce, false, fmt.Errorf("baseNonce must be 12 bytes")
	}
	copy(nonce[:], nonceBytes)
	return key, nonce, true, nil
}

func parseHex(value, label string) ([]byte, error) {
	if len(value)%2 != 0 {
		return nil, fmt.Errorf("%s must contain an even number of hexadecimal characters", label)
	}
	for _, character := range value {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f') || (character >= 'A' && character <= 'F')) {
			return nil, fmt.Errorf("%s is not valid hexadecimal", label)
		}
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("decode %s: %w", label, err)
	}
	return decoded, nil
}

func encodeFresh(data []byte, entries []ubc.MetadataEntry, chunkSize uint32, key []byte, nonce [12]byte, encrypted bool) ([]byte, error) {
	if chunkSize == 0 {
		return nil, fmt.Errorf("chunkSize must be greater than zero")
	}
	if encrypted {
		return ubc.EncodeEncryptedWithFixedNonce(data, key, nonce, entries, chunkSize)
	}
	return ubc.EncodePlain(data, entries, chunkSize)
}

func equalMetadata(actual, expected []ubc.MetadataEntry) bool {
	if len(actual) != len(expected) {
		return false
	}
	for index := range actual {
		if actual[index].Tag != expected[index].Tag || !bytes.Equal(actual[index].Value, expected[index].Value) {
			return false
		}
	}
	return true
}

func die(format string, values ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", values...)
	os.Exit(1)
}
