package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

const (
	headerSize = 40
	footerSize = 36
)

type metadataEntry struct {
	Tag   uint16
	Value []byte
}

type options struct {
	ChunkSize uint32          `json:"chunkSize"`
	Key       string          `json:"key,omitempty"`
	BaseNonce string          `json:"baseNonce,omitempty"`
	Metadata  []metadataValue `json:"metadata,omitempty"`
}

type metadataValue struct {
	Tag   string `json:"tag"`
	Value string `json:"valueHex"`
}

type vector struct {
	ID             string   `json:"id"`
	Description    string   `json:"description"`
	Input          string   `json:"input,omitempty"`
	Options        *options `json:"options,omitempty"`
	Expected       string   `json:"expected"`
	ExpectedSHA256 string   `json:"expectedSha256"`
	ExpectError    *string  `json:"expectError"`
}

type manifest struct {
	Version            int                 `json:"version"`
	CryptoKnownAnswers []cryptoKnownAnswer `json:"cryptoKnownAnswers"`
	Vectors            []vector            `json:"vectors"`
}

type cryptoKnownAnswer struct {
	ID        string `json:"id"`
	Key       string `json:"key"`
	BaseNonce string `json:"baseNonce"`
	RootKey   string `json:"rootKey"`
}

type artifact struct {
	Path string
	Data []byte
}

func main() {
	check := flag.Bool("check", false, "verify generated vectors match files on disk")
	root := flag.String("root", "spec/vectors", "vector directory")
	flag.Parse()

	artifacts, err := buildArtifacts(*root)
	if err != nil {
		fatal(err)
	}
	if *check {
		for _, artifact := range artifacts {
			onDisk, err := os.ReadFile(artifact.Path)
			if err != nil {
				fatal(fmt.Errorf("read %s: %w", artifact.Path, err))
			}
			if !bytes.Equal(onDisk, artifact.Data) {
				fatal(fmt.Errorf("generated artifact differs: %s", artifact.Path))
			}
		}
		return
	}
	for _, artifact := range artifacts {
		if err := os.MkdirAll(filepath.Dir(artifact.Path), 0o755); err != nil {
			fatal(err)
		}
		if err := os.WriteFile(artifact.Path, artifact.Data, 0o644); err != nil {
			fatal(fmt.Errorf("write %s: %w", artifact.Path, err))
		}
	}
}

func buildArtifacts(root string) ([]artifact, error) {
	inputs := []struct {
		name string
		data []byte
	}{
		{"empty.bin", nil},
		{"one-byte.bin", []byte{0xa5}},
		{"chunk-1m.bin", patterned(1 << 20)},
		{"chunk-1m-plus-one.bin", patterned((1 << 20) + 1)},
		{"multi-3m.bin", patterned(3 << 20)},
	}
	artifacts := make([]artifact, 0, len(inputs)+24)
	inputByName := make(map[string][]byte, len(inputs))
	for _, input := range inputs {
		path := filepath.Join(root, "inputs", input.name)
		artifacts = append(artifacts, artifact{path, input.data})
		inputByName[input.name] = input.data
	}

	const keyHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	const nonceHex = "f0e0d0c0b0a0908070605040"
	key := mustDecodeHex(keyHex)
	nonce := mustDecodeHex(nonceHex)
	chunkSize := uint32(1 << 20)
	positive := make([]vector, 0, 12)

	addPositive := func(id, description, inputName string, encrypted bool, metadata []metadataEntry) error {
		container, err := encode(inputByName[inputName], chunkSize, key, nonce, encrypted, metadata)
		if err != nil {
			return err
		}
		expected := filepath.ToSlash(filepath.Join("expected", id+".ubc"))
		artifacts = append(artifacts, artifact{filepath.Join(root, expected), container})
		opts := &options{ChunkSize: chunkSize}
		if encrypted {
			opts.Key, opts.BaseNonce = keyHex, nonceHex
		}
		if len(metadata) > 0 {
			opts.Metadata = jsonMetadata(metadata)
		}
		positive = append(positive, vector{
			ID: id, Description: description, Input: filepath.ToSlash(filepath.Join("inputs", inputName)), Options: opts,
			Expected: expected, ExpectedSHA256: sha256Hex(container), ExpectError: nil,
		})
		return nil
	}
	for _, input := range inputs {
		id := "plain-" + input.name[:len(input.name)-4]
		if err := addPositive(id, "Plain input: "+input.name, input.name, false, nil); err != nil {
			return nil, err
		}
	}
	metadata := []metadataEntry{
		{Tag: 0x0001, Value: []byte("รายงาน-2026.txt")},
		{Tag: 0x0002, Value: []byte("text/plain")},
		{Tag: 0x0003, Value: int64LE(1767225600000)},
		{Tag: 0x1000, Value: []byte{0x00, 0xff, 0x7f}},
	}
	if err := addPositive("plain-metadata", "Plain input with UTF-8 reserved and user metadata tags", "one-byte.bin", false, metadata); err != nil {
		return nil, err
	}
	for _, input := range inputs {
		id := "encrypted-" + input.name[:len(input.name)-4]
		if err := addPositive(id, "AES-256-GCM fixed-nonce input: "+input.name, input.name, true, nil); err != nil {
			return nil, err
		}
	}
	if err := addPositive("encrypted-metadata", "AES-256-GCM fixed-nonce input with authenticated metadata", "one-byte.bin", true, metadata); err != nil {
		return nil, err
	}

	negatives, err := buildNegatives(root, positive, artifacts)
	if err != nil {
		return nil, err
	}
	artifacts = append(artifacts, negatives.artifacts...)
	vectors := append(positive, negatives.vectors...)
	manifestBytes, err := json.MarshalIndent(manifest{Version: 1, CryptoKnownAnswers: []cryptoKnownAnswer{{ID: "encrypted-root-key-fixed", Key: keyHex, BaseNonce: nonceHex, RootKey: hex.EncodeToString(rootKey(key, nonce))}}, Vectors: vectors}, "", "  ")
	if err != nil {
		return nil, err
	}
	manifestBytes = append(manifestBytes, '\n')
	artifacts = append(artifacts, artifact{filepath.Join(root, "vectors.json"), manifestBytes})
	return artifacts, nil
}

type negativeResult struct {
	artifacts []artifact
	vectors   []vector
}

func buildNegatives(root string, positives []vector, artifacts []artifact) (negativeResult, error) {
	byExpected := make(map[string][]byte)
	for _, artifact := range artifacts {
		byExpected[filepath.ToSlash(filepath.Join("expected", filepath.Base(artifact.Path)))] = artifact.Data
	}
	plain := append([]byte(nil), byExpected["expected/plain-one-byte.ubc"]...)
	encrypted := append([]byte(nil), byExpected["expected/encrypted-one-byte.ubc"]...)
	encryptedEmpty := append([]byte(nil), byExpected["expected/encrypted-empty.ubc"]...)
	encryptedMetadata := append([]byte(nil), byExpected["expected/encrypted-metadata.ubc"]...)
	metadata := append([]byte(nil), byExpected["expected/plain-metadata.ubc"]...)
	if len(plain) < headerSize+4+1+footerSize || len(encrypted) < headerSize+4+17+footerSize {
		return negativeResult{}, errors.New("positive vector unexpectedly short")
	}

	items := []struct {
		id, description, code string
		data                  []byte
	}{
		{"negative-bad-magic", "Header magic is invalid", "ERR_BAD_MAGIC", replace(plain, 0, 0x00)},
		{"negative-version-two", "Header version is unsupported", "ERR_UNSUPPORTED_VER", replace(plain, 4, 0x02)},
		{"negative-hash-algo", "Header hash algorithm is unsupported", "ERR_UNSUPPORTED_ALGO", replace(plain, 6, 0x02)},
		{"negative-aead-algo", "Header AEAD algorithm is unsupported", "ERR_UNSUPPORTED_ALGO", replace(plain, 7, 0x02)},
		{"negative-reserved-flag", "Reserved header flag bit is set", "ERR_RESERVED_BITS", replace(plain, 5, 0x80)},
		{"negative-inconsistent-encryption", "Encrypted flag conflicts with no AEAD", "ERR_RESERVED_BITS", replace(plain, 5, 0x01)},
		{"negative-truncated", "Footer magic is missing", "ERR_TRUNCATED", plain[:len(plain)-1]},
		{"negative-root-mismatch", "Plain payload byte is flipped", "ERR_ROOT_MISMATCH", flip(plain, headerSize+4)},
		{"negative-chunk-auth", "Encrypted ciphertext byte is flipped", "ERR_CHUNK_AUTH", flip(encrypted, headerSize+4)},
		{"negative-missing-key", "Encrypted container decoded without a key", "ERR_MISSING_KEY", encrypted},
		{"negative-meta-out-of-order", "Metadata tags are out of ascending order", "ERR_META_MALFORMED", swapMetadataTags(metadata)},
		{"negative-meta-duplicate", "Metadata has a duplicate tag", "ERR_META_MALFORMED", duplicateMetadataTag(metadata)},
		{"negative-meta-overrun", "Metadata TLV length overruns metadata region", "ERR_META_MALFORMED", metadataLengthOverrun(metadata)},
		{"negative-oversized-clen", "Chunk length exceeds bytes remaining", "ERR_TRUNCATED", oversizedChunkLength(plain)},
		{"negative-zero-chunk-size", "Header chunk size is zero", "ERR_RESERVED_BITS", zeroChunkSize(plain)},
		{"negative-empty-metadata", "Metadata flag carries an empty metadata block", "ERR_META_MALFORMED", emptyMetadataBlock(plain)},
		{"negative-trailing-data", "Container has bytes after its footer", "ERR_TRAILING_DATA", append(append([]byte(nil), plain...), 0x00)},
		{"negative-encrypted-zero-chunk-size", "Encrypted header chunk size is zero", "ERR_RESERVED_BITS", zeroChunkSize(encrypted)},
		{"negative-encrypted-oversized-chunk-size", "Encrypted header chunk size cannot fit its tag", "ERR_RESERVED_BITS", oversizedEncryptedChunkSize(encrypted)},
		{"negative-encrypted-short-clen", "Encrypted chunk body is shorter than its GCM tag", "ERR_CHUNK_AUTH", encryptedShortChunk(encrypted)},
		{"negative-encrypted-metadata-tamper", "Valid encrypted metadata change invalidates chunk AAD", "ERR_CHUNK_AUTH", tamperMetadata(encryptedMetadata)},
		{"negative-encrypted-reserved-metadata", "Malformed encrypted metadata precedes missing-key failure", "ERR_META_MALFORMED", malformedReservedMetadata(encryptedMetadata)},
		{"negative-encrypted-cap-missing-key", "Missing key precedes encrypted payload caps", "ERR_MISSING_KEY", oversizedChunkCount(encrypted)},
		{"negative-reserved-metadata", "Reserved metadata value is invalid UTF-8", "ERR_META_MALFORMED", malformedReservedMetadata(metadata)},
		{"negative-encrypted-empty-wrong-key", "Encrypted empty container rejects a wrong key", "ERR_ROOT_MISMATCH", encryptedEmpty},
	}
	result := negativeResult{}
	for _, item := range items {
		expected := filepath.ToSlash(filepath.Join("expected", item.id+".ubc"))
		result.artifacts = append(result.artifacts, artifact{filepath.Join(root, expected), item.data})
		code := item.code
		var vectorOptions *options
		if item.id == "negative-encrypted-empty-wrong-key" {
			vectorOptions = &options{Key: "ff0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"}
		}
		result.vectors = append(result.vectors, vector{ID: item.id, Description: item.description, Options: vectorOptions, Expected: expected, ExpectedSHA256: sha256Hex(item.data), ExpectError: &code})
	}
	return result, nil
}

func encode(input []byte, chunkSize uint32, key, baseNonce []byte, encrypted bool, entries []metadataEntry) ([]byte, error) {
	if chunkSize == 0 {
		return nil, errors.New("chunk size must be positive")
	}
	meta, err := encodeMetadata(entries)
	if err != nil {
		return nil, err
	}
	chunkCount := uint64((len(input) + int(chunkSize) - 1) / int(chunkSize))
	header := make([]byte, headerSize)
	copy(header[:4], "UBC1")
	header[4] = 1
	if encrypted {
		header[5], header[6], header[7] = 1, 1, 1
		copy(header[28:], baseNonce)
	}
	if len(meta) > 0 {
		header[5] |= 0x02
	}
	binary.LittleEndian.PutUint32(header[8:12], chunkSize)
	binary.LittleEndian.PutUint64(header[12:20], chunkCount)
	binary.LittleEndian.PutUint64(header[20:28], uint64(len(input)))
	var aead cipher.AEAD
	if encrypted {
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		aead, err = cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
	}
	output := append([]byte(nil), header...)
	output = append(output, meta...)
	metadataDigest := sha256.Sum256(meta)
	leaves := make([]byte, 0, chunkCount*sha256.Size)
	for index, offset := uint64(0), 0; offset < len(input); index, offset = index+1, offset+int(chunkSize) {
		end := min(offset+int(chunkSize), len(input))
		data := input[offset:end]
		if encrypted {
			data = aead.Seal(nil, chunkNonce(baseNonce, index), data, appendIndex(header, metadataDigest[:], index))
		}
		length := make([]byte, 4)
		binary.LittleEndian.PutUint32(length, uint32(len(data)))
		output = append(output, length...)
		output = append(output, data...)
		hash := sha256.Sum256(data)
		leaves = append(leaves, hash[:]...)
	}
	if encrypted {
		root := hmac.New(sha256.New, rootKey(key, baseNonce))
		_, _ = root.Write(header)
		_, _ = root.Write(meta)
		_, _ = root.Write(leaves)
		output = append(output, root.Sum(nil)...)
	} else {
		rootInput := append(append(append([]byte(nil), header...), meta...), leaves...)
		root := sha256.Sum256(rootInput)
		output = append(output, root[:]...)
	}
	output = append(output, "UBCE"...)
	return output, nil
}

func encodeMetadata(entries []metadataEntry) ([]byte, error) {
	if len(entries) == 0 {
		return nil, nil
	}
	sorted := append([]metadataEntry(nil), entries...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Tag < sorted[j].Tag })
	for i := 1; i < len(sorted); i++ {
		if sorted[i-1].Tag == sorted[i].Tag {
			return nil, errors.New("duplicate metadata tag")
		}
	}
	body := make([]byte, 0)
	for _, entry := range sorted {
		tag, length := make([]byte, 2), make([]byte, 4)
		binary.LittleEndian.PutUint16(tag, entry.Tag)
		binary.LittleEndian.PutUint32(length, uint32(len(entry.Value)))
		body = append(body, tag...)
		body = append(body, length...)
		body = append(body, entry.Value...)
	}
	prefix := make([]byte, 4)
	binary.LittleEndian.PutUint32(prefix, uint32(len(body)))
	return append(prefix, body...), nil
}

var rootInfo = []byte("UBC1 root authentication")

func rootKey(key, baseNonce []byte) []byte {
	prk := hmac.New(sha256.New, baseNonce)
	_, _ = prk.Write(key)
	expand := hmac.New(sha256.New, prk.Sum(nil))
	_, _ = expand.Write(rootInfo)
	_, _ = expand.Write([]byte{1})
	return expand.Sum(nil)
}

func appendIndex(header, metadataDigest []byte, index uint64) []byte {
	aad := append([]byte(nil), header...)
	aad = append(aad, metadataDigest...)
	suffix := make([]byte, 8)
	binary.LittleEndian.PutUint64(suffix, index)
	return append(aad, suffix...)
}
func chunkNonce(base []byte, index uint64) []byte {
	nonce := append([]byte(nil), base...)
	for i := 0; i < 8; i++ {
		nonce[i] ^= byte(index >> (8 * i))
	}
	return nonce
}
func patterned(size int) []byte {
	data := make([]byte, size)
	for i := range data {
		data[i] = byte((i*31 + i/251 + 17) % 256)
	}
	return data
}
func int64LE(value int64) []byte {
	data := make([]byte, 8)
	binary.LittleEndian.PutUint64(data, uint64(value))
	return data
}
func jsonMetadata(entries []metadataEntry) []metadataValue {
	values := make([]metadataValue, len(entries))
	for i, entry := range entries {
		values[i] = metadataValue{fmt.Sprintf("0x%04x", entry.Tag), hex.EncodeToString(entry.Value)}
	}
	return values
}
func sha256Hex(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func mustDecodeHex(value string) []byte {
	data, err := hex.DecodeString(value)
	if err != nil {
		panic(err)
	}
	return data
}
func min(left, right int) int {
	if left < right {
		return left
	}
	return right
}
func replace(data []byte, offset int, value byte) []byte {
	result := append([]byte(nil), data...)
	result[offset] = value
	return result
}
func flip(data []byte, offset int) []byte { return replace(data, offset, data[offset]^0x01) }
func swapMetadataTags(data []byte) []byte {
	result := append([]byte(nil), data...)
	first := headerSize + 4
	second := first + 6 + len([]byte("รายงาน-2026.txt"))
	result[first], result[second] = result[second], result[first]
	result[first+1], result[second+1] = result[second+1], result[first+1]
	return result
}
func duplicateMetadataTag(data []byte) []byte {
	result := append([]byte(nil), data...)
	first := headerSize + 4
	second := first + 6 + len([]byte("รายงาน-2026.txt"))
	copy(result[second:second+2], result[first:first+2])
	return result
}
func metadataLengthOverrun(data []byte) []byte {
	result := append([]byte(nil), data...)
	binary.LittleEndian.PutUint32(result[headerSize+4+2:headerSize+4+6], 0xffffffff)
	return result
}
func oversizedChunkLength(data []byte) []byte {
	result := append([]byte(nil), data...)
	binary.LittleEndian.PutUint32(result[headerSize:headerSize+4], 0xffffffff)
	return result
}
func zeroChunkSize(data []byte) []byte {
	result := append([]byte(nil), data...)
	binary.LittleEndian.PutUint32(result[8:12], 0)
	return result
}
func emptyMetadataBlock(data []byte) []byte {
	result := append([]byte(nil), data...)
	result[5] |= 0x02
	return append(result[:headerSize], append([]byte{0, 0, 0, 0}, result[headerSize:]...)...)
}
func oversizedEncryptedChunkSize(data []byte) []byte {
	result := append([]byte(nil), data...)
	binary.LittleEndian.PutUint32(result[8:12], ^uint32(0))
	return result
}
func encryptedShortChunk(data []byte) []byte {
	result := append([]byte(nil), data[:headerSize]...)
	length := make([]byte, 4)
	binary.LittleEndian.PutUint32(length, 15)
	result = append(result, length...)
	result = append(result, data[headerSize+4:headerSize+4+15]...)
	return append(result, data[headerSize+4+17:]...)
}
func tamperMetadata(data []byte) []byte {
	result := append([]byte(nil), data...)
	position := bytes.Index(result, []byte("รายงาน-2026.txt"))
	if position < 0 {
		panic("filename missing")
	}
	filenameOffset := bytes.Index(result[position:], []byte("-"))
	if filenameOffset < 0 {
		panic("filename separator missing")
	}
	result[position+filenameOffset] = '_'
	recomputeLegacyRoot(result)
	return result
}
func malformedReservedMetadata(data []byte) []byte {
	result := append([]byte(nil), data...)
	position := bytes.Index(result, []byte("รายงาน-2026.txt"))
	if position < 0 {
		panic("filename missing")
	}
	result[position] = 0xff
	return result
}
func oversizedChunkCount(data []byte) []byte {
	result := append([]byte(nil), data...)
	binary.LittleEndian.PutUint64(result[12:20], (1<<20)+1)
	return result
}
func recomputeLegacyRoot(data []byte) {
	footerOffset := len(data) - footerSize
	offset := headerSize
	if data[5]&0x02 != 0 {
		metaLength := int(binary.LittleEndian.Uint32(data[offset : offset+4]))
		offset += 4 + metaLength
	}
	root := sha256.New()
	_, _ = root.Write(data[:offset])
	for index := uint64(0); index < binary.LittleEndian.Uint64(data[12:20]); index++ {
		length := int(binary.LittleEndian.Uint32(data[offset : offset+4]))
		offset += 4
		leaf := sha256.Sum256(data[offset : offset+length])
		_, _ = root.Write(leaf[:])
		offset += length
	}
	if offset != footerOffset {
		panic("invalid container framing")
	}
	copy(data[footerOffset:footerOffset+sha256.Size], root.Sum(nil))
}
func fatal(err error) { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
