package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	ubc "github.com/ubc/vectors/sdk/go"
)

func runEncode(options commandOptions, stdin io.Reader, stdout, stderr io.Writer) int {
	key, err := loadEncodeKey(options.keyFile)
	if err != nil {
		return encodeError(stderr, 2, err)
	}
	baseNonce, err := parseBaseNonce(options.baseNonce)
	if err != nil {
		return encodeError(stderr, 2, err)
	}
	if baseNonce != nil && len(key) == 0 {
		return encodeError(stderr, 2, errors.New("-base-nonce requires a key"))
	}
	if baseNonce != nil && !options.unsafeDeterministic {
		return encodeError(stderr, 2, errors.New("-base-nonce requires -unsafe-deterministic"))
	}
	if len(key) != 0 && options.chunkSize > uint64(^uint32(0)-16) {
		return encodeError(stderr, 2, errors.New("-chunk-size is too large for encrypted containers"))
	}

	input, closeInput, err := openInput(options.inputPath, stdin)
	if err != nil {
		return encodeError(stderr, 1, err)
	}
	if closeInput != nil {
		defer func() {
			if closeInput != nil {
				_ = closeInput.Close()
			}
		}()
	}
	if options.inputPath != "-" && options.outputPath != "-" {
		same, err := samePath(options.inputPath, options.outputPath)
		if err != nil {
			return encodeError(stderr, 1, err)
		}
		if same {
			return encodeError(stderr, 2, errors.New("-in and -out must differ"))
		}
	}

	entries := make([]ubc.MetadataEntry, 0, 2)
	if options.name != "" {
		entries = append(entries, ubc.MetadataEntry{Tag: 1, Value: []byte(options.name)})
	}
	if options.mime != "" {
		entries = append(entries, ubc.MetadataEntry{Tag: 2, Value: []byte(options.mime)})
	}
	if _, err := ubc.EncodeMetadata(entries); err != nil {
		return encodeError(stderr, 2, err)
	}
	output := &deferredWriter{}
	encoder, err := ubc.NewEncoder(output, entries, ubc.EncodeOptions{
		Key:       key,
		ChunkSize: uint32(options.chunkSize),
		BaseNonce: baseNonce,
	})
	if err != nil {
		return encodeError(stderr, 2, err)
	}
	if _, err := io.Copy(encoder, input); err != nil {
		return encodeError(stderr, 1, errors.Join(err, closeInputAndClear(&closeInput), encoder.Abort()))
	}
	if err := closeInputAndClear(&closeInput); err != nil {
		return encodeError(stderr, 1, errors.Join(err, encoder.Abort()))
	}
	stagedOutput, err := createStagedOutput(options.outputPath, stdout)
	if err != nil {
		return encodeError(stderr, 1, errors.Join(err, encoder.Abort()))
	}
	output.writer = stagedOutput.writer
	if err := encoder.Close(); err != nil {
		return encodeError(stderr, 1, errors.Join(err, stagedOutput.discard()))
	}
	if err := stagedOutput.commit(); err != nil {
		return encodeError(stderr, 1, errors.Join(err, stagedOutput.discard()))
	}
	return 0
}

func loadEncodeKey(keyFile string) ([]byte, error) {
	keyFromEnv, hasKeyFromEnv := os.LookupEnv("UBC_KEY")
	if keyFile != "" && hasKeyFromEnv {
		return nil, errors.New("use either -key-file or UBC_KEY, not both")
	}
	if keyFile != "" {
		data, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, fmt.Errorf("read key file: %w", err)
		}
		return parseKey(data)
	}
	if hasKeyFromEnv {
		return parseKey([]byte(keyFromEnv))
	}
	return nil, nil
}

func parseKey(data []byte) ([]byte, error) {
	if len(data) == 32 {
		return append([]byte(nil), data...), nil
	}
	encoded := bytes.TrimSpace(data)
	if len(encoded) == 64 {
		key := make([]byte, 32)
		if _, err := hex.Decode(key, encoded); err == nil {
			return key, nil
		}
	}
	return nil, errors.New("key must be 32 raw bytes or 64 hexadecimal characters")
}

func parseBaseNonce(value string) (*[12]byte, error) {
	if value == "" {
		return nil, nil
	}
	if len(value) != 24 {
		return nil, errors.New("-base-nonce must be 24 hexadecimal characters")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != 12 {
		return nil, errors.New("-base-nonce must be 24 hexadecimal characters")
	}
	var nonce [12]byte
	copy(nonce[:], decoded)
	return &nonce, nil
}

func openInput(path string, stdin io.Reader) (io.Reader, io.Closer, error) {
	if path == "-" {
		return stdin, nil, nil
	}
	input, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open input: %w", err)
	}
	return input, input, nil
}

func samePath(inputPath, outputPath string) (bool, error) {
	inputAbs, err := filepath.Abs(inputPath)
	if err != nil {
		return false, err
	}
	outputAbs, err := filepath.Abs(outputPath)
	if err != nil {
		return false, err
	}
	if inputAbs == outputAbs {
		return true, nil
	}
	inputInfo, err := os.Stat(inputPath)
	if err != nil {
		return false, err
	}
	outputInfo, err := os.Stat(outputPath)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return os.SameFile(inputInfo, outputInfo), nil
}

func encodeError(stderr io.Writer, code int, err error) int {
	_, _ = fmt.Fprintf(stderr, "ubc encode: %v\n", err)
	return code
}

func closeInputAndClear(closer *io.Closer) error {
	if *closer == nil {
		return nil
	}
	err := (*closer).Close()
	*closer = nil
	return err
}

type deferredWriter struct {
	writer io.Writer
}

func (w *deferredWriter) Write(data []byte) (int, error) {
	if w.writer == nil {
		return 0, errors.New("output is not ready")
	}
	return w.writer.Write(data)
}

type stagedOutput struct {
	writer   io.Writer
	file     *os.File
	tempPath string
	path     string
}

func createStagedOutput(path string, stdout io.Writer) (*stagedOutput, error) {
	if path == "-" {
		return &stagedOutput{writer: stdout}, nil
	}
	temp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".ubc-*")
	if err != nil {
		return nil, fmt.Errorf("create output: %w", err)
	}
	return &stagedOutput{writer: temp, file: temp, tempPath: temp.Name(), path: path}, nil
}

func (o *stagedOutput) commit() error {
	if o.file == nil {
		return nil
	}
	if err := o.file.Close(); err != nil {
		return err
	}
	o.file = nil
	if err := os.Rename(o.tempPath, o.path); err != nil {
		return err
	}
	o.tempPath = ""
	return nil
}

func (o *stagedOutput) discard() error {
	var err error
	if o.file != nil {
		err = errors.Join(err, o.file.Close())
		o.file = nil
	}
	if o.tempPath != "" {
		err = errors.Join(err, os.Remove(o.tempPath))
		o.tempPath = ""
	}
	return err
}
