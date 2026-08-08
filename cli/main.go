package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	ubc "github.com/ubc/vectors/sdk/go"
)

const version = "0.1.0"

const defaultChunkSize = 1 << 20

type commandOptions struct {
	inputPath  string
	outputPath string
	keyFile    string
	chunkSize  uint64
	name       string
	mime       string
	baseNonce  string
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	return runWithInput(args, os.Stdin, stdout, stderr)
}

func runWithInput(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printRootUsage(stderr)
		return 2
	}

	switch args[0] {
	case "-h", "--help":
		if len(args) != 1 {
			printRootUsage(stderr)
			return 2
		}
		printRootUsage(stdout)
		return 0
	case "help":
		if len(args) == 1 {
			printRootUsage(stdout)
			return 0
		}
		if len(args) != 2 {
			printRootUsage(stderr)
			return 2
		}
		switch args[1] {
		case "encode", "decode", "verify", "inspect":
			return runCommand(args[1], []string{"--help"}, stdin, stdout, stderr)
		default:
			_, _ = fmt.Fprintf(stderr, "ubc: unknown command %q\n", args[1])
			printRootUsage(stderr)
			return 2
		}
	case "version", "--version":
		if len(args) != 1 {
			printRootUsage(stderr)
			return 2
		}
		_, _ = fmt.Fprintf(stdout, "ubc %s\n", version)
		return 0
	case "encode", "decode", "verify", "inspect":
		return runCommand(args[0], args[1:], stdin, stdout, stderr)
	default:
		_, _ = fmt.Fprintf(stderr, "ubc: unknown command %q\n", args[0])
		printRootUsage(stderr)
		return 2
	}
}

func runCommand(name string, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	options, showHelp, err := parseCommandOptions(name, args)
	if errors.Is(err, flag.ErrHelp) || showHelp {
		printCommandUsage(stdout, name)
		return 0
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "ubc %s: %v\n", name, err)
		printCommandUsage(stderr, name)
		return 2
	}

	if name != "encode" {
		_, _ = fmt.Fprintf(stderr, "ubc %s: not implemented\n", name)
		return 2
	}
	if err := runEncode(options, stdin, stdout); err != nil {
		_, _ = fmt.Fprintf(stderr, "ubc encode: %v\n", err)
		var usageErr *usageError
		if errors.As(err, &usageErr) {
			return 2
		}
		return 1
	}
	return 0
}

func parseCommandOptions(name string, args []string) (commandOptions, bool, error) {
	var options commandOptions
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&options.inputPath, "in", "-", "input path, or - for stdin")
	flags.StringVar(&options.outputPath, "out", "-", "output path, or - for stdout")
	flags.StringVar(&options.keyFile, "key-file", "", "file containing a 32-byte key")
	flags.Uint64Var(&options.chunkSize, "chunk-size", defaultChunkSize, "plaintext bytes per chunk")
	if name == "encode" {
		flags.StringVar(&options.name, "name", "", "filename metadata")
		flags.StringVar(&options.mime, "mime", "", "MIME type metadata")
		flags.StringVar(&options.baseNonce, "base-nonce", "", "fixed nonce for conformance testing only")
	}
	help := flags.Bool("help", false, "show help")
	flags.BoolVar(help, "h", false, "show help")
	if err := flags.Parse(args); err != nil {
		return commandOptions{}, false, err
	}
	if flags.NArg() != 0 {
		return commandOptions{}, false, fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	if options.chunkSize == 0 || options.chunkSize > uint64(^uint32(0)) {
		return commandOptions{}, false, fmt.Errorf("-chunk-size must be between 1 and %d", ^uint32(0))
	}
	return options, *help, nil
}

type usageError struct{ err error }

func (e *usageError) Error() string { return e.err.Error() }
func (e *usageError) Unwrap() error { return e.err }

func newUsageError(format string, args ...any) error {
	return &usageError{err: fmt.Errorf(format, args...)}
}

func runEncode(options commandOptions, stdin io.Reader, stdout io.Writer) error {
	key, err := loadKey(options.keyFile)
	if err != nil {
		return err
	}
	if len(key) != 0 && options.chunkSize > uint64(math.MaxUint32-16) {
		return newUsageError("-chunk-size must not exceed %d when encrypting", uint32(math.MaxUint32-16))
	}

	entries := make([]ubc.MetadataEntry, 0, 2)
	if options.name != "" {
		entries = append(entries, ubc.MetadataEntry{Tag: 0x0001, Value: []byte(options.name)})
	}
	if options.mime != "" {
		entries = append(entries, ubc.MetadataEntry{Tag: 0x0002, Value: []byte(options.mime)})
	}
	if _, err := ubc.EncodeMetadata(entries); err != nil {
		return &usageError{err: err}
	}

	encoderOptions := ubc.EncodeOptions{Key: key, ChunkSize: uint32(options.chunkSize)}
	if options.baseNonce != "" {
		if len(key) == 0 {
			return newUsageError("-base-nonce requires a key and is for conformance testing only")
		}
		nonce, err := decodeHex("-base-nonce", options.baseNonce, 12)
		if err != nil {
			return err
		}
		var baseNonce [12]byte
		copy(baseNonce[:], nonce)
		encoderOptions.BaseNonce = &baseNonce
	}

	input, closeInput, err := openInput(options.inputPath, stdin)
	if err != nil {
		return err
	}
	defer func() { _ = closeInput() }()

	if err := rejectSameInputOutput(options.inputPath, options.outputPath); err != nil {
		return err
	}
	output, err := newStagedOutput(options.outputPath, stdout)
	if err != nil {
		return err
	}
	defer output.discard()
	encoder, err := ubc.NewEncoder(output.file, entries, encoderOptions)
	if err != nil {
		return err
	}

	if _, err := io.Copy(encoder, input); err != nil {
		_ = encoder.Close()
		return err
	}
	if err := closeStdinBeforeReplace(stdin, options.outputPath); err != nil {
		_ = encoder.Close()
		return err
	}
	if err := encoder.Close(); err != nil {
		return err
	}
	return output.publish()
}

func loadKey(keyFile string) ([]byte, error) {
	if keyFile != "" {
		data, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, err
		}
		return decodeKey("key file", data)
	}
	if value, ok := os.LookupEnv("UBC_KEY"); ok && value != "" {
		return decodeKey("UBC_KEY", []byte(value))
	}
	return nil, nil
}

func decodeKey(name string, value []byte) ([]byte, error) {
	if len(value) == 32 {
		return append([]byte(nil), value...), nil
	}
	return decodeHex(name, string(value), 32)
}

func decodeHex(name, value string, length int) ([]byte, error) {
	decoded, err := hex.DecodeString(strings.TrimSpace(value))
	if err != nil || len(decoded) != length {
		return nil, newUsageError("%s must be %d hexadecimal bytes", name, length)
	}
	return decoded, nil
}

func openInput(path string, stdin io.Reader) (io.Reader, func() error, error) {
	if path == "-" {
		return stdin, func() error { return nil }, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	return file, file.Close, nil
}

func rejectSameInputOutput(inputPath, outputPath string) error {
	if inputPath == "-" || outputPath == "-" {
		return nil
	}
	inputInfo, inputErr := os.Stat(inputPath)
	outputInfo, outputErr := os.Stat(outputPath)
	if inputErr == nil && outputErr == nil && os.SameFile(inputInfo, outputInfo) {
		return newUsageError("-in and -out must refer to different files")
	}
	return nil
}

func closeStdinBeforeReplace(stdin io.Reader, outputPath string) error {
	if outputPath == "-" {
		return nil
	}
	inputFile, ok := stdin.(*os.File)
	if !ok {
		return nil
	}
	inputInfo, inputErr := inputFile.Stat()
	outputInfo, outputErr := os.Stat(outputPath)
	if inputErr == nil && outputErr == nil && os.SameFile(inputInfo, outputInfo) {
		return inputFile.Close()
	}
	return nil
}

type stagedOutput struct {
	file       *os.File
	path       string
	outputPath string
	stdout     io.Writer
}

func newStagedOutput(outputPath string, stdout io.Writer) (*stagedOutput, error) {
	directory := ""
	if outputPath != "-" {
		directory = filepath.Dir(outputPath)
	}
	file, err := os.CreateTemp(directory, ".ubc-output-*")
	if err != nil {
		return nil, err
	}
	return &stagedOutput{file: file, path: file.Name(), outputPath: outputPath, stdout: stdout}, nil
}

func (output *stagedOutput) discard() {
	if output.file != nil {
		_ = output.file.Close()
		output.file = nil
	}
	_ = os.Remove(output.path)
}

func (output *stagedOutput) publish() error {
	if output.file != nil {
		if err := output.file.Close(); err != nil {
			return err
		}
		output.file = nil
	}
	if output.outputPath != "-" {
		if err := os.Rename(output.path, output.outputPath); err != nil {
			return err
		}
		output.path = ""
		return nil
	}
	source, err := os.Open(output.path)
	if err != nil {
		return err
	}
	defer func() { _ = source.Close() }()

	_, err = io.Copy(output.stdout, source)
	return err
}

func printRootUsage(output io.Writer) {
	_, _ = fmt.Fprint(output, `Usage: ubc <command> [flags]

Commands:
  encode    write a UBC container
  decode    read a UBC container
  verify    verify a UBC container without writing plaintext
  inspect   print UBC header and metadata
  version   print the CLI version

Run "ubc <command> --help" for command flags.
`)
}

func printCommandUsage(output io.Writer, name string) {
	_, _ = fmt.Fprintf(output, `Usage: ubc %s [flags]

Flags:
  -in <path|->
        input path, or - for stdin
  -out <path|->
        output path, or - for stdout
  -key-file <path>
        raw 32-byte or 64-hex-character key; UBC_KEY may be used instead
  -chunk-size <bytes>
        plaintext bytes per chunk (default %s)
`, name, strconv.FormatUint(defaultChunkSize, 10))
	if name == "encode" {
		_, _ = fmt.Fprint(output, `  -name <value>
        filename metadata
  -mime <value>
        MIME type metadata
  -base-nonce <hex>
        fixed 12-byte nonce for conformance testing only
`)
	}
	_, _ = fmt.Fprint(output, `  -h, -help
        show help
`)
}
