package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
)

const version = "0.1.0"

const defaultChunkSize = 1 << 20

type commandOptions struct {
	inputPath           string
	outputPath          string
	keyFile             string
	chunkSize           uint64
	name                string
	mime                string
	baseNonce           string
	unsafeDeterministic bool
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	return runWithIO(args, os.Stdin, stdout, stderr)
}

func runWithIO(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
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

	if name == "encode" {
		return runEncode(options, stdin, stdout, stderr)
	}
	_, _ = fmt.Fprintf(stderr, "ubc %s: not implemented\n", name)
	return 2
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
		flags.StringVar(&options.baseNonce, "base-nonce", "", "12-byte hexadecimal nonce (test only)")
		flags.BoolVar(&options.unsafeDeterministic, "unsafe-deterministic", false, "allow deterministic nonce for testing")
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
        file containing a 32-byte key; UBC_KEY may be used instead
  -chunk-size <bytes>
        plaintext bytes per chunk (default %s)
`, name, strconv.FormatUint(defaultChunkSize, 10))
	if name == "encode" {
		_, _ = fmt.Fprint(output, `  -name <filename>
        filename metadata
  -mime <type>
        MIME type metadata
  -base-nonce <hex>
        12-byte hexadecimal nonce (test only)
  -unsafe-deterministic
        allow deterministic nonce for testing
`)
	}
	_, _ = fmt.Fprint(output, `  -h, -help
        show help
`)
}
