package main

import (
	"bytes"
	"strings"
	"testing"
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
	if code := run([]string{"encode", "-in", "input"}, &stdout, &stderr); code != 2 {
		t.Fatalf("encode exit code = %d", code)
	}
	if stdout.Len() != 0 || stderr.String() != "ubc encode: not implemented\n" {
		t.Fatalf("stdout = %q, stderr = %q", stdout.String(), stderr.String())
	}
}
