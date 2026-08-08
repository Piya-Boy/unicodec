package main

import (
	"os/exec"
	"testing"
)

func TestGeneratedVectorsAreCurrent(t *testing.T) {
	command := exec.Command("go", "run", ".", "-check", "-root", "../../spec/vectors")
	command.Dir = "."
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("vector check failed: %v\n%s", err, output)
	}
}
