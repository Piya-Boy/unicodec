package main

import (
	"bytes"
	"crypto/sha256"
	"os/exec"
	"strings"
	"testing"
)

func TestGeneratedVectorsAreCurrent(t *testing.T) {
	command := exec.Command("go", "run", ".", "-check", "-root", "../../spec/vectors")
	command.Dir = "."
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("vector check failed: %v\n%s", err, output)
	}
}

func TestEncryptedMetadataTamperUsesValidFilenameAndLegacyRoot(t *testing.T) {
	artifacts, err := buildArtifacts(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, artifact := range artifacts {
		if !strings.HasSuffix(artifact.Path, "negative-encrypted-metadata-tamper.ubc") {
			continue
		}
		if !bytes.Contains(artifact.Data, []byte("รายงาน_2026.txt")) {
			t.Fatal("filename tamper was not generated")
		}
		footerOffset := len(artifact.Data) - footerSize
		copyData := append([]byte(nil), artifact.Data...)
		recomputeLegacyRoot(copyData)
		if !bytes.Equal(artifact.Data[footerOffset:footerOffset+sha256.Size], copyData[footerOffset:footerOffset+sha256.Size]) {
			t.Fatal("legacy root was not recomputed")
		}
		return
	}
	t.Fatal("metadata tamper vector missing")
}
