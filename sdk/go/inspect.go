package ubc

import (
	"errors"
	"io"
)

// ContainerFlags describes the enabled container features.
type ContainerFlags struct {
	Encrypted   bool
	HasMetadata bool
}

// ContainerInfo is the header and metadata prefix of a UBC container.
// Inspect deliberately does not read or validate payload or footer bytes.
type ContainerInfo struct {
	Version    uint8
	Flags      ContainerFlags
	HashAlgo   uint8
	AEADAlgo   uint8
	ChunkSize  uint32
	ChunkCount uint64
	TotalSize  uint64
	Metadata   []MetadataEntry
}

// Inspect reads and validates only a container's header and optional metadata.
// It neither requires an encryption key nor reads any payload bytes.
func Inspect(source io.Reader) (ContainerInfo, error) {
	if source == nil {
		return ContainerInfo{}, errors.New("ubc: nil inspect source")
	}

	headerBytes := make([]byte, HeaderSize)
	if err := readExact(source, headerBytes); err != nil {
		return ContainerInfo{}, err
	}
	header, err := ParseHeader(headerBytes)
	if err != nil {
		return ContainerInfo{}, err
	}

	info := ContainerInfo{
		Version: header.Version,
		Flags: ContainerFlags{
			Encrypted:   header.Encrypted(),
			HasMetadata: header.HasMetadata(),
		},
		HashAlgo:   header.HashAlgo,
		AEADAlgo:   header.AEADAlgo,
		ChunkSize:  header.ChunkSize,
		ChunkCount: header.ChunkCount,
		TotalSize:  header.TotalSize,
	}
	if !header.HasMetadata() {
		return info, nil
	}

	region, err := readMetadataRegion(source, limitsFor(DecodeOptions{}).maxMetaBytes)
	if err != nil {
		return ContainerInfo{}, err
	}
	metadata, _, err := ParseMetadata(region)
	if err != nil {
		return ContainerInfo{}, err
	}
	info.Metadata = copyMetadata(metadata)
	return info, nil
}

func copyMetadata(metadata []MetadataEntry) []MetadataEntry {
	copyOfMetadata := make([]MetadataEntry, len(metadata))
	for i, entry := range metadata {
		copyOfMetadata[i] = MetadataEntry{Tag: entry.Tag, Value: append([]byte(nil), entry.Value...)}
	}
	return copyOfMetadata
}
