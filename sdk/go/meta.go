package ubc

import (
	"encoding/binary"
	"math"
	"sort"
)

type MetadataEntry struct {
	Tag   uint16
	Value []byte
}

func EncodeMetadata(entries []MetadataEntry) ([]byte, error) {
	if len(entries) == 0 {
		return nil, nil
	}
	sorted := append([]MetadataEntry(nil), entries...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Tag < sorted[j].Tag })
	body := make([]byte, 0)
	for index, entry := range sorted {
		if uint64(len(entry.Value)) > math.MaxUint32 || uint64(len(body))+6+uint64(len(entry.Value)) > math.MaxUint32 {
			return nil, ErrMetaMalformed
		}
		if index > 0 && sorted[index-1].Tag == entry.Tag {
			return nil, ErrMetaMalformed
		}
		prefix := make([]byte, 6)
		binary.LittleEndian.PutUint16(prefix[:2], entry.Tag)
		binary.LittleEndian.PutUint32(prefix[2:], uint32(len(entry.Value)))
		body = append(body, prefix...)
		body = append(body, entry.Value...)
	}
	region := make([]byte, 4+len(body))
	binary.LittleEndian.PutUint32(region[:4], uint32(len(body)))
	copy(region[4:], body)
	return region, nil
}

func ParseMetadata(data []byte) ([]MetadataEntry, int, error) {
	if len(data) < 4 {
		return nil, 0, ErrMetaMalformed
	}
	length := binary.LittleEndian.Uint32(data[:4])
	if uint64(length) > uint64(len(data)-4) {
		return nil, 0, ErrMetaMalformed
	}
	body, entries := data[4:4+int(length)], make([]MetadataEntry, 0)
	for offset := 0; offset < len(body); {
		if len(body)-offset < 6 {
			return nil, 0, ErrMetaMalformed
		}
		tag := binary.LittleEndian.Uint16(body[offset:])
		valueLength := binary.LittleEndian.Uint32(body[offset+2:])
		offset += 6
		if uint64(valueLength) > uint64(len(body)-offset) || (len(entries) > 0 && entries[len(entries)-1].Tag >= tag) {
			return nil, 0, ErrMetaMalformed
		}
		value := append([]byte(nil), body[offset:offset+int(valueLength)]...)
		entries = append(entries, MetadataEntry{Tag: tag, Value: value})
		offset += int(valueLength)
	}
	return entries, 4 + int(length), nil
}
