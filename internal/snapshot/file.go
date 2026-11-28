package snapshot

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"

	"github.com/zekihan/gatehouse/internal/config"
)

// LoadFile loads resolved snapshot data from a disposable or locally managed
// file. The returned digest includes the file's behavioral inputs.
func LoadFile(cfg *config.Config, filename string) (*Snapshot, error) {
	raw, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var data *DataPlane
	if err = decoder.Decode(&data); err != nil || data == nil {
		return nil, errors.New("invalid data plane snapshot")
	}
	if err = decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return nil, errors.New("snapshot must contain exactly one JSON object")
	}
	digest, err := Digest(cfg, []Input{{Kind: "DataPlane", Name: "file", Content: raw}})
	if err != nil {
		return nil, err
	}
	return &Snapshot{Digest: digest, Config: cfg, DataPlane: data}, nil
}
