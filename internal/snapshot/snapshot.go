// Package snapshot defines the input identity shared by the compiler and status publisher.
package snapshot

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/zekihan/gatehouse/internal/config"
)

// Snapshot pairs an acknowledgement digest with the operator configuration.
type Snapshot struct {
	Digest    string
	Config    *config.Config
	DataPlane *DataPlane
}

// Input contains the identity and relevant content of one compiler input.
// Content must be JSON. Callers should exclude status and other metadata
// that the compiler does not read. Secrets and dependencies must be included
// when they affect the result, even if their generation is zero.
type Input struct {
	Group      string          `json:"group"`
	Kind       string          `json:"kind"`
	Namespace  string          `json:"namespace"`
	Name       string          `json:"name"`
	Generation int64           `json:"generation"`
	Content    json.RawMessage `json:"content"`
}

func compareInput(a, b Input) int {
	return cmp.Or(cmp.Compare(a.Group, b.Group), cmp.Compare(a.Kind, b.Kind),
		cmp.Compare(a.Namespace, b.Namespace), cmp.Compare(a.Name, b.Name))
}

// Digest hashes the configuration and compiler dependencies. Input ordering,
// whitespace, and JSON object property ordering do not affect the result.
// Errors identify a resource without including its content.
func Digest(cfg *config.Config, inputs []Input) (string, error) {
	if cfg == nil {
		return "", errors.New("snapshot requires operator configuration")
	}
	ordered := append([]Input(nil), inputs...)
	slices.SortFunc(ordered, compareInput)
	for i, input := range ordered {
		if i > 0 && compareInput(ordered[i-1], input) == 0 {
			return "", fmt.Errorf(
				"duplicate snapshot input %s %s/%s",
				input.Kind,
				input.Namespace,
				input.Name,
			)
		}
		content, err := canonicalize(input.Content)
		if err != nil {
			return "", fmt.Errorf(
				"invalid JSON in snapshot input %s %s/%s",
				input.Kind,
				input.Namespace,
				input.Name,
			)
		}
		ordered[i].Content = content
	}
	hash := sha256.New()
	encoder := json.NewEncoder(hash)
	if err := encoder.Encode("gatehouse-snapshot-v1"); err != nil {
		return "", err
	}
	if err := encoder.Encode(cfg); err != nil {
		return "", err
	}
	if err := encoder.Encode(ordered); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func canonicalize(data json.RawMessage) (json.RawMessage, error) {
	if !json.Valid(data) {
		return nil, errors.New("invalid JSON")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	return json.Marshal(value)
}
