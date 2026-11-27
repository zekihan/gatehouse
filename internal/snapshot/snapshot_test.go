package snapshot

import (
	"os"
	"slices"
	"testing"

	"github.com/zekihan/gatehouse/internal/config"
)

func TestDigestTracksDependencies(t *testing.T) {
	data, err := os.ReadFile("../../examples/operator.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	inputs := []Input{
		{
			Kind:      "Secret",
			Namespace: "app",
			Name:      "tls",
			Content:   []byte(`{"cert":"fixture","ca":"test"}`),
		},
		{
			Kind:    "Namespace",
			Name:    "app",
			Content: []byte(`{"labels":{"gatehouse.noqer.com/listeners":"allowed"}}`),
		},
		{
			Group:     "discovery.k8s.io",
			Kind:      "EndpointSlice",
			Namespace: "app",
			Name:      "api",
			Content:   []byte(`{"addresses":["192.0.2.1"]}`),
		},
		{
			Group:      "gateway.networking.k8s.io",
			Kind:       "HTTPRoute",
			Namespace:  "app",
			Name:       "api",
			Generation: 1,
			Content:    []byte(`{"rules":[]}`),
		},
	}
	digest := func(inputs []Input) string {
		t.Helper()
		value, err := Digest(cfg, inputs)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	baseline := digest(inputs)
	ordered := slices.Clone(inputs)
	ordered[0].Content = []byte(` { "ca": "test", "cert": "fixture" } `)
	slices.Reverse(ordered)
	if digest(ordered) != baseline {
		t.Fatal("input ordering or JSON property ordering changed the digest")
	}

	for index, input := range inputs {
		t.Run(input.Kind, func(t *testing.T) {
			changed := slices.Clone(inputs)
			changed[index].Content = []byte(`{"changed":true}`)
			if digest(changed) == baseline {
				t.Fatal("input content did not change digest")
			}
		})
	}
	inputs[3].Generation++
	if digest(inputs) == baseline {
		t.Fatal("object generation did not change digest")
	}
	cfg.Defaults.CrowdSec = false
	if digest(inputs) == baseline || digest(nil) != digest([]Input{}) {
		t.Fatal("unstable digest")
	}
}

func TestDigestRejectsDuplicateAndMalformedInputs(t *testing.T) {
	cfg := new(config.Config)
	input := Input{Kind: "Secret", Name: "test", Content: []byte("{}")}
	if _, err := Digest(cfg, []Input{input, input}); err == nil {
		t.Fatal("duplicate input accepted")
	}
	input.Content = []byte("{")
	if _, err := Digest(cfg, []Input{input}); err == nil {
		t.Fatal("malformed input accepted")
	}
}
