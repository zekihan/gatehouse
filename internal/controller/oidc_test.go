package controller

import (
	"encoding/base64"
	"maps"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/zekihan/gatehouse/internal/config"
)

func TestOIDCSnapshotCredentials(t *testing.T) {
	t.Parallel()
	id := key{secrets, "gatehouse", bootstrapSecret}
	keys := map[string]string{
		"oidc-user-client-secret": "disposable-client",
		"cookie-user-current":     "disposable-current",
		"cookie-user-previous":    "disposable-previous",
	}
	data := map[string]any{
		"oidc-unconfigured-client-secret": base64.StdEncoding.EncodeToString(
			[]byte("outside-class"),
		),
		"gossip-current": base64.StdEncoding.EncodeToString([]byte("unrelated")),
	}
	for name, value := range keys {
		data[name] = base64.StdEncoding.EncodeToString([]byte(value))
	}
	objects := Objects{items: map[key]*unstructured.Unstructured{
		id: {Object: map[string]any{"data": data}},
	}}
	cfg := &config.Config{AuthClasses: map[string]config.AuthClass{"user": {}}}
	operator := key{configMaps, "gatehouse", "operator"}
	now := time.Now()
	first, err := compile(objects, cfg, operator, "edge", now)
	if err != nil {
		t.Fatal(err)
	}
	if !maps.Equal(first.snapshot.DataPlane.OIDCSecrets, keys) {
		t.Fatal("snapshot must contain only configured OIDC credentials")
	}
	delete(data, "cookie-user-previous")
	next, err := compile(objects, cfg, operator, "edge", now)
	if err != nil {
		t.Fatal(err)
	}
	if next.snapshot.Digest == first.snapshot.Digest ||
		len(next.snapshot.DataPlane.OIDCSecrets) != 2 ||
		len(first.snapshot.DataPlane.OIDCSecrets) != 3 {
		t.Fatal("rotation must publish a new digest and leave the previous snapshot immutable")
	}
	delete(objects.items, id)
	missing, err := compile(objects, cfg, operator, "edge", now)
	if err != nil {
		t.Fatal(err)
	}
	if missing.snapshot.Digest == next.snapshot.Digest ||
		len(missing.snapshot.DataPlane.OIDCSecrets) != 0 {
		t.Fatal("bootstrap Secret removal must revoke OIDC credentials")
	}
}
