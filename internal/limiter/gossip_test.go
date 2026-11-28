package limiter

import (
	"bytes"
	"context"
	"io"
	"log"
	"path/filepath"
	"testing"
	"time"

	"github.com/zekihan/gatehouse/internal/config"
)

func TestThreeEncryptedMembers(t *testing.T) {
	current := bytes.Repeat([]byte{0x17}, 32)
	next := bytes.Repeat([]byte{0x3c}, 32)
	a := gossipNode(t, "a", "127.0.0.1:1", current, next)
	if a.Limiter.Ready() {
		t.Fatal("first node ready without a peer")
	}
	seed := a.nodes.LocalNode().Address()
	b := gossipNode(t, "b", seed, next, current)
	c := gossipNode(t, "c", seed, next, current)
	waitFor(t, "all replicas discover each other and resync", func() bool {
		for _, node := range []*Cluster{a, b, c} {
			if node.nodes.NumMembers() != 3 || !node.Limiter.Ready() {
				return false
			}
		}
		return true
	})
	cfg := limits(100, 100, 1, 1)
	done, allowed := a.Limiter.Admit(route, clientIP, host, cfg)
	if !allowed {
		t.Fatal("initial request refused")
	}
	waitFor(t, "remote in-flight admission blocks across all replicas", func() bool {
		return !probeAdmission(b.Limiter, cfg) && !probeAdmission(c.Limiter, cfg)
	})
	done()
	waitFor(t, "release reaches all replicas", func() bool {
		return probeAdmission(b.Limiter, cfg) && probeAdmission(c.Limiter, cfg)
	})
	var out bytes.Buffer
	a.Limiter.Metrics(&out)
	if !bytes.Contains(out.Bytes(), []byte("gatehouse_gossip_peers 2\n")) ||
		!bytes.Contains(out.Bytes(), []byte("gatehouse_limiter_resync_pending 0\n")) {
		t.Fatalf("unexpected cluster metrics: %s", out.String())
	}
}

func gossipNode(t *testing.T, name, seed string, keys ...[]byte) *Cluster {
	t.Helper()
	node, err := NewCluster(Gossip{
		Name: name, Bind: "127.0.0.1:0", Discover: seed,
		StateFile: filepath.Join(t.TempDir(), "epoch"),
		Keyring:   keys, Logger: log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	stopped := make(chan struct{})
	go func() {
		node.Run(ctx)
		close(stopped)
	}()
	t.Cleanup(func() {
		cancel()
		<-stopped
	})
	return node
}

func probeAdmission(node *Limiter, cfg config.Limits) bool {
	done, ok := node.Admit(route, clientIP, host, cfg)
	if ok {
		done()
	}
	return ok
}

func waitFor(t *testing.T, reason string, condition func() bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	tick := time.NewTicker(15 * time.Millisecond)
	defer tick.Stop()
	for !condition() {
		select {
		case <-ctx.Done():
			t.Fatalf("timed out waiting for %s", reason)
		case <-tick.C:
		}
	}
}
