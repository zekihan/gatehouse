package limiter

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/memberlist"
)

// Gossip configures a shared limiter on the Gatehouse headless Service.
type Gossip struct {
	Name      string
	StateFile string
	Bind      string
	Advertise string
	Discover  string
	Keyring   [][]byte
	Logger    *log.Logger
}

type Cluster struct {
	Limiter  *Limiter
	nodes    *memberlist.Memberlist
	seedHost string
	seedPort string
	logger   *log.Logger
}

func NewCluster(options Gossip) (*Cluster, error) {
	if !validName(options.Name) || options.StateFile == "" || options.Discover == "" {
		return nil, errors.New(
			"gossip requires a node name, incarnation file and discovery endpoint",
		)
	}
	keys, err := keyring(options.Keyring)
	if err != nil {
		return nil, err
	}
	seedHost, seedPort, err := net.SplitHostPort(options.Discover)
	if err != nil || seedHost == "" || seedPort == "" {
		return nil, errors.New("gossip discovery requires a hostname and port")
	}
	epoch, err := nextEpoch(options.StateFile)
	if err != nil {
		return nil, fmt.Errorf("persist gossip incarnation: %w", err)
	}
	id := origin{Name: options.Name, Epoch: epoch}
	limiter := newLimiter(id, true)
	d := delegate{Limiter: limiter}
	cfg := memberlist.DefaultLANConfig()
	cfg.Name = id.String()
	cfg.Keyring = keys
	cfg.Logger = options.Logger
	cfg.Delegate = d
	cfg.Events = d
	cfg.PushPullInterval = 5 * time.Second
	cfg.TCPTimeout = 500 * time.Millisecond
	cfg.GossipInterval = 100 * time.Millisecond
	if err := configureAddresses(cfg, options); err != nil {
		return nil, err
	}
	nodes, err := memberlist.Create(cfg)
	if err != nil {
		return nil, fmt.Errorf("start memberlist: %w", err)
	}
	return &Cluster{
		Limiter:  limiter,
		nodes:    nodes,
		seedHost: seedHost,
		seedPort: seedPort,
		logger:   options.Logger,
	}, nil
}

func keyring(supplied [][]byte) (*memberlist.Keyring, error) {
	if len(supplied) < 1 || len(supplied) > 2 {
		return nil, errors.New("gossip requires one current and at most one previous key")
	}
	for _, key := range supplied {
		if len(key) != 32 {
			return nil, errors.New("gossip keys must be 32 bytes")
		}
	}
	keys, err := memberlist.NewKeyring(supplied, supplied[0])
	if err != nil {
		return nil, fmt.Errorf("configure gossip keyring: %w", err)
	}
	return keys, nil
}

func configureAddresses(cfg *memberlist.Config, options Gossip) error {
	var err error
	if options.Bind != "" {
		cfg.BindAddr, cfg.BindPort, err = address(options.Bind)
		if err != nil {
			return fmt.Errorf("gossip bind: %w", err)
		}
	}
	if options.Advertise != "" {
		cfg.AdvertiseAddr, cfg.AdvertisePort, err = address(options.Advertise)
		if err != nil {
			return fmt.Errorf("gossip advertise: %w", err)
		}
	}
	return nil
}

func (c *Cluster) Run(ctx context.Context) {
	defer func() {
		if err := c.nodes.Leave(500 * time.Millisecond); err != nil {
			c.report(err)
		}
		if err := c.nodes.Shutdown(); err != nil {
			c.report(err)
		}
	}()
	var discovery sync.WaitGroup
	discovery.Go(func() { c.discover(ctx) })
	defer discovery.Wait()

	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			c.publish()
		}
	}
}

func (c *Cluster) discover(ctx context.Context) {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for {
		c.joinUnknown(ctx)
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func (c *Cluster) joinUnknown(ctx context.Context) {
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, c.seedHost)
	if err != nil {
		if ctx.Err() == nil {
			c.report(err)
		}
		return
	}
	known := make(map[string]bool)
	for _, peer := range c.nodes.Members() {
		known[peer.Address()] = true
	}
	var seeds []string
	for _, ip := range addresses {
		endpoint := net.JoinHostPort(ip.String(), c.seedPort)
		if !known[endpoint] {
			seeds = append(seeds, endpoint)
		}
	}
	if len(seeds) > 0 {
		if _, err := c.nodes.Join(seeds); err != nil && ctx.Err() == nil {
			c.report(err)
		}
	}
}

func (c *Cluster) report(err error) {
	if c.logger != nil {
		_ = c.logger.Output(2, err.Error()) //nolint:errcheck // Logging is best effort.
	}
}

func (c *Cluster) publish() {
	peers := c.nodes.Members()
	if len(peers) <= 1 {
		return
	}
	data, keys := c.Limiter.export(false)
	if data == nil {
		return
	}
	var sends sync.WaitGroup
	for _, peer := range peers {
		if peer.Name != c.nodes.LocalNode().Name {
			sends.Go(func() {
				if err := c.nodes.SendReliable(peer, data); err != nil {
					c.Limiter.retry(keys)
				}
			})
		}
	}
	sends.Wait()
}

func address(value string) (string, int, error) {
	ip, raw, err := net.SplitHostPort(value)
	if err != nil || net.ParseIP(ip) == nil {
		return "", 0, errors.New("expected an IP and port")
	}
	port, err := strconv.ParseUint(raw, 10, 16)
	if err != nil {
		return "", 0, errors.New("invalid port")
	}
	return ip, int(port), nil
}

func validName(name string) bool {
	return name != "" && len(name) <= 220 && !strings.ContainsAny(name, "~\x00\r\n")
}

func validOrigin(id origin) bool { return validName(id.Name) && id.Epoch > 0 }

func (o origin) String() string {
	return o.Name + "~" + strconv.FormatInt(o.Epoch, 10)
}

func parseOrigin(name string) origin {
	name, epoch, _ := strings.Cut(name, "~")
	n, err := strconv.ParseInt(epoch, 10, 64)
	if err != nil {
		return origin{}
	}
	return origin{Name: name, Epoch: n}
}

// The pod's local volume survives container restarts. Advancing past the
// persisted incarnation also fences the old process after a clock rollback.
func nextEpoch(path string) (int64, error) {
	n := time.Now().UnixNano()
	prior, err := os.ReadFile(path)
	if err == nil {
		previous, parseErr := strconv.ParseInt(string(prior), 10, 64)
		if parseErr != nil || previous < 1 || previous == 1<<63-1 {
			return 0, errors.New("invalid persisted gossip incarnation")
		}
		n = max(n, previous+1)
	} else if !errors.Is(err, os.ErrNotExist) {
		return 0, err
	}
	tmp := path + ".next"
	if err := os.WriteFile(tmp, []byte(strconv.FormatInt(n, 10)), 0o600); err != nil {
		return 0, err
	}
	return n, os.Rename(tmp, path)
}

type delegate struct{ *Limiter }

func (d delegate) NodeMeta(int) []byte             { return nil }
func (d delegate) GetBroadcasts(int, int) [][]byte { return nil }
func (d delegate) NotifyMsg(data []byte)           { d.merge(data, false) }
func (d delegate) LocalState(bool) []byte {
	data, _ := d.export(true)
	return data
}
func (d delegate) MergeRemoteState(data []byte, _ bool) { d.merge(data, true) }

func (d delegate) NotifyJoin(node *memberlist.Node) {
	id := parseOrigin(node.Name)
	if !validOrigin(id) {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	if d.observe(id, now) {
		d.peers[id] = now
	}
}

func (d delegate) NotifyLeave(node *memberlist.Node) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.peers, parseOrigin(node.Name))
}

func (d delegate) NotifyUpdate(*memberlist.Node) {}
