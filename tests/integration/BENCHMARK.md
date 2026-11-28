# OPS-620 data plane benchmark

Measured with Go 1.27.4 on an AMD Ryzen 7 5800X3D using the original
`gatehouse-bench/harness/bench.sh` mix targets and mock backend. Gatehouse
ran on CPUs 2–3, the mock backend on 4, 5, 12 and 13, and Vegeta v12.13.0
on 6, 7, 14 and 15.

| Measurement | Gatehouse | OPS-620 limit |
| --- | ---: | ---: |
| Idle RSS after 5 seconds | 21.73 MiB | 80 MiB |
| mix-100-h1 CPU per request | 0.225 ms | 0.2925 ms |

The HTTP/1.1 run sent 2,000 requests at 100 req/s after a five-second
warm-up. It returned 1,940 HTTP 200, 40 HTTP 204 and 20 expected HTTP 403
responses. Process user and system CPU time totaled 0.45 s, measured from
`/proc/<pid>/stat`. The recorded Go prototype HTTP/1.1 baseline was
0.195 ms/request. Gatehouse used 1.15× that baseline.

The same mix over HTTP/2 also returned the expected status counts and used
0.305 ms/request. The original HTTP/2 Go baseline was 0.270 ms/request.

To repeat, build Gatehouse and the original mock backend. In a scratch
directory, generate P-256 server certificates with
`tests/integration/testdata/fixtures.py` and copy the original benchmark's
disposable client CA and client certificates into its `certs` directory.
The original workload shipped RSA server certificates. Keep its targets,
mock backend, client certificates and client policy. Run `driver.py` with
the original `config/bench.json` as its argument, `BENCH_DIR` pointing to
the scratch directory and `GATEHOUSE_BINARY` pointing to the build. The
driver resolves certificate paths in the scratch directory.

# OPS-626 release benchmark

Gatehouse and Traefik 3.8.0 ran the original
`~/.local/share/gatehouse-bench/harness/bench.sh` scenarios at full duration.
Both used the same local mock backend, routes, P-256 server certificates,
disposable client CA and certificates, and load generators. Traefik loaded
CrowdSec v1.8.2, traefik-real-ip v0.4.0, and traefik-mtls-authz v0.2.1.
The host was an AMD Ryzen 7 5800X3D with Linux amd64. Both proxies used Go
1.27.4. Vegeta was v12.13.0 and oha v1.17.0.

Each proxy ran on CPUs 2–3, the backend on 4, 5, 12 and 13, and the load
generators on 6, 7, 14 and 15. Each repetition included a five-second warm-up,
20-second 100 req/s mixes over HTTP/1.1 and HTTP/2, a 15-second 2,000 req/s
HTTP/1.1 burst, two 15-second 200 req/s handshake scenarios, four 10-second
saturation scenarios, and 2 GiB uploads and downloads. RSS came from
`/proc/<pid>/status` and CPU time from `/proc/<pid>/stat`.

Both configurations retained access logging, request policy evaluation,
CrowdSec polling, and TLS client authentication on the workload's protected
routes. Gatehouse used its JSON log and full CrowdSec snapshots. Traefik used
its common access log, delta polling after startup, and the original
`GOMEMLIMIT=384MiB` benchmark setting. Gatehouse ran in file snapshot mode
with one replica. Kubernetes reconciliation, OIDC login, and gossip traffic
were outside this workload.

For the comparison, Gatehouse used the original workload's rate allowance
of 100,000,000 per rolling minute and a 1,000,000 per-second slot, with
in-flight caps of 1,000 per client and 2,000 per host. Traefik used the original
rate and in-flight middleware. These settings kept throttling out of the
saturation measurements while both implementations still evaluated limits.

A separate Gatehouse run with its default 30,000 req/min and 3,000 req/slot
settings completed the request mixes and burst. The sustained saturation
scenarios returned `429` after reaching their caps, and the following S3
download returned an 18-byte response. The comparison below uses two
Traefik repetitions followed by two Gatehouse repetitions with the
benchmark allowances.

| Measurement | Gatehouse | Traefik + plugins |
| --- | ---: | ---: |
| Startup to HTTP 200 (s) | 0.117 | 0.660–0.793 |
| Idle RSS (MiB) | 57.3–59.2 | 184.4–185.6 |
| Peak RSS (MiB) | 116.6–124.3 | 288.0–308.5 |
| 100 req/s HTTP/1.1 mix p99 (ms) | 0.70–0.71 | 1.10–1.26 |
| 100 req/s HTTP/1.1 mix CPU (ms/request) | 0.240–0.245 | 0.545 |
| 100 req/s HTTP/2 mix p99 (ms) | 0.75–0.78 | 1.74–1.84 |
| 100 req/s HTTP/2 mix CPU (ms/request) | 0.305 | 0.660–0.685 |
| 2,000 req/s HTTP/1.1 burst p99 (ms) | 0.57–0.67 | 4.18–4.63 |
| TLS handshake scenario p99 (ms) | 1.33–1.52 | 2.48–2.81 |
| mTLS handshake scenario p99 (ms) | 1.63–1.64 | 3.43–3.44 |
| S3 saturation HTTP/1.1 (200 responses/s) | 17,634–18,002 | 5,573–5,783 |
| Gzip page saturation HTTP/1.1 (200 responses/s) | 13,253–13,675 | 5,252–5,511 |
| S3 saturation HTTP/2 (200 responses/s) | 15,285–15,562 | 5,007–5,323 |
| mTLS saturation HTTP/1.1 (200 responses/s) | 18,872–20,103 | 4,134–4,243 |
| 2 GiB upload (MiB/s) | 940–955 | 1,000–1,006 |
| 2 GiB download (MiB/s) | 809–810 | 789–809 |

Each 2,000-request mix returned 1,940 HTTP 200s, 40 HTTP 204s, and 20
expected HTTP 403s. Bursts returned 29,100 HTTP 200s and 600 HTTP 204s,
plus 299 or 300 expected HTTP 403s. The load generator issued 29,999
requests in one Gatehouse burst and 30,000 in the other three. Both
handshake scenarios returned 3,000 HTTP 200s per run. All completed
saturation requests returned HTTP 200. oha canceled outstanding requests
at the ten-second deadline. Each transfer moved 2,147,483,648 bytes.
Gatehouse negotiated X25519MLKEM768 with the OpenSSL probe.

The HTTP/1.1 mix stayed within the OPS-620 envelope of 80 MiB idle RSS
and 0.2925 ms of CPU per request. It used 57.3–59.2 MiB and 0.240–0.245 ms
per request with the release code and policies enabled.

To repeat, copy the workload into a scratch directory, generate P-256
server certificates as above, and point the copied Traefik file-provider
and certificate paths at that directory. Install the three pinned plugins
from their tagged sources, including their vendored dependencies, under
`traefik/plugins-local/src/<module-name>`. Create the original runner's
`impl/go/edge-go` entry point as a wrapper around `testdata/driver.py`
with `BENCH_DIR` pointing to the copy and `GATEHOUSE_BINARY` set to the
release build. In the copied driver, use the `web01-root` fixture's
`rateLimit.average`, `rateLimit.burst`, `inFlight.perClientIp`, and
`inFlight.perHost` for the four limit values above. Run the original
backend and `harness/bench.sh` for `traefik-plugins` and `go` in
alternating order.
