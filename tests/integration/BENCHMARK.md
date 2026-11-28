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
