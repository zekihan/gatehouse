#!/usr/bin/env python3
"""Generate disposable benchmark certificates and portable route fixtures."""
import hashlib
import json
import os
import subprocess
from pathlib import Path

C = "certs"
os.umask(0o077)
os.mkdir(C)

STANDARD = ["s3", "miniflux", "whoami", "rl"] + [f"web{i:02d}" for i in range(1, 34)]
MTLS = ["vm-upload", "journald"] + [f"mtls{i:02d}" for i in range(1, 25)]
assert len(STANDARD) == 37 and len(MTLS) == 26
DOMAIN = "bench.test"
PREFIX = "urn:noqer:mtls:clients:"


def sh(*args):
    subprocess.run(args, check=True, cwd=C, stdout=subprocess.DEVNULL)


def fp(path):
    der = subprocess.run(["openssl", "x509", "-in", path, "-outform", "DER"], check=True, capture_output=True).stdout
    return hashlib.sha256(der).hexdigest()


def certs():
    # Server PKI mirrors Let's Encrypt shape: ECDSA root, intermediate and leaf.
    sh("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", "server-root.key", "-out", "server-root.crt",
       "-days", "3650", "-subj", "/CN=Bench Server Root", "-addext", "basicConstraints=critical,CA:TRUE",
       "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    sh("openssl", "req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", "server-int.key", "-out", "server-int.csr", "-subj", "/CN=Bench R11")
    with open(os.path.join(C, "int.ext"), "w") as f:
        f.write("basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign,digitalSignature\n")
    sh("openssl", "x509", "-req", "-in", "server-int.csr", "-CA", "server-root.crt", "-CAkey", "server-root.key", "-CAcreateserial",
       "-out", "server-int.crt", "-days", "1825", "-extfile", "int.ext")
    for h in STANDARD + MTLS:
        name = f"{h}.{DOMAIN}"
        with open(os.path.join(C, f"{h}.ext"), "w") as f:
            f.write(f"subjectAltName=DNS:{name}\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n"
                    "basicConstraints=critical,CA:FALSE\n")
        sh("openssl", "req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", f"{h}.key", "-out", f"{h}.csr", "-subj", f"/CN={name}")
        sh("openssl", "x509", "-req", "-in", f"{h}.csr", "-CA", "server-int.crt", "-CAkey", "server-int.key", "-CAcreateserial",
           "-out", f"{h}.leaf.crt", "-days", "90", "-extfile", f"{h}.ext")
        with open(os.path.join(C, f"{h}.crt"), "w") as out:
            out.write((Path(C) / f"{h}.leaf.crt").read_text() + (Path(C) / "server-int.crt").read_text())
    # Client PKI mirrors mtls-clients-v1: ECDSA P-256 root signing URI-SAN-only leaves.
    sh("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", "client-ca.key",
       "-out", "client-ca.crt", "-days", "3650", "-subj", "/CN=Bench mTLS Clients v1",
       "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    sh("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", "rogue-ca.key",
       "-out", "rogue-ca.crt", "-days", "3650", "-subj", "/CN=Rogue CA",
       "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    for name, ca in [("client-good", "client-ca"), ("client-other", "client-ca"), ("client-blocked", "client-ca"), ("client-rogue", "rogue-ca")]:
        ident = {"client-good": "bench", "client-other": "intruder", "client-blocked": "bench", "client-rogue": "bench"}[name]
        with open(os.path.join(C, f"{name}.ext"), "w") as f:
            f.write(f"subjectAltName=URI:{PREFIX}{ident}\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n"
                    "basicConstraints=critical,CA:FALSE\n")
        sh("openssl", "req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", f"{name}.key",
           "-out", f"{name}.csr", "-subj", f"/CN={name}")
        sh("openssl", "x509", "-req", "-in", f"{name}.csr", "-CA", f"{ca}.crt", "-CAkey", f"{ca}.key", "-CAcreateserial",
           "-out", f"{name}.crt", "-days", "365", "-extfile", f"{name}.ext")


def config():
    client_ca_fp = fp(os.path.join(C, "client-ca.crt"))
    blocked = [fp(os.path.join(C, "client-blocked.crt"))] + [hashlib.sha256(f"blocked-{i}".encode()).hexdigest() for i in range(29)]
    identities = [PREFIX + x for x in ["bench", "gatus-cluster-1", "z-arch", "z-mac", "z-phone", "z-tablet", "z-windows"]]
    std_mw = {"realIp": True, "crowdsec": True, "inFlight": {"perClientIp": 1000, "perHost": 2000},
              "rateLimit": {"average": 100000000, "periodSeconds": 60, "burst": 1000000},
              "securityHeaders": True, "compress": {"encodings": ["gzip"], "minBytes": 1024}}
    rl_mw = dict(std_mw, rateLimit={"average": 60, "periodSeconds": 60, "burst": 5})
    backend = os.environ["BENCH_APP_URL"]
    hosts = []
    for h in STANDARD + MTLS:
        hosts.append({"name": f"{h}.{DOMAIN}", "cert": f"{C}/{h}.crt", "key": f"{C}/{h}.key", "mtls": h in MTLS})
    routes = []

    def add(name, host, path=None, path_type=None, method=None, action="proxy", mw=None, mtls=False, forward_auth=False):
        routes.append({"name": name, "host": f"{host}.{DOMAIN}", "path": path, "pathType": path_type, "method": method,
                       "action": action, "backend": backend, "middlewares": mw or std_mw, "mtlsPolicy": "default" if mtls else None,
                       "forwardAuth": "gatus" if forward_auth else None})

    for h in STANDARD + MTLS:
        if h == "journald":
            continue
        add(f"{h}-root", h, "/", "prefix", mw=rl_mw if h == "rl" else std_mw, mtls=h in MTLS)
    for p in ["/minio/admin", "/rustfs/admin", "/rustfs/console"]:
        add(f"s3-deny{p.replace('/', '-')}", "s3", p, "prefix", action="deny")
    add("whoami-probe", "whoami", "/probe", "exact", method="GET", forward_auth=True)
    add("whoami-health", "whoami", "/health", "exact")
    add("vm-upload-write", "vm-upload", "/api/v1/write", "exact", method="POST", mtls=True)
    add("journald-upload", "journald", "/insert/journald/upload", "exact", method="POST", mtls=True)
    for i in range(1, 21):
        add(f"web{i:02d}-health", f"web{i:02d}", "/health", "exact")
    add("miniflux-api", "miniflux", "/v1/", "prefix")
    assert len(routes) == 90, len(routes)
    cfg = {
        "listen": f'127.0.0.1:{os.environ["BENCH_TLS_PORT"]}',
        "metricsListen": f'127.0.0.1:{os.environ["BENCH_METRICS_PORT"]}',
        "tls": {"minVersion": "1.2", "alpn": ["h2", "http/1.1"],
                "clientCa": f"{C}/client-ca.crt", "hosts": hosts},
        "timeouts": {"readSeconds": 300, "writeSeconds": 300, "idleSeconds": 300, "keepAliveMaxRequests": 1000},
        "crowdsec": {"lapiUrl": os.environ["BENCH_LAPI_URL"], "apiKey": "bench-lapi-key", "updateIntervalSeconds": 60},
        "forwardAuth": {"gatus": {"address": os.environ["BENCH_AUTH_URL"] + "/api/authz/gatus", "authRequestHeaders": ["Authorization"],
                                  "stripAfterAuth": ["Authorization"], "maxResponseBodyBytes": 65536}},
        "mtlsPolicies": {"default": {"trustedIssuers": [client_ca_fp], "identityPrefix": PREFIX, "identities": identities,
                                     "disabledIdentities": [], "blockedFingerprints": blocked,
                                     "forwardIdentityHeader": "X-Mtls-Identity"}},
        "routes": routes,
    }
    Path("bench.json").write_text(json.dumps(cfg, indent=2) + "\n")


if __name__ == "__main__":
    certs()
    config()
