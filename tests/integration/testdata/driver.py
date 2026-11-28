#!/usr/bin/env python3
"""Run the file snapshot data plane against the portable bench fixtures."""

import base64
import json
import os
import signal
import urllib.request
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit


def pem(path, root):
    return base64.b64encode((root / "certs" / Path(path).name).read_bytes()).decode()


def snapshot(legacy, root):
    ip, port = legacy["listen"].rsplit(":", 1)
    port = int(port)
    limits = {
        "perRouteClient": {"perMinute": 30000, "perSecondSlot": 3000, "inFlight": 3000},
        "perRouteHost": {"inFlight": 6000},
    }
    compression = {"encodings": ["zstd", "br", "gzip"], "minBytes": 1024}
    operator = {
        "ports": {port: {"identity": "direct"}},
        "hosts": {},
        "dnsGroups": {"none": None},
        "lanBackends": [],
        "authClasses": {},
        "clientCertProfiles": {
            "clients": {"caSecret": "bench-client-ca", "minVersion": "1.2", "sessionTickets": False}
        },
        "forwardAuthClasses": {},
        "deviceTrust": {"caConfigMap": "bench-device-ca", "exceptions": []},
        "defaults": {"limits": limits, "compression": compression, "crowdsec": True},
    }
    for key, value in legacy["forwardAuth"].items():
        operator["forwardAuthClasses"][key] = {
            "address": value["address"],
            "requestHeaders": value["authRequestHeaders"],
            "stripAfter": value["stripAfterAuth"],
            "maxResponseBytes": value["maxResponseBodyBytes"],
        }
    resolved = {}
    policies = legacy["mtlsPolicies"]
    ca = pem(legacy["tls"]["clientCa"], root)
    for host in legacy["tls"]["hosts"]:
        name = host["name"]
        registry = {
            "namespace": "bench",
            "dnsGroup": "none",
            "proxied": False,
            "ports": [port],
            "protection": "mtls:clients" if host["mtls"] else "public",
        }
        operator["hosts"][name] = registry
        resolved[name] = {
            "certificate": {"certPEM": pem(host["cert"], root), "keyPEM": pem(host["key"], root)},
            "routes": [],
        }
        if host["mtls"]:
            resolved[name]["clientCA"] = ca
            registry["identities"] = policies["default"]["identities"]
    for route in legacy["routes"]:
        registry = operator["hosts"][route["host"]]
        if route["action"] == "deny":
            registry.setdefault("deny", {}).setdefault("prefixes", []).append(route["path"])
            continue
        target = urlsplit(route["backend"])
        rule = {
            "name": route["name"],
            "namespace": "bench",
            "path": route["path"],
            "exact": route["pathType"] == "exact",
            "backend": {
                "service": "bench/backend",
                "port": target.port,
                "endpoints": [target.netloc],
            },
        }
        if route["name"] == "rl-root":
            # A low minute cap makes the wire assertion independent of slot boundaries.
            rule["limits"] = {
                "perRouteClient": {"perMinute": 10, "perSecondSlot": 5, "inFlight": 1000},
                "perRouteHost": {"inFlight": 2000},
            }
        if route["method"]:
            rule["method"] = route["method"]
        if route["mtlsPolicy"]:
            policy = policies[route["mtlsPolicy"]]
            rule["mtls"] = {
                "identityPrefix": policy["identityPrefix"],
                "identities": policy["identities"],
                "disabledIdentities": policy["disabledIdentities"],
                "blockedFingerprints": policy["blockedFingerprints"],
                "trustedAnchors": policy["trustedIssuers"],
                "forwardHeaders": [policy["forwardIdentityHeader"]],
            }
        if route["forwardAuth"]:
            rule["forwardAuth"] = route["forwardAuth"]
            rule["namespace"] = "bench-probes"
            registry.setdefault("delegate", []).append({
                "paths": [route["path"]],
                "methods": [route["method"]],
                "namespace": rule["namespace"],
                "forwardAuth": route["forwardAuth"],
            })
        if route["name"] == "journald-upload":
            rule["deadlines"] = {"requestBody": 1800 * 10**9, "responseBody": 1800 * 10**9}
        resolved[route["host"]]["routes"].append(rule)
    return operator, {"ports": {port: resolved}}, ip, port


def main():
    os.umask(0o077)
    root = Path(os.environ["BENCH_DIR"])
    source = Path(sys.argv[1]) if len(sys.argv) > 1 else root / "bench.json"
    bench = json.loads(source.read_text())
    operator, data, ip, port = snapshot(bench, root)
    cfg, snap = Path("bench-operator.json"), Path("bench-snapshot.json")
    cfg.write_text(json.dumps(operator))
    snap.write_text(json.dumps(data))
    key_file = Path("bench-lapi-key")
    key_file.write_text(bench["crowdsec"]["apiKey"])
    ready_host = next(host["name"] for host in bench["tls"]["hosts"] if host["name"].startswith("web01."))
    command = [
        os.environ["GATEHOUSE_BINARY"], "serve", "--config", str(cfg),
        "--snapshot", str(snap), "--bind", ip, "--metrics", bench["metricsListen"],
        "--crowdsec-lapi", bench["crowdsec"]["lapiUrl"], "--crowdsec-key-file", str(key_file),
        "--ready-route", f"https://{ready_host}:{port}/health",
        "--ready-route-ca-file", str(root / "certs" / "server-root.crt"),
    ]
    ready = os.environ.get("BENCH_READY")
    if not ready:
        os.execv(command[0], command)
    with subprocess.Popen(command) as server:
        def stop(_signal, _frame):
            server.terminate()

        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        while server.poll() is None:
            try:
                with urllib.request.urlopen(f"http://{bench['metricsListen']}/readyz", timeout=0.2):
                    pass
            except OSError:
                time.sleep(0.05)
                continue
            Path(ready).touch()
            break
        return server.wait()


if __name__ == "__main__":
    sys.exit(main())
