#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MultiTunnel Relay Manager
Production-oriented manager for transparent TCP/UDP forwarding from a public
entry node to relay and final servers using GOST v3 or FRP.

Supported engines
-----------------
GOST v3.2.6
  - relay+tls / relay+mtls
  - relay+wss / relay+mwss
  - relay+quic
  - relay+kcp (encrypted KCP)
  - relay+dtls
  - TCP and UDP payloads
  - multi-hop chains and final pools

FRP v0.70.0
  - tcp / kcp / quic / websocket control transports
    (frps cannot terminate wss itself; it needs an external TLS reverse proxy)
  - TLS 1.2+ with mutual certificate verification
  - wire protocol v2 (AEAD)
  - TCP and UDP proxies
  - TCP load-balancing groups and health checks

The program deliberately keeps one systemd unit per service. This isolates
faults and allows independent rollback, logs, restart and health checks.
"""
from __future__ import annotations

import argparse
import getpass
import datetime as dt
import hashlib
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tarfile
import threading
import socketserver
import tempfile
import textwrap
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

APP = "multitunnel"
VERSION = "2.2.0"

ETC = Path(os.environ.get("MTM_ETC", "/etc/multitunnel-manager"))
STATE = ETC / "state.json"
SERVICES = ETC / "services.json"
GENERATED = ETC / "generated"
PKI = ETC / "pki"
SECRETS = ETC / "secrets"
BACKUPS = ETC / "backups"
BIN_DIR = Path(os.environ.get("MTM_BIN", "/opt/multitunnel/bin"))
SYSTEMD_DIR = Path(os.environ.get("MTM_SYSTEMD", "/etc/systemd/system"))
RUN_USER = "mtunnel"
RUN_GROUP = "mtunnel"

GOST_VERSION = "3.2.6"
FRP_VERSION = "0.70.0"

GOST_SHA256 = {
    "linux_amd64": "b39037b0380ea001fb3c0c28441c2e10bfc694f90682739a65b53e55dce5238b",
    "linux_amd64v3": "86d81065dc02c39f085d93f0d8f93ba63da3e00bfa98deab9e9d8a9994c20ed2",
    "linux_arm64": "f674c8f4a033dc1dfd4f0d5e9602fbe5b0d0f81307bf3794f44b5b5d6d622eae",
}
FRP_SHA256 = {
    "linux_amd64": "281cb31e6b915113179c6ebb65b5977a5d9d7fb96f9a70867be83dee3b657721",
    "linux_arm64": "9dd282fd8d1b90a8ee760702ac5b876748b519c6bdfac7c68418f62a05d805c6",
}

ROLES = {"entry", "relay", "final"}
ENGINES = {"gost", "frp"}
PAYLOADS = {"tcp", "udp"}
GOST_TRANSPORTS = {"tls", "mtls", "wss", "mwss", "quic", "kcp", "dtls"}
FRP_TRANSPORTS = {"tcp", "kcp", "quic", "websocket"}
TLS_GOST_TRANSPORTS = {"tls", "mtls", "wss", "mwss", "quic", "dtls"}
UDP_GOST_TRANSPORTS = {"quic", "kcp", "dtls"}
UDP_FRP_TRANSPORTS = {"kcp", "quic"}


class MTMError(RuntimeError):
    pass


def color(text: str, code: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"\033[{code}m{text}\033[0m"


def info(msg: str) -> None:
    print(color("[INFO] ", "36") + msg)


def ok(msg: str) -> None:
    print(color("[OK] ", "32") + msg)


def warn(msg: str) -> None:
    print(color("[WARN] ", "33") + msg)


def fail(msg: str) -> None:
    raise MTMError(msg)


def require_root() -> None:
    if os.geteuid() != 0 and not os.environ.get("MTM_ALLOW_NONROOT"):
        fail("Run as root")


def run(cmd: Sequence[str], *, check: bool = True, capture: bool = False,
        input_text: Optional[str] = None, env: Optional[Dict[str, str]] = None) -> subprocess.CompletedProcess[str]:
    p = subprocess.run(
        list(cmd), text=True, input=input_text,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
        check=False, env=env,
    )
    if check and p.returncode != 0:
        detail = (p.stderr or p.stdout or "").strip()
        raise MTMError(f"Command failed ({p.returncode}): {' '.join(cmd)}\n{detail}")
    return p


def command_exists(name: str) -> bool:
    return shutil.which(name) is not None


def now_stamp() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d-%H%M%S-%fZ")


def mkdirs() -> None:
    for p in (ETC, GENERATED, PKI, SECRETS, BACKUPS, BIN_DIR):
        p.mkdir(parents=True, exist_ok=True)
    if not SERVICES.exists():
        write_json(SERVICES, [])
    for p in (ETC, GENERATED, PKI, SECRETS, BACKUPS):
        try:
            os.chmod(p, 0o750)
        except PermissionError:
            pass


def atomic_write(path: Path, content: str, mode: int = 0o640) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        fail(f"Invalid JSON {path}: {e}")


def write_json(path: Path, obj: Any, mode: int = 0o640) -> None:
    atomic_write(path, json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n", mode)


def clean_name(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9_-]", "", value.strip())
    if not value:
        fail("Empty or invalid service name")
    return value[:64]


def valid_port(value: Any) -> int:
    try:
        p = int(value)
    except Exception:
        fail(f"Invalid port: {value}")
    if p < 1 or p > 65535:
        fail(f"Port out of range: {p}")
    return p


def valid_host(value: str) -> str:
    value = value.strip()
    if not value:
        fail("Host cannot be empty")
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass
    if len(value) > 253 or not re.fullmatch(r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", value):
        fail(f"Invalid host: {value}")
    return value.lower()


def random_secret(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def load_state() -> Dict[str, Any]:
    st = read_json(STATE, {})
    if not st:
        fail("Manager is not initialized. Run: multitunnel init --role entry|relay|final")
    if st.get("role") not in ROLES:
        fail("Invalid role in state.json")
    return st


def load_services() -> List[Dict[str, Any]]:
    data = read_json(SERVICES, [])
    if not isinstance(data, list):
        fail("services.json must contain an array")
    return data


def save_services(items: List[Dict[str, Any]]) -> None:
    write_json(SERVICES, items, 0o640)


def ensure_run_user() -> None:
    if os.environ.get("MTM_TEST_MODE"):
        return
    if run(["getent", "group", RUN_GROUP], check=False, capture=True).returncode != 0:
        run(["groupadd", "--system", RUN_GROUP])
    if run(["id", "-u", RUN_USER], check=False, capture=True).returncode != 0:
        run(["useradd", "--system", "--gid", RUN_GROUP, "--home", "/nonexistent", "--shell", "/usr/sbin/nologin", RUN_USER])
    for p in (ETC, GENERATED, PKI, SECRETS, BIN_DIR):
        run(["chgrp", "-R", RUN_GROUP, str(p)], check=False)
    run(["chmod", "-R", "g+rX", str(ETC), str(BIN_DIR)], check=False)


def install_deps() -> None:
    require_root()
    if not command_exists("apt-get"):
        fail("Only Debian/Ubuntu apt-based systems are currently supported")
    run(["apt-get", "update"])
    run(["apt-get", "install", "-y", "curl", "ca-certificates", "tar", "openssl", "iproute2", "python3", "tcpdump", "netcat-openbsd"])


def machine_arch() -> Tuple[str, str]:
    m = os.uname().machine
    if m == "x86_64":
        return "amd64", "linux_amd64"
    if m in {"aarch64", "arm64"}:
        return "arm64", "linux_arm64"
    fail(f"Unsupported architecture: {m}")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def download(url: str, output: Path, expected_sha256: str) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    run(["curl", "-fL", "--retry", "4", "--retry-delay", "2", url, "-o", str(output)])
    got = sha256_file(output)
    if got.lower() != expected_sha256.lower():
        output.unlink(missing_ok=True)
        fail(f"Checksum mismatch for {url}\nexpected={expected_sha256}\nactual={got}")


def install_gost() -> None:
    require_root()
    mkdirs()
    arch, key = machine_arch()
    asset = f"gost_{GOST_VERSION}_linux_{arch}.tar.gz"
    url = f"https://github.com/go-gost/gost/releases/download/v{GOST_VERSION}/{asset}"
    with tempfile.TemporaryDirectory(prefix="mtm-gost-") as td:
        archive = Path(td) / asset
        download(url, archive, GOST_SHA256[key])
        with tarfile.open(archive, "r:gz") as tf:
            tf.extractall(td, filter="data")
        candidates = list(Path(td).rglob("gost"))
        candidates = [p for p in candidates if p.is_file()]
        if not candidates:
            fail("gost binary not found in release archive")
        shutil.copy2(candidates[0], BIN_DIR / "gost")
        os.chmod(BIN_DIR / "gost", 0o755)
    p = run([str(BIN_DIR / "gost"), "-V"], capture=True)
    ok((p.stdout or p.stderr).strip())


def install_frp() -> None:
    require_root()
    mkdirs()
    arch, key = machine_arch()
    asset = f"frp_{FRP_VERSION}_linux_{arch}.tar.gz"
    url = f"https://github.com/fatedier/frp/releases/download/v{FRP_VERSION}/{asset}"
    with tempfile.TemporaryDirectory(prefix="mtm-frp-") as td:
        archive = Path(td) / asset
        download(url, archive, FRP_SHA256[key])
        with tarfile.open(archive, "r:gz") as tf:
            tf.extractall(td, filter="data")
        for binary in ("frpc", "frps"):
            candidates = [p for p in Path(td).rglob(binary) if p.is_file()]
            if not candidates:
                fail(f"{binary} not found in release archive")
            shutil.copy2(candidates[0], BIN_DIR / binary)
            os.chmod(BIN_DIR / binary, 0o755)
    ok(run([str(BIN_DIR / "frpc"), "--version"], capture=True).stdout.strip())


def install_engine(engine: str) -> None:
    if engine == "gost":
        install_gost()
    elif engine == "frp":
        install_frp()
    else:
        fail(f"Unsupported engine: {engine}")
    ensure_run_user()


def backup() -> Path:
    mkdirs()
    target = BACKUPS / now_stamp()
    target.mkdir(parents=True, exist_ok=False)
    for p in (STATE, SERVICES):
        if p.exists():
            shutil.copy2(p, target / p.name)
    for d in (GENERATED, PKI, SECRETS):
        if d.exists():
            shutil.copytree(d, target / d.name, dirs_exist_ok=True)
    units = target / "units"
    units.mkdir()
    for p in SYSTEMD_DIR.glob("multitunnel-*.service"):
        shutil.copy2(p, units / p.name)
    return target


def init_manager(role: str) -> None:
    require_root()
    if role not in ROLES:
        fail("role must be entry, relay or final")
    mkdirs()
    node_id = socket.gethostname().split(".")[0] + "-" + secrets.token_hex(3)
    write_json(STATE, {
        "version": VERSION,
        "role": role,
        "node_id": node_id,
        "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
    })
    ensure_run_user()
    ok(f"Initialized role={role} node_id={node_id}")


def openssl(*args: str) -> None:
    run(["openssl", *args])


def certificate_sans(hosts: Iterable[str]) -> str:
    entries: List[str] = []
    dns_i = ip_i = 1
    for host in dict.fromkeys(hosts):
        try:
            ipaddress.ip_address(host)
            entries.append(f"IP.{ip_i} = {host}")
            ip_i += 1
        except ValueError:
            entries.append(f"DNS.{dns_i} = {host}")
            dns_i += 1
    if not entries:
        entries.append("DNS.1 = localhost")
    return "\n".join(entries)


def make_ca_and_certs(base: Path, server_hosts: List[str], need_client: bool) -> Dict[str, Path]:
    base.mkdir(parents=True, exist_ok=True)
    ca_key = base / "ca.key"
    ca_crt = base / "ca.crt"
    openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(ca_key))
    openssl("req", "-x509", "-new", "-sha256", "-days", "3650", "-key", str(ca_key),
            "-out", str(ca_crt), "-subj", "/CN=MultiTunnel Private CA")

    server_key = base / "server.key"
    server_csr = base / "server.csr"
    server_crt = base / "server.crt"
    server_ext = base / "server.ext"
    common_name = server_hosts[0] if server_hosts else "multitunnel-server"
    server_ext.write_text(textwrap.dedent(f"""\
        basicConstraints = CA:FALSE
        keyUsage = digitalSignature, keyEncipherment
        extendedKeyUsage = serverAuth
        subjectAltName = @alt_names
        [alt_names]
        {certificate_sans(server_hosts)}
    """), encoding="utf-8")
    openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(server_key))
    openssl("req", "-new", "-sha256", "-key", str(server_key), "-out", str(server_csr),
            "-subj", f"/CN={common_name}")
    openssl("x509", "-req", "-sha256", "-days", "825", "-in", str(server_csr),
            "-CA", str(ca_crt), "-CAkey", str(ca_key), "-CAcreateserial",
            "-out", str(server_crt), "-extfile", str(server_ext))

    result = {"ca": ca_crt, "ca_key": ca_key, "server_crt": server_crt, "server_key": server_key}
    if need_client:
        client_key = base / "client.key"
        client_csr = base / "client.csr"
        client_crt = base / "client.crt"
        client_ext = base / "client.ext"
        client_ext.write_text(textwrap.dedent("""\
            basicConstraints = CA:FALSE
            keyUsage = digitalSignature, keyEncipherment
            extendedKeyUsage = clientAuth
        """), encoding="utf-8")
        openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(client_key))
        openssl("req", "-new", "-sha256", "-key", str(client_key), "-out", str(client_csr),
                "-subj", "/CN=multitunnel-client")
        openssl("x509", "-req", "-sha256", "-days", "825", "-in", str(client_csr),
                "-CA", str(ca_crt), "-CAkey", str(ca_key), "-CAcreateserial",
                "-out", str(client_crt), "-extfile", str(client_ext))
        result.update({"client_crt": client_crt, "client_key": client_key})
    for p in base.iterdir():
        if p.suffix == ".key":
            os.chmod(p, 0o600)
    return result



def make_ca(base: Path) -> Dict[str, Path]:
    """Create one private CA used by every bundle in a deployment pair."""
    base.mkdir(parents=True, exist_ok=True)
    ca_key = base / "ca.key"
    ca_crt = base / "ca.crt"
    openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(ca_key))
    openssl("req", "-x509", "-new", "-sha256", "-days", "3650", "-key", str(ca_key),
            "-out", str(ca_crt), "-subj", "/CN=MultiTunnel Private CA")
    os.chmod(ca_key, 0o600)
    return {"ca": ca_crt, "ca_key": ca_key}


def make_server_cert(base: Path, ca_crt: Path, ca_key: Path, hosts: List[str], stem: str = "server") -> Dict[str, Path]:
    """Issue a server-only certificate with exact DNS/IP SANs."""
    base.mkdir(parents=True, exist_ok=True)
    key = base / f"{stem}.key"
    csr = base / f"{stem}.csr"
    crt = base / f"{stem}.crt"
    ext = base / f"{stem}.ext"
    cn = hosts[0] if hosts else "multitunnel-server"
    ext.write_text(textwrap.dedent(f"""\
        basicConstraints = critical,CA:FALSE
        keyUsage = critical,digitalSignature,keyEncipherment
        extendedKeyUsage = serverAuth
        subjectAltName = @alt_names
        [alt_names]
        {certificate_sans(hosts)}
    """), encoding="utf-8")
    openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(key))
    openssl("req", "-new", "-sha256", "-key", str(key), "-out", str(csr), "-subj", f"/CN={cn}")
    openssl("x509", "-req", "-sha256", "-days", "825", "-in", str(csr),
            "-CA", str(ca_crt), "-CAkey", str(ca_key), "-CAcreateserial",
            "-out", str(crt), "-extfile", str(ext))
    os.chmod(key, 0o600)
    return {"server_crt": crt, "server_key": key}


def safe_host_filename(host: str) -> str:
    value = re.sub(r"[^A-Za-z0-9_.-]", "_", host)
    return value[:180] or "server"

def parse_hops(value: str) -> List[List[str]]:
    """Parse semicolon-separated hop pools: relayA,relayB;finalA,finalB."""
    hops: List[List[str]] = []
    for group in value.split(";"):
        nodes = [valid_host(x) for x in re.split(r"[,\s]+", group.strip()) if x]
        if nodes:
            hops.append(nodes)
    if not hops:
        fail("At least one server/final host is required")
    return hops


def bundle_write(path: Path, service: Dict[str, Any], files: Dict[str, Path]) -> None:
    with tempfile.TemporaryDirectory(prefix="mtm-bundle-") as td:
        root = Path(td)
        write_json(root / "service.json", service, 0o600)
        manifest: Dict[str, str] = {"service.json": sha256_file(root / "service.json")}
        pki_dir = root / "pki"
        pki_dir.mkdir()
        for name, source in files.items():
            dest = pki_dir / name
            shutil.copy2(source, dest)
            if dest.suffix == ".key":
                os.chmod(dest, 0o600)
            manifest[f"pki/{name}"] = sha256_file(dest)
        write_json(root / "manifest.json", {"format": "multitunnel-bundle-v1", "version": VERSION, "files": manifest}, 0o600)
        with tarfile.open(path, "w:gz") as tf:
            tf.add(root / "service.json", arcname="service.json")
            tf.add(root / "manifest.json", arcname="manifest.json")
            for f in pki_dir.iterdir():
                tf.add(f, arcname=f"pki/{f.name}")
    os.chmod(path, 0o600)


def pair_gost(args: argparse.Namespace) -> List[Path]:
    name = clean_name(args.name)
    payload = args.payload
    transport = args.transport
    if payload not in PAYLOADS or transport not in GOST_TRANSPORTS:
        fail("Invalid GOST payload/transport")
    hops = parse_hops(args.hops)
    if transport in UDP_GOST_TRANSPORTS and len(hops) > 1:
        fail("GOST QUIC/KCP/DTLS can only be used as a single hop. Use TLS/MTLS/WSS/MWSS for multi-hop chains")
    unique_hosts = list(dict.fromkeys(host for hop in hops for host in hop))
    listen_port = valid_port(args.listen_port)
    tunnel_port = valid_port(args.tunnel_port)
    local_port = valid_port(args.final_local_port)
    local_ip = valid_host(args.final_local_ip)
    out_dir = Path(args.output).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    username = args.username or ("mt-" + secrets.token_hex(6))
    password = args.secret or random_secret(32)
    server_name_override = valid_host(args.server_name) if args.server_name else None
    path = args.path or f"/{secrets.token_urlsafe(12)}"
    if not path.startswith("/"):
        path = "/" + path

    with tempfile.TemporaryDirectory(prefix="mtm-pair-gost-") as td:
        root = Path(td)
        ca = make_ca(root / "ca")
        common = {
            "schema": 1,
            "name": name,
            "engine": "gost",
            "payload": payload,
            "transport": transport,
            "listen_port": listen_port,
            "tunnel_port": tunnel_port,
            "final_local_ip": local_ip,
            "final_local_port": local_port,
            "hops": hops,
            "auth_user": username,
            "auth_secret": password,
            "server_name": server_name_override,
            "ws_path": path,
            "kcp_profile": args.kcp_profile,
            "enabled": True,
        }
        entry = dict(common, bundle_role="entry")
        entry_path = out_dir / f"mtm-{name}-gost-entry.tar.gz"
        bundle_write(entry_path, entry, {"ca.crt": ca["ca"]})
        outputs = [entry_path]
        for host in unique_hosts:
            cert_names = [host]
            if server_name_override and server_name_override not in cert_names:
                cert_names.append(server_name_override)
            certs = make_server_cert(root / f"server-{safe_host_filename(host)}", ca["ca"], ca["ca_key"], cert_names)
            server = dict(common, bundle_role="server", server_host=host)
            server_path = out_dir / f"mtm-{name}-gost-server-{safe_host_filename(host)}.tar.gz"
            bundle_write(server_path, server, {
                "ca.crt": ca["ca"], "server.crt": certs["server_crt"], "server.key": certs["server_key"]
            })
            outputs.append(server_path)
    return outputs

def pair_frp(args: argparse.Namespace) -> List[Path]:
    name = clean_name(args.name)
    payload = args.payload
    transport = args.transport
    if payload not in PAYLOADS or transport not in FRP_TRANSPORTS:
        fail("Invalid FRP payload/transport")
    entry_host = valid_host(args.entry_host)
    listen_port = valid_port(args.listen_port)
    tunnel_port = valid_port(args.tunnel_port)
    local_port = valid_port(args.final_local_port)
    local_ip = valid_host(args.final_local_ip)
    out_dir = Path(args.output).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    token = args.secret or random_secret(40)
    group_key = args.group_key or random_secret(24)

    with tempfile.TemporaryDirectory(prefix="mtm-pair-frp-") as td:
        certs = make_ca_and_certs(Path(td) / "certs", [entry_host], need_client=True)
        common = {
            "schema": 1,
            "name": name,
            "engine": "frp",
            "payload": payload,
            "transport": transport,
            "entry_host": entry_host,
            "listen_port": listen_port,
            "tunnel_port": tunnel_port,
            "final_local_ip": local_ip,
            "final_local_port": local_port,
            "auth_secret": token,
            "server_name": args.server_name or entry_host,
            "wire_protocol": "v2",
            "load_balance": bool(args.load_balance),
            "group": args.group or f"mtm-{name}",
            "group_key": group_key,
            "enabled": True,
        }
        if payload == "udp" and common["load_balance"]:
            fail("FRP load balancing is supported for TCP, not UDP")
        entry = dict(common, bundle_role="entry")
        final = dict(common, bundle_role="final")
        entry_path = out_dir / f"mtm-{name}-frp-entry.tar.gz"
        final_path = out_dir / f"mtm-{name}-frp-final.tar.gz"
        bundle_write(entry_path, entry, {
            "ca.crt": certs["ca"], "server.crt": certs["server_crt"], "server.key": certs["server_key"]
        })
        bundle_write(final_path, final, {
            "ca.crt": certs["ca"], "client.crt": certs["client_crt"], "client.key": certs["client_key"]
        })
    return [entry_path, final_path]


def verify_bundle(bundle: Path, extract_dir: Path) -> Dict[str, Any]:
    safe_extract_archive(bundle, extract_dir, max_total_size=64 * 1024 * 1024)
    manifest = read_json(extract_dir / "manifest.json", {})
    if manifest.get("format") not in {None, "multitunnel-bundle-v1"}:
        fail("Unsupported bundle manifest format")
    if not isinstance(manifest.get("files"), dict):
        fail("Bundle manifest is missing or invalid")
    for rel, expected in manifest.get("files", {}).items():
        p = extract_dir / rel
        if not p.exists() or not p.is_file() or sha256_file(p) != expected:
            fail(f"Bundle checksum failed: {rel}")
    service = read_json(extract_dir / "service.json", {})
    if service.get("schema") != 1 or service.get("engine") not in ENGINES:
        fail("Unsupported or invalid bundle")
    return service


def validate_service(service: Dict[str, Any], role: str) -> None:
    service["name"] = clean_name(str(service.get("name", "")))
    if service.get("engine") not in ENGINES:
        fail("Invalid engine")
    if service.get("payload") not in PAYLOADS:
        fail("Invalid payload")
    service["listen_port"] = valid_port(service["listen_port"])
    service["tunnel_port"] = valid_port(service["tunnel_port"])
    service["final_local_ip"] = valid_host(service["final_local_ip"])
    service["final_local_port"] = valid_port(service["final_local_port"])
    if service["engine"] == "gost":
        if service.get("transport") not in GOST_TRANSPORTS:
            fail("Invalid GOST transport")
        service["hops"] = [[valid_host(x) for x in hop] for hop in service.get("hops", [])]
        if not service["hops"]:
            fail("GOST service requires hops")
        if service["transport"] in UDP_GOST_TRANSPORTS and len(service["hops"]) > 1:
            fail("GOST QUIC/KCP/DTLS multi-hop chains are unsupported; use a single hop or a TCP-based transport")
    else:
        if service.get("transport") not in FRP_TRANSPORTS:
            fail("Invalid FRP transport")
        service["entry_host"] = valid_host(service["entry_host"])
        if role == "relay":
            fail("FRP engine does not support relay role")
        if service["payload"] == "udp" and service.get("load_balance"):
            fail("FRP UDP load balancing is unsupported")


def import_bundle(bundle_path: str, replace: bool) -> None:
    require_root()
    mkdirs()
    state = load_state()
    bundle = Path(bundle_path).expanduser().resolve()
    if not bundle.exists():
        fail(f"Bundle not found: {bundle}")
    old_items = load_services()
    with tempfile.TemporaryDirectory(prefix="mtm-import-") as td:
        root = Path(td)
        service = verify_bundle(bundle, root)
        role = state["role"]
        bundle_role = service.get("bundle_role")
        if service["engine"] == "gost":
            expected = "entry" if role == "entry" else "server"
        else:
            expected = role
        if bundle_role != expected:
            fail(f"Bundle role={bundle_role}, but this node role={role}; expected bundle role={expected}")
        validate_service(service, role)
        name = service["name"]
        dest_pki = PKI / name
        existing = next((x for x in old_items if x.get("name") == name), None)
        if existing and not replace:
            fail(f"Service {name} already exists; use --replace")
        if dest_pki.exists() and not replace:
            fail(f"PKI for {name} already exists; use --replace")

        old_pki = root / "old-pki"
        if dest_pki.exists():
            shutil.copytree(dest_pki, old_pki)
        try:
            if dest_pki.exists():
                shutil.rmtree(dest_pki)
            shutil.copytree(root / "pki", dest_pki)
            for file in dest_pki.rglob("*"):
                if file.is_file():
                    os.chmod(file, 0o600 if file.suffix == ".key" else 0o640)
            service.pop("bundle_role", None)
            service["pki_dir"] = str(dest_pki)
            items = [x for x in old_items if x.get("name") != name]
            items.append(service)
            save_services(items)
            ensure_run_user()
            rebuild(names=[name])
        except Exception:
            save_services(old_items)
            shutil.rmtree(dest_pki, ignore_errors=True)
            if old_pki.exists():
                shutil.copytree(old_pki, dest_pki)
                for file in dest_pki.rglob("*"):
                    if file.is_file():
                        os.chmod(file, 0o600 if file.suffix == ".key" else 0o640)
            raise
    ok(f"Imported and started: {service['name']}")

def gost_kcp_config(profile: str, secret: str) -> Dict[str, Any]:
    profiles = {
        "stable": {"mode": "normal", "mtu": 1250, "sndwnd": 512, "rcvwnd": 512, "datashard": 10, "parityshard": 3, "nodelay": 0, "interval": 40, "resend": 0, "nc": 0},
        "balanced": {"mode": "fast", "mtu": 1250, "sndwnd": 1024, "rcvwnd": 1024, "datashard": 10, "parityshard": 3, "nodelay": 1, "interval": 30, "resend": 1, "nc": 0},
        "fast": {"mode": "fast2", "mtu": 1200, "sndwnd": 2048, "rcvwnd": 2048, "datashard": 10, "parityshard": 4, "nodelay": 1, "interval": 20, "resend": 2, "nc": 1},
    }
    cfg = dict(profiles.get(profile, profiles["balanced"]))
    cfg.update({
        "key": hashlib.sha256(secret.encode()).hexdigest(),
        "crypt": "aes",
        "nocomp": True,
        "acknodelay": True,
        "sockbuf": 8 * 1024 * 1024,
        "smuxbuf": 8 * 1024 * 1024,
        "streambuf": 2 * 1024 * 1024,
        "smuxver": 2,
        "keepalive": 10,
    })
    return cfg


def gost_tls(role: str, service: Dict[str, Any], server_name: Optional[str] = None) -> Dict[str, Any]:
    pki = Path(service["pki_dir"])
    if role == "entry":
        expected_name = server_name or service.get("server_name")
        if not expected_name:
            fail("Missing TLS server name for GOST client")
        return {"caFile": str(pki / "ca.crt"), "secure": True, "serverName": expected_name, "minVersion": "VersionTLS12"}
    return {"certFile": str(pki / "server.crt"), "keyFile": str(pki / "server.key"), "minVersion": "VersionTLS12"}

def gost_transport_metadata(service: Dict[str, Any]) -> Dict[str, Any]:
    t = service["transport"]
    if t in {"wss", "mwss"}:
        cfg: Dict[str, Any] = {
            "path": service.get("ws_path", "/ws"),
            "compression": False,
            "readBufferSize": 65536,
            "writeBufferSize": 65536,
            "handshakeTimeout": "10s",
        }
        if t == "mwss":
            cfg.update({
                "mux.version": 2,
                "mux.keepaliveInterval": "10s",
                "mux.keepaliveTimeout": "30s",
                "mux.maxFrameSize": 32768,
                "mux.maxReceiveBuffer": 8 * 1024 * 1024,
                "mux.maxStreamBuffer": 256 * 1024,
            })
        return cfg
    if t == "mtls":
        return {
            "mux.version": 2,
            "mux.keepaliveInterval": "10s",
            "mux.keepaliveTimeout": "30s",
            "mux.maxFrameSize": 32768,
            "mux.maxReceiveBuffer": 8 * 1024 * 1024,
            "mux.maxStreamBuffer": 256 * 1024,
        }
    if t == "quic":
        return {"keepalive": True, "ttl": "10s", "handshakeTimeout": "8s", "maxIdleTimeout": "45s"}
    if t == "kcp":
        return {"config": gost_kcp_config(service.get("kcp_profile", "balanced"), service["auth_secret"])}
    return {}


def build_gost_config(role: str, service: Dict[str, Any]) -> Dict[str, Any]:
    name = service["name"]
    transport = service["transport"]
    metadata = gost_transport_metadata(service)
    if role in {"relay", "final"}:
        listener: Dict[str, Any] = {"type": transport}
        if transport in TLS_GOST_TRANSPORTS:
            listener["tls"] = gost_tls(role, service)
        if metadata:
            listener["metadata"] = metadata
        return {
            "log": {"level": "info", "format": "json", "output": "stderr"},
            "services": [{
                "name": name,
                "addr": f":{service['tunnel_port']}",
                "handler": {
                    "type": "relay",
                    "auth": {"username": service["auth_user"], "password": service["auth_secret"]},
                    "metadata": {"nodelay": True, "udpBufferSize": 65535},
                },
                "listener": listener,
            }],
        }

    chain_hops: List[Dict[str, Any]] = []
    for hop_idx, hosts in enumerate(service["hops"]):
        nodes: List[Dict[str, Any]] = []
        for node_idx, host in enumerate(hosts):
            dialer: Dict[str, Any] = {"type": transport}
            if transport in TLS_GOST_TRANSPORTS:
                dialer["tls"] = gost_tls(role, service, service.get("server_name") or host)
            if metadata:
                dialer["metadata"] = metadata
            nodes.append({
                "name": f"hop{hop_idx}-node{node_idx}",
                "addr": f"{host}:{service['tunnel_port']}",
                "connector": {
                    "type": "relay",
                    "auth": {"username": service["auth_user"], "password": service["auth_secret"]},
                    "metadata": {"nodelay": True},
                },
                "dialer": dialer,
            })
        chain_hops.append({
            "name": f"hop-{hop_idx}",
            "selector": {"strategy": "round", "maxFails": 2, "failTimeout": "20s"},
            "nodes": nodes,
        })
    return {
        "log": {"level": "info", "format": "json", "output": "stderr"},
        "services": [{
            "name": name,
            "addr": f":{service['listen_port']}",
            "handler": {"type": service["payload"], "chain": f"chain-{name}"},
            "listener": {"type": service["payload"]},
            "forwarder": {"nodes": [{"name": "target", "addr": f"{service['final_local_ip']}:{service['final_local_port']}"}]},
        }],
        "chains": [{"name": f"chain-{name}", "hops": chain_hops}],
    }


def toml_quote(value: str) -> str:
    return json.dumps(str(value), ensure_ascii=True)


def build_frps_toml(service: Dict[str, Any]) -> str:
    pki = Path(service["pki_dir"])
    transport = service["transport"]
    lines = [
        f"bindAddr = {toml_quote('0.0.0.0')}",
        f"bindPort = {service['tunnel_port']}",
        f"proxyBindAddr = {toml_quote('0.0.0.0')}",
        f"auth.method = {toml_quote('token')}",
        f"auth.token = {toml_quote(service['auth_secret'])}",
        'auth.additionalScopes = ["HeartBeats", "NewWorkConns"]',
        'transport.tcpMux = true',
        'transport.tcpMuxKeepaliveInterval = 20',
        'transport.maxPoolCount = 10',
        'transport.tls.force = true',
        f"transport.tls.certFile = {toml_quote(str(pki / 'server.crt'))}",
        f"transport.tls.keyFile = {toml_quote(str(pki / 'server.key'))}",
        f"transport.tls.trustedCaFile = {toml_quote(str(pki / 'ca.crt'))}",
        f"allowPorts = [{{ single = {service['listen_port']} }}]",
        'log.to = "console"',
        'log.level = "info"',
    ]
    if transport == "kcp":
        lines.append(f"kcpBindPort = {service['tunnel_port']}")
    if transport == "quic":
        lines.append(f"quicBindPort = {service['tunnel_port']}")
    return "\n".join(lines) + "\n"


def build_frpc_toml(service: Dict[str, Any], state: Dict[str, Any]) -> str:
    pki = Path(service["pki_dir"])
    node_id = clean_name(state["node_id"])
    proxy_name = f"{service['name']}-{node_id}"
    lines = [
        f"serverAddr = {toml_quote(service['entry_host'])}",
        f"serverPort = {service['tunnel_port']}",
        f"auth.method = {toml_quote('token')}",
        f"auth.token = {toml_quote(service['auth_secret'])}",
        'auth.additionalScopes = ["HeartBeats", "NewWorkConns"]',
        f"transport.protocol = {toml_quote(service['transport'])}",
        f"transport.wireProtocol = {toml_quote(service.get('wire_protocol', 'v2'))}",
        'transport.tcpMux = true',
        'transport.tcpMuxKeepaliveInterval = 20',
        'transport.poolCount = 2',
        'transport.heartbeatInterval = 10',
        'transport.heartbeatTimeout = 60',
        'transport.tls.enable = true',
        f"transport.tls.certFile = {toml_quote(str(pki / 'client.crt'))}",
        f"transport.tls.keyFile = {toml_quote(str(pki / 'client.key'))}",
        f"transport.tls.trustedCaFile = {toml_quote(str(pki / 'ca.crt'))}",
        f"transport.tls.serverName = {toml_quote(service['server_name'])}",
    ]
    if service["transport"] == "quic":
        lines += [
            'transport.quic.keepalivePeriod = 10',
            'transport.quic.maxIdleTimeout = 45',
            'transport.quic.maxIncomingStreams = 100000',
        ]
    lines += [
        'log.to = "console"',
        'log.level = "info"',
        '',
        '[[proxies]]',
        f"name = {toml_quote(proxy_name)}",
        f"type = {toml_quote(service['payload'])}",
        f"localIP = {toml_quote(service['final_local_ip'])}",
        f"localPort = {service['final_local_port']}",
        f"remotePort = {service['listen_port']}",
        'transport.useEncryption = false',
        'transport.useCompression = false',
    ]
    if service["payload"] == "tcp":
        lines += [
            'healthCheck.type = "tcp"',
            'healthCheck.timeoutSeconds = 3',
            'healthCheck.maxFailed = 3',
            'healthCheck.intervalSeconds = 10',
        ]
        if service.get("load_balance"):
            lines += [
                f"loadBalancer.group = {toml_quote(service['group'])}",
                f"loadBalancer.groupKey = {toml_quote(service['group_key'])}",
            ]
    return "\n".join(lines) + "\n"

def unit_name(service: Dict[str, Any]) -> str:
    return f"multitunnel-{service['engine']}-{clean_name(service['name'])}.service"


def config_path(service: Dict[str, Any], role: str) -> Path:
    ext = "json" if service["engine"] == "gost" else "toml"
    return GENERATED / f"{service['engine']}-{service['name']}-{role}.{ext}"


def binary_for(service: Dict[str, Any], role: str) -> Path:
    if service["engine"] == "gost":
        return BIN_DIR / "gost"
    return BIN_DIR / ("frps" if role == "entry" else "frpc")


def systemd_unit(service: Dict[str, Any], role: str, cfg: Path) -> str:
    binary = binary_for(service, role)
    if service["engine"] == "gost":
        exec_start = f"{binary} -C {cfg}"
    else:
        exec_start = f"{binary} -c {cfg}"
    return textwrap.dedent(f"""\
        [Unit]
        Description=MultiTunnel {service['engine'].upper()} service {service['name']}
        After=network-online.target
        Wants=network-online.target
        StartLimitIntervalSec=60
        StartLimitBurst=10

        [Service]
        Type=simple
        User={RUN_USER}
        Group={RUN_GROUP}
        ExecStart={exec_start}
        Restart=always
        RestartSec=2s
        LimitNOFILE=1048576
        NoNewPrivileges=true
        PrivateTmp=true
        PrivateDevices=true
        ProtectSystem=strict
        ProtectHome=true
        ProtectKernelTunables=true
        ProtectKernelModules=true
        ProtectControlGroups=true
        RestrictSUIDSGID=true
        RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
        LockPersonality=true
        MemoryDenyWriteExecute=true
        CapabilityBoundingSet=CAP_NET_BIND_SERVICE
        AmbientCapabilities=CAP_NET_BIND_SERVICE
        SystemCallArchitectures=native
        UMask=0027

        [Install]
        WantedBy=multi-user.target
    """)

def verify_config(service: Dict[str, Any], role: str, cfg: Path) -> None:
    binary = binary_for(service, role)
    if not binary.exists():
        fail(f"Engine binary missing: {binary}. Run: multitunnel install-engine {service['engine']}")
    if service["engine"] == "gost":
        p = run([str(binary), "-C", str(cfg), "-O", "json"], check=False, capture=True)
    else:
        p = run([str(binary), "verify", "-c", str(cfg)], check=False, capture=True)
    if p.returncode != 0:
        fail(f"Configuration verification failed for {service['name']}:\n{(p.stderr or p.stdout).strip()}")


def port_conflicts(items: List[Dict[str, Any]], role: str) -> None:
    seen: Dict[Tuple[str, int], str] = {}
    for s in items:
        if not s.get("enabled", True):
            continue
        proto = "udp" if ((s["engine"] == "gost" and s["transport"] in UDP_GOST_TRANSPORTS and role != "entry") or
                          (s["engine"] == "frp" and s["transport"] in UDP_FRP_TRANSPORTS and role == "entry")) else "tcp"
        ports: List[Tuple[str, int, str]] = []
        if role == "entry":
            if s["engine"] == "gost":
                ports.append((s["payload"], s["listen_port"], s["name"] + ":client-listen"))
            else:
                ports.append((proto, s["tunnel_port"], s["name"] + ":frps-control"))
                ports.append((s["payload"], s["listen_port"], s["name"] + ":frps-proxy"))
        elif s["engine"] == "gost":
            ports.append((proto, s["tunnel_port"], s["name"] + ":gost-tunnel"))
        for pproto, pport, label in ports:
            key = (pproto, int(pport))
            if key in seen:
                fail(f"Port conflict {pproto}/{pport}: {seen[key]} and {label}")
            seen[key] = label


def rebuild(names: Optional[List[str]] = None, restart: bool = True) -> None:
    require_root()
    mkdirs()
    st = load_state()
    role = st["role"]
    items = load_services()
    for s in items:
        validate_service(s, role)
    port_conflicts(items, role)
    backup()
    ensure_run_user()

    selected = [s for s in items if not names or s["name"] in names]
    for s in selected:
        cfg = config_path(s, role)
        unit = SYSTEMD_DIR / unit_name(s)
        if not s.get("enabled", True):
            if restart and not os.environ.get("MTM_TEST_MODE"):
                run(["systemctl", "disable", "--now", unit_name(s)], check=False)
            continue

        old_cfg = cfg.read_bytes() if cfg.exists() else None
        old_unit = unit.read_bytes() if unit.exists() else None
        try:
            if s["engine"] == "gost":
                write_json(cfg, build_gost_config(role, s), 0o640)
            else:
                if role == "entry":
                    content = build_frps_toml(s)
                elif role == "final":
                    content = build_frpc_toml(s, st)
                else:
                    fail("FRP cannot run on relay role")
                atomic_write(cfg, content, 0o640)
            verify_config(s, role, cfg)
            atomic_write(unit, systemd_unit(s, role, cfg), 0o644)
            if restart and not os.environ.get("MTM_TEST_MODE"):
                run(["systemctl", "daemon-reload"])
                run(["systemctl", "enable", unit.name])
                run(["systemctl", "restart", unit.name])
                p = run(["systemctl", "is-active", unit.name], check=False, capture=True)
                if p.stdout.strip() != "active":
                    fail(f"Service failed to become active: {unit.name}")
        except Exception:
            if old_cfg is None:
                cfg.unlink(missing_ok=True)
            else:
                cfg.write_bytes(old_cfg)
                os.chmod(cfg, 0o640)
            if old_unit is None:
                unit.unlink(missing_ok=True)
            else:
                unit.write_bytes(old_unit)
                os.chmod(unit, 0o644)
            if restart and not os.environ.get("MTM_TEST_MODE"):
                run(["systemctl", "daemon-reload"], check=False)
                if old_unit is not None:
                    run(["systemctl", "restart", unit.name], check=False)
                else:
                    run(["systemctl", "disable", "--now", unit.name], check=False)
            raise
    ok("All selected configurations verified and rebuilt")

def show_services() -> None:
    print(json.dumps(load_services(), ensure_ascii=False, indent=2))


def set_enabled(name: str, enabled: bool) -> None:
    require_root()
    name = clean_name(name)
    old_items = load_services()
    items = json.loads(json.dumps(old_items))
    found = False
    for service in items:
        if service.get("name") == name:
            service["enabled"] = enabled
            found = True
    if not found:
        fail(f"Service not found: {name}")
    save_services(items)
    try:
        rebuild(names=[name])
    except Exception:
        save_services(old_items)
        raise


def remove_service(name: str) -> None:
    require_root()
    name = clean_name(name)
    items = load_services()
    target = next((s for s in items if s.get("name") == name), None)
    if not target:
        fail(f"Service not found: {name}")
    if not os.environ.get("MTM_TEST_MODE"):
        run(["systemctl", "disable", "--now", unit_name(target)], check=False)
    (SYSTEMD_DIR / unit_name(target)).unlink(missing_ok=True)
    for p in GENERATED.glob(f"*-{name}-*.*"):
        p.unlink(missing_ok=True)
    shutil.rmtree(PKI / name, ignore_errors=True)
    save_services([s for s in items if s.get("name") != name])
    if not os.environ.get("MTM_TEST_MODE"):
        run(["systemctl", "daemon-reload"])
    ok(f"Removed: {name}")


def service_status(name: Optional[str] = None) -> None:
    st = load_state()
    items = load_services()
    print(json.dumps(st, ensure_ascii=False, indent=2))
    for s in items:
        if name and s["name"] != name:
            continue
        unit = unit_name(s)
        if os.environ.get("MTM_TEST_MODE"):
            active = "test-mode"
        else:
            p = run(["systemctl", "is-active", unit], check=False, capture=True)
            active = p.stdout.strip() or "inactive"
        print(f"{s['name']}: engine={s['engine']} payload={s['payload']} transport={s['transport']} enabled={s.get('enabled', True)} state={active}")
        cfg = config_path(s, st["role"])
        print(f"  config={cfg}")


def tcp_probe(host: str, port: int, timeout: float = 3.0) -> Tuple[bool, str]:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, "connected"
    except OSError as e:
        return False, str(e)


def health() -> None:
    st = load_state()
    role = st["role"]
    bad = 0
    for s in load_services():
        if not s.get("enabled", True):
            continue
        print(f"[{s['name']}] {s['engine']} {s['payload']}/{s['transport']}")
        if not os.environ.get("MTM_TEST_MODE"):
            p = run(["systemctl", "is-active", unit_name(s)], check=False, capture=True)
            print(f"  systemd: {p.stdout.strip()}")
            if p.stdout.strip() != "active":
                bad += 1
        if role == "entry" and s["engine"] == "gost":
            for idx, hop in enumerate(s["hops"]):
                for host in hop:
                    if s["transport"] in UDP_GOST_TRANSPORTS:
                        print(f"  hop{idx} {host}:{s['tunnel_port']}/udp: listener cannot be validated with TCP probe")
                    else:
                        good, detail = tcp_probe(host, s["tunnel_port"])
                        print(f"  hop{idx} {host}:{s['tunnel_port']}/tcp: {'OK' if good else 'FAIL'} {detail}")
                        bad += 0 if good else 1
        elif role == "final" and s["engine"] in {"gost", "frp"} and s["payload"] == "tcp":
            good, detail = tcp_probe(s["final_local_ip"], s["final_local_port"])
            print(f"  local target: {'OK' if good else 'FAIL'} {detail}")
            bad += 0 if good else 1
    if bad:
        fail(f"Health check found {bad} problem(s)")
    ok("Health check passed")


def doctor() -> None:
    st = load_state()
    role = st["role"]
    print(f"role={role} version={VERSION}")
    for engine, binaries in {"gost": ["gost"], "frp": ["frpc", "frps"]}.items():
        paths = [BIN_DIR / x for x in binaries]
        print(f"{engine}: " + ("installed" if all(p.exists() for p in paths) else "missing"))
    items = load_services()
    for s in items:
        validate_service(s, role)
        cfg = config_path(s, role)
        print(f"{s['name']}: config={'present' if cfg.exists() else 'missing'} unit={unit_name(s)}")
        if cfg.exists() and binary_for(s, role).exists():
            verify_config(s, role, cfg)
            print("  syntax: OK")
    port_conflicts(items, role)
    print("port conflicts: none")


def export_all(output: str) -> None:
    require_root()
    mkdirs()
    out = Path(output).expanduser().resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mtm-export-") as td:
        root = Path(td)
        for source, name in ((STATE, "state.json"), (SERVICES, "services.json")):
            if not source.exists():
                fail(f"Required manager file is missing: {source}")
            shutil.copy2(source, root / name)
        for source, name in ((PKI, "pki"), (SECRETS, "secrets")):
            if source.exists():
                shutil.copytree(source, root / name)
        write_json(root / "manifest.json", {
            "format": "multitunnel-export-v1",
            "manager_version": VERSION,
            "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "files": _tree_hashes(root),
        }, 0o600)
        with tarfile.open(out, "w:gz") as tf:
            for child in sorted(root.iterdir()):
                tf.add(child, arcname=child.name)
    os.chmod(out, 0o600)
    ok(f"Exported and checksummed: {out}")




def uninstall_manager(purge: bool = False) -> None:
    require_root()
    items = load_services() if SERVICES.exists() else []
    if not os.environ.get("MTM_TEST_MODE"):
        for service in items:
            run(["systemctl", "disable", "--now", unit_name(service)], check=False)
        for unit in SYSTEMD_DIR.glob("multitunnel-*.service"):
            unit.unlink(missing_ok=True)
        run(["systemctl", "daemon-reload"], check=False)
    Path("/usr/local/sbin/multitunnel").unlink(missing_ok=True)
    shutil.rmtree("/opt/multitunnel-manager", ignore_errors=True)
    if purge:
        shutil.rmtree(ETC, ignore_errors=True)
        shutil.rmtree(BIN_DIR.parent, ignore_errors=True)
        if not os.environ.get("MTM_TEST_MODE"):
            run(["userdel", RUN_USER], check=False)
        ok("Manager, engines, configuration and PKI removed")
    else:
        ok(f"Manager removed; configuration preserved in {ETC}. Use --purge to remove all data")

def free_local_port(socktype: int = socket.SOCK_STREAM) -> int:
    with socket.socket(socket.AF_INET, socktype) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class _TCPEchoHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        while True:
            data = self.request.recv(65536)
            if not data:
                return
            self.request.sendall(data)


class _ReusableTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def wait_tcp_port(host: str, port: int, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    last = "not ready"
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return
        except OSError as e:
            last = str(e)
            time.sleep(0.1)
    fail(f"Timed out waiting for {host}:{port}: {last}")


def stop_process(proc: subprocess.Popen[Any]) -> None:
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=4)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=2)


def process_log_tail(path: Path, lines: int = 80) -> str:
    if not path.exists():
        return ""
    return "\n".join(path.read_text(encoding="utf-8", errors="replace").splitlines()[-lines:])


def launch_checked(cmd: Sequence[str], log_path: Path) -> Tuple[subprocess.Popen[Any], Any]:
    log_file = log_path.open("w", encoding="utf-8")
    proc = subprocess.Popen(list(cmd), stdout=log_file, stderr=subprocess.STDOUT, text=True)
    time.sleep(0.35)
    if proc.poll() is not None:
        log_file.close()
        fail(f"Process exited during startup: {' '.join(cmd)}\n{process_log_tail(log_path)}")
    return proc, log_file


def echo_roundtrip(port: int) -> None:
    payload = secrets.token_bytes(32768)
    with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
        s.settimeout(8)
        s.sendall(payload)
        received = bytearray()
        while len(received) < len(payload):
            chunk = s.recv(min(65536, len(payload) - len(received)))
            if not chunk:
                break
            received.extend(chunk)
    if bytes(received) != payload:
        fail(f"End-to-end payload mismatch: sent={len(payload)} received={len(received)}")


def selftest_gost(transport: str = "tls") -> None:
    if transport not in GOST_TRANSPORTS:
        fail(f"Unsupported GOST self-test transport: {transport}")
    binary = BIN_DIR / "gost"
    if not binary.exists():
        fail("GOST binary is not installed. Run: multitunnel install-engine gost")
    if not command_exists("openssl"):
        fail("openssl is required for self-test")
    with tempfile.TemporaryDirectory(prefix="mtm-selftest-gost-") as td:
        root = Path(td)
        pki = root / "pki"
        ca = make_ca(root / "ca")
        certs = make_server_cert(root / "server-cert", ca["ca"], ca["ca_key"], ["127.0.0.1"])
        pki.mkdir()
        shutil.copy2(ca["ca"], pki / "ca.crt")
        shutil.copy2(certs["server_crt"], pki / "server.crt")
        shutil.copy2(certs["server_key"], pki / "server.key")
        echo_port = free_local_port()
        tunnel_port = free_local_port(socket.SOCK_DGRAM if transport in UDP_GOST_TRANSPORTS else socket.SOCK_STREAM)
        listen_port = free_local_port()
        service = {
            "name": "selftest", "engine": "gost", "payload": "tcp", "transport": transport,
            "listen_port": listen_port, "tunnel_port": tunnel_port,
            "final_local_ip": "127.0.0.1", "final_local_port": echo_port,
            "hops": [["127.0.0.1"]], "auth_user": "selftest",
            "auth_secret": random_secret(24), "server_name": None,
            "ws_path": "/selftest-" + secrets.token_hex(6), "kcp_profile": "balanced",
            "pki_dir": str(pki), "enabled": True,
        }
        server_cfg = root / "server.json"
        client_cfg = root / "client.json"
        write_json(server_cfg, build_gost_config("final", service), 0o600)
        write_json(client_cfg, build_gost_config("entry", service), 0o600)
        verify_config(service, "final", server_cfg)
        verify_config(service, "entry", client_cfg)
        server_log = root / "gost-server.log"
        client_log = root / "gost-client.log"
        with _ReusableTCPServer(("127.0.0.1", echo_port), _TCPEchoHandler) as echo:
            thread = threading.Thread(target=echo.serve_forever, daemon=True)
            thread.start()
            server = client = None
            server_fh = client_fh = None
            try:
                server, server_fh = launch_checked([str(binary), "-C", str(server_cfg)], server_log)
                if transport not in UDP_GOST_TRANSPORTS:
                    wait_tcp_port("127.0.0.1", tunnel_port, 8)
                client, client_fh = launch_checked([str(binary), "-C", str(client_cfg)], client_log)
                wait_tcp_port("127.0.0.1", listen_port, 10)
                echo_roundtrip(listen_port)
            except Exception as e:
                detail = f"\n--- GOST server ---\n{process_log_tail(server_log)}\n--- GOST client ---\n{process_log_tail(client_log)}"
                raise MTMError(f"GOST {transport} integration test failed: {e}{detail}") from e
            finally:
                if client is not None: stop_process(client)
                if server is not None: stop_process(server)
                if client_fh is not None: client_fh.close()
                if server_fh is not None: server_fh.close()
                echo.shutdown()
                thread.join(timeout=2)
    ok(f"GOST {transport} real end-to-end self-test passed")


def selftest_frp(transport: str = "tcp") -> None:
    if transport not in FRP_TRANSPORTS:
        fail(f"Unsupported FRP self-test transport: {transport}")
    frps = BIN_DIR / "frps"
    frpc = BIN_DIR / "frpc"
    if not frps.exists() or not frpc.exists():
        fail("FRP binaries are not installed. Run: multitunnel install-engine frp")
    if not command_exists("openssl"):
        fail("openssl is required for self-test")
    with tempfile.TemporaryDirectory(prefix="mtm-selftest-frp-") as td:
        root = Path(td)
        certs = make_ca_and_certs(root / "certs", ["127.0.0.1"], need_client=True)
        pki = root / "pki"
        pki.mkdir()
        for dst, src in {
            "ca.crt": certs["ca"], "server.crt": certs["server_crt"], "server.key": certs["server_key"],
            "client.crt": certs["client_crt"], "client.key": certs["client_key"],
        }.items():
            shutil.copy2(src, pki / dst)
        echo_port = free_local_port()
        tunnel_port = free_local_port(socket.SOCK_DGRAM if transport in UDP_FRP_TRANSPORTS else socket.SOCK_STREAM)
        listen_port = free_local_port()
        service = {
            "name": "selftest", "engine": "frp", "payload": "tcp", "transport": transport,
            "entry_host": "127.0.0.1", "listen_port": listen_port, "tunnel_port": tunnel_port,
            "final_local_ip": "127.0.0.1", "final_local_port": echo_port,
            "auth_secret": random_secret(32), "server_name": "127.0.0.1", "wire_protocol": "v2",
            "load_balance": False, "group": "selftest", "group_key": random_secret(16),
            "pki_dir": str(pki), "enabled": True,
        }
        server_cfg = root / "frps.toml"
        client_cfg = root / "frpc.toml"
        atomic_write(server_cfg, build_frps_toml(service), 0o600)
        atomic_write(client_cfg, build_frpc_toml(service, {"node_id": "selftest-node"}), 0o600)
        verify_config(service, "entry", server_cfg)
        verify_config(service, "final", client_cfg)
        server_log = root / "frps.log"
        client_log = root / "frpc.log"
        with _ReusableTCPServer(("127.0.0.1", echo_port), _TCPEchoHandler) as echo:
            thread = threading.Thread(target=echo.serve_forever, daemon=True)
            thread.start()
            server = client = None
            server_fh = client_fh = None
            try:
                server, server_fh = launch_checked([str(frps), "-c", str(server_cfg)], server_log)
                if transport not in UDP_FRP_TRANSPORTS:
                    wait_tcp_port("127.0.0.1", tunnel_port, 8)
                client, client_fh = launch_checked([str(frpc), "-c", str(client_cfg)], client_log)
                wait_tcp_port("127.0.0.1", listen_port, 12)
                echo_roundtrip(listen_port)
            except Exception as e:
                detail = f"\n--- FRPS ---\n{process_log_tail(server_log)}\n--- FRPC ---\n{process_log_tail(client_log)}"
                raise MTMError(f"FRP {transport} integration test failed: {e}{detail}") from e
            finally:
                if client is not None: stop_process(client)
                if server is not None: stop_process(server)
                if client_fh is not None: client_fh.close()
                if server_fh is not None: server_fh.close()
                echo.shutdown()
                thread.join(timeout=2)
    ok(f"FRP {transport} real end-to-end self-test passed")


def selftest(engine: str, gost_transport: str, frp_transport: str) -> None:
    if engine in {"gost", "all"}:
        selftest_gost(gost_transport)
    if engine in {"frp", "all"}:
        selftest_frp(frp_transport)

def ask_text(label: str, default: Optional[str] = None, *, required: bool = False) -> str:
    suffix = f" [{default}]" if default not in (None, "") else ""
    while True:
        value = input(f"{label}{suffix}: ").strip()
        if not value and default is not None:
            return str(default)
        if value or not required:
            return value
        warn("A value is required")


def ask_port(label: str, default: Optional[int] = None) -> int:
    while True:
        raw = ask_text(label, str(default) if default is not None else None, required=True)
        try:
            return valid_port(raw)
        except MTMError as e:
            warn(str(e))


def ask_choice(label: str, choices: Sequence[Tuple[str, str]], default: Optional[str] = None) -> str:
    valid = {key: text for key, text in choices}
    while True:
        print(f"\n{label}")
        for key, text in choices:
            marker = " (default)" if key == default else ""
            print(f"  {key}) {text}{marker}")
        value = input("Select: ").strip() or (default or "")
        if value in valid:
            return value
        warn("Invalid selection")


def ask_yes_no(label: str, default: bool = False) -> bool:
    suffix = "Y/n" if default else "y/N"
    while True:
        value = input(f"{label} [{suffix}]: ").strip().lower()
        if not value:
            return default
        if value in {"y", "yes"}:
            return True
        if value in {"n", "no"}:
            return False
        warn("Enter yes or no")


def select_service(*, allow_all: bool = False) -> Optional[Dict[str, Any]]:
    items = load_services()
    if not items:
        fail("No services are configured")
    print("\nConfigured services")
    if allow_all:
        print("  0) All services")
    for idx, service in enumerate(items, 1):
        state = "enabled" if service.get("enabled", True) else "disabled"
        print(f"  {idx}) {service['name']}  {service['engine']}  {service['payload']}/{service['transport']}  {state}")
    while True:
        raw = input("Select service: ").strip()
        if allow_all and raw == "0":
            return None
        try:
            idx = int(raw)
            if 1 <= idx <= len(items):
                return items[idx - 1]
        except ValueError:
            pass
        match = next((x for x in items if x.get("name") == raw), None)
        if match:
            return match
        warn("Invalid service selection")


def service_summary(service: Dict[str, Any]) -> str:
    rows = [
        f"Name: {service['name']}",
        f"Engine: {service['engine'].upper()}",
        f"Payload: {service['payload'].upper()}",
        f"Transport: {service['transport'].upper()}",
        f"Entry listen port: {service['listen_port']}",
        f"Tunnel port: {service['tunnel_port']}",
        f"Final target: {service['final_local_ip']}:{service['final_local_port']}",
    ]
    if service["engine"] == "gost":
        rows.append("Hops: " + "; ".join(",".join(group) for group in service.get("hops", [])))
        if service.get("server_name"):
            rows.append(f"TLS server name override: {service['server_name']}")
        if service.get("ws_path"):
            rows.append(f"WebSocket path: {service['ws_path']}")
        if service.get("transport") == "kcp":
            rows.append(f"KCP profile: {service.get('kcp_profile', 'balanced')}")
    else:
        rows.append(f"Entry host: {service['entry_host']}")
        rows.append(f"Load balancing: {'enabled' if service.get('load_balance') else 'disabled'}")
    return "\n".join(rows)


def wizard_create_pair() -> List[Path]:
    if not command_exists("openssl"):
        fail("openssl is required to generate deployment bundles")

    engine_key = ask_choice("Tunnel engine", [("1", "GOST"), ("2", "FRP")], "1")
    engine = "gost" if engine_key == "1" else "frp"
    preset_key = ask_choice("Service preset", [
        ("1", "OpenVPN TCP"),
        ("2", "OpenVPN UDP"),
        ("3", "WireGuard / game UDP"),
        ("4", "Xray TCP"),
        ("5", "Xray UDP"),
        ("6", "Custom TCP"),
        ("7", "Custom UDP"),
    ], "1")
    presets = {
        "1": ("openvpn_tcp", "tcp"),
        "2": ("openvpn_udp", "udp"),
        "3": ("wireguard_game", "udp"),
        "4": ("xray_tcp", "tcp"),
        "5": ("xray_udp", "udp"),
        "6": ("custom_tcp", "tcp"),
        "7": ("custom_udp", "udp"),
    }
    default_name, payload = presets[preset_key]
    name = clean_name(ask_text("Service name", default_name, required=True))

    if engine == "gost":
        if payload == "udp":
            transport_choices = [
                ("dtls", "DTLS - lowest overhead for native UDP"),
                ("quic", "QUIC - resilient session over UDP"),
                ("kcp", "KCP - aggressive recovery for lossy links"),
                ("tls", "TLS - TCP fallback"),
                ("mtls", "Multiplexed TLS - TCP fallback"),
                ("wss", "WebSocket over TLS"),
                ("mwss", "Multiplexed WebSocket over TLS"),
            ]
            default_transport = "dtls"
        else:
            transport_choices = [
                ("quic", "QUIC - avoids TCP-over-TCP"),
                ("kcp", "KCP - lossy-link profile"),
                ("dtls", "DTLS - UDP transport"),
                ("tls", "TLS - stable TCP transport"),
                ("mtls", "Multiplexed TLS"),
                ("wss", "WebSocket over TLS"),
                ("mwss", "Multiplexed WebSocket over TLS"),
            ]
            default_transport = "quic"
    else:
        transport_choices = [
            ("quic", "QUIC"),
            ("kcp", "KCP"),
            ("tcp", "TCP with mutual TLS"),
            ("websocket", "WebSocket with mutual TLS"),
        ]
        default_transport = "quic"
    transport = ask_choice("Transport", transport_choices, default_transport)

    default_listen = 51820 if preset_key == "3" else 9001
    listen_port = ask_port("Public listen port on the entry server", default_listen)
    tunnel_port = ask_port("Tunnel port between nodes", 8443)
    final_local_ip = valid_host(ask_text("Final local service IP", "127.0.0.1", required=True))
    final_local_port = ask_port("Final local service port", default_listen)
    output = ask_text("Bundle output directory", "/root/multitunnel-bundles", required=True)

    kwargs: Dict[str, Any] = {
        "engine": engine,
        "name": name,
        "payload": payload,
        "transport": transport,
        "listen_port": listen_port,
        "tunnel_port": tunnel_port,
        "final_local_ip": final_local_ip,
        "final_local_port": final_local_port,
        "secret": None,
        "server_name": None,
        "output": output,
        "hops": None,
        "username": None,
        "path": None,
        "kcp_profile": "balanced",
        "entry_host": None,
        "load_balance": False,
        "group": None,
        "group_key": None,
    }

    if engine == "gost":
        if transport in UDP_GOST_TRANSPORTS:
            kwargs["hops"] = ask_text("Final server IP or hostname", required=True)
        else:
            print("Enter one pool per hop. Separate nodes with commas and hops with semicolons.")
            print("Example: relay1,relay2;final1,final2")
            kwargs["hops"] = ask_text("GOST hop pools", required=True)
        parse_hops(kwargs["hops"])
        if transport == "kcp":
            kwargs["kcp_profile"] = ask_choice("KCP profile", [
                ("stable", "Stable"), ("balanced", "Balanced"), ("fast", "Fast")
            ], "balanced")
        if transport in {"wss", "mwss"}:
            kwargs["path"] = ask_text("WebSocket path", f"/{secrets.token_urlsafe(10)}", required=True)
        if ask_yes_no("Configure advanced authentication or TLS values", False):
            kwargs["username"] = ask_text("Relay username", "mt-" + secrets.token_hex(6), required=True)
            custom_secret = getpass.getpass("Relay password (leave empty to generate): ").strip()
            kwargs["secret"] = custom_secret or None
            server_name = ask_text("TLS server name override (optional)")
            kwargs["server_name"] = server_name or None
    else:
        kwargs["entry_host"] = valid_host(ask_text("Entry server IP or hostname", required=True))
        if payload == "tcp":
            kwargs["load_balance"] = ask_yes_no("Enable FRP TCP load balancing", False)
        if ask_yes_no("Configure advanced FRP values", False):
            server_name = ask_text("TLS server name", kwargs["entry_host"])
            kwargs["server_name"] = server_name or None
            custom_secret = getpass.getpass("FRP authentication token (leave empty to generate): ").strip()
            kwargs["secret"] = custom_secret or None
            if kwargs["load_balance"]:
                kwargs["group"] = ask_text("Load-balancer group", f"mtm-{name}", required=True)
                custom_group_key = getpass.getpass("Load-balancer group key (leave empty to generate): ").strip()
                kwargs["group_key"] = custom_group_key or None

    args = argparse.Namespace(**kwargs)
    preview = {
        "name": name,
        "engine": engine,
        "payload": payload,
        "transport": transport,
        "listen_port": listen_port,
        "tunnel_port": tunnel_port,
        "final_local_ip": final_local_ip,
        "final_local_port": final_local_port,
    }
    if engine == "gost":
        preview["hops"] = parse_hops(str(kwargs["hops"]))
    else:
        preview["entry_host"] = kwargs["entry_host"]
        preview["load_balance"] = kwargs["load_balance"]
    print("\nDeployment summary")
    print(service_summary(preview))
    print(f"Bundle directory: {Path(output).expanduser().resolve()}")
    if not ask_yes_no("Generate deployment bundles", True):
        warn("Bundle generation cancelled")
        return []

    paths = pair_gost(args) if engine == "gost" else pair_frp(args)
    print("\nGenerated bundles")
    for path in paths:
        ok(str(path))

    if STATE.exists() and ask_yes_no("Import a generated bundle on this node now", False):
        state = load_state()
        role = state["role"]
        candidates: List[Path] = []
        if engine == "gost":
            if role == "entry":
                candidates = [p for p in paths if p.name.endswith("-gost-entry.tar.gz")]
            else:
                candidates = [p for p in paths if "-gost-server-" in p.name]
        elif role in {"entry", "final"}:
            candidates = [p for p in paths if p.name.endswith(f"-frp-{role}.tar.gz")]
        if not candidates:
            warn(f"No generated bundle matches the local role: {role}")
        else:
            if len(candidates) == 1:
                selected = candidates[0]
            else:
                selected_key = ask_choice("Bundle to import", [(str(i), p.name) for i, p in enumerate(candidates, 1)], "1")
                selected = candidates[int(selected_key) - 1]
            engine_binary = binary_for({"engine": engine}, role)
            if not engine_binary.exists() and ask_yes_no(f"{engine.upper()} is not installed. Install it now", True):
                install_deps()
                install_engine(engine)
            replace = any(x.get("name") == name for x in load_services())
            if replace:
                replace = ask_yes_no(f"Service {name} exists. Replace it", False)
                if not replace:
                    return paths
            import_bundle(str(selected), replace=replace)
    return paths


def edit_service(name: str, updates: Dict[str, Any]) -> None:
    require_root()
    state = load_state()
    role = state["role"]
    old_items = load_services()
    items = json.loads(json.dumps(old_items))
    service = next((x for x in items if x.get("name") == clean_name(name)), None)
    if not service:
        fail(f"Service not found: {name}")
    for key, value in updates.items():
        if value is not None:
            service[key] = value
    validate_service(service, role)
    port_conflicts(items, role)
    save_services(items)
    try:
        rebuild(names=[service["name"]])
    except Exception:
        save_services(old_items)
        raise
    ok(f"Updated: {service['name']}")


def wizard_edit_service() -> None:
    current = select_service()
    assert current is not None
    edited = json.loads(json.dumps(current))
    print("\nPress Enter to keep the current value.")
    edited["payload"] = ask_choice("Payload protocol", [("tcp", "TCP"), ("udp", "UDP")], edited["payload"])
    if edited["engine"] == "gost":
        edited["transport"] = ask_choice("GOST transport", [(x, x.upper()) for x in sorted(GOST_TRANSPORTS)], edited["transport"])
    else:
        edited["transport"] = ask_choice("FRP transport", [(x, x.upper()) for x in sorted(FRP_TRANSPORTS)], edited["transport"])
    edited["listen_port"] = ask_port("Entry server public listen port", int(edited["listen_port"]))
    edited["tunnel_port"] = ask_port("Inter-node tunnel port", int(edited["tunnel_port"]))
    edited["final_local_ip"] = valid_host(ask_text("Final local service IP", str(edited["final_local_ip"]), required=True))
    edited["final_local_port"] = ask_port("Final local service port", int(edited["final_local_port"]))
    if edited["engine"] == "gost":
        old_hops = ";".join(",".join(group) for group in edited.get("hops", []))
        hops_text = ask_text("GOST hop pools", old_hops, required=True)
        edited["hops"] = parse_hops(hops_text)
        edited["server_name"] = ask_text("TLS server name override", edited.get("server_name") or "") or None
        if edited["transport"] in {"wss", "mwss"}:
            edited["ws_path"] = ask_text("WebSocket path", edited.get("ws_path") or "/ws", required=True)
        if edited["transport"] == "kcp":
            edited["kcp_profile"] = ask_choice("KCP profile", [
                ("stable", "Stable"), ("balanced", "Balanced"), ("fast", "Fast")
            ], edited.get("kcp_profile", "balanced"))
    else:
        edited["entry_host"] = valid_host(ask_text("Entry server IP or hostname", edited["entry_host"], required=True))
        edited["server_name"] = ask_text("TLS server name", edited.get("server_name") or edited["entry_host"], required=True)
        if edited["payload"] == "tcp":
            edited["load_balance"] = ask_yes_no("Enable FRP TCP load balancing", bool(edited.get("load_balance")))
        else:
            edited["load_balance"] = False
        if edited.get("load_balance"):
            edited["group"] = ask_text("Load-balancer group", edited.get("group") or f"mtm-{edited['name']}", required=True)
    print("\nUpdated service summary")
    print(service_summary(edited))
    if ask_yes_no("Apply this configuration", False):
        updates = {key: value for key, value in edited.items() if current.get(key) != value}
        if not updates:
            warn("No changes were made")
            return
        edit_service(current["name"], updates)
    else:
        warn("Edit cancelled")


def service_logs(name: str, lines: int = 80, follow: bool = False) -> None:
    service = next((x for x in load_services() if x.get("name") == clean_name(name)), None)
    if not service:
        fail(f"Service not found: {name}")
    unit = unit_name(service)
    if os.environ.get("MTM_TEST_MODE"):
        print(f"journalctl -u {unit} -n {lines}" + (" -f" if follow else ""))
        return
    cmd = ["journalctl", "-u", unit, "-n", str(max(1, lines))]
    if follow:
        cmd.append("-f")
    else:
        cmd.append("--no-pager")
    try:
        run(cmd, check=False)
    except KeyboardInterrupt:
        print()


def list_backups() -> List[Path]:
    mkdirs()
    return sorted((p for p in BACKUPS.iterdir() if p.is_dir()), reverse=True)


def _replace_tree(source: Path, destination: Path) -> None:
    shutil.rmtree(destination, ignore_errors=True)
    if source.exists():
        shutil.copytree(source, destination)
    else:
        destination.mkdir(parents=True, exist_ok=True)


def _apply_snapshot(source: Path) -> None:
    if not (source / "state.json").exists() or not (source / "services.json").exists():
        fail("Backup does not contain state.json and services.json")
    mkdirs()
    shutil.copy2(source / "state.json", STATE)
    shutil.copy2(source / "services.json", SERVICES)
    for name, destination in (("pki", PKI), ("secrets", SECRETS)):
        _replace_tree(source / name, destination)
    shutil.rmtree(GENERATED, ignore_errors=True)
    GENERATED.mkdir(parents=True, exist_ok=True)
    if not os.environ.get("MTM_TEST_MODE"):
        for unit in SYSTEMD_DIR.glob("multitunnel-*.service"):
            run(["systemctl", "disable", "--now", unit.name], check=False)
            unit.unlink(missing_ok=True)
        run(["systemctl", "daemon-reload"], check=False)
    ensure_run_user()
    rebuild()


def restore_backup(snapshot: str) -> None:
    require_root()
    source = Path(snapshot)
    if not source.is_absolute():
        source = BACKUPS / source
    source = source.resolve()
    backups_root = BACKUPS.resolve()
    if source == backups_root or backups_root not in source.parents or not source.is_dir():
        fail("Invalid backup snapshot")
    safety = backup()
    try:
        _apply_snapshot(source)
    except Exception:
        warn(f"Restore failed. Rolling back to {safety.name}")
        _apply_snapshot(safety)
        raise
    ok(f"Restored automatic backup: {source.name}")


def safe_extract_archive(archive: Path, destination: Path, *, max_total_size: int = 512 * 1024 * 1024) -> None:
    total = 0
    with tarfile.open(archive, "r:gz") as tf:
        for member in tf.getmembers():
            if member.name.startswith("/"):
                fail("Archive contains an absolute path")
            resolved = (destination / member.name).resolve()
            if destination.resolve() not in resolved.parents and resolved != destination.resolve():
                fail("Unsafe path in archive")
            if member.issym() or member.islnk() or not (member.isdir() or member.isfile()):
                fail("Archive contains an unsupported entry type")
            total += max(0, member.size)
            if total > max_total_size:
                fail("Archive exceeds the maximum allowed size")
        try:
            tf.extractall(destination, filter="data")
        except TypeError:
            tf.extractall(destination)


def _tree_hashes(root: Path) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.name != "manifest.json":
            result[str(path.relative_to(root))] = sha256_file(path)
    return result


def restore_export(archive_path: str) -> None:
    require_root()
    archive = Path(archive_path).expanduser().resolve()
    if not archive.is_file():
        fail(f"Backup archive not found: {archive}")
    with tempfile.TemporaryDirectory(prefix="mtm-restore-") as td:
        root = Path(td)
        safe_extract_archive(archive, root)
        manifest = read_json(root / "manifest.json", {})
        if manifest.get("format") != "multitunnel-export-v1":
            fail("Unsupported or missing backup manifest")
        expected = manifest.get("files")
        if not isinstance(expected, dict) or not expected:
            fail("Backup manifest does not contain file checksums")
        actual = _tree_hashes(root)
        if actual != expected:
            fail("Backup checksum verification failed")
        safety = backup()
        try:
            _apply_snapshot(root)
        except Exception:
            warn(f"Restore failed. Rolling back to {safety.name}")
            _apply_snapshot(safety)
            raise
    ok(f"Restored exported backup: {archive}")


def menu_status_and_logs() -> None:
    action = ask_choice("Status and logs", [
        ("1", "Show all service status"),
        ("2", "Show one service status"),
        ("3", "Show recent service logs"),
        ("4", "Follow service logs"),
    ], "1")
    if action == "1":
        service_status()
    else:
        service = select_service()
        assert service is not None
        if action == "2":
            service_status(service["name"])
        elif action == "3":
            lines = int(ask_text("Number of log lines", "80", required=True))
            service_logs(service["name"], lines=lines)
        else:
            print("Press Ctrl+C to stop following logs.")
            service_logs(service["name"], lines=80, follow=True)


def menu_selftest() -> None:
    engine_key = ask_choice("Self-test engine", [("1", "GOST"), ("2", "FRP"), ("3", "Both")], "1")
    engine = {"1": "gost", "2": "frp", "3": "all"}[engine_key]
    gost_transport = "tls"
    frp_transport = "tcp"
    if engine in {"gost", "all"}:
        gost_transport = ask_choice("GOST self-test transport", [(x, x.upper()) for x in sorted(GOST_TRANSPORTS)], "tls")
    if engine in {"frp", "all"}:
        frp_transport = ask_choice("FRP self-test transport", [(x, x.upper()) for x in sorted(FRP_TRANSPORTS)], "tcp")
    selftest(engine, gost_transport, frp_transport)


def menu_restore() -> None:
    kind = ask_choice("Restore source", [("1", "Automatic snapshot"), ("2", "Exported tar.gz archive")], "1")
    if kind == "2":
        archive = ask_text("Backup archive path", required=True)
        if ask_yes_no("Restore this archive and restart all services", False):
            restore_export(archive)
        return
    snapshots = list_backups()
    if not snapshots:
        fail("No automatic backups are available")
    selected = ask_choice("Automatic backup", [(str(i), p.name) for i, p in enumerate(snapshots, 1)], "1")
    snapshot = snapshots[int(selected) - 1]
    if ask_yes_no(f"Restore snapshot {snapshot.name} and restart all services", False):
        restore_backup(snapshot.name)


def menu() -> None:
    options = {
        "1": "Initialize node",
        "2": "Create deployment bundles (guided wizard)",
        "3": "Install GOST",
        "4": "Install FRP",
        "5": "Import service bundle",
        "6": "List services",
        "7": "Edit service",
        "8": "Enable or disable service",
        "9": "Remove service",
        "10": "Rebuild or restart services",
        "11": "Status and logs",
        "12": "Health check",
        "13": "Doctor and validation",
        "14": "Real end-to-end self-test",
        "15": "Export configuration backup",
        "16": "Restore backup",
        "17": "Uninstall manager",
        "0": "Exit",
    }
    while True:
        print(f"\nMultiTunnel Relay Manager {VERSION}")
        for key, text in options.items():
            print(f"{key}) {text}")
        choice = input("Select [0]: ").strip() or "0"
        try:
            if choice == "0":
                return
            if choice == "1":
                role_key = ask_choice("Node role", [("entry", "Entry node (public listen port)"), ("relay", "GOST relay node"), ("final", "Final service node")], "entry")
                init_manager(role_key)
            elif choice == "2":
                wizard_create_pair()
            elif choice == "3":
                install_deps(); install_engine("gost")
            elif choice == "4":
                install_deps(); install_engine("frp")
            elif choice == "5":
                path = ask_text("Bundle path", required=True)
                replace = ask_yes_no("Replace a service with the same name", False)
                import_bundle(path, replace=replace)
            elif choice == "6":
                show_services()
            elif choice == "7":
                wizard_edit_service()
            elif choice == "8":
                service = select_service()
                assert service is not None
                enable = not bool(service.get("enabled", True))
                action = "Enable" if enable else "Disable"
                if ask_yes_no(f"{action} {service['name']}", False):
                    set_enabled(service["name"], enable)
            elif choice == "9":
                service = select_service()
                assert service is not None
                if ask_yes_no(f"Permanently remove {service['name']} and its local PKI", False):
                    remove_service(service["name"])
            elif choice == "10":
                service = select_service(allow_all=True)
                rebuild(names=None if service is None else [service["name"]])
            elif choice == "11":
                menu_status_and_logs()
            elif choice == "12":
                health()
            elif choice == "13":
                doctor()
            elif choice == "14":
                menu_selftest()
            elif choice == "15":
                default_output = f"/root/multitunnel-backup-{now_stamp()}.tar.gz"
                export_all(ask_text("Output tar.gz path", default_output, required=True))
            elif choice == "16":
                menu_restore()
            elif choice == "17":
                purge = ask_yes_no("Also remove engines, configuration, certificates and backups", False)
                confirmation = ask_text("Type UNINSTALL to continue")
                if confirmation == "UNINSTALL":
                    uninstall_manager(purge)
                    return
                warn("Uninstall cancelled")
            else:
                warn("Unknown option")
        except MTMError as e:
            print(color(f"[ERR] {e}", "31"), file=sys.stderr)
        except EOFError:
            return
        except KeyboardInterrupt:
            print("\nReturning to the main menu")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog=APP, description="Production multi-tunnel relay manager")
    p.add_argument("--version", action="version", version=VERSION)
    sp = p.add_subparsers(dest="cmd")

    initp = sp.add_parser("init", help="Initialize this node")
    initp.add_argument("--role", required=True, choices=sorted(ROLES))

    inst = sp.add_parser("install-engine", help="Install a pinned tunnel engine")
    inst.add_argument("engine", choices=sorted(ENGINES))

    pair = sp.add_parser("pair", help="Generate secure entry/server deployment bundles")
    pair.add_argument("--engine", required=True, choices=sorted(ENGINES))
    pair.add_argument("--name", required=True)
    pair.add_argument("--payload", required=True, choices=sorted(PAYLOADS))
    pair.add_argument("--transport", required=True)
    pair.add_argument("--listen-port", required=True, type=int)
    pair.add_argument("--tunnel-port", required=True, type=int)
    pair.add_argument("--final-local-ip", default="127.0.0.1")
    pair.add_argument("--final-local-port", required=True, type=int)
    pair.add_argument("--secret")
    pair.add_argument("--server-name")
    pair.add_argument("--output", default=".")
    pair.add_argument("--hops", help="GOST hop pools: relay1,relay2;final1,final2")
    pair.add_argument("--username")
    pair.add_argument("--path")
    pair.add_argument("--kcp-profile", choices=["stable", "balanced", "fast"], default="balanced")
    pair.add_argument("--entry-host")
    pair.add_argument("--load-balance", action="store_true")
    pair.add_argument("--group")
    pair.add_argument("--group-key")

    sp.add_parser("wizard", help="Open the guided deployment-bundle wizard")

    imp = sp.add_parser("import-bundle", help="Import and start a deployment bundle")
    imp.add_argument("bundle")
    imp.add_argument("--replace", action="store_true")

    sp.add_parser("show", help="Show configured services")
    ena = sp.add_parser("enable"); ena.add_argument("name")
    dis = sp.add_parser("disable"); dis.add_argument("name")
    rem = sp.add_parser("remove"); rem.add_argument("name")

    editp = sp.add_parser("edit", help="Safely edit an imported service")
    editp.add_argument("name")
    editp.add_argument("--payload", choices=sorted(PAYLOADS))
    editp.add_argument("--transport")
    editp.add_argument("--listen-port", type=int)
    editp.add_argument("--tunnel-port", type=int)
    editp.add_argument("--final-local-ip")
    editp.add_argument("--final-local-port", type=int)
    editp.add_argument("--hops", help="GOST hop pools")
    editp.add_argument("--entry-host")
    editp.add_argument("--server-name")
    editp.add_argument("--path", dest="ws_path")
    editp.add_argument("--kcp-profile", choices=["stable", "balanced", "fast"])
    lb = editp.add_mutually_exclusive_group()
    lb.add_argument("--load-balance", dest="load_balance", action="store_true")
    lb.add_argument("--no-load-balance", dest="load_balance", action="store_false")
    editp.set_defaults(load_balance=None)
    editp.add_argument("--group")

    reb = sp.add_parser("rebuild", help="Validate and rebuild service units")
    reb.add_argument("--name")
    reb.add_argument("--no-restart", action="store_true")
    statp = sp.add_parser("status"); statp.add_argument("--name")
    logp = sp.add_parser("logs")
    logp.add_argument("name")
    logp.add_argument("--lines", type=int, default=80)
    logp.add_argument("--follow", action="store_true")
    sp.add_parser("health")
    sp.add_parser("doctor")

    exp = sp.add_parser("export", help="Create a checksummed portable backup")
    exp.add_argument("output")
    sp.add_parser("list-backups", help="List automatic rollback snapshots")
    restorep = sp.add_parser("restore", help="Restore an automatic rollback snapshot")
    restorep.add_argument("snapshot")
    restore_exp = sp.add_parser("restore-export", help="Restore a checksummed exported backup")
    restore_exp.add_argument("archive")

    testp = sp.add_parser("selftest", help="Run real local end-to-end tests with installed binaries")
    testp.add_argument("--engine", choices=["gost", "frp", "all"], default="all")
    testp.add_argument("--gost-transport", choices=sorted(GOST_TRANSPORTS), default="tls")
    testp.add_argument("--frp-transport", choices=sorted(FRP_TRANSPORTS), default="tcp")
    uninst = sp.add_parser("uninstall")
    uninst.add_argument("--purge", action="store_true")
    sp.add_parser("menu")
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if not args.cmd or args.cmd == "menu":
            menu(); return 0
        if args.cmd == "init":
            init_manager(args.role)
        elif args.cmd == "install-engine":
            install_deps(); install_engine(args.engine)
        elif args.cmd == "wizard":
            wizard_create_pair()
        elif args.cmd == "pair":
            if not command_exists("openssl"):
                fail("openssl is required")
            if args.engine == "gost":
                if not args.hops:
                    fail("GOST pair requires --hops")
                paths = pair_gost(args)
            else:
                if not args.entry_host:
                    fail("FRP pair requires --entry-host")
                paths = pair_frp(args)
            for path in paths:
                ok(str(path))
        elif args.cmd == "import-bundle":
            import_bundle(args.bundle, args.replace)
        elif args.cmd == "show":
            show_services()
        elif args.cmd == "enable":
            set_enabled(args.name, True)
        elif args.cmd == "disable":
            set_enabled(args.name, False)
        elif args.cmd == "remove":
            remove_service(args.name)
        elif args.cmd == "edit":
            updates: Dict[str, Any] = {}
            for key in ("payload", "transport", "listen_port", "tunnel_port", "final_local_ip",
                        "final_local_port", "entry_host", "server_name", "ws_path", "kcp_profile",
                        "load_balance", "group"):
                value = getattr(args, key, None)
                if value is not None:
                    updates[key] = value
            if args.hops is not None:
                updates["hops"] = parse_hops(args.hops)
            if not updates:
                fail("No edit options were supplied")
            edit_service(args.name, updates)
        elif args.cmd == "rebuild":
            rebuild(names=[clean_name(args.name)] if args.name else None, restart=not args.no_restart)
        elif args.cmd == "status":
            service_status(args.name)
        elif args.cmd == "logs":
            service_logs(args.name, lines=args.lines, follow=args.follow)
        elif args.cmd == "health":
            health()
        elif args.cmd == "doctor":
            doctor()
        elif args.cmd == "export":
            export_all(args.output)
        elif args.cmd == "list-backups":
            for snapshot in list_backups():
                print(snapshot.name)
        elif args.cmd == "restore":
            restore_backup(args.snapshot)
        elif args.cmd == "restore-export":
            restore_export(args.archive)
        elif args.cmd == "selftest":
            selftest(args.engine, args.gost_transport, args.frp_transport)
        elif args.cmd == "uninstall":
            uninstall_manager(args.purge)
        else:
            parser.error("unknown command")
        return 0
    except MTMError as e:
        print(color(f"[ERR] {e}", "31"), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nInterrupted", file=sys.stderr)
        return 130

if __name__ == "__main__":
    raise SystemExit(main())
