import json
import os
import pathlib
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
MANAGER = ROOT / "multitunnel.py"


def run_cmd(args, env, check=True):
    p = subprocess.run([sys.executable, str(MANAGER), *args], env=env, text=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if check and p.returncode != 0:
        raise AssertionError(f"command failed: {args}\nstdout={p.stdout}\nstderr={p.stderr}")
    return p


def fake_engine(path: pathlib.Path, engine: str):
    if engine == "gost":
        code = r'''#!/usr/bin/env python3
import json, pathlib, sys
if "-V" in sys.argv:
    print("gost 3.2.6-fake")
    raise SystemExit(0)
try:
    cfg = pathlib.Path(sys.argv[sys.argv.index("-C") + 1])
    json.loads(cfg.read_text())
except Exception as e:
    print(e, file=sys.stderr)
    raise SystemExit(2)
print(cfg.read_text())
'''
    else:
        code = r'''#!/usr/bin/env python3
import pathlib, sys, tomllib
if "--version" in sys.argv:
    print("0.70.0-fake")
    raise SystemExit(0)
if "verify" in sys.argv:
    try:
        cfg = pathlib.Path(sys.argv[sys.argv.index("-c") + 1])
        tomllib.loads(cfg.read_text())
    except Exception as e:
        print(e, file=sys.stderr)
        raise SystemExit(2)
    print("syntax is ok")
    raise SystemExit(0)
raise SystemExit(0)
'''
    path.write_text(code)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


class CLIIntegrationTests(unittest.TestCase):
    def base_env(self, root: pathlib.Path):
        env = os.environ.copy()
        env.update({
            "MTM_ETC": str(root / "etc"),
            "MTM_BIN": str(root / "bin"),
            "MTM_SYSTEMD": str(root / "systemd"),
            "MTM_ALLOW_NONROOT": "1",
            "MTM_TEST_MODE": "1",
        })
        (root / "bin").mkdir(parents=True)
        (root / "systemd").mkdir(parents=True)
        return env

    def test_gost_pair_import_both_roles(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            bundles = root / "bundles"
            bundles.mkdir()
            env_pair = self.base_env(root / "pair-env")
            p = run_cmd([
                "pair", "--engine", "gost", "--name", "ovpn", "--payload", "tcp",
                "--transport", "tls", "--listen-port", "19001", "--tunnel-port", "18443",
                "--final-local-port", "19002", "--hops", "127.0.0.1", "--output", str(bundles),
            ], env_pair)
            self.assertIn("gost-entry", p.stdout)
            entry_bundle = bundles / "mtm-ovpn-gost-entry.tar.gz"
            server_bundle = bundles / "mtm-ovpn-gost-server-127.0.0.1.tar.gz"
            self.assertTrue(entry_bundle.exists())
            self.assertTrue(server_bundle.exists())

            entry_root = root / "entry"
            entry_env = self.base_env(entry_root)
            fake_engine(entry_root / "bin" / "gost", "gost")
            run_cmd(["init", "--role", "entry"], entry_env)
            run_cmd(["import-bundle", str(entry_bundle)], entry_env)
            cfg = entry_root / "etc" / "generated" / "gost-ovpn-entry.json"
            data = json.loads(cfg.read_text())
            self.assertEqual(data["services"][0]["addr"], ":19001")
            self.assertEqual(data["chains"][0]["hops"][0]["nodes"][0]["dialer"]["tls"]["serverName"], "127.0.0.1")

            final_root = root / "final"
            final_env = self.base_env(final_root)
            fake_engine(final_root / "bin" / "gost", "gost")
            run_cmd(["init", "--role", "final"], final_env)
            run_cmd(["import-bundle", str(server_bundle)], final_env)
            cfg = final_root / "etc" / "generated" / "gost-ovpn-final.json"
            data = json.loads(cfg.read_text())
            self.assertEqual(data["services"][0]["addr"], ":18443")
            self.assertEqual(data["services"][0]["listener"]["type"], "tls")

    def test_frp_pair_import_both_roles(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            bundles = root / "bundles"
            bundles.mkdir()
            env_pair = self.base_env(root / "pair-env")
            run_cmd([
                "pair", "--engine", "frp", "--name", "xray", "--payload", "tcp",
                "--transport", "quic", "--listen-port", "20001", "--tunnel-port", "20443",
                "--final-local-port", "20002", "--entry-host", "127.0.0.1",
                "--load-balance", "--output", str(bundles),
            ], env_pair)
            entry_bundle = bundles / "mtm-xray-frp-entry.tar.gz"
            final_bundle = bundles / "mtm-xray-frp-final.tar.gz"

            entry_root = root / "entry"
            entry_env = self.base_env(entry_root)
            fake_engine(entry_root / "bin" / "frps", "frp")
            fake_engine(entry_root / "bin" / "frpc", "frp")
            run_cmd(["init", "--role", "entry"], entry_env)
            run_cmd(["import-bundle", str(entry_bundle)], entry_env)
            server_cfg = (entry_root / "etc" / "generated" / "frp-xray-entry.toml").read_text()
            self.assertIn("quicBindPort = 20443", server_cfg)
            self.assertIn("transport.tls.trustedCaFile", server_cfg)

            final_root = root / "final"
            final_env = self.base_env(final_root)
            fake_engine(final_root / "bin" / "frps", "frp")
            fake_engine(final_root / "bin" / "frpc", "frp")
            run_cmd(["init", "--role", "final"], final_env)
            run_cmd(["import-bundle", str(final_bundle)], final_env)
            client_cfg = (final_root / "etc" / "generated" / "frp-xray-final.toml").read_text()
            self.assertLess(client_cfg.index("transport.quic.keepalivePeriod"), client_cfg.index("[[proxies]]"))
            self.assertIn("loadBalancer.group", client_cfg)

    def test_frp_wss_is_rejected(self):
        # frps cannot terminate wss on its bind port without an external TLS
        # reverse proxy, so the manager must not generate such a deployment.
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            bundles = root / "bundles"
            bundles.mkdir()
            p = run_cmd([
                "pair", "--engine", "frp", "--name", "web", "--payload", "tcp",
                "--transport", "wss", "--listen-port", "20101", "--tunnel-port", "20443",
                "--final-local-port", "20102", "--entry-host", "127.0.0.1",
                "--output", str(bundles),
            ], self.base_env(root / "pair-env"), check=False)
            self.assertNotEqual(p.returncode, 0)
            self.assertEqual(list(bundles.iterdir()), [])

    def test_replace_failure_restores_service_and_pki(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            bundles1 = root / "b1"; bundles1.mkdir()
            bundles2 = root / "b2"; bundles2.mkdir()
            pair_env = self.base_env(root / "pair")
            common = [
                "--engine", "gost", "--name", "rollback", "--payload", "tcp",
                "--listen-port", "21001", "--tunnel-port", "21443",
                "--final-local-port", "21002", "--hops", "127.0.0.1",
            ]
            run_cmd(["pair", *common, "--transport", "tls", "--output", str(bundles1)], pair_env)
            run_cmd(["pair", *common, "--transport", "wss", "--output", str(bundles2)], pair_env)

            node = root / "node"
            env = self.base_env(node)
            gost = node / "bin" / "gost"
            fake_engine(gost, "gost")
            run_cmd(["init", "--role", "entry"], env)
            run_cmd(["import-bundle", str(bundles1 / "mtm-rollback-gost-entry.tar.gz")], env)
            services_path = node / "etc" / "services.json"
            ca_path = node / "etc" / "pki" / "rollback" / "ca.crt"
            old_ca = ca_path.read_bytes()
            self.assertEqual(json.loads(services_path.read_text())[0]["transport"], "tls")

            gost.write_text("#!/bin/sh\nexit 2\n")
            gost.chmod(0o755)
            p = run_cmd([
                "import-bundle", str(bundles2 / "mtm-rollback-gost-entry.tar.gz"), "--replace"
            ], env, check=False)
            self.assertNotEqual(p.returncode, 0)
            self.assertEqual(json.loads(services_path.read_text())[0]["transport"], "tls")
            self.assertEqual(ca_path.read_bytes(), old_ca)

    def test_bundle_rejects_path_traversal(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            bad = root / "bad.tar.gz"
            with tarfile.open(bad, "w:gz") as tf:
                info = tarfile.TarInfo("../escape")
                info.size = 1
                import io
                tf.addfile(info, io.BytesIO(b"x"))
            env = self.base_env(root / "node")
            fake_engine(root / "node" / "bin" / "gost", "gost")
            run_cmd(["init", "--role", "entry"], env)
            p = run_cmd(["import-bundle", str(bad)], env, check=False)
            self.assertNotEqual(p.returncode, 0)
            self.assertIn("Unsafe path", p.stderr)


if __name__ == "__main__":
    unittest.main()
