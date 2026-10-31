import importlib.util
import io
import json
import os
import pathlib
import stat
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
MANAGER = ROOT / "multitunnel.py"


def run_cmd(args, env, check=True):
    p = subprocess.run([sys.executable, str(MANAGER), *args], env=env, text=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if check and p.returncode != 0:
        raise AssertionError(f"command failed: {args}\nstdout={p.stdout}\nstderr={p.stderr}")
    return p


def fake_gost(path: pathlib.Path):
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
raise SystemExit(0)
'''
    path.write_text(code)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


spec = importlib.util.spec_from_file_location("multitunnel_menu_test", MANAGER)
mt = importlib.util.module_from_spec(spec)
assert spec.loader
spec.loader.exec_module(mt)


class MenuAndBackupTests(unittest.TestCase):
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

    def test_menu_selftest_and_uninstall_options_are_wired(self):
        with mock.patch("builtins.input", side_effect=["14", "1", "tls", "0"]), \
             mock.patch.object(mt, "selftest") as selftest_mock, \
             redirect_stdout(io.StringIO()):
            mt.menu()
        selftest_mock.assert_called_once_with("gost", "tls", "tcp")

        with mock.patch("builtins.input", side_effect=["17", "n", "UNINSTALL"]), \
             mock.patch.object(mt, "uninstall_manager") as uninstall_mock, \
             redirect_stdout(io.StringIO()):
            mt.menu()
        uninstall_mock.assert_called_once_with(False)

    def test_guided_wizard_builds_gost_udp_pair(self):
        with tempfile.TemporaryDirectory() as td:
            output = pathlib.Path(td) / "bundles"
            fake_outputs = [output / "entry.tar.gz", output / "final.tar.gz"]
            answers = [
                "1", "2", "", "", "", "", "", "", str(output),
                "127.0.0.1", "n", "y",
            ]
            with mock.patch("builtins.input", side_effect=answers), \
                 mock.patch.object(mt, "command_exists", return_value=True), \
                 mock.patch.object(mt, "pair_gost", return_value=fake_outputs) as pair_mock, \
                 mock.patch.object(mt, "STATE", pathlib.Path(td) / "missing-state.json"), \
                 redirect_stdout(io.StringIO()):
                result = mt.wizard_create_pair()
            self.assertEqual(result, fake_outputs)
            args = pair_mock.call_args.args[0]
            self.assertEqual(args.engine, "gost")
            self.assertEqual(args.payload, "udp")
            self.assertEqual(args.transport, "dtls")
            self.assertEqual(args.listen_port, 9001)
            self.assertEqual(args.hops, "127.0.0.1")

    def test_cli_edit_and_export_restore_roundtrip(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            env = self.base_env(root)
            fake_gost(root / "bin" / "gost")
            bundles = root / "bundles"
            bundles.mkdir()
            run_cmd(["init", "--role", "entry"], env)
            run_cmd([
                "pair", "--engine", "gost", "--name", "svc", "--payload", "tcp",
                "--transport", "tls", "--listen-port", "19001", "--tunnel-port", "18443",
                "--final-local-port", "19002", "--hops", "127.0.0.1", "--output", str(bundles),
            ], env)
            run_cmd(["import-bundle", str(bundles / "mtm-svc-gost-entry.tar.gz")], env)
            run_cmd(["edit", "svc", "--listen-port", "19003", "--transport", "quic"], env)
            services = root / "etc" / "services.json"
            self.assertEqual(json.loads(services.read_text())[0]["listen_port"], 19003)
            self.assertEqual(json.loads(services.read_text())[0]["transport"], "quic")

            archive = root / "export.tar.gz"
            run_cmd(["export", str(archive)], env)
            run_cmd(["edit", "svc", "--listen-port", "19004"], env)
            self.assertEqual(json.loads(services.read_text())[0]["listen_port"], 19004)
            run_cmd(["restore-export", str(archive)], env)
            self.assertEqual(json.loads(services.read_text())[0]["listen_port"], 19003)

    def test_export_tampering_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            env = self.base_env(root)
            run_cmd(["init", "--role", "entry"], env)
            archive = root / "export.tar.gz"
            run_cmd(["export", str(archive)], env)

            unpack = root / "unpack"
            unpack.mkdir()
            subprocess.run(["tar", "-xzf", str(archive), "-C", str(unpack)], check=True)
            services = unpack / "services.json"
            services.write_text("[]\n#tampered\n")
            tampered = root / "tampered.tar.gz"
            subprocess.run(["tar", "-czf", str(tampered), "-C", str(unpack), "."], check=True)
            p = run_cmd(["restore-export", str(tampered)], env, check=False)
            self.assertNotEqual(p.returncode, 0)
            self.assertIn("checksum verification failed", p.stderr)


if __name__ == "__main__":
    unittest.main()
