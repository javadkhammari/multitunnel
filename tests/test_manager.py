import argparse
import importlib.util
import json
import os
import pathlib
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("multitunnel", ROOT / "multitunnel.py")
mt = importlib.util.module_from_spec(spec)
assert spec.loader
spec.loader.exec_module(mt)


class ManagerTests(unittest.TestCase):
    def test_parse_hops(self):
        self.assertEqual(mt.parse_hops("1.1.1.1,2.2.2.2;example.com"), [["1.1.1.1", "2.2.2.2"], ["example.com"]])

    def test_gost_tcp_quic_config(self):
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td)
            (p / "ca.crt").write_text("x")
            s = {
                "name": "ovpn", "engine": "gost", "payload": "tcp", "transport": "quic",
                "listen_port": 9001, "tunnel_port": 8443, "final_local_ip": "127.0.0.1",
                "final_local_port": 9001, "hops": [["203.0.113.50"]], "auth_user": "u",
                "auth_secret": "s", "server_name": "203.0.113.50", "ws_path": "/x",
                "kcp_profile": "balanced", "pki_dir": td, "enabled": True,
            }
            cfg = mt.build_gost_config("entry", s)
            self.assertEqual(cfg["services"][0]["listener"]["type"], "tcp")
            self.assertEqual(cfg["chains"][0]["hops"][0]["nodes"][0]["dialer"]["type"], "quic")
            self.assertEqual(cfg["services"][0]["forwarder"]["nodes"][0]["addr"], "127.0.0.1:9001")

    def test_gost_server_kcp_encrypted(self):
        with tempfile.TemporaryDirectory() as td:
            s = {
                "name": "xray", "engine": "gost", "payload": "udp", "transport": "kcp",
                "listen_port": 10000, "tunnel_port": 8443, "final_local_ip": "127.0.0.1",
                "final_local_port": 10000, "hops": [["203.0.113.1"]], "auth_user": "u",
                "auth_secret": "secret", "server_name": "example.com", "ws_path": "/x",
                "kcp_profile": "stable", "pki_dir": td, "enabled": True,
            }
            cfg = mt.build_gost_config("final", s)
            kcp = cfg["services"][0]["listener"]["metadata"]["config"]
            self.assertEqual(kcp["crypt"], "aes")
            self.assertTrue(kcp["key"])

    def test_frp_configs_use_mtls_and_wire_v2(self):
        with tempfile.TemporaryDirectory() as td:
            s = {
                "name": "ovpn", "engine": "frp", "payload": "tcp", "transport": "quic",
                "entry_host": "198.51.100.1", "listen_port": 9001, "tunnel_port": 8443,
                "final_local_ip": "127.0.0.1", "final_local_port": 9001,
                "auth_secret": "token", "server_name": "198.51.100.1", "wire_protocol": "v2",
                "load_balance": True, "group": "g", "group_key": "k", "pki_dir": td,
                "enabled": True,
            }
            server = mt.build_frps_toml(s)
            client = mt.build_frpc_toml(s, {"node_id": "n1"})
            self.assertIn("transport.tls.force = true", server)
            self.assertIn("transport.tls.trustedCaFile", server)
            self.assertIn('transport.wireProtocol = "v2"', client)
            self.assertIn("loadBalancer.group", client)


    def test_gost_udp_transport_rejects_multihop(self):
        service = {
            "name": "bad", "engine": "gost", "payload": "tcp", "transport": "quic",
            "listen_port": 9001, "tunnel_port": 8443, "final_local_ip": "127.0.0.1",
            "final_local_port": 9001, "hops": [["192.0.2.1"], ["192.0.2.2"]],
        }
        with self.assertRaises(mt.MTMError):
            mt.validate_service(service, "entry")

    def test_gost_tls_uses_host_specific_server_name(self):
        with tempfile.TemporaryDirectory() as td:
            s = {
                "name": "ovpn", "engine": "gost", "payload": "tcp", "transport": "tls",
                "listen_port": 9001, "tunnel_port": 8443, "final_local_ip": "127.0.0.1",
                "final_local_port": 9001, "hops": [["192.0.2.10", "node.example"]],
                "auth_user": "u", "auth_secret": "s", "server_name": None, "ws_path": "/x",
                "kcp_profile": "balanced", "pki_dir": td, "enabled": True,
            }
            cfg = mt.build_gost_config("entry", s)
            nodes = cfg["chains"][0]["hops"][0]["nodes"]
            self.assertEqual(nodes[0]["dialer"]["tls"]["serverName"], "192.0.2.10")
            self.assertEqual(nodes[1]["dialer"]["tls"]["serverName"], "node.example")

    def test_frp_quic_options_are_global(self):
        with tempfile.TemporaryDirectory() as td:
            s = {
                "name": "ovpn", "engine": "frp", "payload": "tcp", "transport": "quic",
                "entry_host": "198.51.100.1", "listen_port": 9001, "tunnel_port": 8443,
                "final_local_ip": "127.0.0.1", "final_local_port": 9001,
                "auth_secret": "token", "server_name": "198.51.100.1", "wire_protocol": "v2",
                "load_balance": False, "group": "g", "group_key": "k", "pki_dir": td,
                "enabled": True,
            }
            client = mt.build_frpc_toml(s, {"node_id": "n1"})
            self.assertLess(client.index("transport.quic.keepalivePeriod"), client.index("[[proxies]]"))
            self.assertNotIn("webServer.port", client)

    def test_systemd_start_limit_is_in_unit_section(self):
        s = {"name": "x", "engine": "gost"}
        unit = mt.systemd_unit(s, "entry", pathlib.Path("/tmp/x.json"))
        before_service = unit.split("[Service]", 1)[0]
        self.assertIn("StartLimitIntervalSec=60", before_service)
        self.assertIn("RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6", unit)

    def test_port_conflict_detected(self):
        items = [
            {"name": "a", "engine": "gost", "payload": "tcp", "transport": "tls", "listen_port": 9001, "tunnel_port": 8443, "enabled": True},
            {"name": "b", "engine": "gost", "payload": "tcp", "transport": "tls", "listen_port": 9001, "tunnel_port": 9443, "enabled": True},
        ]
        with self.assertRaises(mt.MTMError):
            mt.port_conflicts(items, "entry")

    @unittest.skipUnless(hasattr(os, "geteuid") and os.geteuid() == 0, "needs root to change file group")
    def test_generated_file_is_readable_by_service_group(self):
        # Regression: configs were written as root:root 0640, so the unprivileged
        # service user could not read them and the unit crash-looped.
        import grp
        group = next((g for g in ("daemon", "nogroup", "users") if _group_exists(g)), None)
        if group is None:
            self.skipTest("no spare system group available")
        with tempfile.TemporaryDirectory() as td:
            cfg = pathlib.Path(td) / "gost-x-entry.json"
            mt.write_json(cfg, {"a": 1}, 0o640)
            with mock.patch.object(mt, "RUN_GROUP", group):
                mt.grant_service_read(cfg)
            st = cfg.stat()
            self.assertEqual(st.st_gid, grp.getgrnam(group).gr_gid)
            self.assertEqual(st.st_mode & 0o777, 0o640)

    def test_unit_that_crashes_after_start_is_detected(self):
        # Regression: a unit that is 'active' for a moment and then fails must not
        # be reported as started.
        states = iter(["active", "failed"])

        def fake_run(cmd, **kwargs):
            out = next(states) if cmd[:2] == ["systemctl", "is-active"] else "log line"
            return mock.Mock(stdout=out, returncode=0)

        with mock.patch.object(mt, "run", side_effect=fake_run), mock.patch.object(mt.time, "sleep"):
            with self.assertRaises(mt.MTMError) as ctx:
                mt.wait_unit_stable("multitunnel-gost-x.service", seconds=5)
        self.assertIn("failed to stay active", str(ctx.exception))


class MuxSessionTests(unittest.TestCase):
    def _service(self, transport, sessions=None, hops=None):
        svc = {
            "name": "x", "engine": "gost", "payload": "tcp", "transport": transport,
            "listen_port": 443, "tunnel_port": 8443, "final_local_ip": "127.0.0.1", "final_local_port": 443,
            "hops": hops or [["203.0.113.20"]], "auth_user": "u", "auth_secret": "s",
            "server_name": None, "ws_path": "/w", "kcp_profile": "balanced", "pki_dir": "/tmp/pki",
        }
        if sessions is not None:
            svc["mux_sessions"] = sessions
        return svc

    def _nodes(self, svc, hop=0):
        cfg = mt.build_gost_config("entry", svc)
        return cfg["chains"][0]["hops"][hop]["nodes"]

    def test_mtls_sessions_create_parallel_nodes(self):
        nodes = self._nodes(self._service("mtls", 4))
        self.assertEqual(len(nodes), 4)
        self.assertEqual({n["addr"] for n in nodes}, {"203.0.113.20:8443"})
        self.assertEqual(len({n["name"] for n in nodes}), 4)

    def test_old_services_without_field_keep_one_session(self):
        self.assertEqual(len(self._nodes(self._service("mtls"))), 1)

    def test_non_mux_transports_ignore_sessions(self):
        self.assertEqual(len(self._nodes(self._service("tls", 4))), 1)
        self.assertEqual(len(self._nodes(self._service("quic", 4))), 1)

    def test_sessions_apply_to_first_hop_only(self):
        svc = self._service("mwss", 3, hops=[["198.51.100.10"], ["203.0.113.20", "203.0.113.21"]])
        self.assertEqual(len(self._nodes(svc, 0)), 3)
        self.assertEqual(len(self._nodes(svc, 1)), 2)

    def test_sessions_validation(self):
        self.assertEqual(mt.valid_mux_sessions("8"), 8)
        for bad in (0, 17, "x"):
            with self.assertRaises(mt.MTMError):
                mt.valid_mux_sessions(bad)


def _group_exists(name):
    import grp
    try:
        grp.getgrnam(name)
        return True
    except KeyError:
        return False


if __name__ == "__main__":
    unittest.main()
