# Test Report: MultiTunnel Relay Manager 2.3.1

Date: 2026-10-31

## Automated tests

`tests/run_all.sh`: Python bytecode compilation, Bash syntax check of the installer, and 27 unit and CLI integration tests. All passed.

Coverage includes:

- GOST and FRP bundle generation and import on every role
- Rollback after a failed service replacement
- Interactive menu rendering and dispatch (self-test, uninstall)
- Guided wizard argument generation
- Safe service editing followed by config validation and rebuild
- Portable export, restore round trip, and rejection of a tampered backup
- GOST configs for TLS, QUIC and encrypted KCP profiles
- Host-specific TLS server names and certificates with IP/DNS SANs
- Rejection of UDP-based multi-hop GOST chains
- Rejection of FRP `wss`
- `show` hides secrets, `show --json` keeps them, and piped output has no ANSI codes
- Generated configs are readable by the unprivileged service group
- A unit that crashes shortly after start is reported as failed
- Mux sessions: N parallel nodes on the first hop for `mtls`/`mwss`, one for other transports, validation limits
- With the real GOST binary, `--mux-sessions 4` and `8` open exactly 4 and 8 tunnel connections and spread client streams evenly across them
- FRP mutual TLS, wire protocol v2 and QUIC option placement
- Managed-port conflict detection
- systemd hardening sections
- Bundle path traversal and unsupported archive entries

## Real engine end-to-end tests

The official GOST 3.2.6 and FRP 0.70.0 binaries were downloaded with `install-engine`, which checked them against the pinned SHA256 checksums. Each transport was then tested with `multitunnel selftest`, which starts both tunnel endpoints and passes random payload through them.

| Engine | Transport | Result |
|---|---|---|
| GOST | tls | passed |
| GOST | mtls | passed |
| GOST | wss | passed |
| GOST | mwss | passed |
| GOST | quic | passed |
| GOST | kcp | passed |
| GOST | dtls | passed |
| FRP | tcp | passed |
| FRP | kcp | passed |
| FRP | quic | passed |
| FRP | websocket | passed |

FRP `wss` failed in version 2.1.0 (`login to the server failed: unexpected EOF`), because frps does not accept WSS on its bind port without an external TLS reverse proxy. Version 2.2.0 removes it.

## Not covered

A local self-test does not measure the real network path between servers. Before a production rollout, test latency, loss, jitter, throughput and reconnect behaviour on the actual servers.
