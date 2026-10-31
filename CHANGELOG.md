# Changelog

## 2.2.0

- Renamed the public entry role to `entry` (`--role entry`, `--entry-host`, `*-entry.tar.gz` bundles)
- Removed FRP `wss`: frps cannot terminate WSS without an external TLS reverse proxy, so those deployments never connected. FRP `websocket` with mutual TLS stays available
- Added a regression test for the FRP `wss` rejection
- Verified every remaining transport end to end with the real GOST 3.2.6 and FRP 0.70.0 binaries
- English documentation

## 2.1.0

- Fully English, step-by-step interactive menu
- Guided bundle wizard with presets for OpenVPN TCP/UDP, WireGuard, Xray and custom services
- Option to import the matching bundle on the current node right after generation
- Safe editing of installed services with config validation and rollback
- Self-test and uninstall wired into the menu
- Status and log viewing (including follow mode) from the menu
- Portable export backups with an internal SHA256 manifest
- Export restore and automatic snapshots with rollback on failure
- New commands: `wizard`, `edit`, `logs`, `list-backups`, `restore`, `restore-export`
- Stricter safe extraction of bundles and backups
- SHA256 of `service.json` added to bundle manifests
- Automated tests increased from 13 to 17

## 2.0.0

- Multi-engine architecture with GOST and FRP
- Secure entry and final bundles with a private CA
- Separate TLS certificate for each GOST server
- GOST TLS, MTLS, WSS, MWSS, QUIC, KCP and DTLS
- Prevention of invalid multi-hop chains over QUIC, KCP and DTLS
- FRP TCP, KCP, QUIC and WebSocket with mutual TLS and wire protocol v2
- TCP and UDP payloads for OpenVPN, Xray and generic services
- GOST multi-hop chains and final pools on TCP-based transports
- FRP load balancing and health checks for TCP
- Config validation with the real binary before restart
- Real end-to-end self-test that runs the binaries and passes payload
- systemd hardening and an unprivileged service user
- Automatic backup and rollback when a restart fails
- Port conflict detection
- Official engine downloads verified against pinned SHA256 checksums
