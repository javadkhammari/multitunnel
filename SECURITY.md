# Security Notes

- Pair bundles contain authentication secrets and private keys. Transfer them only through a trusted channel.
- GOST server bundles are host-specific. Do not reuse one server bundle on another hostname or IP.
- Keep `/etc/multitunnel-manager` readable only by root and the `mtunnel` group.
- The manager pins engine versions and verifies official release archives with SHA256 before installation.
- Newly generated service bundles checksum `service.json` and all PKI files before import.
- Exported backups contain credentials and private keys. They are created with mode `0600` and include an internal SHA256 manifest.
- An internal SHA256 manifest detects corruption or modification after export, but it does not authenticate the person who created the archive. Use a trusted transfer channel and optionally a detached GPG or minisign signature.
- Restore creates a safety snapshot first and rolls back when validation or service startup fails.
- WSS and other wrapped transports provide encryption where TLS is used, but should not be described as universally undetectable.
- Rotate a deployment by generating a new pair and importing it with `--replace` on every participating node during a controlled maintenance window.
