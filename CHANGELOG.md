# Changelog

Fork-specific changes since diverging from [computernewb/nodejs-rfb](https://github.com/computernewb/nodejs-rfb).

## Unreleased

### Added

- **RFB security type 18 support** (GTK-VNC's anonymous-TLS handshake). Needed to talk to GNOME's `gnome-remote-desktop` VNC backend, which only offers this security type — `None`/`VNC`/`NTLM` weren't enough. New `AnonTlsSecurityType` (`src/security/anontls.ts`) wraps the raw socket in a TLS session using anonymous Diffie-Hellman cipher suites (no certificate presented — matches GnuTLS's `NORMAL:+ANON-ECDH:+ANON-DH` priority string), pinned to TLSv1.2 since anonymous key exchange has no TLS 1.3 equivalent. After the handshake, the server re-runs a fresh security-type sub-negotiation inside the now-encrypted channel — byte-for-byte identical wire format to the outer one — so the existing `None`/`VNC`/`NTLM` `authenticate()` implementations are reused as-is for that inner step, no new negotiation code needed. `src/client.ts`, `src/security/`
- `ISecurityType.authenticate()` now optionally returns an upgraded `net.Socket` and takes a `hooks: { detachDataListener }` param, so a security type can hand off to a wrapped socket mid-handshake. The three existing implementations needed only signature updates, no behavioral change.

### Fixed

- **`prepare` script missing**, so installing this package via a `github:` dependency spec (as consumers now do) left them with no compiled output at all — npm only auto-runs `prepare` for git dependencies, not `build`, and `dist/` is gitignored. Added `"prepare": "npm run build"` alongside the existing `build` script.
