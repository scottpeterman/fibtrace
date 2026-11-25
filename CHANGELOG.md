# Changelog

## 0.2.0

First release as `fibtrace2` on PyPI. The command and the import package are still `fibtrace`.

### Security
- Web dashboard binds 127.0.0.1 by default and refuses other addresses while the built-in admin/fibtrace login or LDAP mock mode is active.
- Dashboard login providers: scrypt-hashed local accounts (`fibtrace web --hash-password`), LDAP/Active Directory with an `allowed_groups` gate, and `ldap+local` break-glass. Ported from netlapse.
- Web traces require the user's own SSH credentials: a password, or their own private key pasted or loaded in the browser (never displayed), with an optional passphrase. Server-side key paths and the server account's `~/.ssh` keys are never used.
- Device passwords and keys reach the walker through its environment (`FIBTRACE_PASSWORD`, `FIBTRACE_KEY_DATA`, `FIBTRACE_KEY_PASSPHRASE`), never its command line or disk.

### Changed
- CLI walks default to key auth: `--key-file`, else the first of `~/.ssh/id_ed25519`, `id_ecdsa` or `id_rsa`. `--no-default-key` turns that off. A bad key or passphrase fails before the walk starts.
- Prompt detection returns as soon as the prompt appears instead of waiting a fixed 6 seconds per device.
- License is GPLv3.

### Fixed
- The edge into the final host now carries the delivering interface instead of `null` on connected routes.
- Junos Local routes report their interface (`nh-local-interface`) instead of `?`.
- Browser downloads (terminal log, graph JSON/SVG/PNG, diff JSON) no longer get cancelled in Safari or ignored in Firefox. The terminal log is named with the prefix and local time.
