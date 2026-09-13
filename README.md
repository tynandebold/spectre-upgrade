# spectre-upgrade

A local, offline reimplementation of the [Spectre](https://spectre.app/)
(formerly Master Password) stateless password manager for macOS, with the export
feature that the original app never got right.

Passwords are **derived**, not stored: `master password + full name + site name +
counter` run through a fixed algorithm (scrypt + HMAC-SHA256 + templates) to
produce the same password every time. Nothing secret is written to disk, and the
app makes no network requests.

## Layout

```
crates/spectre-core/   Pure Rust derivation engine (algorithm v3). No I/O.
src-tauri/             Tauri app crate (added in the UI phase).
src/                   Web UI (added in the UI phase).
```

## Status

- [x] Phase 1: toolchain + workspace
- [x] Phase 2: `spectre-core` derivation engine (password / login / answer) + parity test
- [ ] Phase 3: vault + `.mpjson` import
- [ ] Phase 4: UI
- [ ] Phase 5: working export
- [ ] Phase 6: polish (clipboard auto-clear, lock, Touch ID)

## Develop

Rust lives at `~/.cargo/bin` (not on `PATH` yet). Run tests with:

```sh
~/.cargo/bin/cargo test
```

The core is verified against the official Spectre v3 test vector
(`Jejr5[RepuSosp`).
