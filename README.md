# Spectre Upgrade

A local, offline desktop password manager for macOS that derives your passwords
instead of storing them, built as a modern replacement for the unmaintained
[Spectre](https://spectre.app/) (formerly Master Password) app, with the export
feature that the original never got right.

Passwords are **derived, not stored**: `master password + full name + site name +
counter` run through a fixed algorithm (scrypt → HMAC-SHA256 → template) to
produce the same password every time. There is no password database. Nothing
secret is written to disk, and the app makes **no network requests**.

> Unofficial and not affiliated with Spectre. This is a clean-room
> reimplementation of the published **algorithm v3**, verified against the
> official test vector (`Jejr5[RepuSosp`). It produces byte-identical passwords
> to Spectre for v3 identities, so you can move over without changing a single
> password.

## Features

- Derives site passwords, login names, and security answers (all three purpose
  scopes), with per-site counter and result type (Maximum / Long / Medium /
  Short / Basic / PIN / Phrase).
- Two-pane UI: searchable, dense site list + live detail. One-click copy,
  keyboard navigation (arrows / Enter to copy / Esc), A–Z or recent sort.
- "Own (saved)" entries for the handful of passwords that can't be derived.
- Import a Spectre `.mpjson` export; **working export** to a re-importable
  `.mpjson` or a full encrypted backup.
- Security: master key held only in memory, clipboard auto-clears after 30s,
  auto-lock after 5 minutes idle, encrypted-at-rest vault, strict offline.

## Architecture

```
crates/spectre-core/    Pure Rust derivation engine (algorithm v3). No I/O.
crates/spectre-vault/   Import + encrypted-at-rest vault (XChaCha20-Poly1305).
crates/spectre-cli/     Local CLI for verification / scripting.
src-tauri/              Tauri app (Rust command layer; crypto stays in Rust).
src/                    React + TypeScript UI.
```

The 64-byte master key is derived once (scrypt) and kept only in the Rust
process; it never crosses into the webview. Derived secrets are copied to the
clipboard from Rust.

## Build & run

Prerequisites: [Rust](https://rustup.rs) (stable) and Node 18+.

```sh
npm install
npm run tauri dev      # run in development
npm run tauri build    # produce a release .app + .dmg (in target/release/bundle)
```

Run the algorithm tests:

```sh
cargo test
```

macOS builds are unsigned; on first launch, right-click the app → Open, or run
`xattr -dr com.apple.quarantine "Spectre Upgrade.app"`.

## Credits & license

The Spectre / Master Password algorithm was created by
[Maarten Billemont](https://spectre.app/) and is published under the MPL-2.0.
This project is an independent reimplementation. See [`LICENSE`](./LICENSE).
