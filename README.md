# Spectre Upgrade

A local, offline desktop password manager for macOS that derives your passwords
instead of storing them, built as a modern replacement for the unmaintained
[Spectre](https://spectre.app/) (formerly Master Password) app, with the export
feature that the original never got right.

Passwords are **derived, not stored**: `master password + full name + site name +
counter` run through a fixed algorithm (scrypt → HMAC-SHA256 → template) to
produce the same password every time. There is no password database. Nothing
secret is written to disk, and the app makes **no network requests**.

> [!NOTE]
> Unofficial and not affiliated with Spectre. This is a clean-room
> reimplementation of the published **algorithm v3**, verified against the
> official test vector (`Jejr5[RepuSosp`). It produces byte-identical passwords
> to Spectre for v3 identities, so you can move over without changing a single
> password.

## Install on macOS

Apple silicon (arm64). Intel Macs can build from source (Option B).

### Option A — Download the app

1. Download the latest `.dmg` from the
   [**Releases**](https://github.com/tynandebold/spectre-upgrade/releases/latest) page.
2. Open it and drag **Spectre Upgrade** into **Applications**.
3. First launch only: right-click the app → **Open** → **Open**.

> [!IMPORTANT]
> The app is **unsigned** (no paid Apple Developer certificate), so macOS
> Gatekeeper blocks a normal double-click the first time. Right-click → **Open**
> once, or clear the quarantine flag:
> ```sh
> xattr -dr com.apple.quarantine "/Applications/Spectre Upgrade.app"
> ```

### Option B — Build from source (recommended for a password tool)

Building it yourself means you can audit every line, which is the right call for
software that handles your passwords.

Prerequisites: [Rust](https://rustup.rs) (stable) and Node 18+.

```sh
git clone https://github.com/tynandebold/spectre-upgrade
cd spectre-upgrade
npm install
npm run tauri build
cp -R "target/release/bundle/macos/Spectre Upgrade.app" /Applications/
```

## First run

1. Enter your **full name** and **master password**, then **Unlock**.
2. Migrating from Spectre? Click **Sync from app** to pull your current sites
   straight from the Spectre app's data, or **Import file…** for a `.mpjson`
   export.
3. Optional: **Enable Touch ID** (bottom-left) so you can unlock with your
   fingerprint instead of typing your master password.

## Features

- Derives site passwords, login names, and security answers (all three purpose
  scopes), with per-site counter and result type (Maximum / Long / Medium /
  Short / Basic / PIN / Phrase).
- Two-pane UI: searchable, dense site list + live detail. One-click copy,
  keyboard navigation (arrows / Enter to copy / Esc), A–Z or recent sort.
- "Own (saved)" entries for the handful of passwords that can't be derived.
- Import a Spectre `.mpjson` export; **working export** to a re-importable
  `.mpjson` or a full encrypted backup.
- **Touch ID** unlock (opt-in), master key held only in memory, clipboard
  auto-clears after 30s, auto-lock after 5 minutes idle, encrypted-at-rest
  vault, strictly offline.

## How it works

The 64-byte master key is derived once with scrypt and kept only in the Rust
process; it never crosses into the webview. Derived secrets are written to the
clipboard from Rust. The site list and any stored values are encrypted at rest
with a key derived from your master key (XChaCha20-Poly1305).

```
crates/spectre-core/    Pure Rust derivation engine (algorithm v3). No I/O.
crates/spectre-vault/   Import + encrypted-at-rest vault.
crates/spectre-cli/     Local CLI for verification / scripting.
src-tauri/              Tauri app (Rust command layer; crypto stays in Rust).
src/                    React + TypeScript UI.
```

## Develop

```sh
npm run tauri dev   # run in development
cargo test          # algorithm + vault tests (incl. the official vector)
```

## Credits & license

The Spectre / Master Password algorithm was created by
[Maarten Billemont](https://spectre.app/) and is published under the MPL-2.0.
This project is an independent reimplementation, released under the MIT License;
see [`LICENSE`](./LICENSE).
