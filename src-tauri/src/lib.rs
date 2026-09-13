//! Tauri command layer for spectre-upgrade.
//!
//! The master key is derived once on `unlock` and held only in Rust process
//! memory (inside [`AppState`]); it never crosses to the webview. The frontend
//! asks for derived values and issues copy/save commands. Derived secrets are
//! written to the clipboard by Rust, so they need not be handled in JS.

use serde::Serialize;
use spectre_core::Identity;
use spectre_vault::{import_mpjson, Site, User, Vault, STATEFUL_CLASS};
use std::path::PathBuf;
use std::sync::Mutex;
use tauri::{AppHandle, Manager, State};
use tauri_plugin_clipboard_manager::ClipboardExt;

/// An unlocked session. Cleared on `lock` and never serialized.
struct Session {
    key: [u8; 64],
    identity: Identity,
    vault: Vault,
    vault_path: PathBuf,
}

#[derive(Default)]
struct AppState {
    session: Mutex<Option<Session>>,
}

#[derive(Serialize)]
struct UnlockResult {
    #[serde(rename = "siteCount")]
    site_count: usize,
    #[serde(rename = "hasVault")]
    has_vault: bool,
}

#[derive(Serialize)]
struct SiteView {
    name: String,
    #[serde(rename = "typeCode")]
    type_code: u16,
    #[serde(rename = "loginType")]
    login_type: u16,
    counter: u32,
    uses: u32,
    #[serde(rename = "lastUsed")]
    last_used: String,
    url: Option<String>,
    stored: Option<String>,
    stateful: bool,
    algorithm: u8,
}

#[derive(Serialize)]
struct Derived {
    /// `None` for stateful sites with no stored value.
    password: Option<String>,
    login: String,
    answer: String,
}

fn locked_err() -> String {
    "vault is locked".to_string()
}

fn lock_poisoned() -> String {
    "internal state lock poisoned".to_string()
}

impl SiteView {
    fn from_entry(name: &str, site: &Site) -> Self {
        SiteView {
            name: name.to_string(),
            type_code: site.type_code,
            login_type: site.login_type,
            counter: site.counter,
            uses: site.uses,
            last_used: site.last_used.clone(),
            url: site.url.clone(),
            stored: site.stored.clone(),
            stateful: site.is_stateful(),
            algorithm: site.algorithm,
        }
    }
}

/// Derive the master key, then load the on-disk vault (or start empty).
#[tauri::command]
fn unlock(
    app: AppHandle,
    full_name: String,
    master_password: String,
    state: State<AppState>,
) -> Result<UnlockResult, String> {
    if full_name.trim().is_empty() || master_password.is_empty() {
        return Err("full name and master password are required".to_string());
    }

    let t_key = std::time::Instant::now();
    let key = spectre_core::master_key(&full_name, &master_password);
    let identity = Identity::from_master_key(&full_name, key);
    let key_ms = t_key.elapsed().as_millis();

    let t_load = std::time::Instant::now();
    let dir = app.path().app_config_dir().map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let vault_path = dir.join("vault.spectre");

    let (vault, has_vault) = if vault_path.exists() {
        let vault = Vault::load_encrypted(&vault_path, &key)
            .map_err(|_| "wrong master password or corrupted vault".to_string())?;

        (vault, true)
    } else {
        let vault = Vault {
            user: User {
                full_name: full_name.clone(),
                algorithm: 3,
                default_type: 17,
                avatar: 0,
            },
            sites: Default::default(),
        };

        (vault, false)
    };

    let site_count = vault.sites.len();
    eprintln!(
        "[unlock] master key {key_ms} ms, vault load {} ms, {site_count} sites",
        t_load.elapsed().as_millis()
    );

    let session = Session { key, identity, vault, vault_path };

    *state.session.lock().map_err(|_| lock_poisoned())? = Some(session);

    Ok(UnlockResult { site_count, has_vault })
}

/// Drop the in-memory session.
#[tauri::command]
fn lock(state: State<AppState>) -> Result<(), String> {
    *state.session.lock().map_err(|_| lock_poisoned())? = None;

    Ok(())
}

/// All sites, sorted by name (the vault stores them in a BTreeMap).
#[tauri::command]
fn list_sites(state: State<AppState>) -> Result<Vec<SiteView>, String> {
    let guard = state.session.lock().map_err(|_| lock_poisoned())?;
    let session = guard.as_ref().ok_or_else(locked_err)?;

    let sites = session
        .vault
        .sites
        .iter()
        .map(|(name, site)| SiteView::from_entry(name, site))
        .collect();

    Ok(sites)
}

/// Derive password/login/answer for a site with the given (possibly unsaved)
/// settings, for live preview.
#[tauri::command]
fn derive(
    name: String,
    counter: u32,
    type_code: u16,
    login_type: u16,
    state: State<AppState>,
) -> Result<Derived, String> {
    let guard = state.session.lock().map_err(|_| lock_poisoned())?;
    let session = guard.as_ref().ok_or_else(locked_err)?;

    let password = if type_code >= STATEFUL_CLASS {
        session.vault.sites.get(&name).and_then(|s| s.stored.clone())
    } else {
        session.identity.password(&name, counter, type_code)
    };

    // login_type 0 == the standard login (the user's full name); otherwise a
    // generated login name using that template.
    let login = if login_type == 0 {
        session.identity.standard_login().to_string()
    } else {
        session.identity.login(&name, login_type).unwrap_or_default()
    };

    let answer = session.identity.answer(&name, "").unwrap_or_default();

    Ok(Derived { password, login, answer })
}

/// Copy text to the system clipboard from Rust (keeps secrets out of the DOM).
#[tauri::command]
fn copy(app: AppHandle, text: String) -> Result<(), String> {
    app.clipboard().write_text(text).map_err(|e| e.to_string())
}

/// Create or update a site's settings, then persist the vault.
#[tauri::command]
fn save_site(
    name: String,
    counter: u32,
    type_code: u16,
    login_type: u16,
    url: Option<String>,
    stored: Option<String>,
    state: State<AppState>,
) -> Result<SiteView, String> {
    let mut guard = state.session.lock().map_err(|_| lock_poisoned())?;
    let session = guard.as_mut().ok_or_else(locked_err)?;

    let entry = session.vault.sites.entry(name.clone()).or_insert_with(|| Site {
        counter: 1,
        algorithm: 3,
        type_code: 17,
        login_type: 0,
        uses: 0,
        last_used: String::new(),
        url: None,
        password: None,
        stored: None,
    });
    entry.counter = counter;
    entry.type_code = type_code;
    entry.login_type = login_type;
    entry.url = url.filter(|u| !u.trim().is_empty());
    entry.stored = stored.filter(|v| !v.trim().is_empty());

    let view = SiteView::from_entry(&name, entry);
    let key = session.key;
    session
        .vault
        .save_encrypted(&session.vault_path, &key)
        .map_err(|e| e.to_string())?;

    Ok(view)
}

/// Record a use of a site (bump count + timestamp), then persist. The timestamp
/// is supplied by the caller so the backend stays free of a clock dependency.
#[tauri::command]
fn record_use(name: String, now_iso: String, state: State<AppState>) -> Result<(), String> {
    let mut guard = state.session.lock().map_err(|_| lock_poisoned())?;
    let session = guard.as_mut().ok_or_else(locked_err)?;

    session.vault.mark_used(&name, &now_iso);

    let key = session.key;
    session
        .vault
        .save_encrypted(&session.vault_path, &key)
        .map_err(|e| e.to_string())?;

    Ok(())
}

/// Import an `.mpjson` export, replacing the current site set, then persist.
#[tauri::command]
fn import_vault(path: String, state: State<AppState>) -> Result<usize, String> {
    let mut guard = state.session.lock().map_err(|_| lock_poisoned())?;
    let session = guard.as_mut().ok_or_else(locked_err)?;

    let imported = import_mpjson(&path).map_err(|e| e.to_string())?;
    session.vault = imported;

    let key = session.key;
    session
        .vault
        .save_encrypted(&session.vault_path, &key)
        .map_err(|e| e.to_string())?;

    Ok(session.vault.sites.len())
}

/// Import from the live Spectre app's own data store (its Group Container),
/// keyed by the unlocked user's full name. This is the current source of truth
/// and sidesteps the app's broken export entirely.
#[tauri::command]
fn import_from_app(app: AppHandle, state: State<AppState>) -> Result<usize, String> {
    let mut guard = state.session.lock().map_err(|_| lock_poisoned())?;
    let session = guard.as_mut().ok_or_else(locked_err)?;

    let home = app.path().home_dir().map_err(|e| e.to_string())?;
    let path = home
        .join("Library/Group Containers/group.app.spectre/Documents")
        .join(format!("{}.mpjson", session.identity.full_name()));

    if !path.exists() {
        return Err(format!("no live Spectre data found at {}", path.display()));
    }

    let imported = import_mpjson(&path).map_err(|e| e.to_string())?;
    session.vault = imported;

    let key = session.key;
    session
        .vault
        .save_encrypted(&session.vault_path, &key)
        .map_err(|e| e.to_string())?;

    Ok(session.vault.sites.len())
}

/// Export a standard, re-importable `.mpjson` (redacted: derivable passwords are
/// reconstructed on import, so no secrets are written). This is the export the
/// original app never got right. `now_iso` is supplied by the caller.
#[tauri::command]
fn export_mpjson(path: String, now_iso: String, state: State<AppState>) -> Result<usize, String> {
    let guard = state.session.lock().map_err(|_| lock_poisoned())?;
    let session = guard.as_ref().ok_or_else(locked_err)?;

    let text = spectre_vault::export_mpjson_string(&session.vault, &now_iso);
    std::fs::write(&path, text).map_err(|e| e.to_string())?;

    Ok(session.vault.sites.len())
}

/// Export the full vault as an encrypted backup (includes stored "Own" values).
/// Restore by unlocking with the same master password on any machine.
#[tauri::command]
fn export_backup(path: String, state: State<AppState>) -> Result<(), String> {
    let guard = state.session.lock().map_err(|_| lock_poisoned())?;
    let session = guard.as_ref().ok_or_else(locked_err)?;

    let bytes = session
        .vault
        .to_encrypted_bytes(&session.key)
        .map_err(|e| e.to_string())?;
    std::fs::write(&path, bytes).map_err(|e| e.to_string())?;

    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            unlock,
            lock,
            list_sites,
            derive,
            copy,
            save_site,
            record_use,
            import_vault,
            import_from_app,
            export_mpjson,
            export_backup
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
