//! Import a Spectre `.mpjson` export (format 1) into a [`Vault`].

use crate::models::{Site, User, Vault};
use crate::Result;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;

/// Top-level shape of an `.mpjson` file. `export` metadata is intentionally
/// ignored; unknown fields anywhere are ignored by serde.
#[derive(Deserialize)]
struct Root {
    user: RootUser,
    #[serde(default)]
    sites: BTreeMap<String, Site>,
}

#[derive(Deserialize)]
struct RootUser {
    full_name: String,
    #[serde(default = "crate::models::default_algorithm")]
    algorithm: u8,
    #[serde(default = "crate::models::default_type")]
    default_type: u16,
    #[serde(default)]
    avatar: u32,
}

/// Parse an `.mpjson` document from a string.
pub fn import_mpjson_str(text: &str) -> Result<Vault> {
    let root: Root = serde_json::from_str(text)?;

    Ok(Vault {
        user: User {
            full_name: root.user.full_name,
            algorithm: root.user.algorithm,
            default_type: root.user.default_type,
            avatar: root.user.avatar,
        },
        sites: root.sites,
    })
}

/// Read and parse an `.mpjson` file from disk.
pub fn import_mpjson(path: impl AsRef<Path>) -> Result<Vault> {
    let text = std::fs::read_to_string(path)?;

    import_mpjson_str(&text)
}

/// Serialize a vault to a standard, re-importable `.mpjson` string (format 1,
/// redacted). Derivable passwords are reconstructed on import, so no secret
/// values are written; stored "Own" values are intentionally omitted (use the
/// encrypted backup to preserve those).
pub fn export_mpjson_string(vault: &Vault, date: &str) -> String {
    let mut sites = serde_json::Map::new();
    for (name, site) in &vault.sites {
        let mut entry = serde_json::Map::new();
        entry.insert("counter".into(), site.counter.into());
        entry.insert("algorithm".into(), site.algorithm.into());
        entry.insert("type".into(), site.type_code.into());
        entry.insert("login_type".into(), site.login_type.into());
        entry.insert("uses".into(), site.uses.into());
        entry.insert("last_used".into(), site.last_used.clone().into());
        sites.insert(name.clone(), serde_json::Value::Object(entry));
    }

    let doc = serde_json::json!({
        "export": { "date": date, "redacted": true, "format": 1 },
        "user": {
            "avatar": vault.user.avatar,
            "full_name": vault.user.full_name,
            "algorithm": vault.user.algorithm,
            "default_type": vault.user.default_type,
        },
        "sites": serde_json::Value::Object(sites),
    });

    serde_json::to_string_pretty(&doc).expect("vault is always serializable")
}
