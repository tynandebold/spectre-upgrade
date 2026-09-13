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
