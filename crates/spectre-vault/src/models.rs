//! Vault data model. Field names and defaults mirror the `.mpjson` export so a
//! `Site` deserializes directly from an export entry (unknown fields ignored).

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Any result `type` at or above this is a stored ("stateful") value that
/// cannot be derived. The reference app labels these "own / saved".
pub const STATEFUL_CLASS: u16 = 1024;

pub(crate) fn default_algorithm() -> u8 {
    3
}

pub(crate) fn default_type() -> u16 {
    17
}

fn default_counter() -> u32 {
    1
}

/// The user identity carried in an export/vault. The master password is never
/// stored here; only public identity settings are.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    pub full_name: String,
    #[serde(default = "default_algorithm")]
    pub algorithm: u8,
    #[serde(default = "default_type")]
    pub default_type: u16,
    #[serde(default)]
    pub avatar: u32,
}

/// A single site entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Site {
    #[serde(default = "default_counter")]
    pub counter: u32,
    #[serde(default = "default_algorithm")]
    pub algorithm: u8,
    #[serde(rename = "type", default = "default_type")]
    pub type_code: u16,
    #[serde(default)]
    pub login_type: u16,
    #[serde(default)]
    pub uses: u32,
    #[serde(default)]
    pub last_used: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Stored value for stateful entries (base64, as in the export). `None` for
    /// derivable sites.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

impl Site {
    /// True if this entry is stored rather than derived.
    pub fn is_stateful(&self) -> bool {
        self.type_code >= STATEFUL_CLASS
    }
}

/// The full vault: one user plus a name-keyed map of sites. `BTreeMap` keeps a
/// stable, sorted order for deterministic serialization.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vault {
    pub user: User,
    pub sites: BTreeMap<String, Site>,
}
