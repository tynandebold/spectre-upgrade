//! Import + at-rest encryption tests. Uses a small synthetic fixture so the
//! suite is hermetic and never touches real vault data.

use spectre_core::master_key;
use spectre_vault::{export_mpjson_string, import_mpjson_str, Vault};

const FIXTURE: &str = r#"{
  "user": {"full_name": "Robert Lee Mitchell", "algorithm": 3, "default_type": 17, "avatar": 0},
  "export": {"date": "2023-01-01T00:00:00Z", "redacted": true, "format": 1},
  "sites": {
    "github.com":     {"counter": 1, "algorithm": 3, "type": 17, "login_type": 0,  "uses": 5, "last_used": "2023-01-01T00:00:00Z"},
    "bank.example":   {"counter": 2, "algorithm": 3, "type": 16, "login_type": 30, "uses": 1, "last_used": "2023-01-02T00:00:00Z"},
    "stored.example": {"counter": 1, "algorithm": 3, "type": 1056, "login_type": 0, "uses": 0, "last_used": "", "password": "AAECAwQFBgcICQoLDA0ODw=="}
  }
}"#;

fn test_key() -> [u8; 64] {
    master_key("Robert Lee Mitchell", "banana colored duckling")
}

#[test]
fn imports_user_and_sites() {
    let vault = import_mpjson_str(FIXTURE).unwrap();

    assert_eq!(vault.user.full_name, "Robert Lee Mitchell");
    assert_eq!(vault.user.default_type, 17);
    assert_eq!(vault.sites.len(), 3);
    assert_eq!(vault.sites["github.com"].type_code, 17);
    assert_eq!(vault.sites["bank.example"].counter, 2);
}

#[test]
fn detects_stateful_and_preserves_stored_value() {
    let vault = import_mpjson_str(FIXTURE).unwrap();

    assert!(vault.sites["stored.example"].is_stateful());
    assert!(!vault.sites["github.com"].is_stateful());
    assert_eq!(
        vault.sites["stored.example"].password.as_deref(),
        Some("AAECAwQFBgcICQoLDA0ODw==")
    );
}

#[test]
fn encrypt_round_trip_preserves_data() {
    let vault = import_mpjson_str(FIXTURE).unwrap();
    let key = test_key();

    let bytes = vault.to_encrypted_bytes(&key).unwrap();
    let restored = Vault::from_encrypted_bytes(&bytes, &key).unwrap();

    assert_eq!(vault, restored);
}

#[test]
fn ciphertext_hides_site_names() {
    let vault = import_mpjson_str(FIXTURE).unwrap();
    let bytes = vault.to_encrypted_bytes(&test_key()).unwrap();
    let text = String::from_utf8_lossy(&bytes);

    // Site names must not appear in cleartext on disk.
    assert!(!text.contains("github.com"));
    assert!(!text.contains("bank.example"));
}

#[test]
fn wrong_key_fails_to_decrypt() {
    let vault = import_mpjson_str(FIXTURE).unwrap();
    let bytes = vault.to_encrypted_bytes(&test_key()).unwrap();

    let wrong = master_key("Robert Lee Mitchell", "not the password");

    assert!(Vault::from_encrypted_bytes(&bytes, &wrong).is_err());
}

#[test]
fn export_mpjson_round_trips_metadata() {
    let vault = import_mpjson_str(FIXTURE).unwrap();
    let text = export_mpjson_string(&vault, "2026-09-13T00:00:00Z");
    let reimported = import_mpjson_str(&text).unwrap();

    assert_eq!(reimported.sites.len(), vault.sites.len());

    for (name, s) in &vault.sites {
        let r = &reimported.sites[name];

        assert_eq!(r.counter, s.counter);
        assert_eq!(r.type_code, s.type_code);
        assert_eq!(r.login_type, s.login_type);
        assert_eq!(r.uses, s.uses);
        assert_eq!(r.last_used, s.last_used);
    }

    // Redacted: no stored secret leaks into the export.
    assert!(!text.contains("AAECAwQFBgcICQoLDA0ODw=="));
}

#[test]
fn mark_used_bumps_counter_and_timestamp() {
    let mut vault = import_mpjson_str(FIXTURE).unwrap();
    let before = vault.sites["github.com"].uses;

    vault.mark_used("github.com", "2026-09-13T12:00:00Z");

    assert_eq!(vault.sites["github.com"].uses, before + 1);
    assert_eq!(vault.sites["github.com"].last_used, "2026-09-13T12:00:00Z");
}
