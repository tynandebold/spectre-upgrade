//! Parity tests for the v3 derivation core.
//!
//! The password path is pinned to the official published test vector. The login
//! and answer paths reuse the exact same pipeline (only the scope string and
//! template differ), so we assert their shape and determinism here and
//! cross-check the concrete values against the running app for a real site.

use spectre_core::{site_password, Identity, TYPE_LONG, TYPE_NAME};

const FULL_NAME: &str = "Robert Lee Mitchell";
const MASTER: &str = "banana colored duckling";
const SITE: &str = "masterpasswordapp.com";

#[test]
fn official_v3_password_vector() {
    let got = site_password(FULL_NAME, MASTER, SITE, 1, TYPE_LONG).unwrap();

    assert_eq!(got, "Jejr5[RepuSosp");
}

#[test]
fn identity_matches_one_shot() {
    let id = Identity::new(FULL_NAME, MASTER);

    assert_eq!(id.password(SITE, 1, TYPE_LONG).unwrap(), "Jejr5[RepuSosp");
}

#[test]
fn counter_changes_password() {
    let id = Identity::new(FULL_NAME, MASTER);
    let c1 = id.password(SITE, 1, TYPE_LONG).unwrap();
    let c2 = id.password(SITE, 2, TYPE_LONG).unwrap();

    assert_ne!(c1, c2);
}

#[test]
fn login_shape_and_determinism() {
    let id = Identity::new(FULL_NAME, MASTER);
    let login = id.login(SITE, TYPE_NAME).unwrap();

    // Name template is "cvccvcvcv" => 9 lowercase letters.
    assert_eq!(login.len(), 9);
    assert!(login.chars().all(|c| c.is_ascii_lowercase()));
    assert_eq!(login, id.login(SITE, TYPE_NAME).unwrap());
}

#[test]
fn answer_shape_and_context_independence() {
    let id = Identity::new(FULL_NAME, MASTER);
    let generic = id.answer(SITE, "").unwrap();
    let specific = id.answer(SITE, "first pet").unwrap();

    // Phrase template contains spaces; a specific question yields a different
    // answer than the generic one.
    assert!(generic.contains(' '));
    assert_ne!(generic, specific);
    assert_eq!(generic, id.answer(SITE, "").unwrap());
}

#[test]
fn purpose_scopes_are_independent() {
    // Same site, same counter, different purposes => unrelated values.
    let id = Identity::new(FULL_NAME, MASTER);
    let pw = id.password(SITE, 1, TYPE_NAME).unwrap();
    let login = id.login(SITE, TYPE_NAME).unwrap();

    assert_ne!(pw, login);
}
