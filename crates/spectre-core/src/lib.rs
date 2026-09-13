//! `spectre-core`: stateless password derivation for the Spectre / Master
//! Password algorithm, version 3.
//!
//! This is a clean-room port of the proven Python reference, verified against
//! the official test vector `Jejr5[RepuSosp` (see `tests/vectors.rs`). It does
//! pure derivation: no I/O, no persistence, no logging. The master key is held
//! in an [`Identity`] and zeroized when dropped.
//!
//! Pipeline (identical for every purpose, only the scope/context/template vary):
//!   1. `master_key` = scrypt(master_password, salt = authScope|len|fullName)
//!   2. `site_key`   = HMAC-SHA256(master_key, purposeScope|len|site|counter[|len|context])
//!   3. `result`     = fill a template, selecting each char from its class by a seed byte

use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

/// The purpose of a derivation, which selects the scope string mixed into the
/// site key. A different scope yields a completely independent value for the
/// same site, so passwords, logins, and answers never collide.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose {
    /// Site passwords.
    Authentication,
    /// Login / user names.
    Identification,
    /// Security-question answers.
    Recovery,
}

impl Purpose {
    fn scope(self) -> &'static str {
        match self {
            Purpose::Authentication => "com.lyndir.masterpassword",
            Purpose::Identification => "com.lyndir.masterpassword.login",
            Purpose::Recovery => "com.lyndir.masterpassword.answer",
        }
    }
}

// Result-type codes, matching the `type` field in a `.mpjson` export.
pub const TYPE_MAXIMUM: u16 = 16;
pub const TYPE_LONG: u16 = 17;
pub const TYPE_MEDIUM: u16 = 18;
pub const TYPE_SHORT: u16 = 19;
pub const TYPE_BASIC: u16 = 20;
pub const TYPE_PIN: u16 = 21;
pub const TYPE_NAME: u16 = 30;
pub const TYPE_PHRASE: u16 = 31;

/// Any `type` at or above this is a stored ("stateful") value that cannot be
/// derived. The reference app calls these "own / saved" passwords.
pub const STATEFUL_CLASS: u16 = 1024;

// scrypt parameters for algorithm v3: N = 2^15 (32768), r = 8, p = 2, dkLen = 64.
const SCRYPT_LOG_N: u8 = 15;
const SCRYPT_R: u32 = 8;
const SCRYPT_P: u32 = 2;
const MASTER_KEY_LEN: usize = 64;

/// The character class each template symbol expands to. All ASCII, so indexing
/// bytes is safe.
fn char_class(symbol: char) -> &'static str {
    match symbol {
        'V' => "AEIOU",
        'C' => "BCDFGHJKLMNPQRSTVWXYZ",
        'v' => "aeiou",
        'c' => "bcdfghjklmnpqrstvwxyz",
        'A' => "AEIOUBCDFGHJKLMNPQRSTVWXYZ",
        'a' => "AEIOUaeiouBCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz",
        'n' => "0123456789",
        'o' => "@&%?,=[]_:-+*$#!'^~;()/.",
        'x' => "AEIOUaeiouBCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz0123456789!@#$%^&*()",
        ' ' => " ",
        _ => "",
    }
}

/// The template set for a result type, or `None` if the type is stateful or
/// unknown.
fn templates_for(type_code: u16) -> Option<&'static [&'static str]> {
    let templates: &'static [&'static str] = match type_code {
        TYPE_MAXIMUM => &["anoxxxxxxxxxxxxxxxxx", "axxxxxxxxxxxxxxxxxno"],
        TYPE_LONG => &[
            "CvcvnoCvcvCvcv", "CvcvCvcvnoCvcv", "CvcvCvcvCvcvno",
            "CvccnoCvcvCvcv", "CvccCvcvnoCvcv", "CvccCvcvCvcvno",
            "CvcvnoCvccCvcv", "CvcvCvccnoCvcv", "CvcvCvccCvcvno",
            "CvcvnoCvcvCvcc", "CvcvCvcvnoCvcc", "CvcvCvcvCvccno",
            "CvccnoCvccCvcv", "CvccCvccnoCvcv", "CvccCvccCvcvno",
            "CvcvnoCvccCvcc", "CvcvCvccnoCvcc", "CvcvCvccCvccno",
            "CvccnoCvcvCvcc", "CvccCvcvnoCvcc", "CvccCvcvCvccno",
        ],
        TYPE_MEDIUM => &["CvcnoCvc", "CvcCvcno"],
        TYPE_SHORT => &["Cvcn"],
        TYPE_BASIC => &["aaanaaan", "aannaaan", "aaannaaa"],
        TYPE_PIN => &["nnnn"],
        TYPE_NAME => &["cvccvcvcv"],
        TYPE_PHRASE => &[
            "cvcc cvc cvccvcv cvc",
            "cvc cvccvcvcv cvcv",
            "cv cvccv cvc cvcvccv",
        ],
        _ => return None,
    };

    Some(templates)
}

/// Append a big-endian u32 byte-length prefix followed by the UTF-8 bytes.
/// v3 uses the byte length (not the character count).
fn push_scoped(buf: &mut Vec<u8>, value: &str) {
    buf.extend_from_slice(&(value.len() as u32).to_be_bytes());
    buf.extend_from_slice(value.as_bytes());
}

/// Derive the 64-byte master key from a full name and master password.
///
/// The master key always uses the authentication scope, independent of the
/// purpose a later site key is derived for.
pub fn master_key(full_name: &str, master_password: &str) -> [u8; MASTER_KEY_LEN] {
    let mut salt = Vec::new();
    salt.extend_from_slice(Purpose::Authentication.scope().as_bytes());
    push_scoped(&mut salt, full_name);

    let params = scrypt::Params::new(SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P, MASTER_KEY_LEN)
        .expect("valid scrypt params");
    let mut out = [0u8; MASTER_KEY_LEN];
    scrypt::scrypt(master_password.as_bytes(), &salt, &params, &mut out)
        .expect("output length matches params");

    salt.zeroize();
    out
}

/// Derive the 32-byte site key for a given purpose and optional key context.
///
/// `context` is used for security answers (the question keyword); pass `None`
/// for the generic answer and for passwords/logins.
pub fn site_key(
    master_key: &[u8; MASTER_KEY_LEN],
    site_name: &str,
    counter: u32,
    purpose: Purpose,
    context: Option<&str>,
) -> [u8; 32] {
    let mut salt = Vec::new();
    salt.extend_from_slice(purpose.scope().as_bytes());
    push_scoped(&mut salt, site_name);
    salt.extend_from_slice(&counter.to_be_bytes());

    if let Some(ctx) = context {
        if !ctx.is_empty() {
            push_scoped(&mut salt, ctx);
        }
    }

    let mut mac = HmacSha256::new_from_slice(master_key).expect("HMAC accepts any key length");
    mac.update(&salt);
    let digest = mac.finalize().into_bytes();

    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);

    salt.zeroize();
    out
}

/// Fill a template for `type_code` from the site-key seed. Returns `None` for
/// stateful/unknown types.
fn derive_result(seed: &[u8; 32], type_code: u16) -> Option<String> {
    let templates = templates_for(type_code)?;
    let template = templates[seed[0] as usize % templates.len()];

    let mut out = String::with_capacity(template.len());
    for (i, symbol) in template.chars().enumerate() {
        let class = char_class(symbol);

        if class.is_empty() {
            out.push(symbol);
        } else {
            let index = seed[i + 1] as usize % class.len();
            out.push(class.as_bytes()[index] as char);
        }
    }

    Some(out)
}

/// A user identity: the derived master key plus the full name. Construct once,
/// derive many. The key is zeroized on drop.
pub struct Identity {
    full_name: String,
    key: [u8; MASTER_KEY_LEN],
}

impl Identity {
    /// Run scrypt once to derive the master key. This is the slow step
    /// (~100ms); reuse the returned `Identity` for every site.
    pub fn new(full_name: &str, master_password: &str) -> Self {
        Identity {
            full_name: full_name.to_string(),
            key: master_key(full_name, master_password),
        }
    }

    pub fn full_name(&self) -> &str {
        &self.full_name
    }

    /// Derive a site password (authentication scope). `None` for stateful types.
    pub fn password(&self, site: &str, counter: u32, type_code: u16) -> Option<String> {
        let seed = site_key(&self.key, site, counter, Purpose::Authentication, None);

        derive_result(&seed, type_code)
    }

    /// Derive a generated login name (identification scope, counter fixed at 1).
    /// Pass [`TYPE_NAME`] for the app default.
    pub fn login(&self, site: &str, type_code: u16) -> Option<String> {
        let seed = site_key(&self.key, site, 1, Purpose::Identification, None);

        derive_result(&seed, type_code)
    }

    /// The standard login name: the user's full name, verbatim (not derived).
    pub fn standard_login(&self) -> &str {
        &self.full_name
    }

    /// Derive a security answer (recovery scope, counter fixed at 1, phrase
    /// template). An empty `question` yields the generic answer.
    pub fn answer(&self, site: &str, question: &str) -> Option<String> {
        let context = if question.is_empty() { None } else { Some(question) };
        let seed = site_key(&self.key, site, 1, Purpose::Recovery, context);

        derive_result(&seed, TYPE_PHRASE)
    }
}

impl Drop for Identity {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// One-shot password derivation. Convenient for tests and CLI; prefer
/// [`Identity`] when deriving for many sites (it runs scrypt only once).
pub fn site_password(
    full_name: &str,
    master_password: &str,
    site: &str,
    counter: u32,
    type_code: u16,
) -> Option<String> {
    Identity::new(full_name, master_password).password(site, counter, type_code)
}
