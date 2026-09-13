//! Optional Touch ID unlock on macOS.
//!
//! The 64-byte master key is stored in the login Keychain (no entitlement
//! needed, so it works on an unsigned build) and reading it is gated behind a
//! LocalAuthentication Touch ID prompt. Opt-in; deleting the item disables it.
//!
//! Note: a fully Secure-Enclave-bound key (kSecAccessControlBiometry*) requires
//! the data-protection keychain, which needs code-signing entitlements from a
//! paid Apple Developer identity. This app is ad-hoc signed, so we gate access
//! at the app/OS-auth layer instead.

#[cfg(target_os = "macos")]
mod imp {
    use keyring::Entry;

    const SERVICE: &str = "com.tynandebold.spectreupgrade";
    const ACCOUNT: &str = "master-key";

    fn entry() -> Result<Entry, String> {
        Entry::new(SERVICE, ACCOUNT).map_err(|e| e.to_string())
    }

    /// Show the system Touch ID prompt (biometrics, with password fallback).
    /// Returns whether authentication succeeded.
    fn authenticate() -> Result<bool, String> {
        use robius_authentication::{
            AndroidText, BiometricStrength, Context, PolicyBuilder, Text, WindowsText,
        };
        use std::sync::mpsc;

        let policy = PolicyBuilder::new()
            .biometrics(Some(BiometricStrength::Strong))
            .password(true)
            .build()
            .ok_or_else(|| "could not build an authentication policy".to_string())?;

        let text = Text {
            apple: "unlock Spectre Upgrade",
            android: AndroidText {
                title: "Unlock Spectre Upgrade",
                subtitle: None,
                description: None,
            },
            windows: WindowsText::new("Spectre Upgrade", "Unlock Spectre Upgrade")
                .ok_or_else(|| "invalid prompt text".to_string())?,
        };

        // authenticate() is callback-based; bridge it to a blocking call.
        let context = Context::new(());
        let (tx, rx) = mpsc::channel();
        let _ = context.authenticate(text, &policy, move |result| {
            let _ = tx.send(result.is_ok());
        });

        rx.recv().map_err(|_| "authentication did not complete".to_string())
    }

    /// Store the master key in the Keychain (call from an unlocked session).
    pub fn enable(key: &[u8]) -> Result<(), String> {
        entry()?.set_secret(key).map_err(|e| e.to_string())
    }

    /// Prompt for Touch ID and, on success, return the stored key.
    pub fn unlock() -> Result<Option<Vec<u8>>, String> {
        if !authenticate()? {
            return Ok(None);
        }

        match entry()?.get_secret() {
            Ok(bytes) => Ok(Some(bytes)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }

    /// Whether a key is stored (no prompt).
    pub fn is_enabled() -> bool {
        entry().map(|e| e.get_secret().is_ok()).unwrap_or(false)
    }

    /// Remove the stored key.
    pub fn disable() -> Result<(), String> {
        match entry()?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(e.to_string()),
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    pub fn enable(_key: &[u8]) -> Result<(), String> {
        Err("Touch ID is only available on macOS".to_string())
    }

    pub fn unlock() -> Result<Option<Vec<u8>>, String> {
        Ok(None)
    }

    pub fn is_enabled() -> bool {
        false
    }

    pub fn disable() -> Result<(), String> {
        Ok(())
    }
}

pub use imp::{disable, enable, is_enabled, unlock};
