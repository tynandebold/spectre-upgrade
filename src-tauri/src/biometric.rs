//! Optional Touch ID unlock on macOS.
//!
//! Stores the 64-byte master key in the login Keychain behind a biometric
//! access-control policy. The item is released only when Touch ID succeeds
//! (enforced by the OS/Secure Enclave), so reading it prompts for a fingerprint.
//! Everything is opt-in; deleting the item disables it.

#[cfg(target_os = "macos")]
mod imp {
    use core_foundation::base::{CFType, TCFType};
    use core_foundation::boolean::CFBoolean;
    use core_foundation::data::CFData;
    use core_foundation::dictionary::CFDictionary;
    use core_foundation::string::CFString;
    use core_foundation_sys::base::{CFAllocatorRef, CFOptionFlags, CFTypeRef, OSStatus};
    use core_foundation_sys::data::CFDataRef;
    use core_foundation_sys::dictionary::CFDictionaryRef;
    use core_foundation_sys::error::CFErrorRef;
    use core_foundation_sys::string::CFStringRef;
    use std::ptr;

    #[allow(non_upper_case_globals)]
    #[link(name = "Security", kind = "framework")]
    extern "C" {
        static kSecClass: CFStringRef;
        static kSecClassGenericPassword: CFStringRef;
        static kSecAttrService: CFStringRef;
        static kSecAttrAccount: CFStringRef;
        static kSecValueData: CFStringRef;
        static kSecReturnData: CFStringRef;
        static kSecReturnAttributes: CFStringRef;
        static kSecMatchLimit: CFStringRef;
        static kSecMatchLimitOne: CFStringRef;
        static kSecAttrAccessControl: CFStringRef;
        static kSecUseOperationPrompt: CFStringRef;
        static kSecUseAuthenticationUI: CFStringRef;
        static kSecUseAuthenticationUIFail: CFStringRef;
        static kSecAttrAccessibleWhenUnlockedThisDeviceOnly: CFStringRef;

        fn SecAccessControlCreateWithFlags(
            allocator: CFAllocatorRef,
            protection: CFTypeRef,
            flags: CFOptionFlags,
            error: *mut CFErrorRef,
        ) -> CFTypeRef;
        fn SecItemAdd(attributes: CFDictionaryRef, result: *mut CFTypeRef) -> OSStatus;
        fn SecItemCopyMatching(query: CFDictionaryRef, result: *mut CFTypeRef) -> OSStatus;
        fn SecItemDelete(query: CFDictionaryRef) -> OSStatus;
    }

    const SERVICE: &str = "com.tynandebold.spectreupgrade";
    const ACCOUNT: &str = "master-key";

    // kSecAccessControlBiometryCurrentSet: require biometrics, invalidated if the
    // enrolled fingerprint set changes.
    const BIOMETRY_CURRENT_SET: CFOptionFlags = 1 << 3;

    const ERR_SEC_SUCCESS: OSStatus = 0;
    const ERR_SEC_ITEM_NOT_FOUND: OSStatus = -25300;
    const ERR_SEC_INTERACTION_NOT_ALLOWED: OSStatus = -25308;
    const ERR_SEC_USER_CANCELED: OSStatus = -128;
    const ERR_SEC_AUTH_FAILED: OSStatus = -25293;

    /// Borrow one of the `kSec*` string constants as a `CFType` (get rule).
    unsafe fn constant(s: CFStringRef) -> CFType {
        CFString::wrap_under_get_rule(s).as_CFType()
    }

    unsafe fn delete_internal() -> OSStatus {
        let pairs: Vec<(CFType, CFType)> = vec![
            (constant(kSecClass), constant(kSecClassGenericPassword)),
            (constant(kSecAttrService), CFString::new(SERVICE).as_CFType()),
            (constant(kSecAttrAccount), CFString::new(ACCOUNT).as_CFType()),
        ];
        let dict = CFDictionary::from_CFType_pairs(&pairs);

        SecItemDelete(dict.as_concrete_TypeRef())
    }

    /// Store `key` in the Keychain behind Touch ID, replacing any existing item.
    pub fn enable(key: &[u8]) -> Result<(), String> {
        unsafe {
            let mut error: CFErrorRef = ptr::null_mut();
            let access_control = SecAccessControlCreateWithFlags(
                ptr::null(),
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly as CFTypeRef,
                BIOMETRY_CURRENT_SET,
                &mut error,
            );

            if access_control.is_null() {
                return Err("could not create a Touch ID access-control policy".to_string());
            }

            let access_control = CFType::wrap_under_create_rule(access_control);

            let _ = delete_internal();

            let data = CFData::from_buffer(key);
            let pairs: Vec<(CFType, CFType)> = vec![
                (constant(kSecClass), constant(kSecClassGenericPassword)),
                (constant(kSecAttrService), CFString::new(SERVICE).as_CFType()),
                (constant(kSecAttrAccount), CFString::new(ACCOUNT).as_CFType()),
                (constant(kSecValueData), data.as_CFType()),
                (constant(kSecAttrAccessControl), access_control),
            ];
            let dict = CFDictionary::from_CFType_pairs(&pairs);

            let status = SecItemAdd(dict.as_concrete_TypeRef(), ptr::null_mut());

            if status != ERR_SEC_SUCCESS {
                return Err(format!("Keychain add failed (status {status})"));
            }
        }

        Ok(())
    }

    /// Read the stored key, prompting for Touch ID. `Ok(None)` if the user
    /// cancels or no item exists.
    pub fn unlock() -> Result<Option<Vec<u8>>, String> {
        unsafe {
            let prompt = CFString::new("Unlock Spectre Upgrade");
            let pairs: Vec<(CFType, CFType)> = vec![
                (constant(kSecClass), constant(kSecClassGenericPassword)),
                (constant(kSecAttrService), CFString::new(SERVICE).as_CFType()),
                (constant(kSecAttrAccount), CFString::new(ACCOUNT).as_CFType()),
                (constant(kSecReturnData), CFBoolean::true_value().as_CFType()),
                (constant(kSecMatchLimit), constant(kSecMatchLimitOne)),
                (constant(kSecUseOperationPrompt), prompt.as_CFType()),
            ];
            let dict = CFDictionary::from_CFType_pairs(&pairs);

            let mut result: CFTypeRef = ptr::null();
            let status = SecItemCopyMatching(dict.as_concrete_TypeRef(), &mut result);

            match status {
                ERR_SEC_SUCCESS if !result.is_null() => {
                    let data = CFData::wrap_under_create_rule(result as CFDataRef);

                    Ok(Some(data.bytes().to_vec()))
                }
                ERR_SEC_SUCCESS => Ok(None),
                ERR_SEC_USER_CANCELED | ERR_SEC_AUTH_FAILED | ERR_SEC_ITEM_NOT_FOUND => Ok(None),
                other => Err(format!("Touch ID unlock failed (status {other})")),
            }
        }
    }

    /// Whether a Touch ID key is stored (without prompting for a fingerprint).
    pub fn is_enabled() -> bool {
        unsafe {
            let pairs: Vec<(CFType, CFType)> = vec![
                (constant(kSecClass), constant(kSecClassGenericPassword)),
                (constant(kSecAttrService), CFString::new(SERVICE).as_CFType()),
                (constant(kSecAttrAccount), CFString::new(ACCOUNT).as_CFType()),
                (constant(kSecReturnAttributes), CFBoolean::true_value().as_CFType()),
                (constant(kSecMatchLimit), constant(kSecMatchLimitOne)),
                (constant(kSecUseAuthenticationUI), constant(kSecUseAuthenticationUIFail)),
            ];
            let dict = CFDictionary::from_CFType_pairs(&pairs);

            let mut result: CFTypeRef = ptr::null();
            let status = SecItemCopyMatching(dict.as_concrete_TypeRef(), &mut result);

            status == ERR_SEC_SUCCESS || status == ERR_SEC_INTERACTION_NOT_ALLOWED
        }
    }

    /// Remove the stored key, disabling Touch ID unlock.
    pub fn disable() -> Result<(), String> {
        unsafe {
            let status = delete_internal();

            if status == ERR_SEC_SUCCESS || status == ERR_SEC_ITEM_NOT_FOUND {
                Ok(())
            } else {
                Err(format!("could not remove the Touch ID key (status {status})"))
            }
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
