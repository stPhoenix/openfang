//! Stateless session token authentication for the dashboard.
//! Tokens are HMAC-SHA256 signed and contain username + expiry.

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Create a session token: base64(username:expiry_unix:hmac_hex)
pub fn create_session_token(username: &str, secret: &str, ttl_hours: u64) -> String {
    use base64::Engine;
    let expiry = chrono::Utc::now().timestamp() + (ttl_hours as i64 * 3600);
    let payload = format!("{username}:{expiry}");
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC key");
    mac.update(payload.as_bytes());
    let signature = hex::encode(mac.finalize().into_bytes());
    base64::engine::general_purpose::STANDARD.encode(format!("{payload}:{signature}"))
}

/// Verify a session token. Returns the username if valid and not expired.
pub fn verify_session_token(token: &str, secret: &str) -> Option<String> {
    use base64::Engine;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(token)
        .ok()?;
    let decoded_str = String::from_utf8(decoded).ok()?;
    let parts: Vec<&str> = decoded_str.splitn(3, ':').collect();
    if parts.len() != 3 {
        return None;
    }
    let (username, expiry_str, provided_sig) = (parts[0], parts[1], parts[2]);

    let expiry: i64 = expiry_str.parse().ok()?;
    if chrono::Utc::now().timestamp() > expiry {
        return None;
    }

    let payload = format!("{username}:{expiry_str}");
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).ok()?;
    mac.update(payload.as_bytes());
    let expected_sig = hex::encode(mac.finalize().into_bytes());

    use subtle::ConstantTimeEq;
    if provided_sig.len() != expected_sig.len() {
        return None;
    }
    if provided_sig
        .as_bytes()
        .ct_eq(expected_sig.as_bytes())
        .into()
    {
        Some(username.to_string())
    } else {
        None
    }
}

/// Result of password verification.
pub struct PasswordVerifyResult {
    pub valid: bool,
    /// If true, the stored hash is legacy SHA-256 and should be re-hashed with Argon2.
    pub needs_migration: bool,
}

/// Hash a password with Argon2id for config storage.
/// Returns a PHC-format string: `$argon2id$v=19$m=...,t=...,p=...$<salt>$<hash>`
pub fn hash_password(password: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .expect("Argon2 hashing should not fail")
        .to_string()
}

/// Verify a password against a stored hash.
/// Supports both Argon2 PHC strings and legacy SHA-256 hex hashes.
/// When a legacy hash matches, `needs_migration` is set so the caller can upgrade it.
pub fn verify_password(password: &str, stored_hash: &str) -> PasswordVerifyResult {
    if stored_hash.starts_with("$argon2") {
        // Argon2 PHC format
        let parsed = match PasswordHash::new(stored_hash) {
            Ok(h) => h,
            Err(_) => {
                return PasswordVerifyResult {
                    valid: false,
                    needs_migration: false,
                }
            }
        };
        let valid = Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok();
        PasswordVerifyResult {
            valid,
            needs_migration: false,
        }
    } else {
        // Legacy SHA-256 hex format
        let computed = legacy_sha256_hash(password);
        use subtle::ConstantTimeEq;
        let valid = if computed.len() != stored_hash.len() {
            false
        } else {
            computed.as_bytes().ct_eq(stored_hash.as_bytes()).into()
        };
        PasswordVerifyResult {
            valid,
            needs_migration: valid,
        }
    }
}

/// Legacy SHA-256 hash for backward-compatible verification during migration.
fn legacy_sha256_hash(password: &str) -> String {
    use sha2::Digest;
    hex::encode(Sha256::digest(password.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_and_verify_password() {
        let hash = hash_password("secret123");
        assert!(hash.starts_with("$argon2"));
        let result = verify_password("secret123", &hash);
        assert!(result.valid);
        assert!(!result.needs_migration);

        let result = verify_password("wrong", &hash);
        assert!(!result.valid);
    }

    #[test]
    fn test_legacy_sha256_verify_and_migration() {
        // Simulate a legacy SHA-256 hash stored in config
        let legacy_hash = legacy_sha256_hash("secret123");
        assert_eq!(legacy_hash.len(), 64); // SHA-256 hex = 64 chars

        let result = verify_password("secret123", &legacy_hash);
        assert!(result.valid);
        assert!(result.needs_migration);

        let result = verify_password("wrong", &legacy_hash);
        assert!(!result.valid);
        assert!(!result.needs_migration);
    }

    #[test]
    fn test_argon2_hashes_are_unique() {
        let h1 = hash_password("same");
        let h2 = hash_password("same");
        assert_ne!(h1, h2); // Different salts → different hashes
        assert!(verify_password("same", &h1).valid);
        assert!(verify_password("same", &h2).valid);
    }

    #[test]
    fn test_hash_produces_unique_salts() {
        let h1 = hash_password("same");
        let h2 = hash_password("same");
        assert_ne!(h1, h2, "each hash should use a unique salt");
        assert!(verify_password("same", &h1).valid);
        assert!(verify_password("same", &h2).valid);
    }

    #[test]
    fn test_create_and_verify_token() {
        let token = create_session_token("admin", "my-secret", 1);
        let user = verify_session_token(&token, "my-secret");
        assert_eq!(user, Some("admin".to_string()));
    }

    #[test]
    fn test_token_wrong_secret() {
        let token = create_session_token("admin", "my-secret", 1);
        let user = verify_session_token(&token, "wrong-secret");
        assert_eq!(user, None);
    }

    #[test]
    fn test_token_invalid_base64() {
        let user = verify_session_token("not-valid-base64!!!", "secret");
        assert_eq!(user, None);
    }

    #[test]
    fn test_password_hash_length_mismatch() {
        let result = verify_password("x", "short");
        assert!(!result.valid);
    }

    #[test]
    fn test_verify_malformed_argon2_hash() {
        // Starts with $argon2 but is not a valid PHC string.
        let result = verify_password("x", "$argon2id$garbage");
        assert!(!result.valid);
    }
}
