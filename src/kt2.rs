use std::fmt::Debug;
use blake3::{hash, Hasher};
use ring::error::Unspecified;

use crate::{Signature, SecretKey, id::{AccountID, AppID}, Keypair};

/// A trait for generating a random self.
pub trait Gen {
    fn gen() -> Self;
}

/// Implements SymEnc for a tuple struct wrapping a PrivateKey
macro_rules! impl_sym_enc {
    ($id:ident) => {
        impl $id {
            pub fn encrypt(&self, data: &mut Vec<u8>) -> Result<(), Unspecified> {
                self.0.encrypt(data)
            }
            pub fn decrypt(&self, data: &mut Vec<u8>) -> Result<(), Unspecified> {
                self.0.decrypt(data)
            }
        }
    };
}

/// Implements Signing for a tuple struct wrapping a PrivateKey
macro_rules! impl_signing {
    ($id:ident) => {
        impl $id {
            pub fn sign(&self, msg: &[u8]) -> Signature {
                self.0.sign(msg)
            }
        }
    };
}

/// A root data access key for a user. This is synced between devices with full
/// user access.
#[derive(Debug)]
pub struct UserKey(pub SecretKey);

impl Gen for UserKey {
    fn gen() -> Self {
        Self(Keypair::generate(None).secret)
    }
}

impl Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Print a base58-encoded hash of the key. Useful for identifying keys but cannot be used to
        // recover the key.
        write!(
            f,
            "{}",
            bs58::encode(hash(&self.bytes).as_bytes()).into_string()
        )
    }
}

impl UserKey {
    /// Creates a new account key for an account ID.
    pub fn get_account_key(&self, id: &AccountID) -> AccountKey {
        let hash = Hasher::new()
            .update(&self.0.bytes)
            .update(id.as_bytes())
            .finalize();
        AccountKey(Keypair::generate(Some(hash.as_bytes())).secret)
    }
}

#[derive(Debug)]
/// An account data access key. These are derived from a user key and an account ID.
pub struct AccountKey(pub SecretKey);

impl AccountKey {
    pub fn get_app_key(&self, id: &AppID) -> AppKey {
        let hash = Hasher::new()
            .update(&self.0.bytes)
            .update(id.as_bytes())
            .finalize();
        AppKey(Keypair::generate(Some(hash.as_bytes())).secret)
    }
}

#[derive(Debug)]
/// An app data access key. These are derived from an account key and an app ID.
pub struct AppKey(pub SecretKey);

#[derive(Debug)]
/// A multi-user account data access key. These are derived from a list of account keys.
pub struct MultiUserAccountKey(pub SecretKey);

impl MultiUserAccountKey {
    pub fn new(mut account_keys: Vec<AccountKey>) -> Self {
        account_keys.sort_by(|a, b| a.0.bytes.cmp(&b.0.bytes));
        let mut hasher = Hasher::new();
        for key in account_keys {
            hasher.update(&key.0.bytes);
        }
        Self(Keypair::generate(Some(hasher.finalize().as_bytes())).secret)
    }
}

impl MultiUserAccountKey {
    pub fn get_app_key(&self, id: &AppID) -> AppKey {
        let hash = Hasher::new()
            .update(&self.0.bytes)
            .update(id.as_bytes())
            .finalize();
        AppKey(Keypair::generate(Some(hash.as_bytes())).secret)
    }
}

impl_sym_enc!(UserKey);
impl_sym_enc!(AccountKey);
impl_sym_enc!(AppKey);
impl_sym_enc!(MultiUserAccountKey);

impl_signing!(UserKey);
impl_signing!(AccountKey);
impl_signing!(AppKey);
impl_signing!(MultiUserAccountKey);

#[cfg(test)]
mod tests {
    use crate::PublicKey;

    use super::*;
    const MSG: &[u8] = b"hello world";
    
    #[test]
    fn test_user_key() {
        let user_key = UserKey::gen();
        let sig = user_key.sign(MSG);
        assert!(PublicKey::from_sk(&user_key.0).verify(MSG, &sig));
        
        let mut msg = MSG.to_vec();
        user_key.encrypt(&mut msg).unwrap();
        assert_ne!(msg, MSG);
        user_key.decrypt(&mut msg).unwrap();
        assert_eq!(msg, MSG);
    }
    
    #[test]
    fn test_account_key() {
        let user_key = UserKey::gen();
        let account_key = user_key.get_account_key(&AccountID::gen());
        let sig = account_key.sign(MSG);
        assert!(PublicKey::from_sk(&account_key.0).verify(MSG, &sig));
        
        let mut msg = MSG.to_vec();
        account_key.encrypt(&mut msg).unwrap();
        assert_ne!(msg, MSG);
        account_key.decrypt(&mut msg).unwrap();
        assert_eq!(msg, MSG);
    }
    
    #[test]
    fn test_app_key() {
        let user_key = UserKey::gen();
        let account_key = user_key.get_account_key(&AccountID::gen());
        let app_key = account_key.get_app_key(&AppID::gen());
        let sig = app_key.sign(MSG);
        assert!(PublicKey::from_sk(&app_key.0).verify(MSG, &sig));
        
        let mut msg = MSG.to_vec();
        app_key.encrypt(&mut msg).unwrap();
        assert_ne!(msg, MSG);
        app_key.decrypt(&mut msg).unwrap();
        assert_eq!(msg, MSG);
    }
    
    #[test]
    fn test_determinism() {
        let user_key = UserKey::gen();
        
        let account_id = AccountID::gen();
        let account_key = user_key.get_account_key(&account_id);
        let account_key2 = user_key.get_account_key(&account_id);
        assert_eq!(account_key.0.bytes, account_key2.0.bytes);
        
        let app_id = AppID::gen();
        let app_key = account_key.get_app_key(&app_id);
        let app_key2 = account_key2.get_app_key(&app_id);
        assert_eq!(app_key.0.bytes, app_key2.0.bytes);
        
        let multi_user_account_key = MultiUserAccountKey::new(vec![account_key, account_key2]);
        let app_key3 = multi_user_account_key.get_app_key(&app_id);
        let app_key4 = multi_user_account_key.get_app_key(&app_id);
        assert_eq!(app_key3.0.bytes, app_key4.0.bytes);
    }
}