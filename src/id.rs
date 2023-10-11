use std::fmt::Debug;

use rkyv::{Deserialize, Serialize, Archive};

use crate::{kt2::Gen, sign::random_bytes};

pub const ID_LEN: usize = 16;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[derive(Archive, Serialize, Deserialize)]
#[archive(check_bytes)]
#[archive_attr(derive(PartialEq, Eq, Hash))]
/// A primitive 16-byte ID.
pub struct ID([u8; ID_LEN]);

impl ID {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    fn as_string(&self) -> String {
        bs58::encode(&self.0).into_string()
    }
}

impl Debug for ID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_string())
    }
}

impl Gen for ID {
    fn gen() -> Self {
        let mut id = [0u8; ID_LEN];
        random_bytes(&mut id, ID_LEN);
        Self(id)
    }
}

/// Implements Deref for the given ID and target type.
macro_rules! impl_deref {
    ($id:ident, $ty:ty) => {
        impl std::ops::Deref for $id {
            type Target = $ty;

            fn deref(&self) -> &$ty {
                &self.0
            }
        }
    };
}

/// Implements DerefMut for the given ID and target type.
macro_rules! impl_derefmut {
    ($id:ident, $ty:ty) => {
        impl std::ops::DerefMut for $id {
            fn deref_mut(&mut self) -> &mut $ty {
                &mut self.0
            }
        }
    };
}

/// Implements Gen for the given ID.
macro_rules! impl_gen {
    ($id:ident) => {
        impl Gen for $id {
            fn gen() -> Self {
                Self(ID::gen())
            }
        }
    };
}

// these exist to prevent accidentally using the wrong ID
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[derive(Archive, Serialize, Deserialize)]
#[archive(check_bytes)]
#[archive_attr(derive(PartialEq, Eq, Hash))]
pub struct UserID(ID);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[derive(Archive, Serialize, Deserialize)]
#[archive(check_bytes)]
#[archive_attr(derive(PartialEq, Eq, Hash))]
pub struct AccountID(ID);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[derive(Archive, Serialize, Deserialize)]
#[archive(check_bytes)]
#[archive_attr(derive(PartialEq, Eq, Hash))]
pub struct AppID(ID);

impl_deref!(UserID, ID);
impl_deref!(AccountID, ID);
impl_deref!(AppID, ID);

impl_derefmut!(UserID, ID);
impl_derefmut!(AccountID, ID);
impl_derefmut!(AppID, ID);

impl_gen!(UserID);
impl_gen!(AccountID);
impl_gen!(AppID);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_id() {
        let id = ID::gen();
        let id2 = ID::gen();
        assert_ne!(id, id2);
        assert_eq!(id, id);
        assert_eq!(id.as_bytes().len(), ID_LEN);
        assert_eq!(id.as_string().len(), 22);
    }
}