use ring::{aead::{NONCE_LEN, UnboundKey, SealingKey, Aad, OpeningKey, AES_256_GCM, NonceSequence, Nonce, BoundKey}, error::Unspecified};

use crate::{SecretKey, sign::random_bytes};
pub const TAG_LEN: usize = 16;

// `Key` implements `SymEnc` using hardware-accelerated AES-GCM-256.
// Ring is used under the hood.
impl SecretKey {
    pub fn encrypt(&self, data: &mut Vec<u8>) -> Result<(), Unspecified> {
        data.reserve(NONCE_LEN + TAG_LEN);
        let mut nonce = [0u8; NONCE_LEN];
        random_bytes(&mut nonce, NONCE_LEN);
        let unbound_key = UnboundKey::new(&AES_256_GCM, &self.hash)?;
        let nonce_sequence = FixedNonceSeq { nonce };
        let mut bound_key = SealingKey::new(unbound_key, nonce_sequence);
        bound_key.seal_in_place_append_tag(Aad::empty(), data)?;
        data.extend_from_slice(&nonce);
        Ok(())
    }

    pub fn decrypt(&self, data: &mut Vec<u8>) -> Result<(), Unspecified> {
        let wanted_len = data.len() - TAG_LEN - NONCE_LEN;
        if !(data.len() >= NONCE_LEN) {
            return Err(Unspecified);
        }
        let enc_len = data.len() - NONCE_LEN;
        let (enc, slice) = data.split_at_mut(enc_len);
        let mut nonce = [0u8; NONCE_LEN];
        nonce.clone_from_slice(slice);
        let nonce_sequence = FixedNonceSeq { nonce };
        let unbound_key = UnboundKey::new(&AES_256_GCM, &self.hash)?;
        let mut bound_key = OpeningKey::new(unbound_key, nonce_sequence);
        bound_key.open_in_place(Aad::empty(), enc)?;
        data.truncate(wanted_len);
        Ok(())
    }
}

/// A FixedNonceSequence that always returns the same nonce. This is used for encryption.
/// You are explicitly NOT supposed to do this with ring, but we know what we're doing. Don't try this at home.
struct FixedNonceSeq {
    nonce: [u8; NONCE_LEN],
}

impl NonceSequence for FixedNonceSeq {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        Ok(Nonce::assume_unique_for_key(self.nonce))
    }
}