use rand::RngCore;

use crate::{fips202, packing, params, poly, poly::Poly, polyvec, polyvec::{Polyveck, Polyvecl}};
use crate::params::{K, L};

/// Generate random bytes.
/// 
/// # Arguments
/// 
/// * 'bytes' - an array to fill with random data
/// * 'n' - number of bytes to generate
pub fn random_bytes(bytes: &mut [u8], n: usize) {
    rand::prelude::thread_rng().try_fill_bytes(&mut bytes[..n]).unwrap();
}

/// Generate public and private key.
/// 
/// # Arguments
/// 
/// * 'pk' - preallocated buffer for public key
/// * 'sk' - preallocated buffer for private key
/// * 'seed' - optional seed; if None [random_bytes()] is used for randomness generation
pub fn keypair(pk: &mut [u8], sk: &mut [u8], seed: Option<&[u8]>) {
    let mut init_seed = [0u8; params::SEED_BYTES];
    match seed {
        Some(x) => init_seed.copy_from_slice(x),
        None => random_bytes(&mut init_seed, params::SEED_BYTES)
    };

    const SEEDBUF_LEN: usize = 2 * params::SEED_BYTES + params::CRHBYTES;
    let mut seedbuf = [0u8; SEEDBUF_LEN];
    fips202::shake256(&mut seedbuf, SEEDBUF_LEN, &init_seed, params::SEED_BYTES);

    let mut rho = [0u8; params::SEED_BYTES];
    rho.copy_from_slice(&seedbuf[..params::SEED_BYTES]);

    let mut rhoprime = [0u8; params::CRHBYTES];
    rhoprime.copy_from_slice(&seedbuf[params::SEED_BYTES..params::SEED_BYTES + params::CRHBYTES]);

    let mut key = [0u8; params::SEED_BYTES];
    key.copy_from_slice(&seedbuf[params::SEED_BYTES + params::CRHBYTES..]);

    let mut mat = [Polyvecl::default(); K];
    polyvec::matrix_expand(&mut mat, &rho);

    let mut s1 = Polyvecl::default();
    polyvec::l_uniform_eta(&mut s1, &rhoprime, 0);

    let mut s2 = Polyveck::default();
    polyvec::k_uniform_eta(&mut s2, &rhoprime, L as u16);

    let mut s1hat = s1;
    polyvec::l_ntt(&mut s1hat);

    let mut t1 = Polyveck::default();
    polyvec::matrix_pointwise_montgomery(&mut t1, &mat, &s1hat);
    polyvec::k_reduce(&mut t1);
    polyvec::k_invntt_tomont(&mut t1);
    polyvec::k_add(&mut t1, &s2);
    polyvec::k_caddq(&mut t1);

    let mut t0 = Polyveck::default();
    polyvec::k_power2round(&mut t1, &mut t0);

    packing::pack_pk(pk, &rho, &t1);

    let mut tr = [0u8; params::SEED_BYTES];
    fips202::shake256(&mut tr, params::SEED_BYTES, pk, params::PUBLICKEYBYTES);

    packing::pack_sk(sk, &rho, &tr, &key, &t0, &s1, &s2);
}

/// Compute a signature for a given message from a private (secret) key.
///
/// # Arguments
///
/// * 'sig' - preallocated with at least SIGNBYTES buffer
/// * 'msg' - message to sign
/// * 'sk' - private key to use
/// * 'randomized' - indicates wether to randomize the signature or to act deterministicly
pub fn signature(sig: &mut [u8], msg: &[u8], sk: &[u8], randomized: bool) {
    let mut rho = [0u8; params::SEED_BYTES];
    let mut tr = [0u8; params::SEED_BYTES];
    let mut keymu = [0u8; params::SEED_BYTES + params::CRHBYTES];
    let mut t0 = Polyveck::default();
    let mut s1 = Polyvecl::default();
    let mut s2 = Polyveck::default();

    packing::unpack_sk(&mut rho, &mut tr, &mut keymu[..params::SEED_BYTES], &mut t0, &mut s1, &mut s2, &sk);

    let mut state = fips202::KeccakState::default();
    fips202::shake256_absorb(&mut state, &tr, params::SEED_BYTES);
    fips202::shake256_absorb(&mut state, &msg, msg.len());
    fips202::shake256_finalize(&mut state);
    fips202::shake256_squeeze(&mut keymu[params::SEED_BYTES..], params::CRHBYTES, &mut state);

    let mut rhoprime = [0u8; params::CRHBYTES];
    if randomized {
        random_bytes(&mut rhoprime, params::CRHBYTES);
    } else {
        fips202::shake256(&mut rhoprime, params::CRHBYTES, &keymu, params::SEED_BYTES + params::CRHBYTES);
    }

    let mut mat = [Polyvecl::default(); K];
    polyvec::matrix_expand(&mut mat, &rho);
    polyvec::l_ntt(&mut s1);
    polyvec::k_ntt(&mut s2);
    polyvec::k_ntt(&mut t0);

    let mut nonce: u16 = 0;
    let mut y = Polyvecl::default();
    let mut w1 = Polyveck::default();
    let mut w0 = Polyveck::default();
    let mut cp = Poly::default();
    let mut h = Polyveck::default();
    loop {
        polyvec::l_uniform_gamma1(&mut y, &rhoprime, nonce);
        nonce += 1;

        let mut z = y;
        polyvec::l_ntt(&mut z);
        polyvec::matrix_pointwise_montgomery(&mut w1, &mat, &z);
        polyvec::k_reduce(&mut w1);
        polyvec::k_invntt_tomont(&mut w1);
        polyvec::k_caddq(&mut w1);

        polyvec::k_decompose(&mut w1, &mut w0);
        polyvec::k_pack_w1(sig, &w1);

        state.init();
        fips202::shake256_absorb(&mut state, &keymu[params::SEED_BYTES..], params::CRHBYTES);
        fips202::shake256_absorb(&mut state, &sig, K * params::POLYW1_PACKEDBYTES);
        fips202::shake256_finalize(&mut state);
        fips202::shake256_squeeze(sig, params::SEED_BYTES, &mut state);

        poly::challenge(&mut cp, sig);
        poly::ntt(&mut cp);

        polyvec::l_pointwise_poly_montgomery(&mut z, &cp, &s1);
        polyvec::l_invntt_tomont(&mut z);
        polyvec::l_add(&mut z, &y);
        polyvec::l_reduce(&mut z);

        if polyvec::l_chknorm(&z, (params::GAMMA1 - params::BETA) as i32) > 0 {
            continue;
        }

        polyvec::k_pointwise_poly_montgomery(&mut h, &cp, &s2);
        polyvec::k_invntt_tomont(&mut h);
        polyvec::k_sub(&mut w0, &h);
        polyvec::k_reduce(&mut w0);

        if polyvec::k_chknorm(&w0, (params::GAMMA2 - params::BETA) as i32) > 0 {
            continue;
        }

        polyvec::k_pointwise_poly_montgomery(&mut h, &cp, &t0);
        polyvec::k_invntt_tomont(&mut h);
        polyvec::k_reduce(&mut h);

        if polyvec::k_chknorm(&h, params::GAMMA2 as i32) > 0 {
            continue;
        }

        polyvec::k_add(&mut w0, &h);

        let n = polyvec::k_make_hint(&mut h, &w0, &w1);

        if n > params::OMEGA as i32 {
            continue;
        }

        packing::pack_sig(sig, None, &z, &h);

        return;
    }
}

/// Verify a signature for a given message with a public key.
/// 
/// # Arguments
/// 
/// * 'sig' - signature to verify
/// * 'm' - message that is claimed to be signed
/// * 'pk' - public key
/// 
/// Returns 'true' if the verification process was successful, 'false' otherwise
pub fn verify(sig: &[u8], m: &[u8], pk: &[u8]) -> bool {
    let mut buf = [0u8; K * crate::params::POLYW1_PACKEDBYTES];
    let mut rho = [0u8; params::SEED_BYTES];
    let mut mu = [0u8; params::CRHBYTES];
    let mut c = [0u8; params::SEED_BYTES];
    let mut c2 = [0u8; params::SEED_BYTES];
    let mut cp = Poly::default();
    let (mut mat, mut z) = ([Polyvecl::default(); K], Polyvecl::default());
    let (mut t1, mut w1, mut h) = (
        Polyveck::default(),
        Polyveck::default(),
        Polyveck::default(),
    );
    let mut state = fips202::KeccakState::default(); // shake256_init()

    if sig.len() != crate::params::SIGNBYTES {
        return false;
    }

    packing::unpack_pk(&mut rho, &mut t1, pk);
    if !packing::unpack_sig(&mut c, &mut z, &mut h, sig) {
        return false;
    }
    if polyvec::l_chknorm(
        &z,
        (crate::params::GAMMA1 - crate::params::BETA) as i32,
    ) > 0
    {
        return false;
    }

    // Compute CRH(CRH(rho, t1), msg)
    fips202::shake256(
        &mut mu,
        params::SEED_BYTES,
        pk,
        crate::params::PUBLICKEYBYTES,
    );
    fips202::shake256_absorb(&mut state, &mu, params::SEED_BYTES);
    fips202::shake256_absorb(&mut state, m, m.len());
    fips202::shake256_finalize(&mut state);
    fips202::shake256_squeeze(&mut mu, params::CRHBYTES, &mut state);

    // Matrix-vector multiplication; compute Az - c2^dt1
    poly::challenge(&mut cp, &c);
    polyvec::matrix_expand(&mut mat, &rho);

    polyvec::l_ntt(&mut z);
    polyvec::matrix_pointwise_montgomery(&mut w1, &mat, &z);

    poly::ntt(&mut cp);
    polyvec::k_shiftl(&mut t1);
    polyvec::k_ntt(&mut t1);
    let t1_2 = t1.clone();
    polyvec::k_pointwise_poly_montgomery(&mut t1, &cp, &t1_2);

    polyvec::k_sub(&mut w1, &t1);
    polyvec::k_reduce(&mut w1);
    polyvec::k_invntt_tomont(&mut w1);

    // Reconstruct w1
    polyvec::k_caddq(&mut w1);
    polyvec::k_use_hint(&mut w1, &h);
    polyvec::k_pack_w1(&mut buf, &w1);

    // Call random oracle and verify challenge
    state.init();
    fips202::shake256_absorb(&mut state, &mu, params::CRHBYTES);
    fips202::shake256_absorb(
        &mut state,
        &buf,
        K * crate::params::POLYW1_PACKEDBYTES,
    );
    fips202::shake256_finalize(&mut state);
    fips202::shake256_squeeze(&mut c2, params::SEED_BYTES, &mut state);
    // Doesn't require constant time equality check
    if c != c2 {
        return false;
    }
    true
}
