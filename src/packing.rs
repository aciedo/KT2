use crate::{params, poly, polyvec::{Polyveck, Polyvecl}};
const K: usize = params::K;
const L: usize = params::L;
const N: usize = params::N as usize;

/// Bit-pack public key pk = (rho, t1).
/// 
/// # Arguments
/// 
/// * 'pk' - output for public key value
/// * 'rho' - const reference to rho of params::SEEDBYTES length
/// * 't1' - const reference to t1
pub fn pack_pk(pk: &mut [u8], rho: &[u8], t1: &Polyveck) {
    pk[..params::SEED_BYTES].copy_from_slice(&rho[..params::SEED_BYTES]);
    for i in 0..K {
        poly::t1_pack(&mut pk[params::SEED_BYTES + i * params::POLYT1_PACKEDBYTES..], &t1.vec[i]);
    }
}

/// Unpack public key pk = (rho, t1).
/// 
/// # Arguments
/// 
/// * 'rho' - output for rho value of params::SEEDBYTES length
/// * 't1' - output for t1 value
/// * 'pk' - const reference to public key
pub fn unpack_pk(rho: &mut [u8], t1: &mut Polyveck, pk: &[u8]) {
    rho[..params::SEED_BYTES].copy_from_slice(&pk[..params::SEED_BYTES]);
    for i in 0..K {
        poly::t1_unpack(&mut t1.vec[i], &pk[params::SEED_BYTES + i * params::POLYT1_PACKEDBYTES..]);
    }
}

/// Bit-pack secret key sk = (rho, key, tr, s1, s2, t0).
pub fn pack_sk(
    sk: &mut [u8],
    rho: &[u8],
    tr: &[u8],
    key: &[u8],
    t0: &Polyveck,
    s1: &Polyvecl,
    s2: &Polyveck
) {
    sk[..params::SEED_BYTES].copy_from_slice(&rho[0..params::SEED_BYTES]);
    let mut idx = params::SEED_BYTES;

    sk[idx..idx + params::SEED_BYTES].copy_from_slice(&key[0..params::SEED_BYTES]);
    idx += params::SEED_BYTES;

    sk[idx..idx + params::SEED_BYTES].copy_from_slice(&tr[0..params::SEED_BYTES]);
    idx += params::SEED_BYTES;

    for i in 0..L {
        poly::eta_pack(&mut sk[idx + i * params::POLYETA_PACKEDBYTES..], &s1.vec[i]);
    }
    idx += L * params::POLYETA_PACKEDBYTES;

    for i in 0..K {
        poly::eta_pack(&mut sk[idx + i * params::POLYETA_PACKEDBYTES..], &s2.vec[i]);
    }
    idx += K * params::POLYETA_PACKEDBYTES;

    for i in 0..K {
        poly::t0_pack(&mut sk[idx + i * params::POLYT0_PACKEDBYTES..], &t0.vec[i]);
    }
}

/// Unpack secret key sk = (rho, key, tr, s1, s2, t0).
pub fn unpack_sk(
    rho: &mut [u8],
    tr: &mut [u8],
    key: &mut [u8],
    t0: &mut Polyveck,
    s1: &mut Polyvecl,
    s2: &mut Polyveck,
    sk: &[u8]
) {
    rho[..params::SEED_BYTES].copy_from_slice(&sk[..params::SEED_BYTES]);
    let mut idx = params::SEED_BYTES;

    key[..params::SEED_BYTES].copy_from_slice(&sk[idx..idx + params::SEED_BYTES]);
    idx += params::SEED_BYTES;

    tr[..params::SEED_BYTES].copy_from_slice(&sk[idx..idx + params::SEED_BYTES]);
    idx += params::SEED_BYTES;

    for i in 0..L {
        poly::eta_unpack(&mut s1.vec[i], &sk[idx + i * params::POLYETA_PACKEDBYTES..]);
    }
    idx += L * params::POLYETA_PACKEDBYTES;

    for i in 0..K {
        poly::eta_unpack(&mut s2.vec[i], &sk[idx + i * params::POLYETA_PACKEDBYTES..]);
    }
    idx += K * params::POLYETA_PACKEDBYTES;

    for i in 0..K {
        poly::t0_unpack(&mut t0.vec[i], &sk[idx + i * params::POLYT0_PACKEDBYTES..]);
    }
}

/// Bit-pack signature sig = (c, z, h).
pub fn pack_sig(sig: &mut [u8], c: Option<&[u8]>, z: &Polyvecl, h: &Polyveck) {
    if let Some(challenge) = c {
        sig[..params::SEED_BYTES].copy_from_slice(&challenge[..params::SEED_BYTES]);
    }

    let mut idx = params::SEED_BYTES;
    for i in 0..L {
        poly::z_pack(&mut sig[idx + i * params::POLYZ_PACKEDBYTES..], &z.vec[i]);
    }

    idx += L * params::POLYZ_PACKEDBYTES;
    sig[idx..idx + params::OMEGA + K].copy_from_slice(&[0u8; params::OMEGA + K]);

    let mut k = 0;
    for i in 0..K {
        for j in 0..N {
        if h.vec[i].coeffs[j] != 0 {
            sig[idx + k] = j as u8;
            k += 1;
        }
        }
        sig[idx + params::OMEGA + i] = k as u8;
    }
}

/// Unpack signature sig = (z, h, c).
pub fn unpack_sig(
    c: &mut [u8],
    z: &mut Polyvecl,
    h: &mut Polyveck,
    sig: &[u8],
) -> bool {
    c[..params::SEED_BYTES].copy_from_slice(&sig[..params::SEED_BYTES]);
    
    let mut idx = params::SEED_BYTES;
    for i in 0..L {
        poly::z_unpack(&mut z.vec[i], &sig[idx + i * params::POLYZ_PACKEDBYTES..]);
    }
    idx += L * params::POLYZ_PACKEDBYTES;

    let mut k: usize = 0;
    for i in 0..K {
        if sig[idx + params::OMEGA + i] < k as u8 || sig[idx + params::OMEGA + i] > params::OMEGA as u8 {
            return false;
        }
        for j in k..sig[idx + params::OMEGA + i] as usize {
            if j > k && sig[idx + j as usize] <= sig[idx + j as usize - 1] {
                return false;
            }
            h.vec[i].coeffs[sig[idx + j] as usize] = 1;
        }
        k = sig[idx + params::OMEGA + i] as usize;
    }

    for j in k..params::OMEGA {
        if sig[idx + j as usize] > 0 {
            return false;
        }
    }

    true
}