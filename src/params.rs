// Specification defined constans
pub const Q: i32 = (1 << 23) - (1 << 13) + 1; //prime defining the field
pub const N: i32 = 256; //ring defining polynomial degree
pub const R: i32 = 1753; //2Nth root of unity mod Q
pub const D: i32 = 13; //dropped bits

// Implementation specific values
pub const SEED_BYTES: usize = 32;
pub const CRHBYTES: usize = 64;
pub const POLYT1_PACKEDBYTES: usize = 320;
pub const POLYT0_PACKEDBYTES: usize = 416;

// Level 3 constants
pub const TAU: usize = 49; //number of +-1s in c
pub const CHALLENGE_ENTROPY: usize = 225;
pub const GAMMA1: usize = 1 << 19; //y coefficient range
pub const GAMMA2: usize = (crate::params::Q as usize - 1) / 32; //low-order rounding range
pub const K: usize = 6; //rows in A
pub const L: usize = 5; //columns in A
pub const ETA: usize = 4;
pub const BETA: usize = TAU * ETA;
pub const OMEGA: usize = 55;
pub const POLYZ_PACKEDBYTES: usize = 640;
pub const POLYW1_PACKEDBYTES: usize = 128;
pub const POLYETA_PACKEDBYTES: usize = 128;
pub const POLYVECH_PACKEDBYTES: usize = OMEGA + K;
pub const PUBLICKEYBYTES: usize = SEED_BYTES + K * POLYT1_PACKEDBYTES;
pub const SECRETKEYBYTES: usize = 3 * SEED_BYTES + (K + L) * POLYETA_PACKEDBYTES + K * POLYT0_PACKEDBYTES;
pub const SIGNBYTES: usize = SEED_BYTES + L * POLYZ_PACKEDBYTES + POLYVECH_PACKEDBYTES;