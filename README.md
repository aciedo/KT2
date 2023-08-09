# `KT2`

KeyTree2 (KT2) is a 2nd generation, quantum-resistant cryptographic library used for Atlas' Data Access Layer. It is effectively a wrapper around multiple cryptographic primitives:

- Symmetric encryption: AES-256-GCM from [ring](https://docs.rs/ring/0.16.20/ring/)
- Signatures: modified Dilithium3 from CRYSTALS (we've reduced SHAKE256's rounds down to 12)
- Hashes: BLAKE3 from [blake3](https://docs.rs/blake3/latest/blake3/)
- Key encapsulation: Kyber768 from CRYSTALS (not implemented quite yet)

---
> **Use at Your Own Risk**  
> This library has not yet undergone a formal security audit by a recognized authority. As a result, there may be unknown security vulnerabilities, weaknesses, or potential flaws in the code. Users are advised to exercise caution when implementing or using this code.
---

## Build
```bash
cargo build --release
```

## How to use
```rust
use d3::Keypair;

let keypair = Keypair::generate(Some(&seed));
let sk = keypair.secret;
// pk is also available as keypair.public
let signature = keypair.sign(&msg);
// public key can now be separately derived from the secret key
let pk = PublicKey::from_sk(&sk);
let is_verified = pk.verify(&msg, &signature);
```

## Test
```bash
cargo test
```

## Benchmarks

Benchmarks are run using [criterion.rs](https://github.com/japaric/criterion.rs):
```bash
cargo bench
```
Running on an Apple M1 Max

| Benchmark                       | time      |
| :---                            |:----------|
| keypair generation              | 93.799 µs |
| signing                         | 125.73 µs |
| signature verification          | 82.825 µs |

## Docs
```bash
cargo doc --open
```

## Contributor Agreement

By contributing to this repository, you agree that your contributions will be licensed under the [GPLv3 License](https://www.gnu.org/licenses/gpl-3.0.en.html).
