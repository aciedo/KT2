use criterion::{Criterion, criterion_group};

mod d3_benches {
    use d3::{Keypair, PublicKey};

    use super::*;

    fn key_generation(c: &mut Criterion) {
        c.bench_function("d3 keypair gen", move |b| {
            b.iter(|| Keypair::generate(None));
        });
    }

    fn sign(c: &mut Criterion) {
        let keypair = Keypair::generate(None);
        let msg = b"";

        c.bench_function("d3 sign", move |b| b.iter(|| keypair.sign(msg)));
    }

    fn verify(c: &mut Criterion) {
        let keypair = Keypair::generate(None);
        let msg = b"";
        let sig = keypair.sign(msg);

        c.bench_function("d3 verify", move |b| {
            b.iter(|| keypair.verify(msg, sig.as_slice()))
        });
    }
    
    fn derive_pk(c: &mut Criterion) {
        let keypair = Keypair::generate(None);

        c.bench_function("d3 derive pk", move |b| {
            b.iter(|| PublicKey::from_sk(&keypair.secret))
        });
    }

    criterion_group! {
        name = d3_benches;
        config = Criterion::default();
        targets =
            sign,
            verify,
            key_generation,
            derive_pk
    }
}

criterion::criterion_main!(d3_benches::d3_benches);