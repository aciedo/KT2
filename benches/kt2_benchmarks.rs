use criterion::{Criterion, criterion_group};

mod kt2_benches {
    use criterion::Throughput;
    use kt2::{Keypair, PublicKey};

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
            b.iter(|| keypair.verify(msg, &sig))
        });
    }
    
    fn derive_pk(c: &mut Criterion) {
        let keypair = Keypair::generate(None);

        c.bench_function("d3 derive pk", move |b| {
            b.iter(|| PublicKey::from_sk(&keypair.secret))
        });
    }
    
    fn aes(c: &mut Criterion) {
        let mut bytes = vec![0u8; 1024 * 1024 * 64]; // 64 MB
        let keypair = Keypair::generate(None);
        
        let mut group = c.benchmark_group("aes");
        group.throughput(Throughput::Bytes(bytes.len() as u64));
        group.bench_function("encrypt", |b| b.iter(|| keypair.secret.encrypt(&mut bytes)));
        group.bench_function("decrypt", |b| b.iter(|| keypair.secret.decrypt(&mut bytes)));
        group.finish();
    }

    criterion_group! {
        name = d3_benches;
        config = Criterion::default();
        targets =
            sign,
            verify,
            key_generation,
            derive_pk,
            aes
    }
}

criterion::criterion_main!(kt2_benches::d3_benches);