use criterion::{criterion_group, criterion_main, Criterion};

#[cfg(feature = "concrete-lhtlp")]
fn lhtlp_backend(c: &mut Criterion) {
    use openssl::bn::BigNum;
    use threshold_signature::crypto::lhtlp::LhtlpBackend;

    let backend = LhtlpBackend::setup(512, 64).expect("setup");
    let scalar = BigNum::from_u32(42).unwrap();
    c.bench_function("lhtlp_pgen_512_delta64", |b| {
        b.iter(|| backend.pgen(&scalar).unwrap())
    });
    let puzzles = (0..8)
        .map(|_| backend.pgen(&scalar).unwrap())
        .collect::<Vec<_>>();
    c.bench_function("lhtlp_peval_8_512_delta64", |b| {
        b.iter(|| backend.peval(&puzzles).unwrap())
    });
    let aggregate = backend.peval(&puzzles).unwrap();
    c.bench_function("lhtlp_psolve_512_delta64", |b| {
        b.iter(|| backend.psolve(&aggregate).unwrap())
    });
}

#[cfg(not(feature = "concrete-lhtlp"))]
fn lhtlp_backend(c: &mut Criterion) {
    c.bench_function("lhtlp_backend_requires_concrete_feature", |b| b.iter(|| ()));
}

criterion_group!(benches, lhtlp_backend);
criterion_main!(benches);
