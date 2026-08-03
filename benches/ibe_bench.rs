use criterion::{criterion_group, criterion_main, Criterion};

#[cfg(feature = "concrete-ibe")]
fn ibe_backend(c: &mut Criterion) {
    use threshold_signature::crypto::ibe_backend::ConcreteIbeBackend;

    c.bench_function("ibe_cgwfo_setup", |b| b.iter(ConcreteIbeBackend::setup));
    let (pk, sk) = ConcreteIbeBackend::setup();
    let d = [3u8; 32];
    c.bench_function("ibe_cgwfo_extract", |b| {
        b.iter(|| ConcreteIbeBackend::extract(&pk, &sk, b"message", &d).unwrap())
    });
    c.bench_function("ibe_cgwfo_encrypt_signer_index", |b| {
        b.iter(|| ConcreteIbeBackend::encrypt(&pk, b"message", &d, 4).unwrap())
    });
    let usk = ConcreteIbeBackend::extract(&pk, &sk, b"message", &d).unwrap();
    let ct = ConcreteIbeBackend::encrypt(&pk, b"message", &d, 4).unwrap();
    c.bench_function("ibe_cgwfo_decrypt_signer_index", |b| {
        b.iter(|| ConcreteIbeBackend::decrypt(&pk, &usk, b"message", &d, &ct).unwrap())
    });
}

#[cfg(not(feature = "concrete-ibe"))]
fn ibe_backend(c: &mut Criterion) {
    c.bench_function("ibe_backend_requires_concrete_feature", |b| b.iter(|| ()));
}

criterion_group!(benches, ibe_backend);
criterion_main!(benches);
