use criterion::{black_box, criterion_group, criterion_main, Criterion};

#[cfg(feature = "sp1-nizk")]
fn binding_backend(c: &mut Criterion) {
    use binding_host::Sp1NizkSetup;

    c.bench_function("binding_sp1_setup_only_not_a_proof_benchmark", |b| {
        b.iter(|| black_box(Sp1NizkSetup::setup()))
    });
}

#[cfg(not(feature = "sp1-nizk"))]
fn binding_backend(c: &mut Criterion) {
    c.bench_function("binding_backend_requires_concrete_feature", |b| {
        b.iter(|| black_box(()))
    });
}

criterion_group!(benches, binding_backend);
criterion_main!(benches);
