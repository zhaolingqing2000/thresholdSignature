#[cfg(feature = "concrete-lhtlp")]
fn main() {
    use threshold_signature::crypto::lhtlp::LhtlpBackend;

    let bits = std::env::args()
        .nth(1)
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(3072);
    let delta = std::env::args()
        .nth(2)
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(1024);
    let backend = LhtlpBackend::setup(bits, delta).expect("LHTLP setup failed");
    let params = backend.params();
    println!("delta={}", params.delta);
    println!("N={}", hex::encode(&params.n));
    println!("N_squared={}", hex::encode(&params.n_squared));
    println!("g_T={}", hex::encode(&params.g_t));
    println!("h_T={}", hex::encode(&params.h_t));
}

#[cfg(not(feature = "concrete-lhtlp"))]
fn main() {
    eprintln!("lhtlp_setup requires --features concrete-lhtlp");
    std::process::exit(1);
}
