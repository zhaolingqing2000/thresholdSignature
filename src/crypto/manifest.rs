#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackendManifest {
    pub lhtlp: &'static str,
    pub lhtlp_modulus_bits: Option<usize>,
    pub delta: Option<u64>,
    pub ibe: &'static str,
    pub proof_backend: &'static str,
    pub mock_backend_active: bool,
    pub instantiation_label: &'static str,
}

impl BackendManifest {
    pub fn current() -> Self {
        let lhtlp = if cfg!(feature = "concrete-lhtlp") {
            "Malavolta-Thyagarajan reusable LHTLP over Z_N with OpenSSL BigNum"
        } else {
            "test additive puzzle backend"
        };
        let ibe = if cfg!(feature = "concrete-ibe") {
            "ibe::kem::cgw_fo::CGWFO with AES-256-GCM payload encryption"
        } else {
            "test tracing encryption backend"
        };
        let proof_backend = if cfg!(feature = "sp1-nizk") {
            "SP1 v6.1.0 Groth16 binding backend"
        } else {
            "test digest binding backend"
        };
        let binding_backend_available = false;
        let mock_backend_active = !cfg!(feature = "concrete-lhtlp")
            || !cfg!(feature = "concrete-ibe")
            || !cfg!(feature = "sp1-nizk")
            || cfg!(feature = "test-backend")
            || !binding_backend_available;
        let instantiation_label = if mock_backend_active {
            "PARTIAL CONCRETE INSTANTIATION"
        } else {
            "CONCRETE INSTANTIATION"
        };
        Self {
            lhtlp,
            lhtlp_modulus_bits: None,
            delta: None,
            ibe,
            proof_backend,
            mock_backend_active,
            instantiation_label,
        }
    }

    pub fn print(&self) {
        println!("backend_instantiation={}", self.instantiation_label);
        println!("lhtlp_scheme={}", self.lhtlp);
        println!(
            "lhtlp_modulus_bits={}",
            self.lhtlp_modulus_bits
                .map(|v| v.to_string())
                .unwrap_or_else(|| "not configured".to_string())
        );
        println!(
            "delta={}",
            self.delta
                .map(|v| v.to_string())
                .unwrap_or_else(|| "not configured".to_string())
        );
        println!("ibe_scheme={}", self.ibe);
        println!("proof_backend={}", self.proof_backend);
        println!("crate_version={}", env!("CARGO_PKG_VERSION"));
        println!("mock_backend_active={}", self.mock_backend_active);
    }
}
