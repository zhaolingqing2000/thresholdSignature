use binding_core::{
    statement_digest, verify_binding_relation, BindingError, BindingPublicParams, BindingStage,
    BindingStatement, BindingWitness,
};
#[cfg(all(feature = "sp1-nizk", not(feature = "mock-nizk")))]
use sha2::{Digest, Sha512};
#[cfg(all(feature = "sp1-nizk", not(feature = "mock-nizk")))]
use sp1_prover::HashableKey;
#[cfg(all(feature = "sp1-nizk", not(feature = "mock-nizk")))]
use sp1_sdk::{
    blocking::{Elf, ProveRequest, Prover, ProverClient, SP1Stdin},
    ProvingKey, SP1ProofWithPublicValues, SP1ProvingKey, StatusCode,
};
use std::fmt;
#[cfg(all(feature = "sp1-nizk", not(feature = "mock-nizk")))]
use std::{fs, path::PathBuf};
use zeroize::Zeroize;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NizkBackendError {
    MockBackendForbidden,
    FullRelationUnavailable(BindingError),
    Sp1Unavailable(String),
    Sp1SetupFailed(String),
    Sp1ProofFailed(String),
    VerificationFailed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sp1Execution {
    pub statement_digest: [u8; 64],
    pub public_values: Vec<u8>,
    pub instruction_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sp1Proof {
    pub statement_digest: [u8; 64],
    pub proof_bytes: Vec<u8>,
    pub vk_hash: [u8; 32],
    pub elf_hash: [u8; 32],
    pub backend_label: &'static str,
}

#[derive(Clone)]
pub struct Sp1NizkSetup {
    pub vk_hash: [u8; 32],
    pub elf_hash: [u8; 32],
    pub backend_label: &'static str,
    #[cfg(all(feature = "sp1-nizk", not(feature = "mock-nizk")))]
    pk: SP1ProvingKey,
}

impl PartialEq for Sp1NizkSetup {
    fn eq(&self, other: &Self) -> bool {
        self.vk_hash == other.vk_hash
            && self.elf_hash == other.elf_hash
            && self.backend_label == other.backend_label
    }
}

impl Eq for Sp1NizkSetup {}

#[derive(Clone, Debug)]
pub struct Sp1NizkProver {
    setup: Sp1NizkSetup,
}

#[derive(Clone, Debug)]
pub struct Sp1NizkVerifier {
    setup: Sp1NizkSetup,
}

impl Sp1NizkSetup {
    pub fn setup() -> Result<Self, NizkBackendError> {
        #[cfg(all(feature = "sp1-nizk", not(feature = "mock-nizk")))]
        {
            let elf_path = binding_program_elf_path()?;
            let elf_bytes = fs::read(&elf_path).map_err(|err| {
                NizkBackendError::Sp1Unavailable(format!(
                    "SP1 binding guest ELF is unavailable at {}: {err}. Run `cargo prove build` before concrete-binding setup.",
                    elf_path.display()
                ))
            })?;
            let elf_hash = hash_bytes(&elf_bytes);
            let client = ProverClient::builder().cpu().build();
            let pk = client
                .setup(Elf::from(elf_bytes))
                .map_err(|err| NizkBackendError::Sp1SetupFailed(err.to_string()))?;
            let vk_hash = pk.verifying_key().bytes32_raw();
            Ok(Self {
                vk_hash,
                elf_hash,
                backend_label: sp1_backend_label(),
                pk,
            })
        }
        #[cfg(any(not(feature = "sp1-nizk"), feature = "mock-nizk"))]
        {
            Err(NizkBackendError::MockBackendForbidden)
        }
    }

    pub fn prover(&self) -> Sp1NizkProver {
        Sp1NizkProver {
            setup: self.clone(),
        }
    }

    pub fn verifier(&self) -> Sp1NizkVerifier {
        Sp1NizkVerifier {
            setup: self.clone(),
        }
    }

    pub fn execute(
        &self,
        pp: &BindingPublicParams,
        statement: &BindingStatement,
        witness: &BindingWitness,
    ) -> Result<Sp1Execution, NizkBackendError> {
        verify_binding_relation(pp, statement, witness, BindingStage::FullRelation)
            .map_err(NizkBackendError::FullRelationUnavailable)?;
        #[cfg(all(feature = "sp1-nizk", not(feature = "mock-nizk")))]
        {
            let expected_digest = statement_digest(pp, statement);
            let mut stdin = SP1Stdin::new();
            stdin.write(pp);
            stdin.write(statement);
            stdin.write(witness);
            stdin.write(&2u32);
            let client = ProverClient::builder().cpu().build();
            let (public_values, report) = client
                .execute(self.pk.elf().clone(), stdin)
                .run()
                .map_err(|err| NizkBackendError::Sp1ProofFailed(err.to_string()))?;
            if public_values.as_slice() != expected_digest {
                return Err(NizkBackendError::VerificationFailed);
            }
            Ok(Sp1Execution {
                statement_digest: expected_digest,
                public_values: public_values.to_vec(),
                instruction_count: report.total_instruction_count(),
            })
        }
        #[cfg(any(not(feature = "sp1-nizk"), feature = "mock-nizk"))]
        {
            Err(NizkBackendError::MockBackendForbidden)
        }
    }
}

impl Sp1NizkProver {
    pub fn prove(
        &self,
        pp: &BindingPublicParams,
        statement: &BindingStatement,
        witness: &mut BindingWitness,
    ) -> Result<Sp1Proof, NizkBackendError> {
        match verify_binding_relation(pp, statement, witness, BindingStage::FullRelation) {
            Ok(_) => {}
            Err(err) => {
                zeroize_witness(witness);
                return Err(NizkBackendError::FullRelationUnavailable(err));
            }
        }
        #[cfg(all(feature = "sp1-nizk", not(feature = "mock-nizk")))]
        {
            let expected_digest = statement_digest(pp, statement);
            let mut stdin = SP1Stdin::new();
            stdin.write(pp);
            stdin.write(statement);
            stdin.write(witness);
            stdin.write(&2u32);
            let client = ProverClient::builder().cpu().build();
            let proof_with_public_values = client
                .prove(&self.setup.pk, stdin)
                .run()
                .map_err(|err| NizkBackendError::Sp1ProofFailed(err.to_string()))?;
            let public_values = proof_with_public_values.public_values.as_slice();
            if public_values != expected_digest {
                zeroize_witness(witness);
                return Err(NizkBackendError::VerificationFailed);
            }
            let proof_bytes = bincode::serialize(&proof_with_public_values)
                .map_err(|err| NizkBackendError::Sp1ProofFailed(err.to_string()))?;
            if proof_bytes.is_empty() {
                zeroize_witness(witness);
                return Err(NizkBackendError::Sp1ProofFailed(
                    "SP1 returned an empty compressed proof serialization; refusing proof"
                        .to_string(),
                ));
            }
            zeroize_witness(witness);
            return Ok(Sp1Proof {
                statement_digest: expected_digest,
                proof_bytes,
                vk_hash: self.setup.vk_hash,
                elf_hash: self.setup.elf_hash,
                backend_label: self.setup.backend_label,
            });
        }
        #[cfg(any(not(feature = "sp1-nizk"), feature = "mock-nizk"))]
        {
            zeroize_witness(witness);
            return Err(NizkBackendError::MockBackendForbidden);
        }
        #[allow(unreachable_code)]
        {
            zeroize_witness(witness);
            Err(NizkBackendError::Sp1Unavailable(
                "SP1 proof backend is not active".to_string(),
            ))
        }
    }
}

impl Sp1NizkVerifier {
    pub fn verify(
        &self,
        pp: &BindingPublicParams,
        statement: &BindingStatement,
        proof: &Sp1Proof,
    ) -> Result<(), NizkBackendError> {
        if proof.vk_hash != self.setup.vk_hash || proof.elf_hash != self.setup.elf_hash {
            return Err(NizkBackendError::VerificationFailed);
        }
        if proof.statement_digest != statement_digest(pp, statement) {
            return Err(NizkBackendError::VerificationFailed);
        }
        #[cfg(all(feature = "sp1-nizk", not(feature = "mock-nizk")))]
        {
            let proof_with_public_values: SP1ProofWithPublicValues =
                bincode::deserialize(&proof.proof_bytes)
                    .map_err(|_| NizkBackendError::VerificationFailed)?;
            if proof.proof_bytes.is_empty() {
                return Err(NizkBackendError::VerificationFailed);
            }
            if proof_with_public_values.public_values.as_slice() != proof.statement_digest {
                return Err(NizkBackendError::VerificationFailed);
            }
            let client = ProverClient::builder().cpu().build();
            client
                .verify(
                    &proof_with_public_values,
                    self.setup.pk.verifying_key(),
                    Some(StatusCode::SUCCESS),
                )
                .map_err(|_| NizkBackendError::VerificationFailed)
        }
        #[cfg(any(not(feature = "sp1-nizk"), feature = "mock-nizk"))]
        {
            Err(NizkBackendError::MockBackendForbidden)
        }
    }
}

pub fn backend_manifest() -> &'static str {
    if cfg!(all(feature = "sp1-nizk", not(feature = "mock-nizk"))) {
        sp1_backend_label()
    } else {
        "INVALID BENCHMARK: mock-nizk or no NIZK backend is active."
    }
}

fn sp1_backend_label() -> &'static str {
    if cfg!(feature = "sp1-groth16") {
        "SP1 v6.1.0 Groth16 optional backend; functional evaluation uses compressed unless sp1-groth16 is enabled"
    } else {
        "SP1 v6.1.0 core proof backend; functional only, not production performance"
    }
}

fn zeroize_witness(witness: &mut BindingWitness) {
    witness.transcript.m.zeroize();
    witness.transcript.signer_set.zeroize();
    for mu in &mut witness.transcript.mu_vector {
        mu.i.zeroize();
        mu.mu_i.zeroize();
    }
    witness.transcript.mu_vector.clear();
    for entry in &mut witness.transcript.entries {
        entry.mu_i.zeroize();
        entry.rho_i.zeroize();
        entry.b_i.zeroize();
        entry.a_i.zeroize();
        entry.x_i.zeroize();
        entry.pi_gar.xa.zeroize();
        entry.pi_gar.xb.zeroize();
        entry.pi_gar.xpk.zeroize();
        entry.pi_gar.za.zeroize();
        entry.pi_gar.zs.zeroize();
        entry.pi_gar.zr.zeroize();
        entry.pi_gar.zu.zeroize();
    }
    witness.transcript.a_hat.zeroize();
    witness.legacy_transcript.bytes.zeroize();
    witness.a_i.zeroize();
    witness.s_i.zeroize();
    witness.r_i.zeroize();
    witness.u_i.zeroize();
    witness.z_i.zeroize();
    witness.tau_i.zeroize();
    witness.eta_i.zeroize();
    witness.secret_relation.bytes.zeroize();
    witness.response_relation.bytes.zeroize();
    witness.lhtlp_randomness_z.bytes.zeroize();
    witness.lhtlp_randomness_tau.bytes.zeroize();
    witness.ibe_randomness.bytes.zeroize();
    witness.nullifier_randomness.bytes.zeroize();
}

impl fmt::Debug for Sp1NizkSetup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sp1NizkSetup")
            .field("vk_hash", &self.vk_hash)
            .field("elf_hash", &self.elf_hash)
            .field("backend_label", &self.backend_label)
            .finish_non_exhaustive()
    }
}

#[cfg(all(feature = "sp1-nizk", not(feature = "mock-nizk")))]
fn hash_bytes(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha512::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..32]);
    out
}

#[cfg(all(feature = "sp1-nizk", not(feature = "mock-nizk")))]
fn binding_program_elf_path() -> Result<PathBuf, NizkBackendError> {
    if let Ok(path) = std::env::var("SP1_ELF_binding-program") {
        return Ok(PathBuf::from(path));
    }
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    Ok(manifest_dir
        .join("../..")
        .join("target/elf-compilation/riscv64im-succinct-zkvm-elf/release/binding-program"))
}
