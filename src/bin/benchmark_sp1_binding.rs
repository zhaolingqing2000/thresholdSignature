#[cfg(feature = "sp1-nizk")]
fn main() {
    use std::time::Instant;

    use binding_core::{
        concrete_functional_smoke_instance, statement_digest, verify_binding_relation, BindingStage,
    };
    use binding_host::Sp1NizkSetup;

    fn stage<T, F: FnOnce() -> T>(name: &str, f: F) -> T {
        eprintln!("[sp1-smoke] start {name}");
        let start = Instant::now();
        let out = f();
        eprintln!("[sp1-smoke] end {name}: {:.3?}", start.elapsed());
        out
    }

    let (pp, statement, mut witness) =
        stage("construct concrete-functional-params witness", || {
            concrete_functional_smoke_instance()
        });
    let digest = statement_digest(&pp, &statement);
    stage("host full-relation precheck", || {
        verify_binding_relation(&pp, &statement, &witness, BindingStage::FullRelation).unwrap();
    });
    eprintln!("[sp1-smoke] statement_digest={}", hex::encode(digest));

    let setup = match stage("guest ELF load and SP1 setup", Sp1NizkSetup::setup) {
        Ok(setup) => setup,
        Err(err) => {
            eprintln!("[sp1-smoke] setup failed: {err:?}");
            std::process::exit(1);
        }
    };
    eprintln!("[sp1-smoke] elf_hash={}", hex::encode(setup.elf_hash));
    eprintln!("[sp1-smoke] vk_hash={}", hex::encode(setup.vk_hash));
    let execution = match stage("guest-only execution", || {
        setup.execute(&pp, &statement, &witness)
    }) {
        Ok(execution) => execution,
        Err(err) => {
            eprintln!("[sp1-smoke] execute failed: {err:?}");
            std::process::exit(1);
        }
    };
    eprintln!(
        "[sp1-smoke] guest_instruction_count={}",
        execution.instruction_count
    );
    if std::env::var_os("SP1_SMOKE_EXECUTE_ONLY").is_some() {
        eprintln!("[sp1-smoke] execute-only requested; no proof generated");
        return;
    }

    let proof = match stage("prove.compressed().run()", || {
        setup.prover().prove(&pp, &statement, &mut witness)
    }) {
        Ok(proof) => proof,
        Err(err) => {
            eprintln!("[sp1-smoke] prove failed: {err:?}");
            std::process::exit(1);
        }
    };
    eprintln!(
        "[sp1-smoke] serialized_proof_size={}",
        proof.proof_bytes.len()
    );

    if let Err(err) = stage("deserialize and verify", || {
        setup.verifier().verify(&pp, &statement, &proof)
    }) {
        eprintln!("[sp1-smoke] verify failed: {err:?}");
        std::process::exit(1);
    }
    eprintln!("[sp1-smoke] SUCCESS non-mock SP1 Groth16 proof verified");
}

#[cfg(not(feature = "sp1-nizk"))]
fn main() {
    eprintln!("benchmark_sp1_binding requires --no-default-features --features sp1-nizk");
    std::process::exit(1);
}
