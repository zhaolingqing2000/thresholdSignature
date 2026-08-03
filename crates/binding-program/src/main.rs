#![no_main]

use binding_core::{
    verify_binding_relation, BindingPublicParams, BindingStage, BindingStatement, BindingWitness,
};
use sp1_zkvm::io::{commit_slice, read};

sp1_zkvm::entrypoint!(main);

pub fn main() {
    let pp = read::<BindingPublicParams>();
    let statement = read::<BindingStatement>();
    let witness = read::<BindingWitness>();
    let stage = read::<u32>();
    let stage = match stage {
        0 => BindingStage::StatementDigest,
        1 => BindingStage::CommitmentAndNullifier,
        _ => BindingStage::FullRelation,
    };
    let digest = verify_binding_relation(&pp, &statement, &witness, stage)
        .expect("binding relation rejected");
    commit_slice(&digest);
}
