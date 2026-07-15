use threshold_signature::construction::{
    combine, open, setup_construction, sign_encap, trace, verify,
};

fn main() {
    let (params, secrets, mut registry) = setup_construction(5, 2);
    let signer_set = vec![1, 2, 3];
    let message = b"construction end-to-end message";

    let sign_output = sign_encap(&params, &secrets, &mut registry, message, &signer_set)
        .expect("SignEncap failed");
    let sigma = combine(
        &params,
        &registry,
        message,
        &sign_output.d,
        &sign_output.packages,
    )
    .expect("Combine failed");
    let opened = open(&params, &registry, message, &sign_output.d).expect("Open failed");
    let verified = verify(&params, &registry, message, &sigma);
    let traced = trace(&params, &secrets, &registry, message, &sigma).expect("Trace failed");

    println!("verification passed: {}", verified);
    println!(
        "delayed opening matches normal combine: {}",
        opened == sigma
    );
    println!("traced signer set: {:?}", traced);
}
