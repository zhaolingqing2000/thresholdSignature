use threshold_signature::keygen::{kgen, setup};
use threshold_signature::protocol::{
    aggregate_and_verify, gargos_sign_and_bind, verify_aggregate_transcript,
};

fn main() {
    let n = 5;
    let t = 2;
    let signer_set: Vec<u32> = vec![1, 2, 3];
    let message = b"construction end-to-end message";

    // Fig.1: setup public parameters and threshold key shares.
    let params = setup(n, t);
    let (public_key, public_key_shares, secret_key_shares) = kgen(&params);

    // Fig.2: sign and bind each hidden response share to W_i = g^{z_i}.
    let (transcript, response_shares) = gargos_sign_and_bind(
        &params,
        message,
        &signer_set,
        &public_key,
        &public_key_shares,
        &secret_key_shares,
    )
    .expect("signing and witness generation failed");

    // Fig.3: combine z_i into z, aggregate W_i into Y, and verify consistency.
    let transcript = aggregate_and_verify(
        &params,
        &public_key,
        &public_key_shares,
        transcript,
        &response_shares,
    )
    .expect("aggregation verification failed");

    // Fig.4: public verification of both Schnorr validity and witness consistency.
    let ok = verify_aggregate_transcript(
        &params,
        &public_key,
        &public_key_shares,
        message,
        &transcript,
    );

    println!("verification passed: {}", ok);
}
