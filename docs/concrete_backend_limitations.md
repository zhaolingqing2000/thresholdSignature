# Concrete Backend Status and Limitations

## Interface Mapping

- `Setup`: `src/construction.rs::setup_construction`
- `SignEncap`: `src/construction.rs::sign_encap`
- `Combine`: `src/construction.rs::combine`
- `Open`: `src/construction.rs::open`
- `Verify`: `src/construction.rs::verify`
- `Trace`: `src/construction.rs::trace`

The original Gargos signing equations remain in `src/protocol.rs` and
`src/construction.rs::final_from_values_with_aggregate`. This update adds
concrete backend modules and tests without changing the Gargos challenge,
response aggregation, or final Schnorr verification equation.

## Dependencies

- `openssl 0.10.81` with the vendored OpenSSL source feature, used for BigNum
  arithmetic in the LHTLP backend.
- `ibe 0.3.0` with the `cgwfo` feature, used for Chen-Gay-Wee-style IB-KEM over
  BLS12-381.
- `aes-gcm 0.10` for encrypting the fixed-width signer index under the IB-KEM
  shared secret.
- `criterion 0.5` for backend microbenchmarks.

## Threat Model and Implementation Limits

The concrete LHTLP backend implements the reusable puzzle interface with
OpenSSL BigNum operations and fixed-width canonical encodings. Tests validate
functional opening, homomorphic aggregation, malformed-input rejection, and
sequential-squaring accounting. These tests do not prove sequentiality, DCR, or
any number-theoretic assumption.

The concrete IBE backend uses `ibe::kem::cgw_fo::CGWFO` as an identity-based
key encapsulation mechanism and AES-256-GCM for the signer-index payload. Tests
validate correct recovery, identity binding, message/descriptor binding,
ciphertext tamper rejection, and duplicate/out-of-range signer rejection. These
tests do not audit the `ibe` crate or claim production hardening.

The concrete binding proof is not complete. The repository does not yet contain
a RISC Zero guest, image ID, or guest-compatible statement checker for the full
cross-layer relation. The `concrete-binding` feature therefore reports an
explicit blocker and must be labelled `PARTIAL CONCRETE INSTANTIATION`.

## Unresolved Security Properties

- Sequentiality of the LHTLP puzzle.
- DCR-style hardness assumptions over the generated RSA modulus.
- Discrete-log hardness of the underlying Gargos group.
- State-exposure zero knowledge for the binding relation.
- Production-grade side-channel resistance and constant-time behavior across
  all backend code paths.
