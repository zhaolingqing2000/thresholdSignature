# Construction-to-Code Consistency Report

## Source of truth
The implementation in `src/construction.rs` follows the supplied Our Construction algorithms: `Setup`, `SignEncap`, `Combine`, `Open`, `Verify`, and `Trace`.

## Algorithm mapping

| Paper object / algorithm | Code location | Status |
|---|---|---|
| `Setup(1^lambda,n,t,Delta)` | `construction::setup_construction` | Implemented as local prototype setup over existing Gargos key generation, commitment generators, local HTLP/IBE prototypes, and registry initialization. |
| Original Gargos Round 1 | `construction::sign_encap` | Implements `B_i = g*a_i + F0(rho_i)*r(i) + F1(rho_i)*u(i)` and `mu_i = H_com(i,rho_i,B_i)`. |
| Original Gargos Round 2 | `construction::sign_encap` | Implements unweighted `A_i = g*a_i + G0(m,mu)*r(i) + G1(m,mu)*u(i)` and verifies `pi_i^Gar`. |
| Gargos challenge and response | `construction::sign_encap` | Implements `A_hat = sum L_i A_i`, `c = H_sig(A_hat,X,m)`, and `z_i = L_i(a_i + c*s(i))`. |
| `GargosTranscript` and `d=H_ctx(tr_Gar)` | `GargosTranscript`, `session_digest` | Implemented with deterministic canonical byte encoding. |
| `SessionDescriptor` | `SessionDescriptor` | Implemented as `(d,m,A_hat,ell)`. |
| `PrivateResponsePackage Phi_i` | `PrivateResponsePackage` | Implemented as `(d,kappa_i,z_i,tau_i)`. |
| `AuxiliaryHandle Theta_i` | `AuxiliaryHandle` | Implemented as `(C_i,T_i^z,T_i^tau,E_i,nu_i,pi_i^bind)` with no public signer index. |
| Pedersen commitment | `commitment` helper in `construction.rs` | Implements `C_i = g_C*z_i + h_C*tau_i` over Ristretto additive notation. |
| Additive HTLP interface | `AdditivePuzzle`, `puzzle_gen`, `puzzle_eval`, `puzzle_solve` | Interface-compatible local prototype; not a production sequential HTLP. |
| IBE tracing interface | `IbePublicKey`, `IbeMasterKey`, `ibe_encrypt`, `trace` | Message-bound local IBE-style prototype; not a production IBE backend. |
| Binding proof | `BindingProof`, `prove_binding`, `verify_binding` | Statement-binding prototype digest. It detects public statement changes but is not a general-purpose NIZK. |
| Canonical registry | `Registry`, `CanonicalSessionRecord` | Implements unique digest registration, immutable record digest validation, exact handle count, proof checks, and pairwise nullifier check. |
| `Combine` | `construction::combine` | Matches handles by `kappa_i`, checks commitments, aggregates `z`, `tau`, `C`, `T^z`, `T^tau`, and verifies Schnorr plus commitment equations. |
| `Open` | `construction::open` | Reconstructs aggregate puzzles, solves `z` and `tau`, and verifies the same Schnorr and commitment equations. |
| `Verify` | `construction::verify` | Reads the canonical record, validates handles, aggregate objects, Schnorr equation, and commitment opening. |
| `Trace` | `construction::trace` | Calls `Verify`, decrypts every `E_i`, checks range/uniqueness/count, and returns the signer set. |

## Deliberate prototype boundaries
The current Rust code is an integration prototype. The HTLP, IBE, and cross-layer binding proof modules implement the interfaces required by the construction and support correctness/overhead testing, but they are not production cryptographic implementations. The experiment summary and generated section text describe them as local prototype backends rather than claiming production HTLP delay, production IBE security, or a full general-purpose NIZK.

## Tests currently implemented
The release test suite covers original Gargos correctness, normal combine verification, delayed open equality, commitment tampering rejection, digest/message tampering rejection, duplicate nullifier rejection, deterministic canonical serialization, and exact tracing recovery.
