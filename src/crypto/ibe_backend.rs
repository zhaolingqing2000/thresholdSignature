use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use ibe::kem::cgw_fo::CGWFO;
use ibe::kem::IBKEM;
use ibe::{Compress, Derive};
use rand08::SeedableRng;
use rand_chacha08::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

#[derive(Debug)]
pub enum IbeBackendError {
    InvalidLength,
    InvalidCiphertext,
    Aead,
    DuplicateSigner,
    SignerOutOfRange,
}

pub type IbeBackendResult<T> = Result<T, IbeBackendError>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConcreteIbePublicKey {
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConcreteIbeMasterKey {
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConcreteIbeUserKey {
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConcreteTracingCiphertext {
    pub identity_digest: Vec<u8>,
    pub kem_ciphertext: Vec<u8>,
    pub nonce: [u8; 12],
    pub aead_ciphertext: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConcreteIbeRandomness {
    pub xi: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct ConcreteIbeBackend;

impl ConcreteIbeBackend {
    pub const SCHEME: &'static str = "ibe::kem::cgw_fo::CGWFO over BLS12-381";

    pub fn setup() -> (ConcreteIbePublicKey, ConcreteIbeMasterKey) {
        let mut rng = rand08::rngs::OsRng;
        let (pk, sk) = CGWFO::setup(&mut rng);
        (
            ConcreteIbePublicKey {
                bytes: pk.to_bytes().as_ref().to_vec(),
            },
            ConcreteIbeMasterKey {
                bytes: sk.to_bytes().as_ref().to_vec(),
            },
        )
    }

    pub fn extract(
        pk: &ConcreteIbePublicKey,
        sk: &ConcreteIbeMasterKey,
        message: &[u8],
        descriptor: &[u8; 32],
    ) -> IbeBackendResult<ConcreteIbeUserKey> {
        let pk = decode_pk(pk)?;
        let sk = decode_sk(sk)?;
        let id = identity(message, descriptor);
        let mut rng = rand08::rngs::OsRng;
        let usk = CGWFO::extract_usk(Some(&pk), &sk, &id, &mut rng);
        Ok(ConcreteIbeUserKey {
            bytes: usk.to_bytes().as_ref().to_vec(),
        })
    }

    pub fn encrypt(
        pk: &ConcreteIbePublicKey,
        message: &[u8],
        descriptor: &[u8; 32],
        signer_index: u32,
    ) -> IbeBackendResult<ConcreteTracingCiphertext> {
        let xi: [u8; 64] = rand::random();
        Self::encrypt_with_randomness(
            pk,
            message,
            descriptor,
            signer_index,
            &ConcreteIbeRandomness { xi: xi.to_vec() },
        )
    }

    pub fn encrypt_with_randomness(
        pk: &ConcreteIbePublicKey,
        message: &[u8],
        descriptor: &[u8; 32],
        signer_index: u32,
        randomness: &ConcreteIbeRandomness,
    ) -> IbeBackendResult<ConcreteTracingCiphertext> {
        let pk = decode_pk(pk)?;
        let id_digest = identity_digest(message, descriptor);
        let id = <CGWFO as IBKEM>::Id::derive(&id_digest);
        if randomness.xi.len() != 64 {
            return Err(IbeBackendError::InvalidLength);
        }
        let seed = deterministic_seed(b"GARGOS-TRACE-CGWFO-RNG-v1", &randomness.xi, &id_digest);
        let mut rng = ChaCha20Rng::from_seed(seed);
        let (kem_ct, shared) = CGWFO::encaps(&pk, &id, &mut rng);
        let nonce_bytes = deterministic_nonce(&randomness.xi, &id_digest, signer_index);
        let cipher = Aes256Gcm::new_from_slice(&shared.0).map_err(|_| IbeBackendError::Aead)?;
        let plaintext = signer_index.to_be_bytes();
        let aead_ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), plaintext.as_ref())
            .map_err(|_| IbeBackendError::Aead)?;
        Ok(ConcreteTracingCiphertext {
            identity_digest: id_digest.to_vec(),
            kem_ciphertext: kem_ct.to_bytes().as_ref().to_vec(),
            nonce: nonce_bytes,
            aead_ciphertext,
        })
    }

    pub fn decrypt(
        pk: &ConcreteIbePublicKey,
        usk: &ConcreteIbeUserKey,
        message: &[u8],
        descriptor: &[u8; 32],
        ct: &ConcreteTracingCiphertext,
    ) -> IbeBackendResult<u32> {
        let expected = identity_digest(message, descriptor);
        if ct.identity_digest != expected {
            return Err(IbeBackendError::InvalidCiphertext);
        }
        let pk = decode_pk(pk)?;
        let usk = decode_usk(usk)?;
        let kem_ct = decode_ct(ct)?;
        let shared = CGWFO::decaps(Some(&pk), &usk, &kem_ct)
            .map_err(|_| IbeBackendError::InvalidCiphertext)?;
        let cipher = Aes256Gcm::new_from_slice(&shared.0).map_err(|_| IbeBackendError::Aead)?;
        let plaintext = cipher
            .decrypt(Nonce::from_slice(&ct.nonce), ct.aead_ciphertext.as_ref())
            .map_err(|_| IbeBackendError::Aead)?;
        let bytes: [u8; 4] = plaintext
            .as_slice()
            .try_into()
            .map_err(|_| IbeBackendError::InvalidCiphertext)?;
        Ok(u32::from_be_bytes(bytes))
    }

    pub fn serialized_size(ct: &ConcreteTracingCiphertext) -> usize {
        8 + ct.identity_digest.len()
            + 8
            + ct.kem_ciphertext.len()
            + 12
            + 8
            + ct.aead_ciphertext.len()
    }
}

fn deterministic_seed(domain: &[u8], xi: &[u8], id_digest: &[u8; 64]) -> [u8; 32] {
    let mut h = Sha512::new();
    h.update(domain);
    h.update(xi);
    h.update(id_digest);
    let out = h.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&out[..32]);
    seed
}

fn deterministic_nonce(xi: &[u8], id_digest: &[u8; 64], signer_index: u32) -> [u8; 12] {
    let mut h = Sha512::new();
    h.update(b"GARGOS-TRACE-AEAD-NONCE-v1");
    h.update(xi);
    h.update(id_digest);
    h.update(signer_index.to_be_bytes());
    let out = h.finalize();
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&out[..12]);
    nonce
}

pub fn identity_digest(message: &[u8], descriptor: &[u8; 32]) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(b"GARGOS-TRACE-ID-v1");
    h.update((message.len() as u64).to_be_bytes());
    h.update(message);
    h.update(descriptor);
    let out = h.finalize();
    let mut id = [0u8; 64];
    id.copy_from_slice(&out);
    id
}

pub fn identity(message: &[u8], descriptor: &[u8; 32]) -> <CGWFO as IBKEM>::Id {
    <CGWFO as IBKEM>::Id::derive(&identity_digest(message, descriptor))
}

pub fn trace_signer_indexes(
    pk: &ConcreteIbePublicKey,
    usk: &ConcreteIbeUserKey,
    message: &[u8],
    descriptor: &[u8; 32],
    ciphertexts: &[ConcreteTracingCiphertext],
    max_signer_index: u32,
) -> IbeBackendResult<Vec<u32>> {
    let mut out = Vec::with_capacity(ciphertexts.len());
    for ct in ciphertexts {
        let signer = ConcreteIbeBackend::decrypt(pk, usk, message, descriptor, ct)?;
        if signer == 0 || signer > max_signer_index {
            return Err(IbeBackendError::SignerOutOfRange);
        }
        if out.contains(&signer) {
            return Err(IbeBackendError::DuplicateSigner);
        }
        out.push(signer);
    }
    out.sort_unstable();
    Ok(out)
}

fn decode_pk(pk: &ConcreteIbePublicKey) -> IbeBackendResult<<CGWFO as IBKEM>::Pk> {
    let bytes: [u8; CGWFO::PK_BYTES] = pk
        .bytes
        .as_slice()
        .try_into()
        .map_err(|_| IbeBackendError::InvalidLength)?;
    Option::from(<CGWFO as IBKEM>::Pk::from_bytes(&bytes)).ok_or(IbeBackendError::InvalidCiphertext)
}

fn decode_sk(sk: &ConcreteIbeMasterKey) -> IbeBackendResult<<CGWFO as IBKEM>::Sk> {
    let bytes: [u8; CGWFO::SK_BYTES] = sk
        .bytes
        .as_slice()
        .try_into()
        .map_err(|_| IbeBackendError::InvalidLength)?;
    Option::from(<CGWFO as IBKEM>::Sk::from_bytes(&bytes)).ok_or(IbeBackendError::InvalidCiphertext)
}

fn decode_usk(usk: &ConcreteIbeUserKey) -> IbeBackendResult<<CGWFO as IBKEM>::Usk> {
    let bytes: [u8; CGWFO::USK_BYTES] = usk
        .bytes
        .as_slice()
        .try_into()
        .map_err(|_| IbeBackendError::InvalidLength)?;
    Option::from(<CGWFO as IBKEM>::Usk::from_bytes(&bytes))
        .ok_or(IbeBackendError::InvalidCiphertext)
}

fn decode_ct(ct: &ConcreteTracingCiphertext) -> IbeBackendResult<<CGWFO as IBKEM>::Ct> {
    let bytes: [u8; CGWFO::CT_BYTES] = ct
        .kem_ciphertext
        .as_slice()
        .try_into()
        .map_err(|_| IbeBackendError::InvalidLength)?;
    Option::from(<CGWFO as IBKEM>::Ct::from_bytes(&bytes)).ok_or(IbeBackendError::InvalidCiphertext)
}
