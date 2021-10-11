use core::ops::Add;

use bls12_381::{G2Projective, Gt, Scalar};
use ff::Field;
use rand_core::OsRng;
use sha3::{Digest, Sha3_256};

use crate::params::Params;
use crate::recipient::RecipientPublicKey;
use crate::utils::random_nonzero_scalar;

fn hash_to_scalar(label: &[u8], index: u32) -> Scalar {
    let mut attempt = 0u32;
    loop {
        let digest = Sha3_256::new()
            .chain(attempt.to_be_bytes())
            .chain(index.to_be_bytes())
            .chain(label)
            .finalize();

        let maybe_scalar = Scalar::from_bytes(&digest.into()).into();

        match maybe_scalar {
            Some(scalar) => break scalar,
            None => {
                attempt += 1;
            }
        }
    }
}

// Encapsulates a key maker's secret key.
// Just have it for convenience for now, probably won't be a part of the final API.
pub struct KeyMaker {
    secret_key: Scalar,
}

impl KeyMaker {
    pub fn random() -> Self {
        Self {
            secret_key: random_nonzero_scalar(),
        }
    }

    pub fn encryption_key(&self) -> EncryptionKey {
        let params = Params::new();
        let key_part = params.z * self.secret_key;
        EncryptionKey(key_part)
    }

    pub fn make_key_sliver(
        &self,
        label: &[u8],
        recipient_key: &RecipientPublicKey,
        threshold: usize,
        shares: usize,
    ) -> KeySliver {
        // Each key maker needs to create a random polynomial of order T-1,
        // with the power-0 coefficient being fixed
        // (equal to the secret key, to match the encryption key produced earlier).
        let coeffs = (1..threshold)
            .map(|_| Scalar::random(&mut OsRng))
            .collect::<Vec<_>>();

        // Generate shared values deterministically from the label
        // TODO: for now they are public, but it may be possible to use secret sharing
        // so that only Recipient can decrypt them (since we have his key).
        let shared_values = (0..shares)
            .map(|index| hash_to_scalar(label, index as u32))
            .collect::<Vec<_>>();

        // For the DKG process, each DKG Ursula uses the polynomial to derive N "KFrag fragments"
        let reencryption_key_parts = shared_values
            .iter()
            .map(|x| recipient_key.0 * poly_eval(&self.secret_key, &coeffs, x))
            .collect::<Vec<_>>();

        KeySliver {
            shared_values,
            reencryption_key_parts,
        }
    }
}

/// Calculates `coeff0 + sum(coeff[j-1] * x^j, j in [1, threshold))`
fn poly_eval(coeff0: &Scalar, coeffs: &[Scalar], x: &Scalar) -> Scalar {
    let mut result: Scalar = coeffs[coeffs.len() - 1];
    for i in (0..coeffs.len() - 1).rev() {
        result = (result * x) + coeffs[i];
    }
    result * x + coeff0
}

pub struct EncryptionKey(pub(crate) Gt);

impl Add<&EncryptionKey> for &EncryptionKey {
    type Output = EncryptionKey;
    fn add(self, other: &EncryptionKey) -> EncryptionKey {
        EncryptionKey(self.0 + other.0)
    }
}

impl Add<&EncryptionKey> for EncryptionKey {
    type Output = EncryptionKey;
    fn add(self, other: &EncryptionKey) -> EncryptionKey {
        &self + other
    }
}

pub struct KeySliver {
    pub(crate) shared_values: Vec<Scalar>,
    pub(crate) reencryption_key_parts: Vec<G2Projective>,
}
