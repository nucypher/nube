use alloc::vec::Vec;

use bls12_381::{G2Projective, Gt, Scalar};

use crate::encryptor::SymmetricKey;
use crate::params::Params;
use crate::proxy::CapsuleFrag;
use crate::utils::random_nonzero_scalar;

/// Message recipient's secret key.
pub struct RecipientSecretKey(Scalar);

impl RecipientSecretKey {
    /// Generates a random secret key using the default OS RNG.
    pub fn random() -> Self {
        Self(random_nonzero_scalar())
    }

    /// Returns the corresponding public key.
    pub fn public_key(&self) -> RecipientPublicKey {
        RecipientPublicKey::from_secret_key(self)
    }
}

/// Message recipient's public key.
pub struct RecipientPublicKey(pub(crate) G2Projective);

impl RecipientPublicKey {
    fn from_secret_key(sk: &RecipientSecretKey) -> Self {
        let params = Params::new();
        Self(params.h * sk.0)
    }
}

fn lambda_coeff(xs: &[Scalar], i: usize) -> Option<Scalar> {
    let mut res = Scalar::one();
    for j in 0..xs.len() {
        if j != i {
            let inv_diff_opt: Option<Scalar> = (xs[j] - xs[i]).invert().into();
            let inv_diff = inv_diff_opt?;
            res = (res * xs[j]) * inv_diff;
        }
    }
    Some(res)
}

/// Decrypt the re-encrypted message using `threshold` out of `shares` capsule frags.
pub fn decrypt(sk: &RecipientSecretKey, cfrags: &[CapsuleFrag]) -> Option<SymmetricKey> {
    let shared_values = cfrags
        .iter()
        .map(|cfrag| cfrag.shared_value)
        .collect::<Vec<_>>();

    let maybe_lambdas = (0..shared_values.len())
        .map(|idx| lambda_coeff(&shared_values, idx))
        .collect::<Vec<_>>();
    let lambdas = maybe_lambdas.into_iter().collect::<Option<Vec<_>>>()?;

    // Have to convert from subtle::CtOption here.
    let maybe_inv_sk: Option<Scalar> = sk.0.invert().into();
    let inv_sk = maybe_inv_sk?;

    let combined: Gt = lambdas
        .iter()
        .zip(cfrags.iter())
        .map(|(lambda, cfrag)| cfrag.point * lambda)
        .sum();

    Some(SymmetricKey(combined * inv_sk))
}
