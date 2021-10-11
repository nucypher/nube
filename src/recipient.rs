use bls12_381::{G2Projective, Gt, Scalar};

use crate::encryptor::SymmetricKey;
use crate::params::Params;
use crate::proxy::CapsuleFrag;
use crate::utils::random_nonzero_scalar;

pub struct RecipientSecretKey(Scalar);

impl RecipientSecretKey {
    pub fn random() -> Self {
        Self(random_nonzero_scalar())
    }

    pub fn public_key(&self) -> RecipientPublicKey {
        RecipientPublicKey::from_secret_key(self)
    }
}

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

pub fn decrypt(sk: &RecipientSecretKey, cfrags: &[CapsuleFrag]) -> SymmetricKey {
    // hardcoded for now
    let shared_values: Vec<_> = cfrags
        .iter()
        .map(|cfrag| Scalar::from(cfrag.id as u64))
        .collect();

    let lambdas: Vec<_> = (0..shared_values.len())
        .map(|idx| lambda_coeff(&shared_values, idx))
        .collect();
    let combined: Gt = lambdas
        .iter()
        .zip(cfrags.iter())
        .map(|(lambda, cfrag)| cfrag.point * lambda.unwrap())
        .sum();

    SymmetricKey(combined * sk.0.invert().unwrap())
}
