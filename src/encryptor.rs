use bls12_381::{G1Projective, Gt};

use crate::keymaker::EncryptionKey;
use crate::params::Params;
use crate::utils::random_nonzero_scalar;

pub struct Capsule(pub(crate) G1Projective);

#[derive(PartialEq, Debug)]
pub struct SymmetricKey(pub(crate) Gt);

pub fn encrypt(encryption_key: &EncryptionKey) -> (Capsule, SymmetricKey) {
    let params = Params::new();
    let r = random_nonzero_scalar();
    let g_r = params.g * r;
    let secret = encryption_key.0 * r;
    (Capsule(g_r), SymmetricKey(secret))
}
