use bls12_381::{G1Projective, Gt};

use crate::keymaker::EncryptionKey;
use crate::params::Params;
use crate::utils::random_nonzero_scalar;

/// An encapsulated symmetric key used to encrypt the message.
/// Can be distributed publicly.
pub struct Capsule(pub(crate) G1Projective);

// TODO: hide from the user and actually encrypt messages with it.
/// The symmetric key that Encryptor can used to encrypt the message.
/// Needs to be kept secret by Encryptor.
#[derive(PartialEq, Debug)]
pub struct SymmetricKey(pub(crate) Gt);

/// Generate a symmetric key for message encryption and encapsulate it for distribution to Proxies.
pub fn encrypt(encryption_key: &EncryptionKey) -> (Capsule, SymmetricKey) {
    let params = Params::new();
    let r = random_nonzero_scalar();
    let g_r = params.g * r;
    let secret = encryption_key.0 * r;
    (Capsule(g_r), SymmetricKey(secret))
}
