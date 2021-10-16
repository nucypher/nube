use bls12_381::{pairing, G1Affine, G2Affine, Gt, Scalar};

use crate::author::KeyFrag;
use crate::encryptor::Capsule;

/// A re-encrypted fragment of Encryptor's symmetric key.
pub struct CapsuleFrag {
    pub(crate) shared_value: Scalar,
    pub(crate) point: Gt,
}

/// Generates a capsule fragment based on the encapsulated Encryptor's key
/// (created in [`encrypt`](crate::encrypt)) and key frags
/// (created in [`generate_kfrags`](crate::generate_kfrags)).
pub fn reencrypt(capsule: &Capsule, kfrag: &KeyFrag) -> CapsuleFrag {
    CapsuleFrag {
        shared_value: kfrag.shared_value,
        point: pairing(&G1Affine::from(capsule.0), &G2Affine::from(kfrag.point)),
    }
}
