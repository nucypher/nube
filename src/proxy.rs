use bls12_381::{pairing, G1Affine, G2Affine, Gt, Scalar};

use crate::author::KeyFrag;
use crate::encryptor::Capsule;

pub struct CapsuleFrag {
    pub(crate) shared_value: Scalar,
    pub(crate) point: Gt,
}

pub fn reencrypt(capsule: &Capsule, kfrag: &KeyFrag) -> CapsuleFrag {
    CapsuleFrag {
        shared_value: kfrag.shared_value,
        point: pairing(&G1Affine::from(capsule.0), &G2Affine::from(kfrag.point)),
    }
}
