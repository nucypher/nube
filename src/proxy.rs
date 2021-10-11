use bls12_381::{pairing, G1Affine, G2Affine, Gt};

use crate::author::KeyFrag;
use crate::encryptor::Capsule;

pub struct CapsuleFrag {
    pub(crate) id: usize,
    pub(crate) point: Gt,
}

pub fn reencrypt(capsule: &Capsule, kfrag: &KeyFrag) -> CapsuleFrag {
    CapsuleFrag {
        id: kfrag.id,
        point: pairing(&G1Affine::from(capsule.0), &G2Affine::from(kfrag.point)),
    }
}
