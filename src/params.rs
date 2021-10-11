use bls12_381::{pairing, G1Affine, G1Projective, G2Affine, G2Projective, Gt};

pub(crate) struct Params {
    pub(crate) g: G1Projective,
    pub(crate) h: G2Projective,
    pub(crate) z: Gt,
}

impl Params {
    pub(crate) fn new() -> Self {
        let g = G1Affine::generator();
        let h = G2Affine::generator();
        let z = pairing(&g, &h);
        Self {
            g: G1Projective::from(&g),
            h: G2Projective::from(&h),
            z,
        }
    }
}
