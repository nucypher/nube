use bls12_381::Scalar;
use ff::Field;
use rand_core::OsRng;

pub(crate) fn random_nonzero_scalar() -> Scalar {
    // FIXME: make it actually nonzero
    Scalar::random(&mut OsRng)
}
