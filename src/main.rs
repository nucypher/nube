use std::ops::Mul;

use bls12_381::{pairing, G1Affine, G1Projective, G2Affine, G2Projective, Gt, Scalar};
use ff::Field;
use rand_core::OsRng;

struct Params {
    g: G1Projective,
    h: G2Projective,
    z: Gt,
}

impl Params {
    fn new() -> Self {
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

struct SecretKey(Scalar);

impl SecretKey {
    fn new() -> Self {
        Self(Scalar::random(&mut OsRng))
    }

    fn public_key(&self) -> PublicKey {
        PublicKey::from_secret_key(self)
    }
}

struct PublicKey(G2Projective);

impl PublicKey {
    fn from_secret_key(sk: &SecretKey) -> Self {
        let params = Params::new();
        Self(params.h * sk.0)
    }
}

fn poly_eval(coeffs: &[Scalar], x: &Scalar) -> Scalar {
    let mut result: Scalar = coeffs[coeffs.len() - 1];
    for i in (0..coeffs.len() - 1).rev() {
        result = (result * x) + coeffs[i];
    }
    result
}

struct KeySliver {
    shares: usize,
    reencryption_key_parts: Vec<G2Projective>,
    encryption_key_part: Gt,
}

impl KeySliver {
    fn new(delegation_key: &PublicKey, threshold: usize, shares: usize) -> Self {
        // Each Ursula needs to create a random polynomial of order T-1,
        // which means obtaining T random coefficients
        let coeffs: Vec<_> = (0..threshold).map(|_| Scalar::random(&mut OsRng)).collect();

        // NOTE: need for consensus on the share input (i.e. the x value in the polynomial)
        // hardcoded for now
        let shared_values: Vec<_> = (0..shares).map(|x| Scalar::from(x as u64)).collect();

        // For the DKG process, each DKG Ursula uses the polynomial to derive N "KFrag fragments"
        let reencryption_key_parts: Vec<_> = shared_values
            .iter()
            .map(|x| delegation_key.0.mul(poly_eval(&coeffs, x)))
            .collect();

        let params = Params::new();
        let encryption_key_part = params.z.mul(coeffs[0]);

        Self {
            shares,
            reencryption_key_parts,
            encryption_key_part,
        }
    }
}

struct EncryptionKey(Gt);

struct KeyFrag {
    point: G2Projective,
    id: usize,
}

fn generate_kfrags(kslivers: &[KeySliver]) -> (Vec<KeyFrag>, EncryptionKey) {
    // Somehow, DKG Ursulas aggregate these KFragFrags to produce N KFrags
    // and the DKG encryption public key (... need a name for this as well).
    // NOTE: How do we perform this aggregation?
    //  - One option is simply using of the DKG Ursulas
    //  - Another option is using a different, unrelated Ursula
    // NOTE 2: How to verify correctness?
    // NOTE 3: How to deal with sampling and TMap preparation (e.g., encryption of KFrags, etc)

    let shares = kslivers[0].shares;

    let reencryption_keys: Vec<_> = (0..shares)
        .map(|share| {
            kslivers
                .iter()
                .map(|ksliver| ksliver.reencryption_key_parts[share])
                .sum()
        })
        .enumerate()
        .map(|(id, point)| KeyFrag { point, id })
        .collect();
    let encryption_key = kslivers
        .iter()
        .map(|ksliver| ksliver.encryption_key_part)
        .sum();
    (reencryption_keys, EncryptionKey(encryption_key))
}

struct Capsule(G1Projective);

#[derive(PartialEq, Debug)]
struct SymmetricKey(Gt);

fn encrypt(encryption_key: &EncryptionKey) -> (Capsule, SymmetricKey) {
    let params = Params::new();
    let r = Scalar::random(&mut OsRng);
    let g_r = params.g.mul(r);
    let secret = encryption_key.0.mul(r);
    (Capsule(g_r), SymmetricKey(secret))
}

struct CapsuleFrag {
    point: Gt,
    id: usize,
}

fn reencrypt(capsule: &Capsule, kfrag: &KeyFrag) -> CapsuleFrag {
    CapsuleFrag {
        point: pairing(&G1Affine::from(capsule.0), &G2Affine::from(kfrag.point)),
        id: kfrag.id,
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

fn decrypt(sk: &SecretKey, cfrags: &[CapsuleFrag]) -> SymmetricKey {
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
        .map(|(lambda, cfrag)| cfrag.point.mul(lambda.unwrap()))
        .sum();

    SymmetricKey(combined.mul(sk.0.invert().unwrap()))
}

fn main() {
    // Bob
    let recipient_sk = SecretKey::new();
    let recipient_pk = recipient_sk.public_key();

    let threshold = 2;
    let shares = 3;

    // Let's assume there's a DKG of Ñ=4 Ursulas
    // In this example, we're going to create KFrags for a 2-of-3 PRE (T=2, N=3)
    let ksliver0 = KeySliver::new(&recipient_pk, threshold, shares);
    let ksliver1 = KeySliver::new(&recipient_pk, threshold, shares);
    let ksliver2 = KeySliver::new(&recipient_pk, threshold, shares);
    let ksliver3 = KeySliver::new(&recipient_pk, threshold, shares);

    let (kfrags, encryption_key) = generate_kfrags(&[ksliver0, ksliver1, ksliver2, ksliver3]);

    // Now, Enrico encrypts something with the DKG encryption key
    // For simplicity, we don't deal with messages here but only with the computation
    // of the secret factor used to derive the symmetric key that encrypts the message
    let (capsule, symmetric_key) = encrypt(&encryption_key);

    let cfrag0 = reencrypt(&capsule, &kfrags[0]);
    let _cfrag1 = reencrypt(&capsule, &kfrags[1]);
    let cfrag2 = reencrypt(&capsule, &kfrags[2]);

    // Decryption with 2 out of 3 cfrags
    let decrypted_key = decrypt(&recipient_sk, &[cfrag0, cfrag2]);

    assert_eq!(symmetric_key, decrypted_key);
}
