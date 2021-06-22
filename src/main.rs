use bls12_381::pairing;
use bls12_381::G1Affine;
use bls12_381::G2Affine;
use bls12_381::Scalar;

use std::ops::Add;
use std::ops::Mul;

fn main() {
   
    // System parameters
    let g = G1Affine::generator();
    let h = G2Affine::generator();
    let z = pairing(&g, &h);
    
    // First, meet Bob.
    // NOTE: bear with me, I'm just hard-coding "random" values in this example
    let b2 = Scalar::from(0xBB22);
    let delegation_key_b = h.mul(b2);

    // Let's assume there's a DKG of Ñ=3 Ursulas (let's call them alpha, beta and delta)
    // In this example, we're going to create KFrags for a 2-of-2 PRE (T=2, N=2)
    // Each Ursula needs to create a random polynomial of order T-1,
    // which means obtaining T random coefficients
    let alpha_0 = Scalar::from(0xFF00AA00);
    let beta_0  = Scalar::from(0xFF00BB00);
    let delta_0 = Scalar::from(0xFF00DD00);
    let alpha_1 = Scalar::from(0xFF00AA11);
    let beta_1  = Scalar::from(0xFF00BB11);
    let delta_1 = Scalar::from(0xFF00DD11);

    // For the DKG process, each DKG Ursula uses the polynomial to derive N "KFrag fragments"
    // (... need to find a better name for this ...)
    // NOTE: need for consensus on the share input (i.e. the x value in the polynomial)
    // In this example, we've simply used the values x=1 and x=2
    let two = Scalar::from(2);
    let rk_alpha_1 = delegation_key_b.mul(alpha_0 + alpha_1);
    let rk_alpha_2 = delegation_key_b.mul(alpha_0 + alpha_1.mul(two));
    let encryption_key_alpha = z.mul(alpha_0);
    
    let rk_beta_1 = delegation_key_b.mul(beta_0 + beta_1);
    let rk_beta_2 = delegation_key_b.mul(beta_0 + beta_1.mul(two));
    let encryption_key_beta = z.mul(beta_0);

    let rk_delta_1 = delegation_key_b.mul(delta_0 + delta_1);
    let rk_delta_2 = delegation_key_b.mul(delta_0 + delta_1.mul(two));
    let encryption_key_delta = z.mul(delta_0);

    // Somehow, DKG Ursulas aggregate these KFragFrags to produce N KFrags (in this example, N=2)
    // and the DKG encryption public key (... need a name for this as well).
    // NOTE: How do we perform this aggregation?
    //  - One option is simply using of the DKG Ursulas
    //  - Another option is using a different, unrelated Ursula
    // NOTE 2: How to verify correctness?
    // NOTE 3: How to deal with sampling and TMap preparation (e.g., encryption of KFrags, etc)
    let rk_1 = rk_alpha_1.add(&rk_beta_1).add(&rk_delta_1);
    let rk_2 = rk_alpha_2.add(&rk_beta_2).add(&rk_delta_2);
    let dkg_encryption_key = encryption_key_alpha.add(&encryption_key_beta).add(&encryption_key_delta);

    // Now, Enrico encrypts something with the DKG encryption key
    // For simplicity, we don't deal with messages here but only with the computation
    // of the secret factor used to derive the symmetric key that encrypts the message
    let r = Scalar::from(0x43574567476);
    let g_r = &G1Affine::from(g.mul(r));
    let secret = dkg_encryption_key.mul(r);
    
    // ReEncryption with 2 Ursulas, using rk_1 and rk_2 
    let cfrag_1 = pairing(&g_r, &G2Affine::from(rk_1));
    let cfrag_2 = pairing(&g_r, &G2Affine::from(rk_2));

    // Decryption: first cfrag aggregation and then actual decryption
    // Since it's a 2-of-2 PRE, and share inputs were x=1 and x=2, 
    // lambda values are 2 and -1, respectively.
    let lambda_1 = two;
    let lambda_2 = Scalar::one().neg();

    let lambda_cfrag_1 = cfrag_1.mul(lambda_1);
    let lambda_cfrag_2 = cfrag_2.mul(lambda_2);
    let combined_cfrag = lambda_cfrag_1.add(&lambda_cfrag_2);

    let hopefully_secret = combined_cfrag.mul(b2.invert().unwrap());

    // After all this hullabaloo, we're able to recover the same secret factor
    assert_eq!(&secret, &hopefully_secret);

}
