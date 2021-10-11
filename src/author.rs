use bls12_381::G2Projective;

use crate::keymaker::KeySliver;

pub struct KeyFrag {
    pub(crate) id: usize,
    pub(crate) point: G2Projective,
}

pub fn generate_kfrags(kslivers: &[KeySliver]) -> Vec<KeyFrag> {
    // Somehow, DKG Ursulas aggregate these KFragFrags to produce N KFrags
    // and the DKG encryption public key (... need a name for this as well).
    // NOTE: How do we perform this aggregation?
    //  - One option is simply using of the DKG Ursulas
    //  - Another option is using a different, unrelated Ursula
    // NOTE 2: How to verify correctness?
    // NOTE 3: How to deal with sampling and TMap preparation (e.g., encryption of KFrags, etc)

    let shares = kslivers[0].reencryption_key_parts.len();

    let reencryption_keys: Vec<_> = (0..shares)
        .map(|share| {
            kslivers
                .iter()
                .map(|ksliver| ksliver.reencryption_key_parts[share])
                .sum()
        })
        .enumerate()
        .map(|(id, point)| KeyFrag { id, point })
        .collect();

    reencryption_keys
}
