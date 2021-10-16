use bls12_381::{G2Projective, Scalar};

use crate::keymaker::KeySliver;

pub struct KeyFrag {
    pub(crate) shared_value: Scalar,
    pub(crate) point: G2Projective,
}

pub fn generate_kfrags(kslivers: &[KeySliver]) -> Option<Vec<KeyFrag>> {
    // Somehow, DKG Ursulas aggregate these KFragFrags to produce N KFrags
    // and the DKG encryption public key (... need a name for this as well).
    // NOTE: How do we perform this aggregation?
    //  - One option is simply using of the DKG Ursulas
    //  - Another option is using a different, unrelated Ursula
    // NOTE 2: How to verify correctness?
    // NOTE 3: How to deal with sampling and TMap preparation (e.g., encryption of KFrags, etc)

    // check if shared values are the same
    if !kslivers
        .windows(2)
        .all(|w| w[0].shared_values == w[1].shared_values)
    {
        return None;
    }

    let shared_values = &kslivers[0].shared_values;
    let shares = kslivers[0].reencryption_key_parts.len();

    let kfrags = (0..shares)
        .map(|share| {
            (
                shared_values[share],
                kslivers
                    .iter()
                    .map(|ksliver| ksliver.reencryption_key_parts[share])
                    .sum(),
            )
        })
        .map(|(shared_value, point)| KeyFrag {
            shared_value,
            point,
        })
        .collect::<Vec<_>>();

    Some(kfrags)
}
