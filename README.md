# Distributed key generation + proxy re-encryption

[![crate][rust-crate-image]][rust-crate-link] [![Docs][rust-docs-image]][rust-docs-link] ![License][rust-license-image] [![Build Status][rust-build-image]][rust-build-link] [![Coverage][rust-coverage-image]][rust-coverage-link]

`nube` is a Rust implementation of a proxy re-encryption algorithm with distributed key generation.
See `notes/dkg.lyx` for the scheme descriptioin.

[rust-crate-image]: https://img.shields.io/crates/v/nube.svg
[rust-crate-link]: https://crates.io/crates/nube
[rust-docs-image]: https://docs.rs/nube/badge.svg
[rust-docs-link]: https://docs.rs/nube/
[rust-license-image]: https://img.shields.io/crates/l/nube
[rust-build-image]: https://github.com/nucypher/nube/workflows/nube/badge.svg?branch=main&event=push
[rust-build-link]: https://github.com/nucypher/nube/actions?query=workflow%3Anube
[rust-coverage-image]: https://codecov.io/gh/nucypher/nube/branch/main/graph/badge.svg
[rust-coverage-link]: https://codecov.io/gh/nucypher/nube


## Usage example

```rust
use nube::{decrypt, encrypt, generate_kfrags, reencrypt, KeyMaker, RecipientSecretKey};

// In this example, we're going to create KeyFrags for a 2-of-3 PRE (T=2, N=3)
let threshold = 2;
let shares = 3;

//
// Keymakers
//

// Let's assume there's a DKG of Ñ=4 keymakers
let keymaker1 = KeyMaker::random();
let keymaker2 = KeyMaker::random();
let keymaker3 = KeyMaker::random();
let keymaker4 = KeyMaker::random();

//
// Encryptor
//

// Accumulate the encryption key
let key_parts = [
    keymaker1.encryption_key(),
    keymaker2.encryption_key(),
    keymaker3.encryption_key(),
    keymaker4.encryption_key(),
];

let encryption_key = &key_parts[0] + &key_parts[1] + &key_parts[2] + &key_parts[3];

// Now, Encryptor encrypts something with the DKG encryption key
// For simplicity, we don't deal with messages here but only with the computation
// of the secret factor used to derive the symmetric key that encrypts the message
// TODO: use the symmetric key to encrypt a ciphertext.
let (capsule, symmetric_key) = encrypt(&encryption_key);

//
// Recipient
//

// Recipient creates a secret key for decryption,
// and a public key that will be a target for keyslivers/keyfrags.
let recipient_sk = RecipientSecretKey::random();
let recipient_pk = recipient_sk.public_key();

//
// Author
//

// Author creates a label and sends it to Keymakers, requesting key slivers
let label = b"some label";

// Keymakers make key slivers intended for Recipient
let ksliver1 = keymaker1.make_key_sliver(label, &recipient_pk, threshold, shares);
let ksliver2 = keymaker2.make_key_sliver(label, &recipient_pk, threshold, shares);
let ksliver3 = keymaker3.make_key_sliver(label, &recipient_pk, threshold, shares);
let ksliver4 = keymaker4.make_key_sliver(label, &recipient_pk, threshold, shares);

// The slivers are sent back to the Author who repackages them into kfrags.
let kfrags = generate_kfrags(&[ksliver1, ksliver2, ksliver3, ksliver4]).unwrap();

//
// Proxies
//

// Proxies reencrypt the keyfrags.
let cfrag0 = reencrypt(&capsule, &kfrags[0]);
let _cfrag1 = reencrypt(&capsule, &kfrags[1]);
let cfrag2 = reencrypt(&capsule, &kfrags[2]);

//
// Recipient
//

// Recipient decryptis with 2 out of 3 cfrags
let decrypted_key = decrypt(&recipient_sk, &[cfrag0, cfrag2]).unwrap();

assert_eq!(symmetric_key, decrypted_key);
```
