use rand::distributions::Alphanumeric;
use rand::{Rng, RngCore};

use crate::aead128::AEAD128;
use crate::utils::pad_u64;

#[test]
fn test_pad_u64() {
    assert_eq!(pad_u64(0x0000000000000000, 0), 0x0000000000000001);
    assert_eq!(pad_u64(0x00000000000000FF, 1), 0x00000000000001FF);
    assert_eq!(pad_u64(0x000000000000FFFF, 2), 0x000000000001FFFF);
    assert_eq!(pad_u64(0x0000000000FFFFFF, 3), 0x0000000001FFFFFF);
    assert_eq!(pad_u64(0x00000000FFFFFFFF, 4), 0x00000001FFFFFFFF);
    assert_eq!(pad_u64(0x000000FFFFFFFFFF, 5), 0x000001FFFFFFFFFF);
    assert_eq!(pad_u64(0x0000FFFFFFFFFFFF, 6), 0x0001FFFFFFFFFFFF);
    assert_eq!(pad_u64(0x00FFFFFFFFFFFFFF, 7), 0x01FFFFFFFFFFFFFF);
}

#[test]
fn test_empty_vector() {
    let plain = [];
    let ad = [];
    let key = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let nonce = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

    let (cipher, mut tag) = AEAD128::encrypt(key, nonce, &ad, &plain);

    // Cipher should be empty because `plain` was empty.
    assert!(cipher.is_empty());

    assert_eq!(
        tag,
        [
            0x44, 0x27, 0xd6, 0x4b, 0x8e, 0x1e, 0x14, 0x51, 0xfc, 0x44, 0x59, 0x60, 0xf0, 0x83,
            0x9b, 0xb0
        ]
    );

    let decipher = AEAD128::decrypt(key, nonce, &ad, &cipher, tag);
    assert!(decipher.is_some());

    let decipher = decipher.unwrap();
    // Same, deciphered should be empty.
    assert!(decipher.is_empty());
    assert_eq!(plain.to_vec(), decipher);

    // Try deciphering with after altering the `tag`. This should fail.
    tag[0] += 1;
    let decipher = AEAD128::decrypt(key, nonce, &ad, &cipher, tag);
    assert!(decipher.is_none());
}

#[test]
fn test_ad_vector() {
    let plain = [];
    let ad = [0];
    let key = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let nonce = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

    let (cipher, mut tag) = AEAD128::encrypt(key, nonce, &ad, &plain);

    // Cipher should be empty because `plain` was empty.
    assert!(cipher.is_empty());

    assert_eq!(
        tag,
        [
            0x10, 0x3a, 0xb7, 0x9d, 0x91, 0x3a, 0x03, 0x21, 0x28, 0x77, 0x15, 0xa9, 0x79, 0xbb,
            0x85, 0x85
        ]
    );

    let decipher = AEAD128::decrypt(key, nonce, &ad, &cipher, tag);
    assert!(decipher.is_some());

    let decipher = decipher.unwrap();
    // Same, deciphered should be empty.
    assert!(decipher.is_empty());
    assert_eq!(plain.to_vec(), decipher);

    // Try deciphering with after altering the `tag`. This should fail.
    tag[0] += 1;
    let decipher = AEAD128::decrypt(key, nonce, &ad, &cipher, tag);
    assert!(decipher.is_none());
}

#[test]
fn test_ad_vector_1() {
    let plain = [];
    let ad = [0, 1];
    let key = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let nonce = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

    let (cipher, mut tag) = AEAD128::encrypt(key, nonce, &ad, &plain);

    // Cipher should be empty because `plain` was empty.
    assert!(cipher.is_empty());

    assert_eq!(
        tag,
        [
            0xa5, 0x0e, 0x88, 0xe3, 0x0f, 0x92, 0x3b, 0x90, 0xa9, 0xc8, 0x10, 0x18, 0x12, 0x30,
            0xdf, 0x10
        ]
    );

    let decipher = AEAD128::decrypt(key, nonce, &ad, &cipher, tag);
    assert!(decipher.is_some());

    let decipher = decipher.unwrap();
    // Same, deciphered should be empty.
    assert!(decipher.is_empty());
    assert_eq!(plain.to_vec(), decipher);

    // Try deciphering with after altering the `tag`. This should fail.
    tag[0] += 1;
    let decipher = AEAD128::decrypt(key, nonce, &ad, &cipher, tag);
    assert!(decipher.is_none());
}

#[test]
fn test_ad_vector_2() {
    let plain = [];
    let ad = [0, 1, 2];
    let key = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let nonce = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

    let (cipher, mut tag) = AEAD128::encrypt(key, nonce, &ad, &plain);

    // Cipher should be empty because `plain` was empty.
    assert!(cipher.is_empty());

    assert_eq!(
        tag,
        [
            0xae, 0x21, 0x4c, 0x9f, 0x66, 0x63, 0x06, 0x58, 0xed, 0x8d, 0xc7, 0xd3, 0x11, 0x31,
            0x17, 0x4c
        ]
    );

    let decipher = AEAD128::decrypt(key, nonce, &ad, &cipher, tag);
    assert!(decipher.is_some());

    let decipher = decipher.unwrap();
    // Same, deciphered should be empty.
    assert!(decipher.is_empty());
    assert_eq!(plain.to_vec(), decipher);

    // Try deciphering with after altering the `tag`. This should fail.
    tag[0] += 1;
    let decipher = AEAD128::decrypt(key, nonce, &ad, &cipher, tag);
    assert!(decipher.is_none());
}

#[test]
fn test_ad_vector_3() {
    let plain = [];
    let ad = [0, 1, 2, 3];
    let key = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let nonce = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

    let (cipher, mut tag) = AEAD128::encrypt(key, nonce, &ad, &plain);

    // Cipher should be empty because `plain` was empty.
    assert!(cipher.is_empty());

    assert_eq!(
        tag,
        [
            0xc6, 0xff, 0x3c, 0xf7, 0x05, 0x75, 0xb1, 0x44, 0xb9, 0x55, 0x82, 0x0d, 0x9b, 0xc7,
            0x68, 0x5e
        ]
    );

    let decipher = AEAD128::decrypt(key, nonce, &ad, &cipher, tag);
    assert!(decipher.is_some());

    let decipher = decipher.unwrap();
    // Same, deciphered should be empty.
    assert!(decipher.is_empty());
    assert_eq!(plain.to_vec(), decipher);

    // Try deciphering with after altering the `tag`. This should fail.
    tag[0] += 1;
    let decipher = AEAD128::decrypt(key, nonce, &ad, &cipher, tag);
    assert!(decipher.is_none());
}

#[test]
fn test_ad9_vector() {
    let plain = [];
    let ad = [0, 1, 2, 3, 4, 5, 6, 7, 8];
    let key = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let nonce = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

    let (cipher, mut tag) = AEAD128::encrypt(key, nonce, &ad, &plain);

    // Cipher should be empty because `plain` was empty.
    assert!(cipher.is_empty());

    assert_eq!(
        tag,
        [
            0x19, 0x9b, 0x9f, 0x81, 0x5b, 0xa3, 0x7a, 0x38, 0x6d, 0x28, 0x3f, 0x50, 0x4b, 0x8d,
            0x22, 0x77
        ]
    );

    let decipher = AEAD128::decrypt(key, nonce, &ad, &cipher, tag);
    assert!(decipher.is_some());

    let decipher = decipher.unwrap();
    // Same, deciphered should be empty.
    assert!(decipher.is_empty());
    assert_eq!(plain.to_vec(), decipher);

    // Try deciphering with after altering the `tag`. This should fail.
    tag[0] += 1;
    let decipher = AEAD128::decrypt(key, nonce, &ad, &cipher, tag);
    assert!(decipher.is_none());
}

#[test]
fn test_adf_vector() {
    let plain = [];
    let ad = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let key = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let nonce = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

    let (cipher, mut tag) = AEAD128::encrypt(key, nonce, &ad, &plain);

    // Cipher should be empty because `plain` was empty.
    assert!(cipher.is_empty());

    assert_eq!(
        tag,
        [
            0xb7, 0x47, 0xd3, 0x23, 0x5e, 0x97, 0x1c, 0x20, 0xd0, 0x0d, 0xcf, 0x87, 0x40, 0x69,
            0x38, 0xfd
        ]
    );

    let decipher = AEAD128::decrypt(key, nonce, &ad, &cipher, tag);
    assert!(decipher.is_some());

    let decipher = decipher.unwrap();
    // Same, deciphered should be empty.
    assert!(decipher.is_empty());
    assert_eq!(plain.to_vec(), decipher);

    // Try deciphering with after altering the `tag`. This should fail.
    tag[0] += 1;
    let decipher = AEAD128::decrypt(key, nonce, &ad, &cipher, tag);
    assert!(decipher.is_none());
}

#[test]
fn test_ad10_vector() {
    let plain = [];
    let ad = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let key = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let nonce = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

    let (cipher, mut tag) = AEAD128::encrypt(key, nonce, &ad, &plain);

    // Cipher should be empty because `plain` was empty.
    assert!(cipher.is_empty());

    assert_eq!(
        tag,
        [
            0xd9, 0x90, 0xa2, 0x42, 0x65, 0x4d, 0x07, 0x41, 0xc7, 0x52, 0x5e, 0x6f, 0x90, 0x36,
            0x53, 0xed
        ]
    );

    let decipher = AEAD128::decrypt(key, nonce, &ad, &cipher, tag);
    assert!(decipher.is_some());

    let decipher = decipher.unwrap();
    // Same, deciphered should be empty.
    assert!(decipher.is_empty());
    assert_eq!(plain.to_vec(), decipher);

    // Try deciphering with after altering the `tag`. This should fail.
    tag[0] += 1;
    let decipher = AEAD128::decrypt(key, nonce, &ad, &cipher, tag);
    assert!(decipher.is_none());
}

#[test]
fn test_plain_vector() {
    let plain = [0];
    let ad = [];
    let key = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let nonce = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

    let (cipher, mut tag) = AEAD128::encrypt(key, nonce, &ad, &plain);

    // Cipher should be empty because `plain` was empty.
    assert_eq!(cipher.len(), plain.len());

    assert_eq!(cipher, [0xe7]);
    assert_eq!(
        tag,
        [
            0x9f, 0x58, 0xf1, 0xf5, 0x41, 0xfc, 0x51, 0xb5, 0xd4, 0x38, 0xf8, 0xe1, 0xdd, 0x03,
            0xf1, 0x47
        ]
    );

    let decipher = AEAD128::decrypt(key, nonce, &ad, &cipher, tag);
    assert!(decipher.is_some());

    let decipher = decipher.unwrap();
    dbg!(&decipher);
    assert_eq!(plain.to_vec(), decipher);

    // Try deciphering with after altering the `tag`. This should fail.
    tag[0] += 1;
    let decipher = AEAD128::decrypt(key, nonce, &ad, &cipher, tag);
    assert!(decipher.is_none());
}
