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

fn run_test(key: [u8; 16], nonce: [u8; 16], ad: &[u8], plain: &[u8]) {
    // dbg!(&key, &nonce, &ad, &plain);
    let (cipher, mut tag) = AEAD128::encrypt(key, nonce, &ad, &plain);

    let decipher = AEAD128::decrypt(key, nonce, &ad, &cipher, tag);

    assert_eq!(decipher, Some(plain.to_vec()));

    // Try deciphering with after altering the `tag`. This should fail.
    tag[0] += 1;
    let decipher = AEAD128::decrypt(key, nonce, &ad, &cipher, tag);
    assert!(decipher.is_none());
}

#[test]
fn test_empty_vector() {
    let plain = [];
    let ad = [];
    let key = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let nonce = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

    run_test(key, nonce, &ad, &plain);
}

#[test]
fn test_ad_vector() {
    let plain = [];
    let ad = [0];
    let key = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let nonce = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

    run_test(key, nonce, &ad, &plain);
}

#[test]
fn test_ad_vector_1() {
    let plain = [];
    let ad = [0, 1];
    let key = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let nonce = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

    run_test(key, nonce, &ad, &plain);
}

#[test]
fn test_ad_vector_2() {
    let plain = [];
    let ad = [0, 1, 2];
    let key = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let nonce = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

    run_test(key, nonce, &ad, &plain);
}

#[test]
fn test_ad_vector_3() {
    let plain = [];
    let ad = [0, 1, 2, 3];
    let key = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let nonce = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

    run_test(key, nonce, &ad, &plain);
}

#[test]
fn test_ad9_vector() {
    let plain = [];
    let ad = [0, 1, 2, 3, 4, 5, 6, 7, 8];
    let key = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let nonce = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

    run_test(key, nonce, &ad, &plain);
}

#[test]
fn test_adf_vector() {
    let plain = [];
    let ad = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let key = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let nonce = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

    run_test(key, nonce, &ad, &plain);
}

#[test]
fn test_ad10_vector() {
    let plain = [];
    let ad = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let key = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let nonce = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

    run_test(key, nonce, &ad, &plain);
}

#[test]
fn test_plain_vector() {
    let plain = [0];
    let ad = [];
    let key = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let nonce = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

    run_test(key, nonce, &ad, &plain);
}

#[test]
fn test_plain_ad_vector() {
    let plain = [0];
    let ad = [0];
    let key = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let nonce = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

    run_test(key, nonce, &ad, &plain);
}

#[test]
fn test_plain_ad10_vector() {
    let plain = [0];
    let ad = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let key = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let nonce = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

    run_test(key, nonce, &ad, &plain);
}

#[test]
fn test_plain1_vector() {
    let plain = [0, 1];
    let ad = [];
    let key = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let nonce = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

    run_test(key, nonce, &ad, &plain);
}

#[test]
fn test_plain9_vector() {
    let plain = [0, 1, 2, 3, 4, 5, 6, 7, 8];
    let ad = [];
    let key = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let nonce = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

    run_test(key, nonce, &ad, &plain);
}

#[test]
fn test_plain9_ad9_vector() {
    let plain = [0, 1, 2, 3, 4, 5, 6, 7, 8];
    let ad = [0, 1, 2, 3, 4, 5, 6, 7, 8];
    let key = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let nonce = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

    run_test(key, nonce, &ad, &plain);
}

#[test]
fn test_plain16_vector() {
    let plain = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let ad = [];
    let key = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let nonce = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

    run_test(key, nonce, &ad, &plain);
}

#[test]
fn test_plain16_ad16_vector() {
    let plain = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let ad = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let key = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let nonce = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

    run_test(key, nonce, &ad, &plain);
}

/*
#[test]
fn test_plain1_vector() {
    let plain = [0, 1, 2,3,4,5,6,7,8,9,10,11,12,13,14,15,16];
    let ad = [];
    let key = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let nonce = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

    run_test(key, nonce, &ad, &plain);
}
#[test]
fn test_plain1_vector() {
    let plain = [0, 1, 2,3,4,5,6,7,8,9,10,11,12,13,14,15,16];
    let ad = [];
    let key = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let nonce = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

    run_test(key, nonce, &ad, &plain);
}
*/

/*
#[test]
fn test_plain_ad10_vector() {
    let plain = [0];
    let ad = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let key = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let nonce = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

    let (mut cipher, mut tag) = AEAD128::encrypt(key, nonce, &ad, &plain);

    // Cipher should be empty because `plain` was empty.
    assert_eq!(cipher.len(), plain.len());

    assert_eq!(cipher, [0x98]);
    assert_eq!(
        tag,
        [
            0xbd, 0x6c, 0xb9, 0xc3, 0x87, 0xd7, 0x1d, 0x27, 0x5a, 0x5d, 0x50, 0xe5, 0x52, 0x5c,
            0x64, 0x3c
        ]
    );

    let decipher = AEAD128::decrypt(key, nonce, &ad, &cipher, tag);
    assert!(decipher.is_some());

    let decipher = decipher.unwrap();
    assert_eq!(plain.to_vec(), decipher);

    // Deciphering altered ciphertext
    cipher[0] += 1;
    let decipher = AEAD128::decrypt(key, nonce, &ad, &cipher, tag);
    assert!(decipher.is_none());

    /* let decipher = decipher.unwrap();
    assert_eq!(decipher, vec![0x01]); */

    // Try deciphering with after altering the `tag`. This should fail.
    tag[0] += 1;
    let decipher = AEAD128::decrypt(key, nonce, &ad, &cipher, tag);
    assert!(decipher.is_none());
}
*/
