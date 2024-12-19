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
fn test_flow() {
    let mut rng = rand::thread_rng();

    // Random 20 chars plaintext
    let plaintext: String = (&mut rng)
        .sample_iter(&Alphanumeric)
        .take(20)
        .map(char::from)
        .collect();
    // Random 30 chars Associated data
    let ad: String = (&mut rng)
        .sample_iter(&Alphanumeric)
        .take(30)
        .map(char::from)
        .collect();

    // Random 16 bytes `key` and `nonce`.
    let mut key = [0; 16];
    rng.fill_bytes(&mut key);
    let mut nonce = [0; 16];
    rng.fill_bytes(&mut nonce);

    let (cipher, tag) = AEAD128::encrypt(key, nonce, ad.as_bytes(), plaintext.as_bytes());
    let decipher = AEAD128::decrypt(key, nonce, ad.as_bytes(), &cipher, tag);

    assert!(decipher.is_some());

    let decipher = decipher.unwrap();

    assert_eq!(plaintext.as_bytes(), decipher);
}

/*
#[test]
fn _test_hash256() {
        Ascon-Hash("")
    0x 7346bc14f036e87ae03d0997913088f5f68411434b3cf8b54fa796a80d251f91
    Ascon-HashA("")
    0x aecd027026d0675f9de7a8ad8ccf512db64b1edcf0b20c388a0c7cc617aaa2c4
    Ascon-Hash("The quick brown fox jumps over the lazy dog")
    0x 3375fb43372c49cbd48ac5bb6774e7cf5702f537b2cf854628edae1bd280059e
    Ascon-Hash("The quick brown fox jumps over the lazy dog.")
    0x c9744340ed476ac235dd979d12f5010a7523146ee90b57ccc4faeb864efcd048

    assert!(true);
}
        */

/*
#[test]
fn test_xof128() {
    Ascon-Xof("", 32)
    0x 5d4cbde6350ea4c174bd65b5b332f8408f99740b81aa02735eaefbcf0ba0339e
    Ascon-XofA("", 32)
    0x 7c10dffd6bb03be262d72fbe1b0f530013c6c4eadaabde278d6f29d579e3908d

    assert!(true);
}
    */
