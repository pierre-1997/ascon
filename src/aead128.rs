use log::{debug, error};
use std::u64;

use crate::{
    round::{self, state_to_str},
    utils::pad_u64,
};

#[derive(Debug)]
pub struct AEAD128 {
    /// 128 bits symmetric key.
    key: [u64; 2],
    /// 128 bits random nonce.
    nonce: [u64; 2],
    /// 320 bits internal state.
    state: [u64; 5],
}

const RATE: usize = 16;

/// This is the initialization vector of `Ascon-AEAD128`.
/// With, `v`, `a`, `b`, `t`, `r/8` as:
/// - `v`: Unique identifier of the algorithm.
/// - `a`: Number of rounds during initialization and finalization.
/// - `b`: Number of rounds during the processing of `Associated Data`, plaintext and ciphertext.
/// - `t`: 128 for `Ascon-AEAD128` (arbitrary?).
/// - `r/8`: Number of input bytes processed per invocation of the underlying permutation.
///
/// For `Ascon-AEAD128`, these values are:
/// |    v     |     a    |     b    |     t     |    r/8   |
/// | (8 bits) | (4 bits) | (4 bits) | (16 bits) | (8 bits) |
/// | 1        |   12     |     8    |    128    |    16    |
const IV: u64 = 0x00001000808c0001;

/// Domain separation constant (which is XORed with `state[4]`).
const DSEP: u64 = 0x80u64 << 56;

impl AEAD128 {
    /// Instanciate a new Ascon-AEAD128.
    fn new(key: [u8; 16], nonce: [u8; 16]) -> Self {
        let key = [
            u64::from_le_bytes([
                key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7],
            ]),
            u64::from_le_bytes([
                key[8], key[9], key[10], key[11], key[12], key[13], key[14], key[15],
            ]),
        ];
        let nonce = [
            u64::from_le_bytes([
                nonce[0], nonce[1], nonce[2], nonce[3], nonce[4], nonce[5], nonce[6], nonce[7],
            ]),
            u64::from_le_bytes([
                nonce[8], nonce[9], nonce[10], nonce[11], nonce[12], nonce[13], nonce[14],
                nonce[15],
            ]),
        ];

        Self {
            key,
            nonce,
            state: [0; 5],
        }
    }

    /// Initialization function for Ascon-AEAD128.
    fn initialize(&mut self) {
        self.state = [IV, self.key[0], self.key[1], self.nonce[0], self.nonce[1]];
        debug!(" init 1st key xor: {}", state_to_str(&self.state));

        round::do_n_rounds(&mut self.state, 12);

        self.xor_key();
        debug!(" init 2nd key xor: {}", state_to_str(&self.state));
    }

    /// This function performs `Ascon-AEAD128` encryption.
    ///
    /// Returns `(ciphertext, tag)` as:
    /// - `ciphertext` (`Vec<u8>`): The encrypted bytes.
    /// - `tag` (`[u8; 16]`): The associated authentication tag.
    pub fn encrypt(key: [u8; 16], nonce: [u8; 16], ad: &[u8], plain: &[u8]) -> (Vec<u8>, [u8; 16]) {
        let mut aead128 = Self::new(key, nonce);

        // Initialize
        aead128.initialize();

        // Process Associated Data
        aead128.process_adata(ad);

        // Process Plaintext
        let cipher = aead128.process_plain(plain);
        /*
        println!(
            "cipher = {{{}}}",
            cipher[..std::cmp::min(16, cipher.len())]
                .iter()
                .map(|b| format!("0x{:02x}", b))
                .collect::<Vec<String>>()
                .join(", ")
        );
        */

        // Finalization
        aead128.finalize();

        // Return the encrypted bytes along its authentication tag.
        (cipher, aead128.get_tag())
    }

    /// This function performs `Ascon-AEAD128` decryption.
    ///
    /// Returns `Some(plaintext)` on success, and `None on failure.
    pub fn decrypt(
        key: [u8; 16],
        nonce: [u8; 16],
        ad: &[u8],
        cipher: &[u8],
        tag: [u8; 16],
    ) -> Option<Vec<u8>> {
        let mut aead128 = Self::new(key, nonce);

        // Initialize
        aead128.initialize();

        // Process Associated Data
        aead128.process_adata(ad);

        // Process cipher
        let plain = aead128.process_cipher(cipher);

        // Finalization
        aead128.finalize();

        // Retrieve the tag and compare it with the one we were supposed to have.
        let ptag = aead128.get_tag();
        if ptag != tag {
            error!(
                "INVALID TAG: 0x{:x}{:x} - PTAG: 0x{:x}{:x}",
                u64::from_le_bytes(tag[0..8].try_into().unwrap()),
                u64::from_le_bytes(tag[8..16].try_into().unwrap()),
                u64::from_le_bytes(ptag[0..8].try_into().unwrap()),
                u64::from_le_bytes(ptag[8..16].try_into().unwrap()),
            );
        }

        (ptag == tag).then_some(plain)
    }

    /// This performs the `Associated Data` absorption of the `Ascon-AEAD128` algorithm.
    fn process_adata(&mut self, ad: &[u8]) {
        // We only need 2 temporary u64 in total.
        let mut t1 = [0; 8];
        let mut t2 = [0; 8];

        if !ad.is_empty() {
            let mut iter = ad.chunks_exact(RATE);
            // Load the exact chunks in S0 and S1 and do 8 rounds.
            for c in iter.by_ref() {
                t1.copy_from_slice(&c[0..8]);
                t2.copy_from_slice(&c[8..16]);

                self.state[0] ^= u64::from_le_bytes(t1);
                self.state[1] ^= u64::from_le_bytes(t2);

                // Apply 8 rounds to state
                round::do_n_rounds(&mut self.state, 8);
            }

            // Pad the last 2 chunks and do 8 rounds.
            let mut remainder = iter.remainder();
            t1 = [0; 8];
            let mut pt = &mut self.state[0];

            if remainder.len() >= 8 {
                t1.copy_from_slice(&remainder[0..8]);
                *pt ^= u64::from_le_bytes(t1);
                remainder = &remainder[8..];
                pt = &mut self.state[1];
            }

            t1 = [0; 8];
            t1[..remainder.len()].copy_from_slice(remainder);
            *pt ^= pad_u64(u64::from_le_bytes(t1), remainder.len());

            debug!("        pad adata: {}", state_to_str(&self.state));

            // Apply 8 rounds to state
            round::do_n_rounds(&mut self.state, 8);
        }

        // Domain separation
        self.state[4] ^= DSEP;
        debug!("domain separation: {}", state_to_str(&self.state));
    }

    /// This function processes the `plaintext` during `Ascon-AEAD128` encryption.
    ///
    /// TODO: Do a `Stream`...
    fn process_plain(&mut self, plain: &[u8]) -> Vec<u8> {
        let mut t1 = [0; 8];
        let mut out = Vec::with_capacity(plain.len());

        let mut iter = plain.chunks_exact(16);
        for c in iter.by_ref() {
            t1.copy_from_slice(&c[0..8]);
            self.state[0] ^= u64::from_le_bytes(t1);

            t1.copy_from_slice(&c[8..16]);
            self.state[1] ^= u64::from_le_bytes(t1);

            out.extend_from_slice(&self.state[0].to_le_bytes());
            out.extend_from_slice(&self.state[1].to_le_bytes());

            debug!(" absorb plaintext: {}", state_to_str(&self.state));
            round::do_n_rounds(&mut self.state, 8);
        }

        // Pad the last 2 chunks and do 8 rounds.
        let mut remainder = iter.remainder();
        let mut pt = &mut self.state[0];

        if remainder.len() >= 8 {
            t1 = [0; 8];
            t1.copy_from_slice(&remainder[0..8]);
            *pt ^= u64::from_le_bytes(t1);

            out.extend_from_slice(&self.state[0].to_le_bytes());

            remainder = &remainder[8..];
            pt = &mut self.state[1];
        }

        t1 = [0; 8];
        t1[..remainder.len()].copy_from_slice(remainder);
        *pt ^= pad_u64(u64::from_le_bytes(t1), remainder.len());

        out.extend_from_slice(&(*pt).to_le_bytes()[..remainder.len()]);

        debug!("    pad plaintext: {}", state_to_str(&self.state));

        out
    }

    /// This function processes the `ciphertext` during `Ascon-AEAD128` decryption.
    fn process_cipher(&mut self, cipher: &[u8]) -> Vec<u8> {
        let mut tmp_bytes = [0; 8];
        let mut t1;

        let mut out = Vec::with_capacity(cipher.len());

        let mut iter = cipher.chunks_exact(16);
        for c in iter.by_ref() {
            tmp_bytes.copy_from_slice(&c[0..8]);
            t1 = u64::from_le_bytes(tmp_bytes);
            out.extend_from_slice(&(self.state[0] ^ t1).to_le_bytes());
            self.state[0] = t1;

            tmp_bytes.copy_from_slice(&c[8..16]);
            t1 = u64::from_le_bytes(tmp_bytes);
            out.extend_from_slice(&(self.state[1] ^ t1).to_le_bytes());
            self.state[1] = t1;

            round::do_n_rounds(&mut self.state, 8)
        }

        // Pad the last 2 chunks and do 8 rounds.
        let mut remainder = iter.remainder();
        let mut pt = &mut self.state[0];

        if remainder.len() >= 8 {
            tmp_bytes = [0; 8];
            tmp_bytes.copy_from_slice(&remainder[0..8]);

            out.extend(
                pt.to_le_bytes()
                    .iter()
                    .zip(&remainder[0..8])
                    .map(|(s, t)| s ^ t),
            );
            *pt = u64::from_le_bytes(tmp_bytes);

            remainder = &remainder[8..];
            pt = &mut self.state[1];
        }

        *pt = pad_u64(*pt, remainder.len());

        // Store the rest of the message
        if !remainder.is_empty() {
            tmp_bytes = [0; 8];
            tmp_bytes[..remainder.len()].copy_from_slice(remainder);
            *pt ^= u64::from_le_bytes(tmp_bytes);
            out.extend_from_slice(&(*pt).to_le_bytes()[..remainder.len()]);

            // Clear the trailing bytes before setting just the end
            *pt = (*pt) & (!0u64 << (8 * remainder.len())) ^ u64::from_le_bytes(tmp_bytes);
        }

        debug!("   pad ciphertext: {}", state_to_str(&self.state));

        out
    }

    /// This is the finalization step of the `Ascon-AEAD128` algorithm.
    fn finalize(&mut self) {
        // XOR the key with S2 and S3
        self.state[2] ^= self.key[0];
        self.state[3] ^= self.key[1];

        debug!("final 1st key xor: {}", state_to_str(&self.state));

        // Do the final 12 rounds
        round::do_n_rounds(&mut self.state, 12);

        // Finally, XOR the key with S3 and S4 to get the Tag.
        self.xor_key();
        debug!("final 2nd key xor: {}", state_to_str(&self.state));
    }

    /// The tag is the concatenation of S3 and S4.
    pub fn get_tag(&mut self) -> [u8; 16] {
        let mut tag = [0; 16];
        tag[0..8].copy_from_slice(&self.state[3].to_le_bytes());
        tag[8..16].copy_from_slice(&self.state[4].to_le_bytes());

        /*
        println!(
            "tag = [{}]",
            tag.iter()
                .map(|b| format!("0x{:02x}", b))
                .collect::<Vec<String>>()
                .join(", ")
        );
        */

        tag
    }

    /// This small function just XORs the key with the last two `state` words.
    fn xor_key(&mut self) {
        self.state[3] ^= self.key[0];
        self.state[4] ^= self.key[1];
    }
}
