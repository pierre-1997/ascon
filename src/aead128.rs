use std::u64;

use crate::utils::pad_u64;

#[derive(Debug)]
struct AEAD128 {
    key: [u64; 2],
    nonce: [u64; 2],
    state: [u64; 5],
}

const RATE: usize = 16;

const IV: u64 = 0x00001000808c0001;
const DSEP: u64 = 0x80u64 << 56;

const ROUND_CONSTANTS: [u64; 16] = [
    0x000000000000003c,
    0x000000000000002d,
    0x000000000000001e,
    0x000000000000000f,
    0x00000000000000f0,
    0x00000000000000e1,
    0x00000000000000d2,
    0x00000000000000c3,
    0x00000000000000b4,
    0x00000000000000a5,
    0x0000000000000096,
    0x0000000000000087,
    0x0000000000000078,
    0x0000000000000069,
    0x000000000000005a,
    0x000000000000004b,
];

impl AEAD128 {
    pub fn new(key: [u8; 16], nonce: [u8; 16]) -> Self {
        let key = [
            u64::from_be_bytes([
                key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7],
            ]),
            u64::from_be_bytes([
                key[8], key[9], key[10], key[11], key[12], key[13], key[14], key[15],
            ]),
        ];
        let nonce = [
            u64::from_be_bytes([
                nonce[0], nonce[1], nonce[2], nonce[3], nonce[4], nonce[5], nonce[6], nonce[7],
            ]),
            u64::from_be_bytes([
                nonce[8], nonce[9], nonce[10], nonce[11], nonce[12], nonce[13], nonce[14],
                nonce[15],
            ]),
        ];

        let mut state = [IV, key[0], key[1], nonce[0], nonce[1]];

        for i in 0..12 {
            Self::round(&mut state, ROUND_CONSTANTS[i]);
        }

        Self { key, nonce, state }
    }

    /*

    x0 ^= x4; x4 ^= x3; x2 ^= x1;
    t0 = x0; t1 = x1; t2 = x2; t3 = x3; t4 = x4;
    t0 =~ t0; t1 =~ t1; t2 =~ t2; t3 =~ t3; t4 =~ t4;
    t0 &= x1; t1 &= x2; t2 &= x3; t3 &= x4; t4 &= x0;
    x0 ^= t1; x1 ^= t2; x2 ^= t3; x3 ^= t4; x4 ^= t0;
    x1 ^= x0; x0 ^= x4; x3 ^= x2; x2 =~ x2;
    */
    /// TODO: Check that this function returns the same result as the naive implementation.
    fn round(state: &mut [u64; 5], round_constant: u64) {
        let x0 = state[0] ^ state[4];
        let x2 = state[2] ^ round_constant ^ state[1];
        let x4 = state[4] ^ state[3];

        let t0 = !x0 & state[1];
        let t1 = !state[1] & x2;
        let t2 = !x2 & state[3];
        let t3 = !state[3] & x4;
        let t4 = !x4 & x0;

        state[0] = x0 ^ t1;
        state[1] ^= t2;
        state[2] = x2 ^ t3;
        state[3] ^= t4;
        state[4] = x4 ^ t0;

        state[1] ^= state[0];
        state[0] ^= state[4];
        state[3] ^= state[2];
        state[2] = !state[2];
    }

    fn encrypt(key: [u8; 16], nonce: [u8; 16], ad: &[u8], plain: &[u8]) -> (Vec<u8>, [u8; 16]) {
        let mut aead128 = Self::new(key, nonce);

        // Key setup
        aead128.xor_key();

        // Process Associated Data
        aead128.process_adata(ad);

        // Process Plaintext
        let cypher = aead128.process_plaintext(plain);

        // Finalize
        aead128.finalize();

        (cypher, aead128.get_tag())
    }

    fn process_adata(&mut self, ad: &[u8]) {
        // We only need 2 temporary u64 in total.
        let mut t1 = [0; 8];
        let mut t2 = [0; 8];

        if !ad.is_empty() {
            let mut iter = ad.chunks_exact(RATE);
            // Load the exact chunks in S0 and S1 and do 8 rounds.
            while let Some(c) = iter.next() {
                t1.copy_from_slice(&c[0..8]);
                t2.copy_from_slice(&c[8..15]);

                self.state[0] ^= u64::from_be_bytes(t1);
                self.state[1] ^= u64::from_be_bytes(t2);

                // Apply 8 rounds to state
                for i in 0..8 {
                    Self::round(&mut self.state, ROUND_CONSTANTS[i]);
                }
            }

            // Pad the last 2 chunks and do 8 rounds.
            let remainder = iter.remainder();
            t1 = [0; 8];
            t1.copy_from_slice(&remainder[0..]);
            if remainder.len() > 8 {
                self.state[0] ^= u64::from_be_bytes(t1);

                // Reset t2
                t2 = [0; 8];
                t2.copy_from_slice(&remainder[8..]);
                self.state[1] ^= pad_u64(u64::from_be_bytes(t2), remainder.len() - 8);
            } else {
                self.state[0] ^= pad_u64(u64::from_be_bytes(t1), remainder.len());
            }

            // Apply 8 rounds to state
            for i in 0..8 {
                Self::round(&mut self.state, ROUND_CONSTANTS[i]);
            }
        }

        // Domain separation
        self.state[4] ^= DSEP;
    }

    // TODO: Do a `Stream`...
    fn process_plaintext(&mut self, plain: &[u8]) -> Vec<u8> {
        let mut t1 = [0; 8];
        let mut t2 = [0; 8];
        let mut out = Vec::with_capacity(plain.len());

        let mut iter = plain.chunks_exact(16);
        while let Some(c) = iter.next() {
            t1.copy_from_slice(&c[0..8]);
            t2.copy_from_slice(&c[8..15]);

            self.state[0] ^= u64::from_be_bytes(t1);
            self.state[1] ^= u64::from_be_bytes(t2);

            out.extend_from_slice(&self.state[0].to_be_bytes());
            out.extend_from_slice(&self.state[1].to_be_bytes());

            for i in 0..8 {
                Self::round(&mut self.state, ROUND_CONSTANTS[i]);
            }
        }

        // Pad the last 2 chunks and do 8 rounds.
        let remainder = iter.remainder();
        t1 = [0; 8];
        t1.copy_from_slice(&remainder[0..]);
        if remainder.len() > 8 {
            self.state[0] ^= u64::from_be_bytes(t1);

            // Reset t2
            t2 = [0; 8];
            t2.copy_from_slice(&remainder[8..]);
            self.state[1] ^= pad_u64(u64::from_be_bytes(t2), remainder.len() - 8);
        } else {
            self.state[0] ^= pad_u64(u64::from_be_bytes(t1), remainder.len());
        }

        out.extend_from_slice(&self.state[0].to_be_bytes());
        out.extend_from_slice(&self.state[1].to_be_bytes());

        out
    }

    fn finalize(&mut self) {
        // XOR the key with S2 and S3
        self.state[2] ^= self.key[0];
        self.state[3] ^= self.key[1];

        // Do the final 12 rounds
        for i in 0..12 {
            Self::round(&mut self.state, ROUND_CONSTANTS[i]);
        }

        // Finally, XOR the key with S3 and S4 to get the Tag.
        self.xor_key();
    }

    /// The tag is the concatenation of S3 and S4.
    pub fn get_tag(&mut self) -> [u8; 16] {
        let mut tag = [0; 16];
        tag.copy_from_slice(&self.state[3].to_be_bytes());
        tag[8..16].copy_from_slice(&self.state[4].to_be_bytes());

        tag
    }

    fn xor_key(&mut self) {
        self.state[3] ^= self.key[0];
        self.state[4] ^= self.key[1];
    }

    fn hash256(m: &[u8]) -> [u8; 32] {
        // Initialization
        // Message absorbing
        // Output squeezing
        todo!()
    }

    fn xof128() {
        todo!()
    }

    fn add_constant(&mut self, round: usize) {
        self.state[2] ^= ROUND_CONSTANTS[round];
    }

    fn substitute(&mut self) {
        todo!()
    }

    fn diffuse(&mut self) {
        todo!()
    }

    fn naive_round(&mut self) {
        // self.add_constant()
        // self.substitute()
        // self.diffuse()
    }
}