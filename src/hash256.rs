use crate::{round, utils::pad_u64};

/// This is the initialization vector of `Ascon-Hash256`.
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
/// | 2        |   12     |    12    |    256    |    8     |
const IV: u64 = 0x0000080100cc0002;

#[derive(Debug, Default)]
pub struct Hash256 {
    /// 320 bits internal state.
    state: [u64; 5],
}

impl Hash256 {
    pub fn hash(data: &[u8]) -> [u8; 32] {
        // Initialize the state using the IV.
        let mut hash256 = Hash256::initialize();

        // Process the data to hash
        hash256.process_data(data);

        // Return the squeezed hash.
        hash256.squeeze()
    }

    fn initialize() -> Self {
        let mut out = Hash256::default();
        out.state[0] = IV;
        round::do_n_rounds(&mut out.state, 12);
        out
    }

    fn process_data(&mut self, data: &[u8]) {
        // Chunk the message into 64bits blocks.
        let mut iter = data.chunks_exact(8);
        // Safety: We chunked by exact 8 so we should be able to construct a `u64` from each chunk.
        for c in iter
            .by_ref()
            .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
        {
            self.state[0] ^= c;
            round::do_n_rounds(&mut self.state, 12);
        }

        // Process the last partial block if any.
        let remainder = iter.remainder();
        let mut t1 = [0; 8];
        t1[..remainder.len()].copy_from_slice(remainder);
        let last_c = pad_u64(u64::from_le_bytes(t1), remainder.len());
        self.state[0] ^= last_c;
    }

    /// Squeezing phase
    fn squeeze(&mut self) -> [u8; 32] {
        let mut out = [0; 32];
        for i in 0..4 {
            round::do_n_rounds(&mut self.state, 12);
            out[(i * 8)..(i * 8 + 8)].copy_from_slice(&self.state[0].to_le_bytes());
        }

        out
    }
}
