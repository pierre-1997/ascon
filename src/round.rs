use log::debug;

/// These are the round constants used in the `Ascon` permutation.
const ROUND_CONSTANTS: [u64; 16] = [
    // These 4 round constants are never used because we only go up to 12 rounds max:
    0x000000000000003c,
    0x000000000000002d,
    0x000000000000001e,
    0x000000000000000f,
    // These are actually used:
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

pub fn do_n_rounds(state: &mut [u64; 5], n: usize) {
    for i in 0..n {
        round(state, ROUND_CONSTANTS[16 - n + i]);
    }
}

/// This is the round function of `Ascon`.
///
/// (TODO: Write about the number of temp variables used.)
fn round(state: &mut [u64; 5], round_constant: u64) {
    // Constant Addition Layer
    state[2] ^= round_constant;

    // Substitution Layer (S-Box)
    state[0] ^= state[4];
    state[2] ^= state[1];
    state[4] ^= state[3];

    let mut t0 = state[0] ^ (!state[1] & state[2]);
    let mut t1 = state[1] ^ (!state[2] & state[3]);
    let mut t2 = state[2] ^ (!state[3] & state[4]);
    let mut t3 = state[3] ^ (!state[4] & state[0]);
    let t4 = state[4] ^ (!state[0] & state[1]);

    t1 ^= t0;
    t0 ^= t4;
    t3 ^= t2;
    // NOTE: `ascon-c` does this one **after** the linear diffuse. Why?
    t2 = !t2;

    // Linear Diffusion Layer
    state[0] = t0 ^ t0.rotate_right(19) ^ t0.rotate_right(28);
    state[1] = t1 ^ t1.rotate_right(61) ^ t1.rotate_right(39);
    state[2] = t2 ^ t2.rotate_right(1) ^ t2.rotate_right(6);
    state[3] = t3 ^ t3.rotate_right(10) ^ t3.rotate_right(17);
    state[4] = t4 ^ t4.rotate_right(7) ^ t4.rotate_right(41);

    debug!("   round output: {}", state_to_str(state));
}

/// Displays the internal 5 word state.
pub fn state_to_str(state: &[u64; 5]) -> String {
    format!(
        "x0=0x{:x} x1=0x{:x} x2=0x{:x} x3=0x{:x} x4=0x{:x}",
        state[0], state[1], state[2], state[3], state[4]
    )
}
