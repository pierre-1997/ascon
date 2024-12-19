pub fn pad_u64(value: u64, size: usize) -> u64 {
    value ^ (1 << (8 * size))
}
