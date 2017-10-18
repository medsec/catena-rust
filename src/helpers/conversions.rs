/// Convert a `Vec<u8>` to a `Vec<u64>`. The input vector length has to be a multiple of 8.
pub fn vec_u8_to_vec_u64(vec_u8: &Vec<u8>) -> Vec<u64> {
    if vec_u8.len() % 8 != 0 {
        panic!("input vector length has to be multiple of 8");
    }
    let mut vec_u64: Vec<u64> = Vec::new();
    for i in 0..vec_u8.len() / 8 {
        vec_u64.push(bytes_to_u64(&vec_u8, i * 8));
    }
    vec_u64
}

/// Convert 8 bytes of a `&[u8]` to a little-endian `u64` value.
pub fn bytes_to_u64(bytes: &[u8], offset: usize) -> u64 {
    ( bytes[offset    ] as u64 & 0xFF)        |
    ((bytes[offset + 1] as u64 & 0xFF) <<  8) |
    ((bytes[offset + 2] as u64 & 0xFF) << 16) |
    ((bytes[offset + 3] as u64 & 0xFF) << 24) |
    ((bytes[offset + 4] as u64 & 0xFF) << 32) |
    ((bytes[offset + 5] as u64 & 0xFF) << 40) |
    ((bytes[offset + 6] as u64 & 0xFF) << 48) |
    ((bytes[offset + 7] as u64 & 0xFF) << 56)
}

/// Convert 8 bytes of a `&[u8]` to a big-endian `u64` value.
pub fn bytes_to_u64_be(bytes: &[u8], offset: usize) -> u64 {
    ((bytes[offset    ] as u64 & 0xFF) << 56) |
    ((bytes[offset + 1] as u64 & 0xFF) << 48) |
    ((bytes[offset + 2] as u64 & 0xFF) << 40) |
    ((bytes[offset + 3] as u64 & 0xFF) << 32) |
    ((bytes[offset + 4] as u64 & 0xFF) << 24) |
    ((bytes[offset + 5] as u64 & 0xFF) << 16) |
    ((bytes[offset + 6] as u64 & 0xFF) <<  8) |
    ( bytes[offset + 7] as u64 & 0xFF)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic]
    fn vec_u8_to_vec_u64_panic_test() {
        let input = vec![0u8; 2];
        let _out = vec_u8_to_vec_u64(&input);
    }
}
