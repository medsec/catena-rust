//! Wrapper for Blake2b
extern crate blake2_rfc;

/// The cryptographic hash function Blake2b which can be used as H. This is a
/// wrapper for `blake2_rfc::blake2b::blake2b()`
pub fn hash(x: &Vec<u8>) -> Vec<u8> {
    blake2_rfc::blake2b::blake2b(64, &[], x).as_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    #[test]
    fn blake2b_test_1() {
        let x: Vec<u8> = Vec::new();

        let expected: Vec<u8> = vec![0x78, 0x6a, 0x02, 0xf7, 0x42, 0x01, 0x59,
                                     0x03, 0xc6, 0xc6, 0xfd, 0x85, 0x25, 0x52,
                                     0xd2, 0x72, 0x91, 0x2f, 0x47, 0x40, 0xe1,
                                     0x58, 0x47, 0x61, 0x8a, 0x86, 0xe2, 0x17,
                                     0xf7, 0x1f, 0x54, 0x19, 0xd2, 0x5e, 0x10,
                                     0x31, 0xaf, 0xee, 0x58, 0x53, 0x13, 0x89,
                                     0x64, 0x44, 0x93, 0x4e, 0xb0, 0x4b, 0x90,
                                     0x3a, 0x68, 0x5b, 0x14, 0x48, 0xb7, 0x55,
                                     0xd5, 0x6f, 0x70, 0x1a, 0xfe, 0x9b, 0xe2,
                                     0xce];
        assert_eq!(hash(&x), expected);
    }

    #[test]
    fn blake2b_test_2() {
        let x = b"The quick brown fox jumps over the lazy dog".to_vec();

        let expected = "a8add4bdddfd93e4877d2746e62817b116364a1fa7bc148d95090bc\
                        7333b3673f82401cf7aa2e4cb1ecd90296e3f14cb5413f8ed77be73\
                        045b13914cdcd6a918".to_string().to_be_bytes();

        assert_eq!(hash(&x), expected);
    }
}
