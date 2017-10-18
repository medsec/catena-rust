/// Concatenate p 0-bytes to a Vec<u8> x.
pub fn zero_padding(x: Vec<u8>, p: usize) -> Vec<u8> {
    let padding = vec![0;p];
    [&x[..],&padding[..]].concat()
}

/// Concatenate p 0-bytes before a Vec<u8> x.
fn zero_padding_front(x: Vec<u8>, p: usize) -> Vec<u8> {
    let padding = vec![0;p];
    [&padding[..], &x[..]].concat()
}

/// Elementwise XOR of two Vec<u8>. If they differ in length, the shorter one is
/// padded with zeros at the front.
pub fn xor(lhs: Vec<u8>, rhs: Vec<u8>) -> Vec<u8> {
    let mut lhs_copy = lhs;
    let mut rhs_copy = rhs;
    let mut xor: Vec<u8> = Vec::new();

    // add padding if neccessary
    let length_difference = lhs_copy.len() as isize - rhs_copy.len() as isize;
    if length_difference < 0 {
        lhs_copy = zero_padding_front(lhs_copy, -length_difference as usize);
    } else if length_difference > 0 {
        rhs_copy = zero_padding_front(rhs_copy, length_difference as usize);
    }

    // elementwise xor
    for i in 0..lhs_copy.len() {
        xor.push(lhs_copy[i] ^ rhs_copy[i]);
    }

    xor
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_padding_test() {
        let x = vec![1u8];
        let padded = zero_padding(x, 2);
        let expected = vec![1u8, 0u8, 0u8];

        assert_eq!(padded, expected);
    }

    #[test]
    fn xor_test_1() {
        let lhs = vec![0u8];
        let rhs = vec![0u8];

        let expected = vec![0u8];

        assert_eq!(xor(lhs,rhs),expected);
    }

    #[test]
    fn xor_test_2() {
        let lhs: Vec<u8> = Vec::new();
        let rhs: Vec<u8> = Vec::new();

        let expected: Vec<u8> = Vec::new();

        assert_eq!(xor(lhs,rhs),expected);
    }

    #[test]
    fn xor_test_3() {
        let lhs = vec![0u8, 0u8];
        let rhs = vec![0u8];

        let expected = vec![0u8, 0u8];

        assert_eq!(xor(lhs,rhs),expected);
    }

    #[test]
    fn xor_test_4() {
        let lhs = vec![0u8];
        let rhs = vec![0u8, 1u8];

        let expected = vec![0u8, 1u8];

        assert_eq!(xor(lhs,rhs),expected);
    }

    #[test]
    fn xor_test_5() {
        let lhs = vec![0u8, 2u8];
        let rhs = vec![0u8, 1u8];

        let expected = vec![0u8, 3u8];

        assert_eq!(xor(lhs,rhs),expected);
    }

    #[test]
    fn xor_test_6() {
        let lhs = vec![4u8];
        let rhs = vec![0u8, 1u8];

        let expected = vec![0u8, 5u8];

        assert_eq!(xor(lhs,rhs),expected);
    }
}
