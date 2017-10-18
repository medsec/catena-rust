//! Phi layer with least significant bit index function.

/// Index function that returns the g last bits.
fn lsb(v: &Vec<u8>, g: u8) -> usize {
    let mask: u64 = 0xFFFFFFFFFFFFFFFF - ((1 << g) - 1);
    let last = ::helpers::conversions::bytes_to_u64_be(v, v.len() - 8);
    let result = last & !mask;
    result as usize
}

/// Phi layer with LSB index function.
pub fn phi_lsb <T: ::catena::Algorithms>(
    algorithms: &mut T,
    g: u8,
    v: Vec<u8>,
    mu: &Vec<u8>,
    k: usize
) -> Vec<u8> {
    ::components::phi::phi_layer(
        algorithms,
        g,
        v,
        mu,
        k,
        &lsb)
}

#[cfg(test)]
mod tests {
    use super::*;
    use helpers::files::JSONTests;

    #[test]
    fn lsb_index_test() {
        let json = ::helpers::files::open_json("test/test_vectors/lsbIndex.json".to_string());
        let unwrapped_json = json.as_ref().unwrap();
        let number_of_tests = unwrapped_json.clone().as_array().unwrap().len();

        for i in 0..number_of_tests {
            let ref inputs = unwrapped_json[i]["inputs"];
            let state = inputs.parse_hex("state");
            let g = inputs.parse_u8("num_bits");

            let ref outputs = unwrapped_json[i]["outputs"];
            let expected = outputs.parse_usize("res");

            assert_eq!(lsb(&state, g), expected);
        }
    }
}
