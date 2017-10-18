//! An implementation of Catena-Horsefly-Full. This variant of Catena provides high throughput.

/// The choices for H, H', F, Γ and Φ for Catena-Horsefly-Full.
///
/// These choices are:
///
/// - H: Blake2b
/// - H': Blake2b
/// - F: BRH(23,2)
/// - Γ: SaltMix
/// - Φ: Identity function
#[derive(Clone, Copy, Debug)]
pub struct HorseflyFullAlgorithms;

impl ::catena::Algorithms for HorseflyFullAlgorithms {
    fn h (&self, x: &Vec<u8>) -> Vec<u8> {
        ::components::hash::blake2b::hash(x)
    }

    fn h_prime (&mut self, x: &Vec<u8>) -> Vec<u8> {
        ::components::hash::blake2b::hash(x)
    }

    #[allow(unused_variables)]
    fn gamma (&mut self, garlic:u8, state: Vec<u8>, gamma: &Vec<u8>, k: usize) -> Vec<u8> {
        state
        // ::components::gamma::saltmix::saltmix(self, garlic, state, gamma, k)
    }

    fn f (&mut self, garlic: &u8, state: &mut Vec<u8>, lambda: u8, n: usize, k: usize)
    -> Vec<u8> {
        ::components::graph::generic_graph::bit_reversal_hash(
            self, garlic, state, lambda, n, k)
    }

    #[allow(unused_variables)]
    fn phi (&mut self, garlic: u8, state: Vec<u8>, mu: &Vec<u8>, k: usize) -> Vec<u8> {
        state
    }
}

/// Constructor for a Catena-Horsefly-Full instance.
pub fn new() -> ::catena::Catena<HorseflyFullAlgorithms> {
    let hff_algorithms = HorseflyFullAlgorithms;
    ::catena::Catena {
        algorithms: hff_algorithms,
        vid: "Horsefly-Full",
        n: 64,
        k: 64,
        g_low: 23,
        g_high: 23,
        lambda: 1,
        }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::HexRepresentation;
    use helpers::files::JSONTests;

    fn catena_test_from_json<T: ::catena::Algorithms>(
        mut catena: ::catena::Catena<T>, file: &str)
    {
        let json = ::helpers::files::open_json(file.to_string());
        let unwrapped_json = json.as_ref().unwrap();
        let number_of_tests = unwrapped_json.clone().as_array().unwrap().len();

        for n in 0..number_of_tests {
            let ref inputs = unwrapped_json[n]["inputs"];

            let pwd = inputs.parse_hex("pwd");
            let salt = inputs.parse_hex("salt");
            let gamma = inputs.parse_hex("gamma");
            let ad = inputs.parse_hex("aData");
            let len = inputs.parse_u16("outputLength");

            let ref outputs = unwrapped_json[n]["outputs"];
            let expected = outputs.parse_string("res");

            assert_eq!(
                catena.hash(
                    &pwd,
                    &salt,
                    &ad,
                    len,
                    &gamma).to_hex_string(),
                expected);
        }
    }

    #[test]
    fn horseflyfull_reduced_test_from_json() {
        let mut test_catena = new();
        test_catena.g_low = 13;
        test_catena.g_high = 13;
        catena_test_from_json(test_catena, "test/test_vectors/catenaHorseflyFullReduced.json");
    }

    #[test]
    #[cfg(feature="fulltest")]
    fn horseflyfull_test_from_json() {
        let test_catena = new();
        catena_test_from_json(
            test_catena, "test/test_vectors/catenaHorseflyFull.json");
    }
}
