//! An implementation of Catena-Lanternfly-Full. This variant of Catena is a hybrid approach that
//! aims for best performance while remaining suitable security against ASIC-based adversaries,
//! tradeoff attacks and resistance to CTAs.

/// The choices for H, H', F, Γ and Φ for Catena-Lanternfly-Full.
///
/// These choices are:
///
/// - H: Blake2b
/// - H': Blake2b
/// - F: GRH3(22,2)
/// - Γ: SaltMix
/// - Φ: Standard phi-layer with lsb index function
#[derive(Clone, Copy, Debug)]
pub struct LanternflyFull;

impl ::catena::Algorithms for LanternflyFull {
    fn h (&self, x: &Vec<u8>) -> Vec<u8> {
        ::components::hash::blake2b::hash(x)
    }

    fn h_prime (&mut self, x: &Vec<u8>) -> Vec<u8> {
        ::components::hash::blake2b::hash(x)
    }

    fn gamma (&mut self, garlic:u8, state: Vec<u8>, gamma: &Vec<u8>, k: usize) -> Vec<u8> {
        ::components::gamma::saltmix::saltmix(self, garlic, state, gamma, k)
    }

    fn f (&mut self, garlic: &u8, state: &mut Vec<u8>, lambda: u8, n: usize, k: usize)
    -> Vec<u8> {
        ::components::graph::generic_graph::gray_bit_reversal_hash(
            self, garlic, state, lambda, n, k, 3)
    }

    #[allow(unused_variables)]
    fn phi (&mut self, garlic: u8, state: Vec<u8>, mu: &Vec<u8>, k: usize) -> Vec<u8> {
        state
    }
}

/// Constructor for a Catena-Lanternfly-Full instance.
pub fn new() -> ::catena::Catena<LanternflyFull> {
    let lff_algorithms = LanternflyFull;
    ::catena::Catena {
        algorithms: lff_algorithms,
        vid: "Lanternfly-Full",
        n: 64,
        k: 64,
        g_low: 22,
        g_high: 22,
        lambda: 2,
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
    fn lanternflyfull_reduced_test_from_json() {
        let mut test_catena = new();
        test_catena.g_low = 9;
        test_catena.g_high = 9;
        catena_test_from_json(test_catena, "test/test_vectors/catenaLanternflyFullReduced.json");
    }

    #[test]
    #[cfg(feature="fulltest")]
    fn lanternflyfull_test_from_json() {
        let test_catena = new();
        catena_test_from_json(
            test_catena, "test/test_vectors/catenaLanternflyFull.json");
    }
}
