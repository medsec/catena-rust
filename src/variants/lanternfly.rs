//! An implementation of Catena-Lanternfly. This variant of Catena is a hybrid approach that aims
//! for best performance while remaining suitable security against ASIC-based adversaries, tradeoff
//! attacks and resistance to CTAs.

/// The choices for H, H', F, Γ and Φ for Catena-Lanternfly.
///
/// These choices are:
///
/// - H: Blake2b
/// - H': Argon2 compression function with G = G_B
/// - F: GRH3(17,2)
/// - Γ: SaltMix
/// - Φ: Standard phi-layer with lsb index function
#[derive(Clone, Copy, Debug)]
pub struct LanternflyAlgorithms;

impl ::catena::Algorithms for LanternflyAlgorithms {
    fn h (&self, x: &Vec<u8>) -> Vec<u8> {
        ::components::hash::blake2b::hash(x)
    }

    fn h_prime (&mut self, x: &Vec<u8>) -> Vec<u8> {
        ::components::fasthash::cf_argon2::cf_argon2_gb(x)
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

/// Constructor for a Catena-Lanternfly instance.
pub fn new() -> ::catena::Catena<LanternflyAlgorithms> {
    let lf_algorithms = LanternflyAlgorithms;
    ::catena::Catena {
        algorithms: lf_algorithms,
        vid: "Lanternfly",
        n: 64,
        k: 1024,
        g_low: 17,
        g_high: 17,
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
    fn lanternfly_reduced_test_from_json() {
        let mut test_catena = new();
        test_catena.g_low = 9;
        test_catena.g_high = 9;
        catena_test_from_json(test_catena, "test/test_vectors/catenaLanternflyReduced.json");
    }

    #[test]
    #[cfg(feature="fulltest")]
    fn lanternfly_test_from_json() {
        let test_catena = new();
        catena_test_from_json(
            test_catena, "test/test_vectors/catenaLanternfly.json");
    }
}
