//! An implementation of Catena-Butterfly. This variant of Catena provides
//! λ-memory hardness. It should be used in a setting, where the defender has
//! limited memory available.

/// The choices for H, H', F, Γ and Φ for Catena-Butterfly.
///
/// These choices are:
///
/// - H: Blake2b
/// - H': Blake2b-1
/// - F: DBH(16,4)
/// - Γ: SaltMix
/// - Φ: Identity function
#[derive(Clone, Copy, Debug)]
pub struct ButterflyAlgorithms {
    blake2b_1: ::components::fasthash::blake2b1::Blake2b1,
}

impl ::catena::Algorithms for ButterflyAlgorithms {
    fn h (&self, x: &Vec<u8>) -> Vec<u8> {
        ::components::hash::blake2b::hash(x)
    }

    fn h_prime (&mut self, x: &Vec<u8>) -> Vec<u8> {
        self.blake2b_1.hash(x)
    }

    fn reset_h_prime(&mut self) {
        self.blake2b_1.reset();
    }

    fn gamma (&mut self, garlic: u8, state: Vec<u8>, gamma: &Vec<u8>, k: usize) -> Vec<u8> {
        ::components::gamma::saltmix::saltmix(self, garlic, state, gamma, k)
    }

    fn f (&mut self, garlic: &u8, state: &mut Vec<u8>, lambda: u8, n: usize, k: usize)
    -> Vec<u8> {
        ::components::graph::double_butterfly_graph::double_butterfly_hash(
            self, garlic, state.clone(), lambda, n, k)
    }

    #[allow(unused_variables)]
    fn phi (&mut self, garlic: u8, state: Vec<u8>, mu: &Vec<u8>, k: usize) -> Vec<u8> {
        state
    }
}

/// Constructor for a Catena-Butterfly instance.
pub fn new() -> ::catena::Catena<ButterflyAlgorithms> {
    let bf_algorithms = ButterflyAlgorithms {
        blake2b_1: Default::default(),
    };
    ::catena::Catena {
        algorithms: bf_algorithms,
        vid: "Butterfly",
        n: 64,
        k: 64,
        g_low: 16,
        g_high: 16,
        lambda: 4,
        }
}
