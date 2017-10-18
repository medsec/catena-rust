//! An implementation of Catena-Butterfly-Full which is suitable as a
//! key-derivation function. This variant of Catena provides λ-memory hardness.
//! It should be used in a setting, where the defender has limited memory
//! available.

/// The choices for H, H', F, Γ and Φ for Catena-Butterfly-Full.
///
/// These choices are:
///
/// - H: Blake2b
/// - H': Blake2b
/// - F: DBH(17,4)
/// - Γ: SaltMix
/// - Φ: Identity function
#[derive(Clone, Copy, Debug)]
pub struct ButterflyFullAlgorithms;

impl ::catena::Algorithms for ButterflyFullAlgorithms {
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
        ::components::graph::double_butterfly_graph::double_butterfly_hash(
            self, garlic, state.clone(), lambda, n, k)
    }

    #[allow(unused_variables)]
    fn phi (&mut self, garlic: u8, state: Vec<u8>, mu: &Vec<u8>, k: usize) -> Vec<u8> {
        state
    }
}

/// Constructor for a Catena-Butterfly-Full instance.
pub fn new() -> ::catena::Catena<ButterflyFullAlgorithms> {
    let bff_algorithms = ButterflyFullAlgorithms;
    ::catena::Catena {
        algorithms: bff_algorithms,
        vid: "Butterfly-Full",
        n: 64,
        k: 64,
        g_low: 17,
        g_high: 17,
        lambda: 4,
        }
}
