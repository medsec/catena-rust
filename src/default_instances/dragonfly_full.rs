//! An implementation of Catena-Dragonfly-Full which is suitable as a
//! key-derivation function. This variant of Catena provides memory hardness.
//! It should be used in a setting, where the defender can afford to allocate
//! much memory without any problems.

/// The choices for H, H', F, Γ and Φ for Catena-Dragonfly-Full.
///
/// These choices are:
///
/// - H: Blake2b
/// - H': Blake2b
/// - F: BRH(22,2)
/// - Γ: SaltMix
/// - Φ: Identity function
#[derive(Clone, Copy, Debug)]
pub struct DragonflyFullAlgorithms;

impl ::catena::Algorithms for DragonflyFullAlgorithms {
    fn h (&self, x: &Vec<u8>) -> Vec<u8> {
        ::components::hash::blake2b::hash(x)
    }

    fn h_prime (&mut self, x: &Vec<u8>) -> Vec<u8> {
        ::components::hash::blake2b::hash(x)
    }

    fn gamma (&mut self, garlic: u8, state: Vec<u8>, gamma: &Vec<u8>, k: usize) -> Vec<u8> {
        ::components::gamma::saltmix::saltmix(self, garlic, state, gamma, k)
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

/// Constructor for a Catena-Dragonfly-Full instance.
pub fn new() -> ::catena::Catena<DragonflyFullAlgorithms> {
    let dff_algorithms = DragonflyFullAlgorithms;
    ::catena::Catena {
        algorithms: dff_algorithms,
        vid: "Dragonfly-Full",
        n: 64,
        k: 64,
        g_low: 22,
        g_high: 22,
        lambda: 2,
        }
}

#[cfg(test)]
mod tests{
}
