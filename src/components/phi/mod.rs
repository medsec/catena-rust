//! Implementations for Phi

use bytes::ByteState;

pub mod lsb;

fn phi_layer <T: ::catena::Algorithms>(
    algorithms: &mut T,
    g: u8,
    mut v: Vec<u8>,
    mu: &Vec<u8>,
    k: usize,
    pi: &Fn(&Vec<u8>, u8) -> usize
) -> Vec<u8> {
    let mut j = pi(mu, g);
    let v_g = v.get_word(k, (1 << g) - 1);
    let v_j = v.get_word(k, j);
    let input = [&v_g[..], &v_j[..]].concat();
    v.set_word(k, 0, algorithms.h_prime(&input));
    for i in 1..(1 << g) {
        j = pi(&v.get_word(k, i - 1), g);
        let v_i = v.get_word(k, i - 1);
        let v_j = v.get_word(k, j);
        let input = [&v_i[..], &v_j[..]].concat();
        v.set_word(k, i, algorithms.h_prime(&input));
    }
    v
}
