//! Generic graph-based hashing

use bytes::ByteState;

/// Hash with (g, λ)-Bit-Reversal Graph
pub fn bit_reversal_hash <T: ::catena::Algorithms>(
        algorithms: &mut T,
        garlic: &u8,
        state: &mut Vec<u8>,
        lambda: u8,
        n: usize,
        k: usize
    ) -> Vec<u8> {

    generic_graph_based_hash(
        algorithms,
        garlic,
        state,
        lambda,
        n,
        k,
        &brg_index)
}

/// Hash with Shifted (g, λ)-Bit-Reversal Graph
pub fn shifted_bit_reversal_hash <T: ::catena::Algorithms>(
        algorithms: &mut T,
        garlic: &u8,
        state: &mut Vec<u8>,
        lambda: u8,
        n: usize,
        k: usize,
        c: u8) -> Vec<u8> {

    let index = |g, i| {
        sbrg_index(g, i, c)
    };

    generic_graph_based_hash(
        algorithms,
        garlic,
        state,
        lambda,
        n,
        k,
        &index)
}

/// Hash with (g, λ, l)-Gray-Reversal Graph
pub fn gray_bit_reversal_hash <T: ::catena::Algorithms>(
        algorithms: &mut T,
        garlic: &u8,
        state: &mut Vec<u8>,
        lambda: u8,
        n: usize,
        k: usize,
        l: u8) -> Vec<u8> {

    let index = |g, i| {
        grg_index(g, i, l)
    };

    generic_graph_based_hash(
        algorithms,
        garlic,
        state,
        lambda,
        n,
        k,
        &index)
}

fn generic_graph_based_hash <T: ::catena::Algorithms>(
        algorithms: &mut T,
        garlic: &u8,
        v: &mut Vec<u8>,
        lambda: u8,
        n: usize,
        k: usize,
        index_function: &Fn(u64, u8) -> u64) -> Vec<u8> {

    let dim: usize = (1 << garlic) as usize;

    let mut r: Vec<u8>;

    for _ in 0..lambda {

        let index = index_function(0, *garlic) as usize;
        r = ::components::graph::h_first(
            algorithms,
            v.get_word(k, dim - 1),
            v.get_word(k, index),
            n, k);

        for i in 1..dim {
            let index = index_function(i as u64, *garlic) as usize;
            let r_i = r.get_word(k, i - 1);
            let v_index = v.get_word(k, index);
            let mut hashed = algorithms.h_prime(&[&r_i[..], &v_index[..]].concat());

            r.append(&mut hashed);
        }
        *v = r;
    }
    (*v).to_vec()
}

fn brg_index(index: u64, g: u8) -> u64 {
     if g == 0  {
         0
     } else {
         let mut x: u64 = index;
          x = reverse_byte_order(x);
          x = ((x & 0x0f0f0f0f0f0f0f0fu64) << 4) |
              ((x & 0xf0f0f0f0f0f0f0f0u64) >> 4);
          x = ((x & 0x3333333333333333u64) << 2) |
              ((x & 0xccccccccccccccccu64) >> 2);
          x = ((x & 0x5555555555555555u64) << 1) |
              ((x & 0xaaaaaaaaaaaaaaaau64) >> 1);
          x = x >> (64 - g);
          x
     }
}

fn reverse_byte_order(index: u64) -> u64 {
        ((index & 0x00000000000000FFu64) << 56) |
        ((index & 0x000000000000FF00u64) << 40) |
        ((index & 0x0000000000FF0000u64) << 24) |
        ((index & 0x00000000FF000000u64) <<  8) |
        ((index & 0x000000FF00000000u64) >>  8) |
        ((index & 0x0000FF0000000000u64) >> 24) |
        ((index & 0x00FF000000000000u64) >> 40) |
        ((index & 0xFF00000000000000u64) >> 56)
}

fn sbrg_index(i: u64, g: u8, c: u8) -> u64 {
    (brg_index(i, g) + c as u64) % (1 << g) as u64
}

fn grg_index(index: u64, g: u8, l: u8) -> u64 {
    brg_index(index, g) ^ (brg_index(!index, g) >> (g as f64 / l as f64).ceil()as u64)
}




#[cfg(test)]
mod tests {
    use super::*;
    use bytes::HexRepresentation;
    use bytes::Bytes;

    #[test]
    fn reverse_byte_order_test() {
        let test_bytes: u64 = 0x1000000000000000;
        let test_byte2: u64 = 0xff00000000000000;
        assert_eq!( 0x10, reverse_byte_order(test_bytes));
        assert_eq!( 0xff, reverse_byte_order(test_byte2));
    }

    #[test]
    fn brg_index_test_from_json() {
        let json = ::helpers::files::open_json("test/test_vectors/brgIndex.json".to_string());
        let unwrapped_json = json.as_ref().unwrap();
        let number_of_tests = unwrapped_json.clone().as_array().unwrap().len();

        for i in 0..number_of_tests {
            let ref inputs = unwrapped_json[i]["inputs"];
            let index = inputs["index"].as_u64().unwrap();
            let g = inputs["g"].as_u64().unwrap() as u8;

            let ref outputs = unwrapped_json[i]["outputs"]["res"];
            let expected = outputs.as_u64().unwrap();

            assert_eq!(brg_index(index, g), expected);
        }
    }

    #[test]
    fn sbrg_index_test_from_json() {
        let json = ::helpers::files::open_json("test/test_vectors/sbrgIndex.json".to_string());
        let unwrapped_json = json.as_ref().unwrap();
        let number_of_tests = unwrapped_json.clone().as_array().unwrap().len();

        for i in 0..number_of_tests {
            let ref inputs = unwrapped_json[i]["inputs"];
            let index = inputs["index"].as_u64().unwrap();
            let g = inputs["g"].as_u64().unwrap() as u8;
            let c = inputs["c"].as_u64().unwrap() as u8;

            let ref outputs = unwrapped_json[i]["outputs"]["res"];
            let expected = outputs.as_u64().unwrap();

            assert_eq!(sbrg_index(index, g, c), expected);
        }
    }

    #[test]
    fn grg_index_test_from_json() {
        let json = ::helpers::files::open_json("test/test_vectors/grgIndex.json".to_string());
        let unwrapped_json = json.as_ref().unwrap();
        let number_of_tests = unwrapped_json.clone().as_array().unwrap().len();

        for i in 0..number_of_tests {
            let ref inputs = unwrapped_json[i]["inputs"];
            let index = inputs["index"].as_u64().unwrap();
            let g = inputs["g"].as_u64().unwrap() as u8;
            let l = inputs["l"].as_u64().unwrap() as u8;

            let ref outputs = unwrapped_json[i]["outputs"]["res"];
            let expected = outputs.as_u64().unwrap();

            assert_eq!(grg_index(index, g, l), expected);
        }
    }

    fn brg_test_from_json<T: ::catena::Algorithms>(mut catena: ::catena::Catena<T>, file: &str) {
        let json = ::helpers::files::open_json(file.to_string());
        let unwrapped_json = json.as_ref().unwrap();
        let number_of_tests = unwrapped_json.clone().as_array().unwrap().len();

        for i in 0..number_of_tests {
            catena.algorithms.reset_h_prime();
            let ref inputs = unwrapped_json[i]["inputs"];
            let state_string = inputs["state"].to_string();
            let state_string_trimmed = state_string.trim_matches('\"');
            let mut state = state_string_trimmed.to_string().to_be_bytes();
            let garlic = inputs["garlic"].as_u64().unwrap() as u8;
            let lambda = inputs["lambda"].as_u64().unwrap() as u8;

            let ref outputs = unwrapped_json[i]["outputs"]["res"];
            let expected_string = outputs.to_string();
            let expected = expected_string.trim_matches('\"');

            let n: usize;
            let k: usize;
            {
                n = catena.n;
                k = catena.k;
            }

            let result = bit_reversal_hash(
                &mut catena.algorithms,
                &garlic,
                &mut state,
                lambda,
                n,
                k);

            assert_eq!(result.to_hex_string(), expected, "test #{:?} failed", i);
        }
    }

    #[test]
    fn brg_test_dragonfly_from_json() {
        let catena = ::default_instances::dragonfly::new();
        brg_test_from_json(catena, "test/test_vectors/brgAny.json");
    }

    #[test]
    fn brg_test_dragonflyfull_from_json() {
        let catena = ::default_instances::dragonfly_full::new();
        brg_test_from_json(catena, "test/test_vectors/brgAnyFull.json");
    }

    fn sbrg_test_from_json<T: ::catena::Algorithms>(mut catena: ::catena::Catena<T>, file: &str) {
        let json = ::helpers::files::open_json(file.to_string());
        let unwrapped_json = json.as_ref().unwrap();
        let number_of_tests = unwrapped_json.clone().as_array().unwrap().len();

        for i in 0..number_of_tests {
            catena.algorithms.reset_h_prime();
            let ref inputs = unwrapped_json[i]["inputs"];
            let state_string = inputs["state"].to_string();
            let state_string_trimmed = state_string.trim_matches('\"');
            let mut state = state_string_trimmed.to_string().to_be_bytes();
            let garlic = inputs["garlic"].as_u64().unwrap() as u8;
            let lambda = inputs["lambda"].as_u64().unwrap() as u8;
            let c = inputs["c"].as_u64().unwrap() as u8;

            let ref outputs = unwrapped_json[i]["outputs"]["res"];
            let expected_string = outputs.to_string();
            let expected = expected_string.trim_matches('\"');

            let n: usize;
            let k: usize;
            {
                n = catena.n;
                k = catena.k;
            }

            let result = shifted_bit_reversal_hash(
                &mut catena.algorithms,
                &garlic,
                &mut state,
                lambda,
                n,
                k,
                c);

            assert_eq!(result.to_hex_string(), expected, "test #{:?} failed", i);
        }
    }

    #[test]
    fn sbrg_test_dragonfly_from_json() {
        let catena = ::default_instances::dragonfly::new();
        sbrg_test_from_json(catena, "test/test_vectors/sbrgAny.json");
    }

    #[test]
    fn sbrg_test_dragonflyfull_from_json() {
        let catena = ::default_instances::dragonfly_full::new();
        sbrg_test_from_json(catena, "test/test_vectors/sbrgAnyFull.json");
    }

    fn grg_test_from_json<T: ::catena::Algorithms>(mut catena: ::catena::Catena<T>, file: &str) {
        let json = ::helpers::files::open_json(file.to_string());
        let unwrapped_json = json.as_ref().unwrap();
        let number_of_tests = unwrapped_json.clone().as_array().unwrap().len();

        for i in 0..number_of_tests {
            catena.algorithms.reset_h_prime();
            let ref inputs = unwrapped_json[i]["inputs"];
            let state_string = inputs["state"].to_string();
            let state_string_trimmed = state_string.trim_matches('\"');
            let mut state = state_string_trimmed.to_string().to_be_bytes();
            let garlic = inputs["garlic"].as_u64().unwrap() as u8;
            let lambda = inputs["lambda"].as_u64().unwrap() as u8;
            let l = inputs["l"].as_u64().unwrap() as u8;

            let ref outputs = unwrapped_json[i]["outputs"]["res"];
            let expected_string = outputs.to_string();
            let expected = expected_string.trim_matches('\"');

            let n: usize;
            let k: usize;
            {
                n = catena.n;
                k = catena.k;
            }

            let result = gray_bit_reversal_hash(
                &mut catena.algorithms,
                &garlic,
                &mut state,
                lambda,
                n,
                k,
                l);

            assert_eq!(result.to_hex_string(), expected, "test #{:?} failed", i);
        }
    }

    #[test]
    fn grg_test_dragonfly_from_json() {
        let catena = ::default_instances::dragonfly::new();
        grg_test_from_json(catena, "test/test_vectors/grgAny.json");
    }

    #[test]
    fn grg_test_dragonflyfull_from_json() {
        let catena = ::default_instances::dragonfly_full::new();
        grg_test_from_json(catena, "test/test_vectors/grgAnyFull.json");
    }
}
