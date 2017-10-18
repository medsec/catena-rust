//! Double-Butterfly-Graph-based hashing

use bytes::ByteState;

/// Hash with Double Butterfly Graph
pub fn double_butterfly_hash<T: ::catena::Algorithms>(
        algorithms: &mut T,
        garlic: &u8,
        state: Vec<u8>,
        lambda: u8,
        n: usize,
        k: usize) -> Vec<u8> {

    let mut v: Vec<u8> = state;

    let j_limit = 2 * *garlic;
    let i_limit: u64 = (1 << garlic) as u64;

    for _ in 0..lambda {
        for j in 1..j_limit {
            let mut r: Vec<u8> = ::components::graph::h_first(
                algorithms,
                ::helpers::vectors::xor(
                    v.get_word(k, i_limit as usize - 1), v.get_word(k, 0)),
                v.get_word(k,
                           dbh_index(*garlic, j - 1, 0) as usize),
                           n,
                           k);
            for i in 1..i_limit {
                let ri_xor_vi = ::helpers::vectors::xor(
                    r.get_word(k, i as usize - 1),
                    v.get_word(k, i as usize));
                let v_p_index = v.get_word(k,
                    dbh_index(*garlic, j - 1, i) as usize);
                let ri_xor_vi_concat = [&ri_xor_vi[..],
                    &v_p_index[..]].concat();

                let ri = &mut algorithms.h_prime(&ri_xor_vi_concat);
                r.append(ri);
            }
            v = r;

        }

    }
    v
}

fn dbh_index(g: u8, j: u8, i: u64) -> u64 {
    if j <= g - 1 {
        i ^ (1 << (g - 1 - j))
    }
    else {
        i ^ (1 << (j - (g - 1)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::HexRepresentation;
    use bytes::Bytes;

    #[test]
    fn test_dbh_index_from_json() {
        let json = ::helpers::files::open_json("test/test_vectors/dbhIndex.json".to_string());
        let unwrapped_json = json.as_ref().unwrap();
        let number_of_tests = unwrapped_json.clone().as_array().unwrap().len();

        for n in 0..number_of_tests {
            let ref inputs = unwrapped_json[n]["inputs"];
            let g = inputs["g"].as_u64().unwrap() as u8;
            let j = inputs["j"].as_u64().unwrap() as u8;
            let i = inputs["i"].as_u64().unwrap();

            let ref outputs = unwrapped_json[n]["outputs"];
            let expected = outputs["res"].as_u64().unwrap();

            assert_eq!(dbh_index(g, j, i),
                       expected);
        }
    }

    fn dbh_test_from_json<T: ::catena::Algorithms>(mut catena: ::catena::Catena<T>, file: &str) {
        let json = ::helpers::files::open_json(file.to_string());
        let unwrapped_json = json.as_ref().unwrap();
        let number_of_tests = unwrapped_json.clone().as_array().unwrap().len();

        for i in 0..number_of_tests {
            catena.algorithms.reset_h_prime();
            let ref inputs = unwrapped_json[i]["inputs"];
            let state_string = inputs["state"].to_string();
            let state_string_trimmed = state_string.trim_matches('\"');
            let state = state_string_trimmed.to_string().to_be_bytes();
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

            let result = double_butterfly_hash(
                &mut catena.algorithms,
                &garlic,
                state,
                lambda,
                n,
                k);

            assert_eq!(result.to_hex_string(), expected, "test #{:?} failed", i);
        }
    }

    #[test]
    fn dbh_test_butterfly_from_json() {
        let catena = ::default_instances::butterfly::new();
        dbh_test_from_json(catena, "test/test_vectors/dbhAny.json");
    }

    #[test]
    fn dbh_test_butterflyfull_from_json() {
        let catena = ::default_instances::butterfly_full::new();
        dbh_test_from_json(catena, "test/test_vectors/dbhAnyFull.json");
    }
}
