//! Implementations for F

pub mod generic_graph;
pub mod double_butterfly_graph;

fn h_first <T: ::catena::Algorithms>(
        catena_instance: &T,
        v_alpha: Vec<u8>,
        v_beta: Vec<u8>,
        n: usize,
        k: usize) -> Vec<u8> {

    let v = &[&v_alpha[..], &v_beta[..]].concat();
    let w_0 = catena_instance.h(&v);
    let l = k/n;

    let mut r: Vec<u8> = Vec::new();

    r.append(&mut w_0.clone());

    for i in 1..l {
        let mut i_w = vec!(i as u8);
        i_w.append(&mut w_0.clone());
        let mut w_i = catena_instance.h(&i_w);
        r.append(&mut w_i);
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    fn h_first_test(hash_1: Vec<u8>, hash_2: Vec<u8>) -> Vec<u8> {
        let mut test_catena = ::default_instances:: dragonfly::new();
        let hfirst = h_first(&mut test_catena.algorithms, hash_1, hash_2,
                                    test_catena.n, test_catena.k);
        hfirst
    }

    #[test]
    fn h_first_test_1() {
        let path: String = String::from("test/test_vectors/hFirstAny.json");
        let json = ::helpers::files::open_json(path);
        let json_v1_tmp = json.as_ref().unwrap()[0]["inputs"]["v"][0].to_string();
        let json_v1 = json_v1_tmp.trim_matches('\"');
        let hash_1: Vec<u8> = json_v1.to_string().to_be_bytes();
        let json_v2_tmp = json.as_ref().unwrap()[0]["inputs"]["v"][1].to_string();
        let json_v2 = json_v2_tmp.trim_matches('\"');
        let hash_2: Vec<u8> = json_v2.to_string().to_be_bytes();
        let h_first: Vec<u8> = h_first_test(hash_1,hash_2);
        let json_w_tmp = json.as_ref().unwrap()[0]["outputs"]["w"].to_string();
        let json_w = json_w_tmp.trim_matches('\"');
        let hash_w: Vec<u8> = json_w.to_string().to_be_bytes();

        assert_eq!(hash_w,h_first);
    }

    #[test]
    fn h_first_test_2() {
        let path: String = String::from("test/test_vectors/hFirstAny.json");
        let json = ::helpers::files::open_json(path);
        let json_v1_tmp = json.as_ref().unwrap()[1]["inputs"]["v"][0].to_string();
        let json_v1 = json_v1_tmp.trim_matches('\"');
        let hash_1: Vec<u8> = json_v1.to_string().to_be_bytes();
        let json_v2_tmp = json.as_ref().unwrap()[1]["inputs"]["v"][1].to_string();
        let json_v2 = json_v2_tmp.trim_matches('\"');
        let hash_2: Vec<u8> = json_v2.to_string().to_be_bytes();
        let h_first: Vec<u8> = h_first_test(hash_1,hash_2);
        let json_w_tmp = json.as_ref().unwrap()[1]["outputs"]["w"].to_string();
        let json_w = json_w_tmp.trim_matches('\"');
        let hash_w: Vec<u8> = json_w.to_string().to_be_bytes();

        assert_eq!(hash_w,h_first);
    }
}
