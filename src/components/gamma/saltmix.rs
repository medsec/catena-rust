//! The function SaltMix, one instantiation for Γ

use bytes::ByteState;

/// The function SaltMix, one instantiation for Γ
/// which uses xorshift1024star
pub fn saltmix <T: ::catena::Algorithms>(
        catena_instance: &mut T,
        garlic: u8,
        mut state: Vec<u8>,
        salt: &Vec<u8>,
        k: usize) -> Vec<u8> {

    // H(s)
    let hash_1: Vec<u8> = catena_instance.h(&salt);
    // H(H(s))
    let hash_2: Vec<u8> = catena_instance.h(&hash_1);

    // H(s) || H(H(s)) as 64-bit-word state
    let mut r: Vec<u64> = Vec::new();
    r.append(&mut ::helpers::conversions::vec_u8_to_vec_u64(&hash_1));
    r.append(&mut ::helpers::conversions::vec_u8_to_vec_u64(&hash_2));

    let mut p = 0;

    let mut j_1: usize;
    let mut j_2: usize;

    for _ in 0..(1 << (garlic as f64 * 3f64 / 4f64).ceil() as u32) {

        j_1 = xorshift_1024_star(&mut r, &mut p, garlic) as usize;
        j_2 = xorshift_1024_star(&mut r, &mut p, garlic) as usize;

        let new_value = &catena_instance.h_prime(
            &[&state.get_word(k, j_1)[..],
            &state.get_word(k, j_2)[..]].concat());

        for i in 0..k {
            state[j_1 * k + i] = new_value[i];
        }
    }
    state
}

fn xorshift_1024_star(
    r: &mut Vec<u64>,
    p: &mut u8,
    garlic: u8) -> u64 {
    let mut s: Vec<u64> = Vec::new();
    s.push(r[*p as usize]);
    *p = (*p + 1) % 16;
    s.push(r[*p as usize]);
    s[1] = s[1] ^ (s[1] << 31);
    s[1] = s[1] ^ (s[1] >> 11);
    s[0] = s[0] ^ (s[0] >> 30);
    r[*p as usize] = s[0] ^ s[1];
    let idx = r[*p as usize].wrapping_mul(1181783497276652981);
    let a = idx >> (64 - garlic);
    a
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use bytes::HexRepresentation;

    #[test]
    fn xorshift_1024_star_test_1() {
        let mut vec: Vec<u64> = vec!(
            0x0123456789abcdef,
            0x0123456789abcdf0,
            0x0123456789abcdf1,
            0x0123456789abcdf2,
            0x0123456789abcdf3,
            0x0123456789abcdf4,
            0x0123456789abcdf5,
            0x0123456789abcdf6,
            0x0123456789abcdf7,
            0x0123456789abcdf8,
            0x0123456789abcdf9,
            0x0123456789abcdfa,
            0x0123456789abcdfb,
            0x0123456789abcdfc,
            0x0123456789abcdfd,
            0x0123456789abcdfe);
        let mut p = 1;
        let g = 64;
        let result = xorshift_1024_star(&mut vec, &mut p, g);
        let expected_idx = 0x17D3885BABA0909E;
        let expected_s: Vec<u64> = vec!(
            0x0123456789abcdef,
            0x0123456789abcdf0,
            0xC4CD582CF76C20E6,
            0x0123456789abcdf2,
            0x0123456789abcdf3,
            0x0123456789abcdf4,
            0x0123456789abcdf5,
            0x0123456789abcdf6,
            0x0123456789abcdf7,
            0x0123456789abcdf8,
            0x0123456789abcdf9,
            0x0123456789abcdfa,
            0x0123456789abcdfb,
            0x0123456789abcdfc,
            0x0123456789abcdfd,
            0x0123456789abcdfe);
        assert_eq!(result, expected_idx);
        assert_eq!(vec, expected_s);
    }

    #[test]
    fn xorshift_1024_star_test_2() {
        let mut vec = vec!(
            0x0123456789abcdef,
            0x0123456789abcdf0,
            0x0123456789abcdf1,
            0x0123456789abcdf2,
            0x0123456789abcdf3,
            0x0123456789abcdf4,
            0x0123456789abcdf5,
            0x0123456789abcdf6,
            0x0123456789abcdf7,
            0x0123456789abcdf8,
            0x0123456789abcdf9,
            0x0123456789abcdfa,
            0x0123456789abcdfb,
            0x0123456789abcdfc,
            0x0123456789abcdfd,
            0x0123456789abcdfe);
        let mut p = 2;
        let g = 64;
        let result = xorshift_1024_star(&mut vec, &mut p, g);
        let expected_idx = 0x840D2A0DA7209534;
        let expected_s: Vec<u64> = vec!(
            0x0123456789abcdef,
            0x0123456789abcdf0,
            0x0123456789abcdf1,
            0xC4CD582D775C20E4,
            0x0123456789abcdf3,
            0x0123456789abcdf4,
            0x0123456789abcdf5,
            0x0123456789abcdf6,
            0x0123456789abcdf7,
            0x0123456789abcdf8,
            0x0123456789abcdf9,
            0x0123456789abcdfa,
            0x0123456789abcdfb,
            0x0123456789abcdfc,
            0x0123456789abcdfd,
            0x0123456789abcdfe);
        assert_eq!(result, expected_idx);
        assert_eq!(vec, expected_s);
    }

    #[test]
    fn xorshift_1024_star_test_3() {
        let mut vec = vec!(
            0x0123456789abcdef,
            0x0123456789abcdf0,
            0x0123456789abcdf1,
            0x0123456789abcdf2,
            0x0123456789abcdf3,
            0x0123456789abcdf4,
            0x0123456789abcdf5,
            0x0123456789abcdf6,
            0x0123456789abcdf7,
            0x0123456789abcdf8,
            0x0123456789abcdf9,
            0x0123456789abcdfa,
            0x0123456789abcdfb,
            0x0123456789abcdfc,
            0x0123456789abcdfd,
            0x0123456789abcdfe);
        let mut p = 15;
        let g = 64;
        let result = xorshift_1024_star(&mut vec, &mut p, g);
        let expected_idx = 0x8B1A3545F6C06BEE;
        let expected_s: Vec<u64> = vec!(
            0xC4CD5823F68C20F6,
            0x0123456789abcdf0,
            0x0123456789abcdf1,
            0x0123456789abcdf2,
            0x0123456789abcdf3,
            0x0123456789abcdf4,
            0x0123456789abcdf5,
            0x0123456789abcdf6,
            0x0123456789abcdf7,
            0x0123456789abcdf8,
            0x0123456789abcdf9,
            0x0123456789abcdfa,
            0x0123456789abcdfb,
            0x0123456789abcdfc,
            0x0123456789abcdfd,
            0x0123456789abcdfe);
        assert_eq!(result, expected_idx);
        assert_eq!(vec, expected_s);
    }

    fn test_saltmix_from_json<T: ::catena::Algorithms>(
        mut catena: ::catena::Catena<T>, file: &str)
    {
        let json = ::helpers::files::open_json(file.to_string());
        let unwrapped_json = json.as_ref().unwrap();
        let number_of_tests = unwrapped_json.clone().as_array().unwrap().len();

        let k: usize;
        {
            k = catena.k;
        }

        for i in 0..number_of_tests {
            let ref inputs = unwrapped_json[i]["inputs"];
            let hash_string = inputs["hash"].to_string();
            let hash_string_trimmed = hash_string.trim_matches('\"');
            let hash = hash_string_trimmed.to_string().to_be_bytes();
            let garlic = inputs["garlic"].as_u64().unwrap();
            let salt_string = inputs["salt"].to_string();
            let salt_string_trimmed = salt_string.trim_matches('\"');
            let salt = salt_string_trimmed.to_string().to_be_bytes();

            let ref outputs = unwrapped_json[i]["outputs"]["output_hash"];
            let expected_string = outputs.to_string();
            let expected = expected_string.trim_matches('\"');

            let result = saltmix(
                &mut catena.algorithms,
                garlic as u8,
                hash,
                &salt,
                k).to_hex_string();
            assert_eq!(result, expected);
        }
    }

    #[test]
    fn test_saltmix_dragonflyfull_from_json() {
        let test_catena = ::default_instances:: dragonfly_full::new();
        test_saltmix_from_json(test_catena, "test/test_vectors/saltmixAnyFull.json");
    }
}
