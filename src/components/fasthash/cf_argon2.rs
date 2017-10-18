//! Compression function of Argon2

use ::bytes::Bytes;
use ::bytes::ByteState;

/// Compression function of Argon2 with G = G_L
/// The input `x` has to be of length 2048.
pub fn cf_argon2_gl(
    x: &Vec<u8>
) -> Vec<u8> {
    cf_argon2_wrapper(x, &permute_gl)
}

/// Compression function of Argon2 with G = G_B
/// The input `x` has to be of length 2048.
pub fn cf_argon2_gb(
    x: &Vec<u8>
) -> Vec<u8> {
    // println!("X: {:?}", (&x[..10]).to_vec().to_hex_string());
    cf_argon2_wrapper(x, &permute_gb)
}

/// Wrapper for `cf_argon2` with one 2048 byte input instead of two 1024 byte inputs.
fn cf_argon2_wrapper(
    x: &Vec<u8>,
    p: &Fn(u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64)
        -> Vec<u8>
) -> Vec<u8> {
    let x_len = x.len();
    if x_len != 2048 {
        panic!("Input length has to be 2048 but is {:?}.", x_len);
    }
    let a = (&x[..x_len / 2]).to_vec();
    let b = (&x[x_len / 2..]).to_vec();
    cf_argon2(a, b, &p)
}

/// Compression function of Argon2 as defined in the specification
///
/// # Inputs
/// - x: 1024 byte block
/// - y: 1024 byte block
/// - p: round function
fn cf_argon2(
    x: Vec<u8>,
    y: Vec<u8>,
    p: &Fn(u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64)
        -> Vec<u8>
) -> Vec<u8> {
    let r = ::helpers::vectors::xor(x, y);

    let mut q: Vec<u8> = Vec::new();
    // update rows
    for i in 0..8 {
        let j = i * 16;
        q.append(&mut p(
                ::helpers::conversions::bytes_to_u64(&r.get_word(8, j), 0),
                ::helpers::conversions::bytes_to_u64(&r.get_word(8, j + 1), 0),
                ::helpers::conversions::bytes_to_u64(&r.get_word(8, j + 2), 0),
                ::helpers::conversions::bytes_to_u64(&r.get_word(8, j + 3), 0),
                ::helpers::conversions::bytes_to_u64(&r.get_word(8, j + 4), 0),
                ::helpers::conversions::bytes_to_u64(&r.get_word(8, j + 5), 0),
                ::helpers::conversions::bytes_to_u64(&r.get_word(8, j + 6), 0),
                ::helpers::conversions::bytes_to_u64(&r.get_word(8, j + 7), 0),
                ::helpers::conversions::bytes_to_u64(&r.get_word(8, j + 8), 0),
                ::helpers::conversions::bytes_to_u64(&r.get_word(8, j + 9), 0),
                ::helpers::conversions::bytes_to_u64(&r.get_word(8, j + 10), 0),
                ::helpers::conversions::bytes_to_u64(&r.get_word(8, j + 11), 0),
                ::helpers::conversions::bytes_to_u64(&r.get_word(8, j + 12), 0),
                ::helpers::conversions::bytes_to_u64(&r.get_word(8, j + 13), 0),
                ::helpers::conversions::bytes_to_u64(&r.get_word(8, j + 14), 0),
                ::helpers::conversions::bytes_to_u64(&r.get_word(8, j + 15), 0)));
    }
    // update columns
    for i in 0..8 {
        let j = i * 2;
        let update = p(
            ::helpers::conversions::bytes_to_u64_be(&q.get_word(8, j), 0),
            ::helpers::conversions::bytes_to_u64_be(&q.get_word(8, j + 1), 0),
            ::helpers::conversions::bytes_to_u64_be(&q.get_word(8, j + 16), 0),
            ::helpers::conversions::bytes_to_u64_be(&q.get_word(8, j + 17), 0),
            ::helpers::conversions::bytes_to_u64_be(&q.get_word(8, j + 32), 0),
            ::helpers::conversions::bytes_to_u64_be(&q.get_word(8, j + 33), 0),
            ::helpers::conversions::bytes_to_u64_be(&q.get_word(8, j + 48), 0),
            ::helpers::conversions::bytes_to_u64_be(&q.get_word(8, j + 49), 0),
            ::helpers::conversions::bytes_to_u64_be(&q.get_word(8, j + 64), 0),
            ::helpers::conversions::bytes_to_u64_be(&q.get_word(8, j + 65), 0),
            ::helpers::conversions::bytes_to_u64_be(&q.get_word(8, j + 80), 0),
            ::helpers::conversions::bytes_to_u64_be(&q.get_word(8, j + 81), 0),
            ::helpers::conversions::bytes_to_u64_be(&q.get_word(8, j + 96), 0),
            ::helpers::conversions::bytes_to_u64_be(&q.get_word(8, j + 97), 0),
            ::helpers::conversions::bytes_to_u64_be(&q.get_word(8, j + 112), 0),
            ::helpers::conversions::bytes_to_u64_be(&q.get_word(8, j + 113), 0));
        q.set_word(16, i,      update.get_word(16, 0));
        q.set_word(16, i + 8,  update.get_word(16, 1));
        q.set_word(16, i + 16, update.get_word(16, 2));
        q.set_word(16, i + 24, update.get_word(16, 3));
        q.set_word(16, i + 32, update.get_word(16, 4));
        q.set_word(16, i + 40, update.get_word(16, 5));
        q.set_word(16, i + 48, update.get_word(16, 6));
        q.set_word(16, i + 56, update.get_word(16, 7));
    }
    q.reverse_words(8);
    let result = ::helpers::vectors::xor(r, q);
    result
}

fn permute(
    mut v0: u64,
    mut v1: u64,
    mut v2: u64,
    mut v3: u64,
    mut v4: u64,
    mut v5: u64,
    mut v6: u64,
    mut v7: u64,
    mut v8: u64,
    mut v9: u64,
    mut v10: u64,
    mut v11: u64,
    mut v12: u64,
    mut v13: u64,
    mut v14: u64,
    mut v15: u64,
    g: &Fn(u64, u64, u64,u64) -> (u64, u64, u64, u64)) -> Vec<u8> {

    let mut new_values = g(v0, v4, v8,  v12);
    v0 = new_values.0;
    v4 = new_values.1;
    v8 = new_values.2;
    v12 = new_values.3;
    new_values = g(v1, v5, v9,  v13);
    v1 = new_values.0;
    v5 = new_values.1;
    v9 = new_values.2;
    v13 = new_values.3;
    new_values = g(v2, v6, v10, v14);
    v2 = new_values.0;
    v6 = new_values.1;
    v10 = new_values.2;
    v14 = new_values.3;
    new_values = g(v3, v7, v11, v15);
    v3 = new_values.0;
    v7 = new_values.1;
    v11 = new_values.2;
    v15 = new_values.3;
    new_values = g(v0, v5, v10, v15);
    v0 = new_values.0;
    v5 = new_values.1;
    v10 = new_values.2;
    v15 = new_values.3;
    new_values = g(v1, v6, v11, v12);
    v1 = new_values.0;
    v6 = new_values.1;
    v11 = new_values.2;
    v12 = new_values.3;
    new_values = g(v2, v7, v8, v13);
    v2 = new_values.0;
    v7 = new_values.1;
    v8 = new_values.2;
    v13 = new_values.3;
    new_values = g(v3, v4, v9, v14);
    v3 = new_values.0;
    v4 = new_values.1;
    v9 = new_values.2;
    v14 = new_values.3;

    let mut result: Vec<u8> = Vec::new();
    result.append(&mut v0.to_be_bytes());
    result.append(&mut v1.to_be_bytes());
    result.append(&mut v2.to_be_bytes());
    result.append(&mut v3.to_be_bytes());
    result.append(&mut v4.to_be_bytes());
    result.append(&mut v5.to_be_bytes());
    result.append(&mut v6.to_be_bytes());
    result.append(&mut v7.to_be_bytes());
    result.append(&mut v8.to_be_bytes());
    result.append(&mut v9.to_be_bytes());
    result.append(&mut v10.to_be_bytes());
    result.append(&mut v11.to_be_bytes());
    result.append(&mut v12.to_be_bytes());
    result.append(&mut v13.to_be_bytes());
    result.append(&mut v14.to_be_bytes());
    result.append(&mut v15.to_be_bytes());
    result
}

fn gb(mut a: u64, mut b: u64, mut c: u64, mut d: u64) -> (u64, u64, u64, u64) {
    a = a.wrapping_add(b.wrapping_add(2u64.wrapping_mul(lsw(a).wrapping_mul(lsw(b)))));
    d = (d ^ a).rotate_right(32);
    c = c.wrapping_add(d.wrapping_add(2u64.wrapping_mul(lsw(c).wrapping_mul(lsw(d)))));
    b = (b ^ c).rotate_right(24);
    a = a.wrapping_add(b.wrapping_add(2u64.wrapping_mul(lsw(a).wrapping_mul(lsw(b)))));
    d = (d ^ a).rotate_right(16);
    c = c.wrapping_add(d.wrapping_add(2u64.wrapping_mul(lsw(c).wrapping_mul(lsw(d)))));
    b = (b ^ c).rotate_right(63);
    (a, b, c, d)
}

fn gl(mut a: u64, mut b: u64, mut c: u64, mut d: u64) -> (u64, u64, u64, u64) {
    a = a.wrapping_add(b);
    d = (d ^ a).rotate_right(32);
    c = c.wrapping_add(d);
    b = (b ^ c).rotate_right(24);
    a = a.wrapping_add(b);
    d = (d ^ a).rotate_right(16);
    c = c.wrapping_add(d);
    b = (b ^ c).rotate_right(63);
    (a, b, c, d)
}

// truncate x to the last 32 least significant bits
fn lsw (x: u64) -> u64 {
    x & 0x00000000FFFFFFFF
}

fn permute_gl (
    v0: u64,
    v1: u64,
    v2: u64,
    v3: u64,
    v4: u64,
    v5: u64,
    v6: u64,
    v7: u64,
    v8: u64,
    v9: u64,
    v10: u64,
    v11: u64,
    v12: u64,
    v13: u64,
    v14: u64,
    v15: u64
) -> Vec<u8> {
    permute(
        v0,
        v1,
        v2,
        v3,
        v4,
        v5,
        v6,
        v7,
        v8,
        v9,
        v10,
        v11,
        v12,
        v13,
        v14,
        v15,
        &gl)
}

fn permute_gb (
    v0: u64,
    v1: u64,
    v2: u64,
    v3: u64,
    v4: u64,
    v5: u64,
    v6: u64,
    v7: u64,
    v8: u64,
    v9: u64,
    v10: u64,
    v11: u64,
    v12: u64,
    v13: u64,
    v14: u64,
    v15: u64
) -> Vec<u8> {
    permute(
        v0,
        v1,
        v2,
        v3,
        v4,
        v5,
        v6,
        v7,
        v8,
        v9,
        v10,
        v11,
        v12,
        v13,
        v14,
        v15,
        &gb)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::HexRepresentation;
    use helpers::files::JSONTests;

    #[test]
    fn gb_test() {
        let test_file = "test/test_vectors/gB.json".to_string();

        let json = ::helpers::files::open_json(test_file);
        let unwrapped_json = json.as_ref().unwrap();
        let number_of_tests = unwrapped_json.clone().as_array().unwrap().len();

        for i in 0..number_of_tests {
            let ref inputs = unwrapped_json[i]["inputs"];
            let a = inputs.parse_u64("a");
            let b = inputs.parse_u64("b");
            let c = inputs.parse_u64("c");
            let d = inputs.parse_u64("d");

            let ref outputs = unwrapped_json[i]["outputs"];
            let expected_a = outputs.parse_u64("a");
            let expected_b = outputs.parse_u64("b");
            let expected_c = outputs.parse_u64("c");
            let expected_d = outputs.parse_u64("d");

            let output = gb(a, b, c, d);
            // println!("{{");
            // println!("\"inputs\": {{");
            // println!("\"a\": {:?},", a);
            // println!("\"b\": {:?},", b);
            // println!("\"c\": {:?},", c);
            // println!("\"d\": {:?}", d);
            // println!("}},");
            // println!("\"outputs\": {{");
            // println!("\"a\": {:?},", output.0);
            // println!("\"b\": {:?},", output.1);
            // println!("\"c\": {:?},", output.2);
            // println!("\"d\": {:?}", output.3);
            // println!("}}");
            // println!("}},");
            assert_eq!(output.0, expected_a);
            assert_eq!(output.1, expected_b);
            assert_eq!(output.2, expected_c);
            assert_eq!(output.3, expected_d);
        }
    }

    #[test]
    fn gl_test() {
        let test_file = "test/test_vectors/gL.json".to_string();

        let json = ::helpers::files::open_json(test_file);
        let unwrapped_json = json.as_ref().unwrap();
        let number_of_tests = unwrapped_json.clone().as_array().unwrap().len();

        for i in 0..number_of_tests {
            let ref inputs = unwrapped_json[i]["inputs"];
            let a = inputs.parse_u64("a");
            let b = inputs.parse_u64("b");
            let c = inputs.parse_u64("c");
            let d = inputs.parse_u64("d");

            let ref outputs = unwrapped_json[i]["outputs"];
            let expected_a = outputs.parse_u64("a");
            let expected_b = outputs.parse_u64("b");
            let expected_c = outputs.parse_u64("c");
            let expected_d = outputs.parse_u64("d");

            let output = gl(a, b, c, d);


            // println!("{{");
            // println!("\"inputs\": {{");
            // println!("\"a\": {:?},", a);
            // println!("\"b\": {:?},", b);
            // println!("\"c\": {:?},", c);
            // println!("\"d\": {:?}", d);
            // println!("}},");
            // println!("\"outputs\": {{");
            // println!("\"a\": {:?},", output.0);
            // println!("\"b\": {:?},", output.1);
            // println!("\"c\": {:?},", output.2);
            // println!("\"d\": {:?}", output.3);
            // println!("}}");
            // println!("}},");
            assert_eq!(output.0, expected_a);
            assert_eq!(output.1, expected_b);
            assert_eq!(output.2, expected_c);
            assert_eq!(output.3, expected_d);
        }
    }

    #[test]
    fn permute_gb_test() {
        let test_file = "test/test_vectors/permuteGb.json".to_string();

        let json = ::helpers::files::open_json(test_file);
        let unwrapped_json = json.as_ref().unwrap();
        let number_of_tests = unwrapped_json.clone().as_array().unwrap().len();

        for i in 0..number_of_tests {
            let ref inputs = unwrapped_json[i]["inputs"];
            let v0 = inputs.parse_u64("v0");
            let v1 = inputs.parse_u64("v1");
            let v2 = inputs.parse_u64("v2");
            let v3 = inputs.parse_u64("v3");
            let v4 = inputs.parse_u64("v4");
            let v5 = inputs.parse_u64("v5");
            let v6 = inputs.parse_u64("v6");
            let v7 = inputs.parse_u64("v7");
            let v8 = inputs.parse_u64("v8");
            let v9 = inputs.parse_u64("v9");
            let v10 = inputs.parse_u64("v10");
            let v11 = inputs.parse_u64("v11");
            let v12 = inputs.parse_u64("v12");
            let v13 = inputs.parse_u64("v13");
            let v14 = inputs.parse_u64("v14");
            let v15 = inputs.parse_u64("v15");

            let ref outputs = unwrapped_json[i]["outputs"];
            let expected = outputs.parse_string("res");

            let output = permute_gb(
                v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15);

            assert_eq!(output.to_hex_string(), expected);
        }
    }

    #[test]
    fn permute_gl_test() {
        let test_file = "test/test_vectors/permuteGl.json".to_string();

        let json = ::helpers::files::open_json(test_file);
        let unwrapped_json = json.as_ref().unwrap();
        let number_of_tests = unwrapped_json.clone().as_array().unwrap().len();

        for i in 0..number_of_tests {
            let ref inputs = unwrapped_json[i]["inputs"];
            let v0 = inputs.parse_u64("v0");
            let v1 = inputs.parse_u64("v1");
            let v2 = inputs.parse_u64("v2");
            let v3 = inputs.parse_u64("v3");
            let v4 = inputs.parse_u64("v4");
            let v5 = inputs.parse_u64("v5");
            let v6 = inputs.parse_u64("v6");
            let v7 = inputs.parse_u64("v7");
            let v8 = inputs.parse_u64("v8");
            let v9 = inputs.parse_u64("v9");
            let v10 = inputs.parse_u64("v10");
            let v11 = inputs.parse_u64("v11");
            let v12 = inputs.parse_u64("v12");
            let v13 = inputs.parse_u64("v13");
            let v14 = inputs.parse_u64("v14");
            let v15 = inputs.parse_u64("v15");

            let ref outputs = unwrapped_json[i]["outputs"];
            let expected = outputs.parse_string("res");

            let output = permute_gl(
                v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15);

            assert_eq!(output.to_hex_string(), expected);
        }
    }

    #[test]
    fn cf_argon2_gb_test() {
        let test_file = "test/test_vectors/cfArgon2Gb.json".to_string();

        let json = ::helpers::files::open_json(test_file);
        let unwrapped_json = json.as_ref().unwrap();
        let number_of_tests = unwrapped_json.clone().as_array().unwrap().len();

        for i in 0..number_of_tests {
            let ref inputs = unwrapped_json[i]["inputs"];
            let data = inputs.parse_hex("data");

            let ref outputs = unwrapped_json[i]["outputs"];
            let expected = outputs.parse_string("res");

            let output = cf_argon2_gb(&data).to_hex_string();

            assert_eq!(output, expected);
        }
    }

    #[test]
    fn cf_argon2_gl_test() {
        let test_file = "test/test_vectors/cfArgon2Gl.json".to_string();

        let json = ::helpers::files::open_json(test_file);
        let unwrapped_json = json.as_ref().unwrap();
        let number_of_tests = unwrapped_json.clone().as_array().unwrap().len();

        for i in 0..number_of_tests {
            let ref inputs = unwrapped_json[i]["inputs"];
            let data = inputs.parse_hex("data");

            let ref outputs = unwrapped_json[i]["outputs"];
            let expected = outputs.parse_string("res");

            let output = cf_argon2_gl(&data).to_hex_string();

            assert_eq!(output, expected);
        }
    }

    #[test]
    #[should_panic]
    fn cf_argon_gl_panic_test() {
        let input = vec![0u8];
        let _out = cf_argon2_gl(&input);
    }
}
