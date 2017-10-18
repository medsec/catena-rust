//! The Catena functions as specified in the paper.
extern crate rand;

use bytes::Bytes;
use bytes::ByteState;
use self::rand::Rng;

use std::f32;

/// The possible domains (modes) of Catena.
#[derive(Clone, Copy, Debug)]
enum Domain {
    PasswordScrambling,
    KeyDerivation,
    ProofOfWork,
}

/// Defines a Catena instance.
#[derive(Clone, Debug)]
pub struct Catena <T: Algorithms> {
    /// H, H', F, Gamma and Phi.
    pub algorithms: T,
    /// The version ID of the Catena instance.
    pub vid: &'static str,
    /// Output length of H in bytes.
    pub n: usize,
    /// Output length of H' in bytes; k mod n = 0.
    pub k: usize,
    /// Minimum garlic.
    pub g_low: u8,
    /// Maximum garlic.
    pub g_high: u8,
    /// The depth of the graph structure.
    pub lambda: u8,
}

/// These functions are the variable algorithms of Catena instances. These can
/// either be implemented by users or the implementations from
/// `catena::components` can be used.
#[allow(unused_variables)]
pub trait Algorithms {
    /// The cryptographic hash function H of the Catena specification. Possible
    /// cryptographic hash functions can be found in `catena::components::hash`.
    fn h (&self, x: &Vec<u8>) -> Vec<u8>;

    /// The (possible reduced) hash function H' of the Catena specification.
    /// Either the reduced hash functions from `catena::components::fasthash` or
    /// the cryptographic hash functions from `catena::components::hash` can be
    /// used.
    fn h_prime (&mut self, x: &Vec<u8>) -> Vec<u8>;

    /// Reset the state of the reduced hash function H'. This is not neccessary
    /// if H' = H.
    fn reset_h_prime(&mut self) { }

    /// The optional password-independent random layer Γ of the Catena
    /// specification. Possible functions can be found in
    /// `catena::components::gamma`.
    fn gamma(&mut self, garlic: u8, state: Vec<u8>, gamma: &Vec<u8>, k: usize)
        -> Vec<u8>;

    /// The graph-based hash function F of the Catena specification.
    /// Graph-based hash function can be found in `catena::components::graph`.
    fn f(&mut self, garlic: &u8, state: &mut Vec<u8>, lambda: u8, n: usize, k: usize)
        -> Vec<u8>;

    /// The optional password-dependent random layer Φ of the Catena
    /// specification. Possible functions can be found in
    /// `catena::components::phi`.
    fn phi(&mut self, garlic: u8, state: Vec<u8>, mu: &Vec<u8>, k: usize) -> Vec<u8>;
}

/// These are the algorithms of Catena. They are generated with the
/// implementations from `algorithms`.
impl<T: Algorithms> Catena <T> {

    /// Password scrambling function of Catena
    ///
    /// # Inputs
    ///
    /// - pwd: The password to be hashed.
    /// - salt: The salt value.
    /// - associated_data: Associated data of the user and/or the host.
    /// - output_length: The length of the final hash in bytes.
    /// - gamma: A public and password-independent input
    ///
    /// For more information about the input values, consider the Catena
    /// specification.
    pub fn hash (
        &mut self,
        pwd: &Vec<u8>,
        salt: &Vec<u8>,
        associated_data: &Vec<u8>,
        output_length: u16,
        gamma: &Vec<u8>
    ) -> Vec<u8> {

        let tweak = self.compute_tweak(
            Domain::PasswordScrambling,
            output_length, salt.len() as u16,
            &associated_data);

        let g_low: u8;
        let g_high: u8;

        {
            g_low = self.g_low;
            g_high = self.g_high;
        }

        self.catena(
            &pwd,
            &tweak,
            salt,
            g_low,
            g_high,
            output_length,
            &gamma)
    }

    /// Compute an encrypted hash for a given password.
    ///
    /// # Inputs
    ///
    /// - pwd: The password to be hashed.
    /// - salt: The salt value.
    /// - associated_data: Associated data of the user and/or the host.
    /// - output_length: The length of the final hash in bytes.
    /// - gamma: A public and password-independent input
    /// - g_high: The maximum garlic.
    /// - server_key: The key which is used to encrypt the output of Catena.
    ///
    /// For more information about the input values, consider the Catena
    /// specification.
    pub fn keyed_hashing (
        &mut self,
        user_pwd: Vec<u8>,
        salt: Vec<u8>,
        a_data: &Vec<u8>,
        output_length: u16,
        gamma: &Vec<u8>,
        user_id: Vec<u8>,
        g_high: u8,
        server_key: &Vec<u8>
    ) -> Vec<u8> {
        let keystream = self.compute_keystream(
                &server_key,
                &user_id,
                g_high,
                output_length as usize);

            ::helpers::vectors::xor(
                self.hash(&user_pwd, &salt, a_data, output_length, gamma),
                keystream)
        }

    /// Key-Derivation function Catena-KG
    ///
    /// For more information about the input values, consider the Catena
    /// specification.
    pub fn generate_key (
        &mut self,
        pwd: Vec<u8>,
        associated_data: &Vec<u8>,
        salt: Vec<u8>,
        output_length: u16,
        gamma: Vec<u8>,
        key_size: u16,
        key_identifier: Vec<u8>
    ) -> Vec<u8> {
        let tweak = self.compute_tweak(
            Domain::KeyDerivation,
            output_length,
            salt.len() as u16,
            associated_data);

        let g_low: u8;
        let g_high: u8;

        {
            g_low = self.g_low;
            g_high = self.g_high;
        }

        self.key_generation(
            pwd,
            tweak,
            salt,
            g_low,
            g_high,
            output_length,
            gamma,
            key_size,
            key_identifier)
    }

    /// Compute the new hash with `g_high = old_g_high` for an updated security
    /// parameter `new_g_high` independent from the client.
    /// The value for `new_g_high` has to be bigger than `old_g_high`.
    pub fn client_independent_update (
        &mut self,
        old_hash: Vec<u8>,
        old_g_high: u8,
        new_g_high: u8,
        gamma: &Vec<u8>,
        output_length: u16
    ) -> Vec<u8> {

        let n: usize;

        {
            n = self.n;
        }

        if old_g_high >= new_g_high {
            panic!("new_g_high has to be bigger than old_g_high");
        }

        let mut new_hash: Vec<u8> = old_hash.clone();

        for g in old_g_high + 1 .. new_g_high + 1 {
            if new_hash.len() < n {
                new_hash = ::helpers::vectors::zero_padding(
                    new_hash.clone(), n - output_length as usize);
            }

            // compute flap(g, h || 0^∗ , γ)
            let flap =
                self.flap(
                    g,
                    new_hash,
                    gamma);

            // compute H(g || flap(g, h || 0^∗ , γ))
            new_hash = self.h2(
                &g.to_le_bytes(),
                &flap);

            // compute truncate(H(g || flap(g, h || 0^∗ , γ)), m)
            new_hash.truncate(output_length as usize);
        }

        new_hash
    }

    /// Compute the new encrypted hash with `g_high = old_g_high` for an updated
    /// security parameter `new_g_high` independent from the client for an
    /// encrypted hash.
    /// The value for `new_g_high` has to be bigger than `old_g_high`.
    pub fn keyed_client_independent_update (
        &mut self,
        old_encrypted_hash: Vec<u8>,
        old_g_high: u8,
        new_g_high: u8,
        gamma: &Vec<u8>,
        output_length: u16,
        server_key: &Vec<u8>,
        user_id: &Vec<u8>
    ) -> Vec<u8> {
        let keystream = self.compute_keystream(
            &server_key,
            &user_id,
            old_g_high,
            output_length as usize);

        let old_hash = ::helpers::vectors::xor(
            old_encrypted_hash, keystream);

        let new_hash = self.client_independent_update(
            old_hash,
            old_g_high,
            new_g_high,
            gamma,
            output_length);

        let new_keystream = self.compute_keystream(
            &server_key,
            &user_id,
            new_g_high,
            output_length as usize);

        ::helpers::vectors::xor(new_hash, new_keystream)
    }

    /// The client-side computation for the server relief.
    pub fn client_prep (
        &mut self,
        pwd: Vec<u8>,
        salt: Vec<u8>,
        associated_data: &Vec<u8>,
        output_length: u16,
        gamma: &Vec<u8>
    ) -> Vec<u8> {

        let tweak = self.compute_tweak(
            Domain::PasswordScrambling,
            output_length,
            salt.len() as u16,
            associated_data);

        let mut x = self.h3(&tweak, &pwd, &salt);

        let g_low: u8;
        let g_high: u8;
        let n: usize;

        {
            g_low = self.g_low;
            g_high = self.g_high;
            n = self.n;
        }

        x = self.flap((g_low + 1) / 2, x, &gamma);
        x = self.algorithms.h(&x);

        // normal iterations
        if g_high > g_low {
            for g in g_low .. g_high {
                if x.len() < n {
                    x = ::helpers::vectors::zero_padding(x, n - output_length as usize);
                }
                x = self.flap(g, x, &gamma);
                x = self.h2(&g.to_le_bytes(), &x);
                x.truncate(output_length as usize);
            }
        }

        // omit the last invocation of H
        if x.len() < n {
            x = ::helpers::vectors::zero_padding(x, n - output_length as usize);
        }
        x = self.flap(g_high, x, &gamma);

        x
    }

    /// The server-side computation for the server-relief.
    pub fn server_final (
        &mut self,
        client_output: Vec<u8>,
        output_length: u16
    ) -> Vec<u8> {

        let mut x = client_output.clone();
        let g = self.g_high.to_le_bytes();
        x = self.h2(&g, &x);
        x.truncate(output_length as usize);
        x
    }

    /// Server side of Catena proof of work mode.
    ///
    /// # Inputs
    ///
    /// - pwd: the password to be hashed
    /// - salt: the salt value
    /// - associated_data: associated data of the user
    /// - gamma: a public and password-independent input
    /// - output_length: length of the final hash in bytes
    /// - p: number of secret bits <= 64
    /// - mode:
    ///     - 0: salt mode
    ///     - 1: password mode
    ///
    /// # Returns
    ///
    /// - password
    /// - salt
    /// - associated data
    /// - gamma
    /// - output length
    /// - output hash
    /// - p
    /// - mode (0 = salt; 1 = password)

    pub fn proof_of_work_server(
        &mut self,
        pwd: &Vec<u8>,
        salt: &mut Vec<u8>,
        associated_data: &Vec<u8>,
        gamma: &Vec<u8>,
        output_len: u16,
        p: usize,
        mode: u8
    ) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, u16, Vec<u8>, usize, u8) {

        let g_low: u8;
        let g_high: u8;

        {
            g_low = self.g_low;
            g_high = self.g_high;
        }

        let tweak = self.compute_tweak(
            Domain::ProofOfWork,
            output_len,
            salt.len() as u16,
            associated_data);

        let hash = self.catena(
            &pwd,
            &tweak,
            &salt,
            g_low,
            g_high,
            output_len,
            &gamma);


        if mode == 0 {
            let p_bits: u64 = (1 << (8 * ((p / 8) + 1))) - (1 << p);
            let mut mask = p_bits.to_be_bytes();

            // remove preceding 0-bytes
            while mask[0] == 0  && mask.len() > 1{
                let _ = mask.remove(0);
            }

            let salt_len = salt.len();
            let mask_len = mask.len();

            for (i, ..) in mask.iter().enumerate() {
                let salt_byte = salt[salt_len - (i + 1)];
                let mask_byte = mask[mask_len - (i + 1)];
                salt[salt_len - (i + 1)] = mask_byte & salt_byte;
            }

            (pwd.to_vec(),
             salt.to_vec(),
             associated_data.to_vec(),
             gamma.to_vec(),
             output_len,
             hash,
             p,
             mode)
        } else if mode == 1 {
            let bin_len =
                (format!("{:b}", pwd[0])).len() + ((pwd.len() -1 ) * 8);
            if bin_len != p {
                panic!("pwd is not p bit long");
            }

            let empty_pwd: Vec<u8> = Vec::new();
            (empty_pwd, salt.to_vec(), associated_data.to_vec(), gamma.to_vec(), output_len, hash, p, mode)
        } else {
            panic!("Invalid mode for proof of work");
        }
    }

    /// Client side computation of proof of work
    ///
    /// # Inputs
    ///
    /// - pwd: the password to be hashed
    /// - salt: the salt value
    /// - associated_data: associated data of the user
    /// - gamma: a public and password-independent input
    /// - output_length: length of the final hash in bytes
    /// - hash: hash to check if the computed password or salt is correct
    /// - p: number of secret bits <= 64
    /// - mode:
    ///     - 0: salt mode
    ///     - 1: password mode

    pub fn proof_of_work_client(
        &mut self,
        pwd: Vec<u8>,
        salt: Vec<u8>,
        associated_data: Vec<u8>,
        gamma: Vec<u8>,
        output_len: u16,
        hash: Vec<u8>,
        p: usize,
        mode: u8
    ) -> Vec<u8> {

        let g_low: u8;
        let g_high: u8;

        {
            g_low = self.g_low;
            g_high = self.g_high;
        }

        let tweak = self.compute_tweak(
            Domain::ProofOfWork,
            output_len,
            salt.len() as u16,
            &associated_data);

        let border: u64 = 1 << p;
        let rand_num = rand::thread_rng().gen_range(0, (1 << p) - 1);

        if mode == 0 {

            for i in 0..border {

                let mut new_vec = ((i + rand_num) % (border)).to_be_bytes();

                while new_vec[0] == 0 && new_vec.len() > 1{
                    let _ = new_vec.remove(0);
                }

                let len = salt.len();
                let len_new_vec = new_vec.len();

                let mut tmp_salt = salt.clone();

                for (i, _) in new_vec.iter().enumerate() {

                    let tmp = tmp_salt[len - (i + 1)];
                    tmp_salt[len - (i + 1)] = new_vec[len_new_vec - (i + 1)] 
                        | tmp;
                }

                let hash_to_test = self.catena(
                    &pwd,
                    &tweak,
                    &tmp_salt,
                    g_low,
                    g_high,
                    output_len,
                    &gamma);

                if hash == hash_to_test {
                    return tmp_salt
                }
            }

            panic!("No salt found");

        } else if mode == 1 {

            for i in 0..border+1 {

                let mut new_vec = ((i + rand_num) % (border)).to_be_bytes();

                while (new_vec[0] == 0) & (new_vec.len() > 1){
                    let _ = new_vec.remove(0);
                }

                let hash_to_test = self.catena(
                    &new_vec,
                    &tweak,
                    &salt,
                    g_low,
                    g_high,
                    output_len,
                    &gamma);

                if hash == hash_to_test {
                    return new_vec;
                }

            }
            panic!("No password found");
        } else {
            panic!("Invalid mode for proof of work");
        }
    }

    /// Password-scrambling function of Catena
    fn catena (
        &mut self,
        pwd: &Vec<u8>,
        t: &Vec<u8>,
        s: &Vec<u8>,
        g_low: u8,
        g_high: u8,
        m: u16,
        gamma: &Vec<u8>
    ) -> Vec<u8> {

        let n: usize;

        {
            n = self.n;
        }

        let mut x = self.algorithms.h(
            &[&t[..], &pwd[..], &s[..]].concat());
        x = self.flap((g_low + 1) / 2, x, &gamma);
        x = self.algorithms.h(&x);
        for g in g_low..g_high + 1 {
            if x.len() < n {
                x = ::helpers::vectors::zero_padding(x, n - m as usize);
            }
            x = self.flap(g, x, &gamma);
            x = self.h2(&g.to_le_bytes(), &x);
            x.truncate(m as usize);
        }
        x
    }

    /// Flap function of Catena
    fn flap(
        &mut self,
        garlic: u8,
        x: Vec<u8>,
        gamma: &Vec<u8>
    ) -> Vec<u8> {

        let n: usize;
        let k: usize;

        {
            n = self.n;
            k = self.k;
        }

        let (vminus2, vminus1) = self.h_init(x);

        let g: usize = 1 << garlic;

        let mut state: Vec<Vec<u8>> = Vec::with_capacity(g + 2);
        state.push(vminus2);
        state.push(vminus1);

        self.algorithms.reset_h_prime();

        for i in 2..(g + 2) {
            let state_i = self.h_prime2(
                state[i - 1].clone(), state[i - 2].clone());
            state.push(state_i);
        }

        // remove v_(-2) and v_(-1)
        state = state[2..].to_vec();

        // Append all k-byte values
        let mut v: Vec<u8> = Vec::with_capacity((g + 2) * k);
        for element in &state {
            v.append(&mut element.clone());
        }

        self.algorithms.reset_h_prime();
        v = self.algorithms.gamma(garlic, v, gamma, k);
        self.algorithms.reset_h_prime();
        v = self.algorithms.f(&garlic, &mut v, self.lambda, n, k);
        self.algorithms.reset_h_prime();

        // last state word as mu
        let mu = v.get_word(k, g - 1);
        v = self.algorithms.phi(garlic, v, &mu, k);

        // only the last state word is used
        v.get_word(k, g - 1)
    }

    fn h_init (
        &mut self,
        x: Vec<u8>
    ) ->  (Vec<u8>, Vec<u8>){
        let n: usize;
        let k: usize;

        {
            n = self.n;
            k = self.k;
        }

        let l: usize = 2 * k / n;
        let mut w: Vec<u8> = Vec::new();
        for i in 0..l {
            w = [&w[..],
                 &self.h2(&vec![i as u8], &x)].concat();
        }
        let vminus2 = [&w[0..(w.len() / 2)]].concat();
        let vminus1 = [&w[(w.len() / 2)..]].concat();

        (vminus2,vminus1)
    }

    /// Compute the tweak for a given domain.
    ///
    /// # Inputs
    ///
    /// - mode: The domain for which Catena is used.
    /// - output_len: The output length of the final hash.
    /// - salt_len: The length of the salt.
    /// - a_data: Associated data.
    fn compute_tweak(
        &self,
        mode: Domain,
        output_len: u16,
        salt_len: u16,
        a_data: &Vec<u8>)
    -> Vec<u8> {

        let d: u8;
        match mode {
            Domain::PasswordScrambling => d = 0,
            Domain::KeyDerivation => d = 1,
            Domain::ProofOfWork => d = 2,
        }

        // compute H(V)
        let hv = self.algorithms.h(&self.vid.as_bytes().to_vec());

        // compute H(AD)
        let had = self.algorithms.h(a_data);

        let tweak = [&hv[..], &[d, self.lambda], &output_len.to_le_bytes()[..],
        &salt_len.to_le_bytes()[..], &had[..]].concat();

        tweak
    }

    /// Compute h(a || b)
    fn h2(&mut self, a: &Vec<u8>, b: &Vec<u8>) -> Vec<u8> {
        let input = [&a[..], &b[..]].concat();
        self.algorithms.h(&input)
    }

    /// Compute h(a || b || c)
    fn h3(&mut self, a: &Vec<u8>, b: &Vec<u8>, c: &Vec<u8>) -> Vec<u8> {
        let input = [&a[..], &b[..], &c[..]].concat();
        self.algorithms.h(&input)
    }

    /// Compute h(a || b || c || d)
    fn h4(&mut self, a: &Vec<u8>, b: &Vec<u8>, c: &Vec<u8>, d: &Vec<u8>)
        -> Vec<u8> {
        let input = [&a[..], &b[..], &c[..], &d[..]].concat();
        self.algorithms.h(&input)
    }

    /// Compute h_prime(a || b)
    fn h_prime2(&mut self, a: Vec<u8>, b: Vec<u8>) -> Vec<u8> {
        let input = [&a[..], &b[..]].concat();
        self.algorithms.h_prime(&input)
    }

    /// Key-Derivation Function Catena-KG
    fn key_generation (
        &mut self,
        pwd: Vec<u8>,
        tweak: Vec<u8>,
        salt: Vec<u8>,
        g_low: u8,
        g_high: u8,
        m: u16,
        gamma: Vec<u8>,
        key_size: u16,
        key_identifier: Vec<u8>
    ) -> Vec<u8> {
        let n: usize;

        {
            n = self.n;
        }

        let x = self.catena(&pwd, &tweak, &salt, g_low, g_high, m, &gamma);
        let mut k: Vec<u8> = Vec::new();

        let limit = (f32::ceil(key_size as f32 / n as f32) + 1.0) as u16;

        for i in 1..limit {
            k.append(
                &mut self.h4(
                    &i.to_le_bytes(),
                    &key_identifier,
                    &key_size.to_le_bytes(),
                    &x));
        }

        k.truncate(key_size as usize);
        k
    }

    /// Compute Keystream for keyed hashing
    fn compute_keystream(
        &mut self,
        server_key: &Vec<u8>,
        user_id: &Vec<u8>,
        g_high: u8,
        output_length: usize
    ) -> Vec<u8> {
            let mut keystream = self.h4(
                server_key,
                user_id,
                &g_high.to_le_bytes(),
                server_key);

            keystream.truncate(output_length);

            keystream
    }
}


#[cfg(test)]
mod tests {
    use bytes::HexRepresentation;
    use bytes::Bytes;
    use helpers::files::JSONTests;
    use super::*;

    fn proof_of_work_server_test_from_json <T: Algorithms>(
        mut catena: ::catena::Catena<T>, file: &str)
    {
        let json = ::helpers::files::open_json(file.to_string());
        let unwrapped_json = json.as_ref().unwrap();
        let numbers_of_tests = unwrapped_json.clone().as_array().unwrap().len();

        for i in 0..numbers_of_tests {
            let ref inputs = unwrapped_json[i]["inputs"];

            let pwd = inputs.parse_hex("pwd");
            let mut salt = inputs.parse_hex("salt");
            let ad = inputs.parse_hex("aData");
            let gamma = inputs.parse_hex("gamma");
            let out_len = inputs.parse_u16("outLen");
            let p = inputs.parse_usize("p");
            let mode = inputs.parse_u8("mode");

            let (result_pwd,
                 result_salt,
                 result_ad,
                 result_gamma,
                 result_out_len,
                 result_hash,
                 result_p,
                 result_mode) = catena.proof_of_work_server(
                     &pwd,
                     &mut salt,
                     &ad,
                     &gamma,
                     out_len,
                     p,
                     mode);

            let ref outputs = unwrapped_json[i]["outputs"];

            let expected_pwd = outputs.parse_hex("pwd");
            let expected_salt = outputs.parse_hex("salt");
            let expected_ad = outputs.parse_hex("aData");
            let expected_gamma = outputs.parse_hex("gamma");
            let expected_out_len = outputs.parse_u16("outLen");
            let expected_hash = outputs.parse_hex("outHash");
            let expected_p = outputs.parse_usize("p");
            let expected_mode = outputs.parse_u8("mode");

            assert_eq!(result_pwd.to_hex_string(), expected_pwd.to_hex_string());
            assert_eq!(result_salt.to_hex_string(), expected_salt.to_hex_string());
            assert_eq!(result_ad.to_hex_string(), expected_ad.to_hex_string());
            assert_eq!(result_gamma.to_hex_string(), expected_gamma.to_hex_string());
            assert_eq!(result_out_len, expected_out_len);
            assert_eq!(result_hash.to_hex_string(), expected_hash.to_hex_string());
            assert_eq!(result_p, expected_p);
            assert_eq!(result_mode, expected_mode);
        }
    }

    #[test]
    fn proof_of_work_server_salt_test_butterfly_reduced() {
        let mut catena_bf = ::default_instances::butterfly::new();
            catena_bf.g_low = 9;
            catena_bf.g_high = 9;
        proof_of_work_server_test_from_json(
            catena_bf,
            "test/test_vectors/proofOfWorkServerSaltButterflyReduced.json");
    }

    #[test]
    fn proof_of_work_server_pwd_test_butterfly_reduced() {
        let mut catena_bf = ::default_instances::butterfly::new();
            catena_bf.g_low = 9;
            catena_bf.g_high = 9;
        proof_of_work_server_test_from_json(
            catena_bf,
            "test/test_vectors/proofOfWorkServerPwdButterflyReduced.json");
    }

    #[test]
    #[should_panic]
    fn proof_of_work_server_panic_test_1() {
        let pwd: Vec<u8> = vec!(0, 0);
        let mut salt: Vec<u8> = vec!(0, 0);
        let ad: Vec<u8> = vec!(0, 0);
        let gamma: Vec<u8> = vec!(0, 0);
        let out_len: u16 = 64;
        let p = 1;
        let mode: u8 = 6;

        let mut catena_bf = ::default_instances::butterfly::new();

        let _result = catena_bf.proof_of_work_server(
            &pwd,
            &mut salt,
            &ad,
            &gamma,
            out_len,
            p,
            mode);
    }

    #[test]
    #[should_panic]
    /// test for wrong password length panic
    fn proof_of_work_server_panic_test_2() {
        let pwd: Vec<u8> = vec!(0, 0);
        let mut salt: Vec<u8> = vec!(0, 0);
        let ad: Vec<u8> = vec!(0, 0);
        let gamma: Vec<u8> = vec!(0, 0);
        let out_len: u16 = 64;
        let p = 1;
        let mode: u8 = 1;

        let mut catena_bf = ::default_instances::butterfly::new();

        let _result = catena_bf.proof_of_work_server(
            &pwd,
            &mut salt,
            &ad,
            &gamma,
            out_len,
            p,
            mode);
    }

    fn proof_of_work_client_test_from_json <T: Algorithms>(
        mut catena: ::catena::Catena<T>, file: &str)
    {
        let json = ::helpers::files::open_json(file.to_string());
        let unwrapped_json = json.as_ref().unwrap();
        let numbers_of_tests = unwrapped_json.clone().as_array().unwrap().len();

        for i in 0..numbers_of_tests {
            let ref inputs = unwrapped_json[i]["inputs"];

            let pwd = inputs.parse_hex("pwd");
            let salt = inputs.parse_hex("salt");
            let ad = inputs.parse_hex("aData");
            let gamma = inputs.parse_hex("gamma");
            let out_len = inputs.parse_u16("outLen");
            let hash = inputs.parse_hex("hash");
            let p = inputs.parse_usize("p");
            let mode = inputs.parse_u8("mode");

            let result = catena.proof_of_work_client(
                pwd,
                salt,
                ad,
                gamma,
                out_len,
                hash,
                p,
                mode);

            let ref outputs = unwrapped_json[i]["outputs"];

            let expected = outputs.parse_hex("res");

            assert_eq!(result.to_hex_string(), expected.to_hex_string());
        }
    }

    #[test]
    fn proof_of_work_client_salt_test_butterfly_reduced() {
        let mut catena_bf = ::default_instances::butterfly::new();
            catena_bf.g_low = 9;
            catena_bf.g_high = 9;
        proof_of_work_client_test_from_json(
            catena_bf,
            "test/test_vectors/proofOfWorkClientSaltButterflyReduced.json");
    }

    #[test]
    fn proof_of_work_client_pwd_test_butterfly_reduced() {
        let mut catena_bf = ::default_instances::butterfly::new();
            catena_bf.g_low = 9;
            catena_bf.g_high = 9;
        proof_of_work_client_test_from_json(
            catena_bf,
            "test/test_vectors/proofOfWorkClientPwdButterflyReduced.json");
    }

    #[test]
    #[should_panic]
    /// test for invalid mode
    fn proof_of_work_client_panic_test_1() {
        let pwd: Vec<u8> = vec!(0, 0);
        let salt: Vec<u8> = vec!(0, 0);
        let ad: Vec<u8> = vec!(0, 0);
        let gamma: Vec<u8> = vec!(0, 0);
        let out_len: u16 = 64;
        let hash: Vec<u8> = vec!(0, 0);
        let p = 1;
        let mode: u8 = 3;

        let mut catena_bf = ::default_instances::butterfly::new();

        let _result = catena_bf.proof_of_work_client(
            pwd,
            salt,
            ad,
            gamma,
            out_len,
            hash,
            p,
            mode);
    }

    #[test]
    #[should_panic]
    /// test for salt not found panic
    fn proof_of_work_client_panic_test_2() {
        let pwd: Vec<u8> = vec!(0, 0);
        let salt: Vec<u8> = vec!(0, 0);
        let ad: Vec<u8> = vec!(0, 0);
        let gamma: Vec<u8> = vec!(0, 0);
        let out_len: u16 = 64;
        let hash: Vec<u8> = vec!(0, 0);
        let p = 1;
        let mode: u8 = 0;

        let mut catena_bf = ::default_instances::butterfly::new();

        let _result = catena_bf.proof_of_work_client(
            pwd,
            salt,
            ad,
            gamma,
            out_len,
            hash,
            p,
            mode);
    }

    #[test]
    #[should_panic]
    /// test for password not found panic
    fn proof_of_work_client_panic_test_3() {
        let pwd: Vec<u8> = vec!(0, 0);
        let salt: Vec<u8> = vec!(0, 0);
        let ad: Vec<u8> = vec!(0, 0);
        let gamma: Vec<u8> = vec!(0, 0);
        let out_len: u16 = 64;
        let hash: Vec<u8> = vec!(0, 0);
        let p = 1;
        let mode: u8 = 1;

        let mut catena_bf = ::default_instances::butterfly::new();

        let _result = catena_bf.proof_of_work_client(
            pwd,
            salt,
            ad,
            gamma,
            out_len,
            hash,
            p,
            mode);
    }

    fn h_init_test_from_json<T: Algorithms>(
        mut catena: ::catena::Catena<T>, test_file: String)
    {
        let json = ::helpers::files::open_json(test_file);
        let unwrapped_json = json.as_ref().unwrap();
        let number_of_tests = unwrapped_json.clone().as_array().unwrap().len();

        for i in 0..number_of_tests {
            let ref inputs = unwrapped_json[i]["inputs"];
            let ref outputs = unwrapped_json[i]["outputs"]["v"];
            let expected_1_tmp = outputs[0].to_string();
            let expected_2_tmp = outputs[1].to_string();
            let expected_1 = expected_1_tmp.trim_matches('\"');
            let expected_2 = expected_2_tmp.trim_matches('\"');

            let x = inputs.parse_hex("x");

            let output = catena.h_init(x);

            assert_eq!(output.0.to_hex_string(),
                       expected_1.to_string().to_be_bytes().to_hex_string());
            assert_eq!(output.1.to_hex_string(),
                       expected_2.to_string().to_be_bytes().to_hex_string());
        }
    }

    #[test]
    fn h_init_test() {
        let catena_dff = ::default_instances::dragonfly_full::new();
        h_init_test_from_json(
            catena_dff, "test/test_vectors/hInitAnyFull.json".to_string());
    }

    fn compute_tweak_test_from_json<T: Algorithms>(
        catena: ::catena::Catena<T>, file: &str)
    {
        let json = ::helpers::files::open_json(file.to_string());
        let unwrapped_json = json.as_ref().unwrap();
        let number_of_tests = unwrapped_json.clone().as_array().unwrap().len();

        for i in 0..number_of_tests {
            let ref inputs = unwrapped_json[i]["inputs"];

            let out_length = inputs.parse_u16("outLen");
            let salt_length = inputs.parse_u16("sLen");
            let ad = inputs.parse_utf8string("aData");
            let domain = inputs.parse_u64("d");

            let ref outputs = unwrapped_json[i]["outputs"];
            let expected = outputs.parse_string("res");

            let mode: Domain;
            if domain == 0 {
                mode = Domain::PasswordScrambling;
            } else if domain == 1 {
                mode = Domain::KeyDerivation;
            } else {
                mode = Domain::ProofOfWork;
            }

            let output = catena.compute_tweak(
                mode,
                out_length,
                salt_length,
                &ad);

            assert_eq!(output.to_hex_string(),
                       expected);
        }
    }

    #[test]
    fn compute_tweak_test_dragonflyfull() {
        let catena = ::default_instances::dragonfly_full::new();
        compute_tweak_test_from_json(
            catena, "test/test_vectors/tweakDragonflyFull.json");
    }

    #[test]
    fn compute_tweak_test_dragonfly() {
        let catena = ::default_instances::dragonfly::new();
        compute_tweak_test_from_json(
            catena, "test/test_vectors/tweakDragonfly.json");
    }

    #[test]
    fn compute_tweak_test_butterfly() {
        let catena = ::default_instances::butterfly::new();
        compute_tweak_test_from_json(
            catena, "test/test_vectors/tweakButterfly.json");
    }

    #[test]
    fn compute_tweak_test_butterflyfull() {
        let catena = ::default_instances::butterfly_full::new();
        compute_tweak_test_from_json(
            catena, "test/test_vectors/tweakButterflyFull.json");
    }

    fn catena_test_from_json<T: Algorithms>(
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
    #[cfg(feature="fulltest")]
    fn butterfly_test_from_json() {
        let test_catena = ::default_instances::butterfly::new();
        catena_test_from_json(
            test_catena, "test/test_vectors/catenaButterfly.json");
    }

    #[test]
    fn butterfly_reduced_test_from_json() {
        let mut test_catena = ::default_instances::butterfly::new();
        test_catena.g_low = 9;
        test_catena.g_high = 9;
        catena_test_from_json(
            test_catena, "test/test_vectors/catenaButterflyReduced.json");
    }

    #[test]
    #[cfg(feature="fulltest")]
    fn butterflyfull_test_from_json() {
        let test_catena = ::default_instances::butterfly_full::new();
        catena_test_from_json(
            test_catena, "test/test_vectors/catenaButterflyFull.json");
    }

    #[test]
    fn butterflyfull_reduced_test_from_json() {
        let mut test_catena = ::default_instances::butterfly_full::new();
        test_catena.g_low = 9;
        test_catena.g_high = 9;
        catena_test_from_json(
            test_catena, "test/test_vectors/catenaButterflyFullReduced.json");
    }

    #[test]
    #[cfg(feature="fulltest")]
    fn dragonfly_test_from_json() {
        let test_catena = ::default_instances::dragonfly::new();
        catena_test_from_json(
            test_catena, "test/test_vectors/catenaDragonfly.json");
    }

    #[test]
    fn dragonfly_reduced_test_from_json() {
        let mut test_catena = ::default_instances::dragonfly::new();
        test_catena.g_low = 14;
        test_catena.g_high = 14;
        catena_test_from_json(
            test_catena, "test/test_vectors/catenaDragonflyReduced.json");
    }

    #[test]
    #[cfg(feature="fulltest")]
    fn dragonflyfull_test_from_json() {
        let test_catena = ::default_instances::dragonfly_full::new();
        catena_test_from_json(
            test_catena, "test/test_vectors/catenaDragonflyFull.json");
    }

    #[test]
    fn dragonflyfull_reduced_test_from_json() {
        let mut test_catena = ::default_instances::dragonfly_full::new();
        test_catena.g_low = 14;
        test_catena.g_high = 14;
        catena_test_from_json(
            test_catena, "test/test_vectors/catenaDragonflyFullReduced.json");
    }

    fn keyed_hash_test_from_json<T: Algorithms>(
        mut catena: ::catena::Catena<T>, file: &str)
    {
        let json = ::helpers::files::open_json(file.to_string());
        let unwrapped_json = json.as_ref().unwrap();
        let number_of_tests = unwrapped_json.clone().as_array().unwrap().len();

        for n in 0..number_of_tests {
            let ref inputs = unwrapped_json[n]["inputs"];
            let pwd = inputs.parse_hex("pwd");
            let key = inputs.parse_hex("key");
            let salt = inputs.parse_hex("salt");
            let gamma = inputs.parse_hex("gamma");
            let ad = inputs.parse_hex("aData");
            let uid = inputs.parse_hex("userID");
            let len = inputs.parse_u16("outputLength");

            let ref outputs = unwrapped_json[n]["outputs"];
            let expected = outputs.parse_string("res");

            let g: u8;
            {
                g = catena.g_high;
            }

            assert_eq!(
                catena.keyed_hashing(
                    pwd,
                    salt,
                    &ad,
                    len,
                    &gamma,
                    uid,
                    g,
                    &key).to_hex_string(),
                expected);
        }
    }

    #[test]
    #[cfg(feature="fulltest")]
    fn keyed_butterfly_test_from_json() {
        let test_catena = ::default_instances::butterfly::new();
        keyed_hash_test_from_json(
            test_catena, "test/test_vectors/keyedHashButterfly.json");
    }

    #[test]
    fn keyed_butterfly_reduced_test_from_json() {
        let mut test_catena = ::default_instances::butterfly::new();
        test_catena.g_low = 9;
        test_catena.g_high = 9;
        keyed_hash_test_from_json(
            test_catena, "test/test_vectors/keyedHashButterflyReduced.json");
    }

    #[test]
    #[cfg(feature="fulltest")]
    fn keyed_butterflyfull_test_from_json() {
        let test_catena = ::default_instances::butterfly_full::new();
        keyed_hash_test_from_json(
            test_catena, "test/test_vectors/keyedHashButterflyFull.json");
    }

    #[test]
    #[cfg(feature="fulltest")]
    fn keyed_dragonfly_test_from_json() {
        let test_catena = ::default_instances::dragonfly::new();
        keyed_hash_test_from_json(
            test_catena, "test/test_vectors/keyedHashDragonfly.json");
    }

    #[test]
    fn keyed_dragonfly_reduced_test_from_json() {
        let mut test_catena = ::default_instances::dragonfly::new();
        test_catena.g_low = 14;
        test_catena.g_high = 14;
        keyed_hash_test_from_json(
            test_catena, "test/test_vectors/keyedHashDragonflyReduced.json");
    }

    #[test]
    #[cfg(feature="fulltest")]
    fn keyed_dragonflyfull_test_from_json() {
        let test_catena = ::default_instances::dragonfly_full::new();
        keyed_hash_test_from_json(
            test_catena, "test/test_vectors/keyedHashDragonflyFull.json");
    }

    fn server_relief_complete_test_from_json<T: Algorithms>(
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

            let client_result = catena.client_prep(
                pwd,
                salt,
                &ad,
                len,
                &gamma);

            let server_result = catena.server_final(
                client_result,
                len);

            assert_eq!(server_result.to_hex_string(),
                       expected);
        }
    }

    #[test]
    #[cfg(feature="fulltest")]
    fn server_relief_complete_butterfly_test_from_json() {
        let test_catena = ::default_instances::butterfly::new();
        server_relief_complete_test_from_json(
            test_catena, "test/test_vectors/catenaButterfly.json");
    }

    #[test]
    fn server_relief_complete_butterfly_reduced_test_from_json() {
        let mut test_catena = ::default_instances::butterfly::new();
        test_catena.g_low = 9;
        test_catena.g_high = 9;
        server_relief_complete_test_from_json(
            test_catena, "test/test_vectors/catenaButterflyReduced.json");
    }

    #[test]
    #[cfg(feature="fulltest")]
    fn server_relief_complete_butterflyfull_test_from_json() {
        let test_catena = ::default_instances::butterfly_full::new();
        server_relief_complete_test_from_json(
            test_catena, "test/test_vectors/catenaButterflyFull.json");
    }

    #[test]
    #[cfg(feature="fulltest")]
    fn server_relief_complete_dragonfly_test_from_json() {
        let test_catena = ::default_instances::dragonfly::new();
        server_relief_complete_test_from_json(
            test_catena, "test/test_vectors/catenaDragonfly.json");
    }

    #[test]
    fn server_relief_complete_dragonfly_reduced_test_from_json() {
        let mut test_catena = ::default_instances::dragonfly::new();
        test_catena.g_low = 14;
        test_catena.g_high = 14;
        server_relief_complete_test_from_json(
            test_catena, "test/test_vectors/catenaDragonflyReduced.json");
    }

    #[test]
    #[cfg(feature="fulltest")]
    fn server_relief_complete_dragonflyfull_test_from_json() {
        let test_catena = ::default_instances::dragonfly_full::new();
        server_relief_complete_test_from_json(
            test_catena, "test/test_vectors/catenaDragonflyFull.json");
    }

    fn server_relief_client_test_from_json<T: Algorithms>(
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

            let client_result = catena.client_prep(
                pwd,
                salt,
                &ad,
                len,
                &gamma);

            assert_eq!(client_result.to_hex_string(),
                       expected);
        }
    }

    #[test]
    fn server_relief_client_dragonfly_reduced_test_from_json() {
        let mut test_catena = ::default_instances::dragonfly::new();
        test_catena.g_low = 14;
        test_catena.g_high = 14;
        server_relief_client_test_from_json(
            test_catena,
            "test/test_vectors/serverReliefClientDragonflyReduced.json");
    }

    #[test]
    fn server_relief_client_butterfly_reduced_test_from_json() {
        let mut test_catena = ::default_instances::butterfly::new();
        test_catena.g_low = 9;
        test_catena.g_high = 9;
        server_relief_client_test_from_json(
            test_catena,
            "test/test_vectors/serverReliefClientButterflyReduced.json");
    }

    #[test]
    fn server_relief_client_butterfly_reduced_different_g_test_from_json() {
        let mut test_catena = ::default_instances::butterfly::new();
        test_catena.g_low = 8;
        test_catena.g_high = 9;
        server_relief_client_test_from_json(
            test_catena,
            "test/test_vectors/serverReliefClientButterflyReducedDifferentG.json");
    }

    fn server_relief_server_test_from_json<T: Algorithms>(
        mut catena: ::catena::Catena<T>, file: &str)
    {
        let json = ::helpers::files::open_json(file.to_string());
        let unwrapped_json = json.as_ref().unwrap();
        let number_of_tests = unwrapped_json.clone().as_array().unwrap().len();

        for n in 0..number_of_tests {
            let ref inputs = unwrapped_json[n]["inputs"];
            let hash = inputs.parse_hex("hash");
            let len = inputs.parse_u16("outputLength");

            let ref outputs = unwrapped_json[n]["outputs"];
            let expected = outputs.parse_string("res");

            let result = catena.server_final(
                hash,
                len);

            assert_eq!(result.to_hex_string(),
            expected);
        }
    }

    #[test]
    fn server_relief_server_dragonfly_reduced_test_from_json() {
        let mut test_catena = ::default_instances::dragonfly::new();
        test_catena.g_low = 14;
        test_catena.g_high = 14;
        server_relief_server_test_from_json(
            test_catena,
            "test/test_vectors/serverReliefServerDragonflyReduced.json");
    }

    #[test]
    fn server_relief_server_butterfly_reduced_test_from_json() {
        let mut test_catena = ::default_instances::butterfly::new();
        test_catena.g_low = 9;
        test_catena.g_high = 9;
        server_relief_server_test_from_json(
            test_catena,
            "test/test_vectors/serverReliefServerButterflyReduced.json");
    }

    fn flap_test_from_json<T: Algorithms>(
        mut catena: ::catena::Catena<T>, file: &str)
    {
        let json = ::helpers::files::open_json(file.to_string());
        let unwrapped_json = json.as_ref().unwrap();
        let number_of_tests = unwrapped_json.clone().as_array().unwrap().len();

        for i in 0..number_of_tests {
            let ref inputs = unwrapped_json[i]["inputs"];
            let g = inputs.parse_u8("g");
            let pwd = inputs.parse_hex("pwd");
            let gamma = inputs.parse_hex("gamma");

            let ref outputs = unwrapped_json[i]["outputs"];
            let expected = outputs.parse_string("res");

            assert_eq!(catena.flap(g, pwd, &gamma).to_hex_string(),
            expected);
        }
    }

    #[test]
    fn flap_test_dragonfly_from_json() {
        let catena = ::default_instances::dragonfly::new();
        flap_test_from_json(catena, "test/test_vectors/flapDragonfly.json");
    }

    #[test]
    fn flap_test_dragonflyfull_from_json() {
        let catena = ::default_instances::dragonfly_full::new();
        flap_test_from_json(catena, "test/test_vectors/flapDragonflyFull.json");
    }

    #[test]
    fn flap_test_butterfly_from_json() {
        let catena = ::default_instances::butterfly::new();
        flap_test_from_json(catena, "test/test_vectors/flapButterfly.json");
    }

    #[test]
    fn flap_test_butterflyfull_from_json() {
        let catena = ::default_instances::butterfly_full::new();
        flap_test_from_json(catena, "test/test_vectors/flapButterflyFull.json");
    }

    fn kd_test_from_json<T: Algorithms>(
        mut catena: ::catena::Catena<T>, file: &str)
    {
        let json = ::helpers::files::open_json(file.to_string());
        let unwrapped_json = json.as_ref().unwrap();
        let number_of_tests = unwrapped_json.clone().as_array().unwrap().len();

        for i in 0..number_of_tests {
            let ref inputs = unwrapped_json[i]["inputs"];
            let pwd = inputs.parse_hex("pwd");
            let ad = inputs.parse_hex("ad");
            let salt = inputs.parse_hex("salt");
            let gamma = inputs.parse_hex("gamma");
            let ki = inputs.parse_hex("key_identifier");
            let output_length = inputs.parse_u16("output_length");
            let key_size = inputs.parse_u16("key_size");

            let ref outputs = unwrapped_json[i]["outputs"];
            let expected = outputs.parse_string("res");

            assert_eq!(catena.generate_key(
                    pwd,
                    &ad,
                    salt,
                    output_length,
                    gamma,
                    key_size,
                    ki).to_hex_string(),
            expected);
        }
    }

    #[test]
    #[cfg(feature="fulltest")]
    fn kd_test_butterfly_from_json() {
        let catena = ::default_instances::butterfly::new();
        kd_test_from_json(
            catena, "test/test_vectors/keyDerivationButterfly.json");
    }

    #[test]
    #[cfg(feature="fulltest")]
    fn kd_test_butterflyfull_from_json() {
        let catena = ::default_instances::butterfly_full::new();
        kd_test_from_json(
            catena, "test/test_vectors/keyDerivationButterflyFull.json");
    }

    #[test]
    fn kd_test_butterfly_reduced_from_json() {
        let mut catena = ::default_instances::butterfly::new();
        catena.g_low = 9;
        catena.g_high = 9;
        kd_test_from_json(
            catena, "test/test_vectors/keyDerivationButterflyReduced.json");
    }

    #[test]
    #[cfg(feature="fulltest")]
    fn kd_test_dragonfly_from_json() {
        let catena = ::default_instances::dragonfly::new();
        kd_test_from_json(catena, "test/test_vectors/keyDerivationDragonfly.json");
    }

    #[test]
    #[cfg(feature="fulltest")]
    fn kd_test_dragonflyfull_from_json() {
        let catena = ::default_instances::dragonfly_full::new();
        kd_test_from_json(
            catena, "test/test_vectors/keyDerivationDragonflyFull.json");
    }

    #[test]
    fn kd_test_dragonfly_reduced_from_json() {
        let mut catena = ::default_instances::dragonfly::new();
        catena.g_low = 14;
        catena.g_high = 14;
        kd_test_from_json(
            catena, "test/test_vectors/keyDerivationDragonflyReduced.json");
    }

    fn ci_update_test_from_json<T: Algorithms>(
        mut catena: ::catena::Catena<T>, file: &str)
    {
        let json = ::helpers::files::open_json(file.to_string());
        let unwrapped_json = json.as_ref().unwrap();
        let number_of_tests = unwrapped_json.clone().as_array().unwrap().len();

        for i in 0..number_of_tests {
            let ref inputs = unwrapped_json[i]["inputs"];
            let old_hash = inputs.parse_hex("oldHash");
            let g_new = inputs.parse_u8("gNew");
            let gamma = inputs.parse_hex("gamma");
            let out_length = inputs.parse_u16("outLen");

            let ref outputs = unwrapped_json[i]["outputs"];
            let expected = outputs.parse_string("res");

            let g_old: u8;
            {
                g_old = catena.g_high;
            }

            let output = catena.client_independent_update(
                old_hash,
                g_old,
                g_new,
                &gamma,
                out_length);

            assert_eq!(output.to_hex_string(),
                       expected);
        }
    }

    #[test]
    #[should_panic]
    fn ci_update_panic_test() {
        let mut catena = ::default_instances::dragonfly::new();

        let old_hash = vec![0u8];
        let g_old = 2;
        let g_new = 1;
        let gamma = vec![0u8];
        let out_length = 1;

        let _output = catena.client_independent_update(
            old_hash,
            g_old,
            g_new,
            &gamma,
            out_length);
    }

    #[test]
    fn ci_update_test_dragonfly_reduced_from_json() {
        let mut catena = ::default_instances::dragonfly::new();
        catena.g_low = 14;
        catena.g_high = 14;
        ci_update_test_from_json(
            catena, "test/test_vectors/ciUpdateDragonflyReduced.json");
    }

    fn keyed_ci_update_test_from_json<T: Algorithms>(
        mut catena: ::catena::Catena<T>, file: &str)
    {
        let json = ::helpers::files::open_json(file.to_string());
        let unwrapped_json = json.as_ref().unwrap();
        let number_of_tests = unwrapped_json.clone().as_array().unwrap().len();

        for i in 0..number_of_tests {
            let ref inputs = unwrapped_json[i]["inputs"];
            let old_hash = inputs.parse_hex("oldHash");
            let g_new = inputs.parse_u8("gNew");
            let gamma = inputs.parse_hex("gamma");
            let out_length = inputs.parse_u16("outLen");
            let server_key = inputs.parse_hex("key");
            let uid = inputs.parse_hex("userID");

            let ref outputs = unwrapped_json[i]["outputs"];
            let expected = outputs.parse_string("res");

            let g_old: u8;
            {
                g_old = catena.g_high;
            }

            let output = catena.keyed_client_independent_update(
                old_hash,
                g_old,
                g_new,
                &gamma,
                out_length,
                &server_key,
                &uid);

            assert_eq!(output.to_hex_string(),
                       expected, "test #{:?} failed", i);
        }
    }

    #[test]
    fn keyed_ci_update_test_dragonfly_reduced_from_json() {
        let mut catena = ::default_instances::dragonfly::new();
        catena.g_low = 14;
        catena.g_high = 14;
        keyed_ci_update_test_from_json(
            catena, "test/test_vectors/ciUpdateKeyedDragonflyReduced.json");
    }
}
