//! Blake2b-1, a reduced version of Blake2b with a single round and
//! finalization.

const BLAKE2B_IV: [u64; 8] = [0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
                              0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
                              0x510e527fade682d1, 0x9b05688c2b3e6c1f,
                              0x1f83d9abfb41bd6b, 0x5be0cd19137e2179];

const BLAKE2B_IV0: u64 = 0x6a09e667f2bdc948;

const BLAKE2B_SIGMA: [[usize; 16]; 12] =
[
    [ 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 ],
    [14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 ],
    [11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 ],
    [ 7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 ],
    [ 9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 ],
    [ 2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 ],
    [12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 ],
    [13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 ],
    [ 6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 ],
    [10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0 ],
    [ 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 ],
    [14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 ]
];

const BLOCK_LENGTH_BYTES: u64 = 128;

/// The internal state of Blake2b_1. This has to be a field of the algorithms of
/// a Catena instance.
///
/// See `catena::default_instances::butterfly` and
/// `catena::default_instances::dragonfly` for examples how to use Blake2b1.
#[derive(Clone, Copy, Debug)]
pub struct Blake2b1 {
    /// current round of Blake2b_1
    r: u8,
    h: [u64; 8],
    v: [u64; 16],
    t_0: u64,
    t_1: u64,
}

impl Default for Blake2b1 {
    fn default() -> Blake2b1{
        let mut new_blake = Blake2b1{
            r: 0,
            v: [0; 16],
            h: [0; 8],
            t_0: 0,
            t_1: 0,
        };
        new_blake.reset();
        new_blake
    }
}

impl Blake2b1 {
    /// Set the current round number to `r % 12`.
    pub fn set_r(&mut self, r: u8) {
        self.r = r % 12;
    }

    /// Increase the internal round counter by 1. If the internal round is 11 it
    /// gets set to 0.
    pub fn increase_r(&mut self) {
        self.r = (self.r + 1) % 12;
    }

    /// Reset the internal state of Blake2b_1.
    pub fn reset(&mut self) {
        self.r = 0;
        self.t_0 = 0;
        self.t_1 = 0;
        self.v = [0; 16];
        self.h = [0; 8];

        self.init();
    }

    /// Call the reduced hash function Blake2b_1 and increase the internal round
    /// counter `r` by 1. The input x has to be of length 128.
    pub fn hash(&mut self, x: &Vec<u8>) -> Vec<u8> {

        self.t_0 += BLOCK_LENGTH_BYTES;
        if self.t_0 == 0 {
            self.t_1 += 1;
        }

        self.compress(x);

        let mut out: Vec<u8> = Vec::new();
        for i in 0..self.h.len() {
            out.append(&mut u64_to_bytes(self.h[i]).to_vec());
        }

        self.increase_r();

        out
    }

    fn init(&mut self) {
        self.h = [BLAKE2B_IV0,
                  BLAKE2B_IV[1],
                  BLAKE2B_IV[2],
                  BLAKE2B_IV[3],
                  BLAKE2B_IV[4],
                  BLAKE2B_IV[5],
                  BLAKE2B_IV[6],
                  BLAKE2B_IV[7]];
    }

    fn initialize_v(&mut self) {
        self.v = [self.h[0], self.h[1], self.h[2], self.h[3],
                  self.h[4], self.h[5], self.h[6], self.h[7],
                  BLAKE2B_IV[0],
                  BLAKE2B_IV[1],
                  BLAKE2B_IV[2],
                  BLAKE2B_IV[3],
                  self.t_0 ^ BLAKE2B_IV[4],
                  self.t_1 ^ BLAKE2B_IV[5],
                  !BLAKE2B_IV[6],
                  BLAKE2B_IV[7]];
    }

    fn compress(&mut self, message: &[u8]) {
        self.initialize_v();

        let mut m: [u64; 16] = [0;16];
        // TODO: use iterator
        for i in 0..16 {
            m[i] = bytes_to_u64(message, i * 8);
        }

        let round: usize;
        {
            round = self.r as usize;
        }

        self.g(m[BLAKE2B_SIGMA[round][0]],
               m[BLAKE2B_SIGMA[round][1]], 0, 4, 8, 12);
        self.g(m[BLAKE2B_SIGMA[round][2]],
               m[BLAKE2B_SIGMA[round][3]], 1, 5, 9, 13);
        self.g(m[BLAKE2B_SIGMA[round][4]],
               m[BLAKE2B_SIGMA[round][5]], 2, 6, 10, 14);
        self.g(m[BLAKE2B_SIGMA[round][6]],
               m[BLAKE2B_SIGMA[round][7]], 3, 7, 11, 15);
        self.g(m[BLAKE2B_SIGMA[round][8]],
               m[BLAKE2B_SIGMA[round][9]],  0, 5, 10, 15);
        self.g(m[BLAKE2B_SIGMA[round][10]],
               m[BLAKE2B_SIGMA[round][11]], 1, 6, 11, 12);
        self.g(m[BLAKE2B_SIGMA[round][12]],
               m[BLAKE2B_SIGMA[round][13]], 2, 7, 8, 13);
        self.g(m[BLAKE2B_SIGMA[round][14]],
               m[BLAKE2B_SIGMA[round][15]], 3, 4, 9, 14);

        for offset in 0..8 {
            self.h[offset] =
                self.h[offset] ^ self.v[offset] ^ self.v[offset + 8];
        }
    }

    fn g(&mut self, m1: u64, m2: u64, pos_a: usize, pos_b: usize, pos_c: usize,
         pos_d: usize) {
        self.v[pos_a] = self.v[pos_a].wrapping_add(self.v[pos_b]);
        self.v[pos_a] = self.v[pos_a].wrapping_add(m1);
        self.v[pos_d] = rotr64(self.v[pos_d] ^ self.v[pos_a], 32);
        self.v[pos_c] = self.v[pos_c].wrapping_add(self.v[pos_d]);
        self.v[pos_b] = rotr64(self.v[pos_b] ^ self.v[pos_c], 24);

        self.v[pos_a] = self.v[pos_a].wrapping_add(self.v[pos_b]);
        self.v[pos_a] = self.v[pos_a].wrapping_add(m2);
        self.v[pos_d] = rotr64(self.v[pos_d] ^ self.v[pos_a], 16);
        self.v[pos_c] = self.v[pos_c].wrapping_add(self.v[pos_d]);
        self.v[pos_b] = rotr64(self.v[pos_b] ^ self.v[pos_c], 63);
    }
}

fn rotr64(x: u64, rot: usize) -> u64 {
    x.rotate_right(rot as u32) | (x << (64 - rot))
}

/// Convert an `u64` value into `[u8; 8]` in little-endian byte order.
fn u64_to_bytes(u_64: u64) -> [u8; 8] {
    [u_64        as u8,
    (u_64 >>  8) as u8,
    (u_64 >> 16) as u8,
    (u_64 >> 24) as u8,
    (u_64 >> 32) as u8,
    (u_64 >> 40) as u8,
    (u_64 >> 48) as u8,
    (u_64 >> 56) as u8]
}

/// Convert a little-endian `&[u8]` to a little endian `u64` value.
fn bytes_to_u64(bytes: &[u8], offset: usize) -> u64 {
    ( bytes[offset    ] as u64 & 0xFF)        |
    ((bytes[offset + 1] as u64 & 0xFF) <<  8) |
    ((bytes[offset + 2] as u64 & 0xFF) << 16) |
    ((bytes[offset + 3] as u64 & 0xFF) << 24) |
    ((bytes[offset + 4] as u64 & 0xFF) << 32) |
    ((bytes[offset + 5] as u64 & 0xFF) << 40) |
    ((bytes[offset + 6] as u64 & 0xFF) << 48) |
    ((bytes[offset + 7] as u64 & 0xFF) << 56)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use bytes::HexRepresentation;

    #[test]
    fn blake2b1_test() {
        let test_file = "test/test_vectors/blake2b1.json".to_string();

        let mut blake2b1: Blake2b1 = Default::default();

        let json = ::helpers::files::open_json(test_file);
        let unwrapped_json = json.as_ref().unwrap();
        let number_of_tests = unwrapped_json.clone().as_array().unwrap().len();

        for i in 0..number_of_tests {
            let ref inputs = unwrapped_json[i]["inputs"];
            let ref outputs = unwrapped_json[i]["outputs"]["res"];
            let expected_tmp = outputs.to_string();
            let expected = expected_tmp.trim_matches('\"');

            let reset = inputs["reset"].as_bool().unwrap();
            let data_untrimmed = inputs["data"].to_string();
            let data = data_untrimmed.trim_matches('\"');
            let round: u8 = inputs["r"].as_u64().unwrap() as u8;

            if reset {
                blake2b1.reset();
            }

            blake2b1.set_r(round);

            let output = blake2b1.hash(&data.to_string().to_be_bytes());

            assert_eq!(output.to_hex_string(),
                       expected.to_string().to_be_bytes().to_hex_string());
        }
    }

    #[test]
    fn increase_r_test() {
        let mut blake2b1: Blake2b1 = Default::default();
        for _ in 0..15 {
            blake2b1.increase_r();
        }
        assert_eq!(blake2b1.r, 3);
    }
}
