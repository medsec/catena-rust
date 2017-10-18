//! Functions and traits for byte-vectors

/// Hex representation
pub trait HexRepresentation {
    /// convert to hex string
    fn to_hex_string(&self) -> String;
}

impl HexRepresentation for Vec<u8> {
    fn to_hex_string(&self) -> String {
        let strs: Vec<String> = self.iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        strs.join("")
    }
}

impl <T: Bytes> HexRepresentation for T {
    fn to_hex_string(&self) -> String {
        self.to_be_bytes().to_hex_string()
    }
}

/// Trait for the internal state in Catena
pub trait ByteState {
    /// get a word of `word_size` at position `index`
    fn get_word(&self, word_size: usize, index: usize) -> Vec<u8>;
    /// set a word of `word_size` at position `index`
    fn set_word(&mut self, word_size: usize, index: usize, new_value: Vec<u8>);
    /// reverse all words
    fn reverse_words(&mut self, word_size: usize);
}

impl ByteState for Vec<u8> {
    fn get_word(&self, word_size: usize, index: usize) -> Vec<u8> {
        [&self[index * word_size .. (index + 1) * word_size]].concat()
    }

    fn set_word(&mut self, word_size: usize, index: usize, new_value: Vec<u8>) {
        for i in 0..word_size {
            self[index * word_size + i] = new_value[i];
        }
    }

    fn reverse_words(&mut self, word_size: usize) {
        // TODO if len mod size != 0 panic stuff
        let mut reversed: Vec<u8> = Vec::new();
        let number_of_words = self.len() / word_size;
        // iterate over all words
        for i in 0..number_of_words {
            for j in 0..word_size {
                let word_pos = i * word_size;
                let end_of_word = word_pos + word_size - 1;
                // add each word in reversed order
                reversed.push(self[end_of_word - j]);
            }
        }
        for i in 0..reversed.len() {
            self[i] = reversed[i];
        }
    }
}

impl <T: Bytes> ByteState for T {
    fn get_word(&self, word_size: usize, index: usize) -> Vec<u8> {
        self.to_be_bytes().get_word(word_size, index)
    }

    fn set_word(&mut self, word_size: usize, index: usize, new_value: Vec<u8>) {
        self.to_be_bytes().set_word(word_size, index, new_value)
    }

    fn reverse_words(&mut self, word_size: usize) {
        self.to_be_bytes().reverse_words(word_size);
    }
}

/// Everything that is convertible to a Vec<u8>
pub trait Bytes {
    /// convert to `Vec<u8>` in big endian
    fn to_be_bytes(&self) -> Vec<u8>;
    /// convert to `Vec<u8> in little endian
    fn to_le_bytes(&self) -> Vec<u8>;
}

impl Bytes for u8 {
    fn to_be_bytes(&self) -> Vec<u8> {
        vec![*self]
    }

    fn to_le_bytes(&self) -> Vec<u8> {
        vec![*self]
    }
}

impl Bytes for u16 {
    fn to_be_bytes(&self) -> Vec<u8> {
        let v_1: u8 = ((*self >> 8) & 0xff) as u8;
        let v_2: u8 = ( *self       & 0xff) as u8;

        let v = vec![v_1, v_2];
        v
    }

    fn to_le_bytes(&self) -> Vec<u8> {
        let v_1: u8 = ( *self       & 0xff) as u8;
        let v_2: u8 = ((*self >> 8) & 0xff) as u8;

        let v = vec![v_1, v_2];
        v
    }
}

impl Bytes for u32 {
    fn to_be_bytes(&self) -> Vec<u8> {
    let v_1: u8 = ((*self >> 24) & 0xff) as u8;
    let v_2: u8 = ((*self >> 16) & 0xff) as u8;
    let v_3: u8 = ((*self >> 8)  & 0xff) as u8;
    let v_4: u8 = ( *self        & 0xff) as u8;

    let v = vec![v_1, v_2, v_3, v_4];
    v
    }

    fn to_le_bytes(&self) -> Vec<u8> {
    let v_1: u8 = ( *self        & 0xff) as u8;
    let v_2: u8 = ((*self >> 8)  & 0xff) as u8;
    let v_3: u8 = ((*self >> 16) & 0xff) as u8;
    let v_4: u8 = ((*self >> 24) & 0xff) as u8;

    let v = vec![v_1, v_2, v_3, v_4];
    v
    }
}

impl Bytes for u64 {
    fn to_be_bytes(&self) -> Vec<u8> {
        let mut vec_u8: Vec<u8> = Vec::new();
        vec_u8.append(&mut(vec!(((self & 0xff00000000000000u64) >> 56) as u8)));
        vec_u8.append(&mut(vec!(((self & 0x00ff000000000000u64) >> 48) as u8)));
        vec_u8.append(&mut(vec!(((self & 0x0000ff0000000000u64) >> 40) as u8)));
        vec_u8.append(&mut(vec!(((self & 0x000000ff00000000u64) >> 32) as u8)));
        vec_u8.append(&mut(vec!(((self & 0x00000000ff000000u64) >> 24) as u8)));
        vec_u8.append(&mut(vec!(((self & 0x0000000000ff0000u64) >> 16) as u8)));
        vec_u8.append(&mut(vec!(((self & 0x000000000000ff00u64) >> 8 ) as u8)));
        vec_u8.append(&mut(vec!(( self & 0x00000000000000ffu64       ) as u8)));
        vec_u8
    }

    fn to_le_bytes(&self) -> Vec<u8> {
        let mut vec_u8: Vec<u8> = Vec::new();
        vec_u8.append(&mut(vec!(( self & 0x00000000000000ffu64       ) as u8)));
        vec_u8.append(&mut(vec!(((self & 0x000000000000ff00u64) >> 8 ) as u8)));
        vec_u8.append(&mut(vec!(((self & 0x0000000000ff0000u64) >> 16) as u8)));
        vec_u8.append(&mut(vec!(((self & 0x00000000ff000000u64) >> 24) as u8)));
        vec_u8.append(&mut(vec!(((self & 0x000000ff00000000u64) >> 32) as u8)));
        vec_u8.append(&mut(vec!(((self & 0x0000ff0000000000u64) >> 40) as u8)));
        vec_u8.append(&mut(vec!(((self & 0x00ff000000000000u64) >> 48) as u8)));
        vec_u8.append(&mut(vec!(((self & 0xff00000000000000u64) >> 56) as u8)));
        vec_u8
    }
}

impl Bytes for Vec<u64> {
    fn to_be_bytes(&self) -> Vec<u8> {
        let mut vec_u8: Vec<u8> = Vec::new();
        for i in self {
            vec_u8.append(&mut i.to_be_bytes());
        }
        vec_u8
    }

    fn to_le_bytes(&self) -> Vec<u8> {
        unimplemented!();
    }
}

impl Bytes for String {
    fn to_be_bytes(&self) -> Vec<u8> {
        let mut result: Vec<u8> = Vec::new();

        let mut counter = 0;
        let mut first_char: char = '0';
        for c in self.chars() {
            if counter % 2 == 0 {
                first_char = c;
            } else {
                let mut hex = String::from("");
                hex.push(first_char);
                hex.push(c);
                match u8::from_str_radix(&hex, 16) {
                    Err(why) => panic!("{:?}", why),
                    Ok(value) => result.push(value),
                }
            }

            counter = counter + 1;
        }
        result
    }

    fn to_le_bytes(&self) -> Vec<u8> {
        unimplemented!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_to_vec_u8_test_1() {
        let x = "78".to_string();
        let expected: Vec<u8> = vec![120];

        assert_eq!(x.to_be_bytes(), expected);
    }

    #[test]
    fn hex_to_vec_u8_test_2() {
        let mut input = "786A02F742015903C6C6FD852552D272912F4740E".to_string();
        input.push_str(&"15847618A86E217F71F5419D25E1031AFEE58531".to_string());
        input.push_str(&"3896444934EB04B903A685B1448B755D56F701AF".to_string());
        input.push_str(&"E9BE2CE".to_string());

        let expected: Vec<u8> = vec![0x78, 0x6a, 0x02, 0xf7, 0x42, 0x01, 0x59,
                                     0x03, 0xc6, 0xc6, 0xfd, 0x85, 0x25, 0x52,
                                     0xd2, 0x72, 0x91, 0x2f, 0x47, 0x40, 0xe1,
                                     0x58, 0x47, 0x61, 0x8a, 0x86, 0xe2, 0x17,
                                     0xf7, 0x1f, 0x54, 0x19, 0xd2, 0x5e, 0x10,
                                     0x31, 0xaf, 0xee, 0x58, 0x53, 0x13, 0x89,
                                     0x64, 0x44, 0x93, 0x4e, 0xb0, 0x4b, 0x90,
                                     0x3a, 0x68, 0x5b, 0x14, 0x48, 0xb7, 0x55,
                                     0xd5, 0x6f, 0x70, 0x1a, 0xfe, 0x9b, 0xe2,
                                     0xce];
        assert_eq!(input.to_be_bytes(), expected);
    }
}
