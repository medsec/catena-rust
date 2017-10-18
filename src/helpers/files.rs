extern crate serde_json;
use std::fs::File;
use std::io::Read;
use bytes::Bytes;

/// Opens a text file
#[allow(dead_code)]
#[allow(unused_results)]
pub fn open_file(path: String) -> String {
    let mut file = File::open(path) .expect("Unable to open file");
    let mut content = String::new();
    file.read_to_string(&mut content).expect("Unable to read string");
    content
}

/// Opens a json file.
#[allow(dead_code)]
pub fn open_json(data: String) 
        -> Result<serde_json::Value, serde_json::Error> {
    let path: String = String::from(data); 
    let file = open_file(path);
    let file_slice: &str = &file[..];
    let v: serde_json::Value = serde_json::from_str(file_slice)?;
    Ok(v)
}

#[allow(unused_must_use)]
#[allow(dead_code)]
pub fn write_json_to_file(json: String, path: String) {
    use std::fs::File;
    use std::io::{Write, BufWriter};

    let file = File::create(path)
        .expect("unabel to create fiel");
    let mut file = BufWriter::new(file);
    file.write_all(json.as_bytes());
}

/// Parse tests from JSON files
pub trait JSONTests {
    /// Parse a string as a hex encoded byte vector.
    fn parse_hex(&self, field_name: &str) -> Vec<u8>;
    /// Parse an integer as `u8`.
    fn parse_u8(&self, field_name: &str) -> u8;
    /// Parse an integer as `u16`.
    fn parse_u16(&self, field_name: &str) -> u16;
    /// Parse an integer as `u32`.
    fn parse_u32(&self, field_name: &str) -> u32;
    /// Parse an integer as `u64`.
    fn parse_u64(&self, field_name: &str) -> u64;
    /// Parse an integer as `usize`.
    fn parse_usize(&self, field_name: &str) -> usize;
    /// Parse a string as UTF-8 encoded byte vector.
    fn parse_utf8string(&self, field_name: &str) -> Vec<u8>;
    /// Parse a string as `String`.
    fn parse_string(&self, field_name: &str) -> String;
}

impl JSONTests for serde_json::Value {
    fn parse_hex(&self, field_name: &str) -> Vec<u8> {
        let parsed_string = self[field_name].to_string();
        let trimmed_string = parsed_string.trim_matches('\"');
        trimmed_string.to_string().to_be_bytes()
    }

    fn parse_u8(&self, field_name: &str) -> u8 {
        self[field_name].as_u64().unwrap() as u8
    }

    fn parse_u16(&self, field_name: &str) -> u16 {
        self[field_name].as_u64().unwrap() as u16
    }

    fn parse_u32(&self, field_name: &str) -> u32 {
        self[field_name].as_u64().unwrap() as u32
    }

    fn parse_u64(&self, field_name: &str) -> u64 {
        self[field_name].as_u64().unwrap()
    }

    fn parse_usize(&self, field_name: &str) -> usize {
        self[field_name].as_u64().unwrap() as usize
    }

    fn parse_utf8string(&self, field_name: &str) -> Vec<u8> {
        let parsed_string = self[field_name].to_string();
        let trimmed_string = parsed_string.trim_matches('\"');
        trimmed_string.as_bytes().to_vec()
    }

    fn parse_string(&self, field_name: &str) -> String {
        let parsed_string = self[field_name].to_string();
        parsed_string.trim_matches('\"').to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_json_test() {
        let path: String = String::from("test/test_vectors/hFirstAny.json");
        let json = open_json(path);
        assert_eq!(json.as_ref().unwrap()[0]["outputs"]["w"],"42297f69f2eb6b985c20c7b4d593e11f6e9b1fe4104a37c3bb4e1700bf7bb49e81a7a4356277184050053e5ac37dbb737fcd49df3a00d4f4057b17017ae476b6");
    }
}
