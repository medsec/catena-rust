extern crate catena;
extern crate time;

use catena::bytes::Bytes;
use std::error::Error;
use std::io::prelude::*;
use std::fs::File;
use std::path::Path;

fn main() {
    let pwd   = "012345".as_bytes().to_vec();
    let ad    = "000000".to_string().to_be_bytes();
    let salt  = "6789ab".to_string().to_be_bytes();
    let gamma = "6789ab".to_string().to_be_bytes();
    let output_length = 64;

    let number_of_tests = 10;

    let catena_df = catena::default_instances::dragonfly::new();
    let catena_dff = catena::default_instances::dragonfly_full::new();
    let catena_bf = catena::default_instances::butterfly::new();
    let catena_bff = catena::default_instances::butterfly_full::new();
    let catena_hf = catena::variants::horsefly::new();
    let catena_hff = catena::variants::horsefly_full::new();
    let catena_sf = catena::variants::stonefly::new();
    let catena_sff = catena::variants::stonefly_full::new();
    let catena_mf = catena::variants::mydasfly::new();
    let catena_mff = catena::variants::mydasfly_full::new();
    let catena_lf = catena::variants::lanternfly::new();
    let catena_lff = catena::variants::lanternfly_full::new();

    benchmark(
        catena_df,
        number_of_tests,
        "performance_df.txt",
        &pwd,
        &salt,
        &ad,
        output_length,
        &gamma);

    benchmark(
        catena_dff,
        number_of_tests,
        "performance_dff.txt",
        &pwd,
        &salt,
        &ad,
        output_length,
        &gamma);

    benchmark(
        catena_bf,
        number_of_tests,
        "performance_bf.txt",
        &pwd,
        &salt,
        &ad,
        output_length,
        &gamma);

    benchmark(
        catena_bff,
        number_of_tests,
        "performance_bff.txt",
        &pwd,
        &salt,
        &ad,
        output_length,
        &gamma);

    benchmark(
        catena_hf,
        number_of_tests,
        "performance_hf.txt",
        &pwd,
        &salt,
        &ad,
        output_length,
        &gamma);

    benchmark(
        catena_hff,
        number_of_tests,
        "performance_hff.txt",
        &pwd,
        &salt,
        &ad,
        output_length,
        &gamma);

    benchmark(
        catena_sf,
        number_of_tests,
        "performance_sf.txt",
        &pwd,
        &salt,
        &ad,
        output_length,
        &gamma);

    benchmark(
        catena_sff,
        number_of_tests,
        "performance_sff.txt",
        &pwd,
        &salt,
        &ad,
        output_length,
        &gamma);

    benchmark(
        catena_lf,
        number_of_tests,
        "performance_lf.txt",
        &pwd,
        &salt,
        &ad,
        output_length,
        &gamma);

    benchmark(
        catena_lff,
        number_of_tests,
        "performance_lff.txt",
        &pwd,
        &salt,
        &ad,
        output_length,
        &gamma);

    benchmark(
        catena_mf,
        number_of_tests,
        "performance_mf.txt",
        &pwd,
        &salt,
        &ad,
        output_length,
        &gamma);

    benchmark(
        catena_mff,
        number_of_tests,
        "performance_mff.txt",
        &pwd,
        &salt,
        &ad,
        output_length,
        &gamma);
}

fn benchmark<T: catena::catena::Algorithms>(
    mut catena: catena::catena::Catena<T>,
    number_of_tests: usize,
    filename: &'static str,
    pwd: &Vec<u8>,
    salt: &Vec<u8>,
    ad: &Vec<u8>,
    output_length: u16,
    gamma: &Vec<u8>)
{
    let start = time::now();
    for _ in 0..number_of_tests {
        let _hash = catena.hash(pwd, salt, ad, output_length, gamma);
    }
    let end = time::now();
    let time = (end - start).num_milliseconds() / number_of_tests as i64;

    let path = Path::new(filename);
    let display = path.display();

    // Open a file in write-only mode, returns `io::Result<File>`
    let mut file = match File::create(&path) {
        Err(why) => panic!("couldn't create {}: {}",
                           display,
                           why.description()),
        Ok(file) => file,
    };

    // Write the current time to `file`, returns `io::Result<()>`
    match file.write_all(time.to_string().as_bytes()) {
        Err(why) => {
            panic!("couldn't write to {}: {}", display,
                   why.description())
        },
        Ok(_) => println!("{:?}: {:?}", filename, time),
    }
}
