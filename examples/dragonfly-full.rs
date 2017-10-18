extern crate catena;

use std::env;
use catena::bytes::Bytes;
use catena::bytes::HexRepresentation;

fn main() {
    let mut catena_dff = catena::default_instances::dragonfly_full::new();

    let args: Vec<_> = env::args().collect();
    if args.len() == 6 {
    let pwd   = args[1].as_bytes().to_vec();
    let ad    = args[2].to_be_bytes();
    let salt  = args[3].to_be_bytes();
    let gamma = args[4].to_be_bytes();
    let output_length = args[5].parse::<u16>().unwrap();

    let hash = catena_dff.hash(&pwd, &salt, &ad, output_length, &gamma);
    println!("{:?}", hash.to_hex_string());
        } else {
            println!("Catena-Dragonfly-Full password scrambler");
            println!("");
            println!("Usage:");
            println!("  {:?} pwd ad salt gamma m", args[0]);
            println!("");
            println!("Arguments:");
            println!("  pwd:   password as string");
            println!("  ad:    associated data as hex");
            println!("  salt:  salt as hex");
            println!("  gamma: γ as hex");
            println!("  m:     output length");
        }
}
