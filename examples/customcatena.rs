extern crate catena;

// This is an example on how to define and use own Catena versions

// define struct for H, H', Gamma, F and Phi
struct CustomCatena;

// define H, H', Gamma, F and Phi
#[allow(unused_variables)]
impl catena::catena::Algorithms for CustomCatena {
    fn h (&self, x: &Vec<u8>) -> Vec<u8> {
        catena::components::hash::blake2b::hash(x)
    }
    fn h_prime (&mut self, x: &Vec<u8>) -> Vec<u8> { self.h(x) }
    fn gamma (&mut self, garlic: u8, state: Vec<u8>, gamma: &Vec<u8>, k: usize)
        -> Vec<u8> { state }
    fn f (&mut self, garlic: &u8, state: &mut Vec<u8>, lambda: u8, n: usize, k: usize)
        -> Vec<u8> { state.clone() }
    fn phi (&mut self, garlic: u8, state: Vec<u8>, mu: &Vec<u8>, k: usize) -> Vec<u8> { state }
}

fn main() {
    // create an instance of CustomCatena
    let mut custom_catena = catena::catena::Catena {
        algorithms: CustomCatena,
        vid: "CustomCatena",
        g_low: 10,
        g_high: 10,
        lambda: 10,
        n: 64,
        k: 64,
    };

    let pwd   = b"password".to_vec();
    let ad    = b"associated_data".to_vec();
    let salt  = b"salt".to_vec();
    let gamma = b"gamma".to_vec();
    let output_length = 64;

    // use the methods of the custom Catena
    let hash = custom_catena.hash(&pwd, &salt, &ad, output_length, &gamma);
    println!("{:?}", hash);
}
