//! Implementation of the flexible memory-consuming password-scrambler Catena in Rust.
//!
//! # Design
//!
//! Each Catena instance is defined by the `Catena` struct:
//!
//! ```
//! #[derive(Clone, Debug)]
//! pub struct Catena <T: Algorithms> {
//!   /// H, H', F, Gamma and Phi.
//!   pub algorithms: T,
//!   /// The version ID of the Catena instance.
//!   pub vid: &'static str,
//!   /// Output length of H in bytes.
//!   pub n: usize,
//!   /// Output length of H' in bytes; k mod n = 0.
//!   pub k: usize,
//!   /// Minimum garlic.
//!   pub g_low: u8,
//!   /// Maximum garlic.
//!   pub g_high: u8,
//!   /// The depth of the graph structure.
//!   pub lambda: u8,
//! }
//! ```
//!
//! The trait `Algorithms` defines the variable components of Catena instances:
//!
//! ```
//! pub trait Algorithms {
//!     /// The cryptographic hash function H
//!     fn h (&self, x: &Vec<u8>) -> Vec<u8>;
//!
//!     /// The (possible reduced) hash function H'
//!     fn h_prime (&mut self, x: &Vec<u8>) -> Vec<u8>;
//!
//!     /// Reset the state of the reduced hash function H'.
//!     /// This is not neccessary if H' = H.
//!     fn reset_h_prime(&mut self) { }
//!
//!     /// The optional password-independent random layer Γ
//!     fn gamma(&mut self, garlic: u8, state: Vec<u8>,
//!       gamma: &Vec<u8>, k: usize) -> Vec<u8>;
//!
//!     /// The graph-based hash function F
//!     fn f(&mut self, garlic: &u8, state: &mut Vec<u8>,
//!       lambda: u8, n: usize, k: usize) -> Vec<u8>;
//!
//!     /// The optional password-dependent random layer Φ
//!     fn phi(&mut self, garlic: u8, state: Vec<u8>, mu: &Vec<u8>,
//!       k: usize) -> Vec<u8>;
//! }
//! ```
//!
//! # Usage
//!
//! There are two ways to use the Catena library. The first is to use a default
//! instance or variant of Catena:
//!
//! ```
//! let mut catena_dff = catena::default_instances::dragonfly_full::new();
//! let hash = catena_dff.hash(&pwd, &salt, &ad, output_length, &gamma);
//! ```
//!
//! The second possibility is to create a custom Catena instance. First one has to
//! define a struct with the `Algorithms` trait.
//!
//! ```
//! // define struct for H, H', Gamma, F and Phi
//! struct CustomCatena;
//!
//! // define H, H', Gamma, F and Phi
//! #[allow(unused_variables)]
//! impl catena::catena::Algorithms for CustomCatena {
//!     fn h (&self, x: &Vec<u8>) -> Vec<u8> {
//!         catena::components::hash::blake2b::hash(x)
//!     }
//!
//!     fn h_prime (&mut self, x: &Vec<u8>) -> Vec<u8> { self.h(x) }
//!
//!     fn gamma (&mut self, garlic: u8, state: Vec<u8>, gamma: &Vec<u8>, k: usize
//!     ) -> Vec<u8> { state }
//!
//!     fn f (&mut self, garlic: &u8, state: &mut Vec<u8>, lambda: u8, n: usize, k: usize
//!     ) -> Vec<u8> { state.clone() }
//!
//!     fn phi (&mut self, garlic: u8, state: Vec<u8>, mu: &Vec<u8>, k: usize) -> Vec<u8> { state }
//! }
//! ```
//!
//! In this example we define a Catena instance
//! which uses Blake2b for H and H' and the identity function for Gamma, F, and Phi.
//!
//! Then we can instantiate a `Catena` struct and set the values for the version ID,
//! g_low, g_high, lambda, n and k:
//!
//! ```
//! let mut custom_catena = catena::catena::Catena {
//!     algorithms: CustomCatena,
//!     vid: "CustomCatena",
//!     g_low: 10,
//!     g_high: 10,
//!     lambda: 10,
//!     n: 64,
//!     k: 64,
//! };
//! ```
//!
//! After that we can use this `Catena` instance like the predefined default instances and variants:
//!
//! ```
//! let hash = custom_catena.hash(&pwd, &salt, &ad, output_length, &gamma);
//! ```

#![deny(missing_docs,
        missing_debug_implementations,
        missing_copy_implementations,
        trivial_casts,
        trivial_numeric_casts,
        unsafe_code,
        unused_extern_crates,
        unused_import_braces,
        unused_qualifications,
        unused_results)]

pub mod catena;
pub mod default_instances;
pub mod variants;
pub mod components;
pub mod bytes;
mod helpers;

#[cfg(test)]
mod tests {
}
