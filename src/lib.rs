//! Implementation of the memory-consuming password-scrambler Catena in Rust.

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
