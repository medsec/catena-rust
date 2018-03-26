# Catena-Rust

This is an implementation of the memory-consuming password scrambler Catena in
Rust.

##

For the tests the test vectors from the [Catena Test Vectors
Repository](https://github.com/RanaExMachina/catena-testvectors), which are
included as a git submodule, are required. To clone this repository with all
submodules run

```
git clone --recursive https://github.com/medsec/catena-rust.git
```

## Requirements

- rustc
- cargo

## Building Catena-Rust

For building the release version run

```
cargo build --release
```

## Tests

Run the tests with

```
cargo test
```

These tests use Catena instances with reduced garlic (14 for Dragonfly variants,
13 for Horsefly variants and 9 for Butterfly, Stonefly, Mydasfly and Lanternfly
variants).  To run the additional tests with the non-reduced variants you have
to enable the `fulltest` feature for compilation:

```
cargo test --features fulltest
```

### Code Coverage

Requirements:
- kcov (note that old version do not support Rust executables)

To get the line coverage build the test executable with

```
$ cargo test --no-run
```

And the build the report with

```
$ kcov --verify --exclude-pattern=/.cargo target/coverage target/debug/$TEST_EXECUTABLE
```

The `--verify` flag makes kcov skip invalid breakpoints. With
`--exclude-pattern=/.cargo` external crates get ignored in the report. With
better Rust support those flags may not be needed in the future.

On systems with older kcov versions which do not have the `verify` flag, you can
just omit it.

The report is then found in `target/coverage/index.html`.

## Documentation

Build the documentation with

```
cargo doc
```

The compiled documentation is in `target/doc/catena`.

## Examples

### CustomCatena

This example shows how to define and use a custom version of Catena.
Build with

```
cargo build --example customcatena
```

### Dragonfly Full

This example shows how to use the predefined default instance Catena-Dragonfly.
Build with

```
cargo build --example dragonfly-full
```
