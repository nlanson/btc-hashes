# Bitcoin Hashes
A pure Rust implementation of hash functions and cryptographic computations used in Bitcoin.

## Installation
Add the following under `[dependencies]` in your `Cargo.toml`:
```
btc-hashes = { git = "https://github.com/nlanson/btc-hashes" }
```

## Usage
```rust
   use btc-hashes::{
      HashEngine, Sha256
   }
   
   let mut engine = Sha256::new();
   engine.input(<data as a slice of bytes>);
   let digest = engine.hash();
```