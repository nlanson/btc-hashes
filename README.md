# Rust Secure Hash Algorithm 2
A pure Rust implementation of the SHA2 hash function family

## Installation
Add the following under `[dependencies]` in your `Cargo.toml`:
```
sha2 = { git = "https://github.com/nlanson/sha2" }
```

## Usage
```rust
   // ...
   use sha2::{Sha224, Sha256, HashEngine};
   // ...
   
   let mut hash_engine = Sha256::new();
   hash_engine.input(<data as a slice of bytes>);
   let digest = hash_engine.hash();
```



