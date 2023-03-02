# Plonky2-keccak256

Plonky2 implementation of Solidity compatible Keccak256 circuit.

## Usage

```rust
let mut input_target = vec![];
for i in 0..input_bits.len() {
    input_target.push(builder.constant_bool(input_bits[i]));
}
let output_target = keccak256_circuit(input_target, &mut builder);
```

## Test

```

cargo test -r test_keccak256 -- --nocapture

```

Result

```

[src/keccak.rs:119] num_blocks = 1
time = 2654 ms
degree = 32768, degree_bits= 15
test keccak::tests::test_keccak256_circuit ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 6 filtered out; finished in 6.85s

```
