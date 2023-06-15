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

[src/keccak.rs:276] builder.num_gates() = 13702
time = 1028 ms
degree = 16384, degree_bits= 14
test keccak::tests::test_keccak256_circuit ... ok
```
