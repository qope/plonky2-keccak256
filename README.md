# Plonky2-keccak256

Currently, the keccak256 circuit with a fixed length is only available. In the future, I plan to implement a circuit with a variable input length (where the length does not need to be specified during circuit build).

## Usage

```rust
let mut input_t = vec![];
for i in 0..input_bits.len() {
    input_t.push(builder.constant_bool(input_bits[i]));
}
let output_t = keccak256_circuit(input_t, &mut builder);
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

```

```
