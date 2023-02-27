# Plonky2-keccak256

Currently, the keccak256 circuit with a fixed length input of 512 bits is only available. In the future, I plan to implement a circuit with a variable input length (where the length does not need to be specified during circuit build).

# Test

```
cargo test -r test_keccak256 -- --nocapture
```

Result

```
running 1 test
time = 2433 ms
degree = 32768, degree_bits= 15
test keccak::tests::test_keccak256 ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 3 filtered out; finished in 6.20s
```

