use crate::constants::{ROTR, ROUND_CONSTANTS};

fn round(a: [u64; 25], rc: u64) -> [u64; 25] {
    let mut a = a;
    // θ step
    let mut c = [0u64; 5];
    for x in 0..5 {
        c[x] = xor(
            a[x + 0 * 5],
            xor(
                a[x + 1 * 5],
                xor(a[x + 2 * 5], xor(a[x + 3 * 5], a[x + 4 * 5])),
            ),
        );
    }
    let mut d = [0u64; 5];
    for x in 0..5 {
        d[x] = xor(c[(x + 4) % 5], rot(c[(x + 1) % 5], 1));
    }
    for x in 0..5 {
        for y in 0..5 {
            a[x + y * 5] = xor(a[x + y * 5], d[x]);
        }
    }

    // ρ and π steps
    let mut b = [0u64; 25];
    for x in 0..5 {
        for y in 0..5 {
            b[y + ((2 * x + 3 * y) % 5) * 5] = rot(a[x + y * 5], ROTR[x + y * 5]);
        }
    }

    // χ step
    for x in 0..5 {
        for y in 0..5 {
            a[x + y * 5] = xor(
                b[x + y * 5],
                and(not(b[(x + 1) % 5 + y * 5]), b[(x + 2) % 5 + y * 5]),
            );
        }
    }

    // ι step
    a[0] = xor(a[0], rc);
    return a;
}

fn keccakf(input: Vec<bool>) -> Vec<bool> {
    let a = input.chunks(64).map(|e| from_bits(e)).collect::<Vec<_>>();
    let mut a = a.try_into().unwrap();
    for i in 0..24 {
        a = round(a, ROUND_CONSTANTS[i]);
    }
    return a.iter().flat_map(|x| u64_to_bits(*x)).collect::<Vec<_>>();
}

fn from_bits(bools: &[bool]) -> u64 {
    let mut result: u64 = 0;
    let mut shift = 0;
    for &bit in bools {
        if bit {
            result |= 1 << shift;
        }
        shift += 1;
        if shift == 64 {
            break;
        }
    }
    result
}

fn u64_to_bits(num: u64) -> Vec<bool> {
    let mut result = Vec::with_capacity(64);
    let mut n = num;
    for _ in 0..64 {
        result.push(n & 1 == 1);
        n >>= 1;
    }
    result
}

fn u8_to_bits(num: u8) -> Vec<bool> {
    let mut result = Vec::with_capacity(8);
    let mut n = num;
    for _ in 0..8 {
        result.push(n & 1 == 1);
        n >>= 1;
    }
    result
}

fn from_bits_to_u8(bools: &[bool]) -> u8 {
    assert_eq!(bools.len(), 8);
    let mut result: u8 = 0;
    let mut shift = 0;
    for &bit in bools {
        if bit {
            result |= 1 << shift;
        }
        shift += 1;
        if shift == 8 {
            break;
        }
    }
    result
}

fn xor(x: u64, y: u64) -> u64 {
    return x ^ y;
}

fn rot(x: u64, i: usize) -> u64 {
    return x.rotate_left(i as u32);
}

fn and(x: u64, y: u64) -> u64 {
    return x & y;
}

fn not(x: u64) -> u64 {
    return !x;
}

pub fn keccak256(input: &[u8]) -> Vec<u8> {
    let block_size = 136; // in bytes
    let num_blocks = input.len() / block_size + 1;

    let mut padded = vec![0u8; block_size * num_blocks];
    for i in 0..input.len() {
        padded[i] = input[i];
    }
    padded[input.len()] = 0x01;
    let last_index = padded.len() - 1;
    padded[last_index] ^= 0x80;

    let padded_bits = padded
        .iter()
        .flat_map(|x| u8_to_bits(*x))
        .collect::<Vec<_>>();

    let mut m = vec![false; 1600];

    for i in 0..num_blocks {
        for j in 0..block_size * 8 {
            m[j] ^= padded_bits[i * block_size * 8 + j];
        }
        m = keccakf(m);
    }
    let z = m[0..256]
        .chunks(8)
        .map(|x| from_bits_to_u8(x))
        .collect::<Vec<_>>();
    z
}

pub fn keccak256_bits(input: Vec<bool>) -> Vec<bool> {
    assert_eq!(input.len() % 8, 0); // input should be bytes.
    let block_size_in_bytes = 136; // in bytes
    let input_len_in_bytes = input.len() / 8;
    let num_blocks = input_len_in_bytes / block_size_in_bytes + 1;

    let mut padded = vec![];
    for _ in 0..block_size_in_bytes * 8 * num_blocks {
        padded.push(false);
    }

    // register input
    for i in 0..input_len_in_bytes * 8 {
        padded[i] = input[i];
    }

    // append 0x01 = 1000 0000 after the last input
    padded[input_len_in_bytes * 8] = true;

    // pad 0s
    let last_index = padded.len() - 1;
    for i in input_len_in_bytes * 8 + 1..last_index {
        padded[i] = false;
    }

    // xor 0x80 = 0000 0001 with the last byte.
    // however the last bit is ensured to be 0, so just fill 1.
    padded[last_index] = true;

    let mut m = vec![false; 1600];
    for i in 0..num_blocks {
        for j in 0..block_size_in_bytes * 8 {
            let word = j / 64;
            let bit = j % 64;
            m[word * 64 + bit] ^= padded[i * block_size_in_bytes * 8 + j];
        }
        m = keccakf(m);
    }
    m[0..256].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;
    use tiny_keccak::{Hasher, Keccak};

    fn expected_keccak(input: &[u8]) -> String {
        let mut hasher = Keccak::v256();
        hasher.update(&input);
        let mut hash = [0u8; 32];
        hasher.finalize(&mut hash);
        let expected = hex::encode(hash);
        expected
    }

    fn random_bytes_vec<R: Rng>(lenght: usize, rng: &mut R) -> Vec<u8> {
        let rand_vec = (0..lenght).map(|_| rng.gen()).collect::<Vec<u8>>();
        rand_vec
    }

    #[test]
    fn test_keccak256_without_ciruit() {
        let rng = &mut rand::thread_rng();
        for length in [1, 4, 136, 272, 1000, 20000] {
            let input = random_bytes_vec(length, rng);
            let z = keccak256(&input);
            let hex_out = hex::encode(&z);
            assert_eq!(hex_out, expected_keccak(&input));
        }
    }

    #[test]
    fn test_keccak256_bits_without_ciruit() {
        let rng = &mut rand::thread_rng();
        for length in [1, 4, 136, 272, 1000, 20000] {
            let input = random_bytes_vec(length, rng);
            let input_bits = input
                .iter()
                .flat_map(|x| u8_to_bits(*x))
                .collect::<Vec<_>>();
            let z = keccak256_bits(input_bits);
            let z_u8 = z.chunks(8).map(|x| from_bits_to_u8(x)).collect::<Vec<_>>();
            let hex_out = hex::encode(&z_u8);
            assert_eq!(hex_out, expected_keccak(&input));
        }
    }

    #[test]
    fn test_keccakf_without_ciruit() {
        let input = "bb45f489bea73ef400b0ef4cd65dcec3565b0fd75c6eb248f1fefc84dd216650327e5a5c9b02ed7ce898f8ecb2e045cded87742a7723e7fddd9ac96c8aa70f4601000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        let expected_output = "61060054a4f8cd82609992a7604a95c9165bc95ae016a5299dd7d400dddbea9a3069922d826066fae8aad9aac3d937d6b6db11d4e3ce7663ef4236ca2f1a97a3de6259030506c8f50dcec6588ba1e7598a5f39e74f8f858f3fc04a371d52d761cb369205487758026a035dc5edd42a6bb4f1cc84c2f5a4f7915993a7b209935c40a06104fc2d4d3e337a79a6671f69fb0b3a14ccdf72f66f59828ab0f43bedab3622aa17746d3e536b9bd39974f215916563a5ed55d944d6137ce8cf03677e57bc75e502054f51b0";

        let input_u8 = hex::decode(input).unwrap();
        let input_bits = input_u8
            .iter()
            .flat_map(|x| u8_to_bits(*x))
            .collect::<Vec<_>>();
        let output_bits = keccakf(input_bits);
        let output_hex = hex::encode(
            output_bits
                .chunks(8)
                .map(|x| from_bits_to_u8(x))
                .collect::<Vec<_>>(),
        );
        assert_eq!(output_hex, expected_output);
    }
}
