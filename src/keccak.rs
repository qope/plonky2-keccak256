use std::marker::PhantomData;

use crate::constants::{ROTR, ROUND_CONSTANTS};
use crate::u64target::{xor_circuit, U64Target};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{target::BoolTarget, witness::PartialWitness},
    plonk::circuit_builder::CircuitBuilder,
};

pub struct KeccakTarget<F, const D: usize> {
    words: Vec<U64Target<F, D>>,
    _phantom: PhantomData<F>,
}

impl<F, const D: usize> KeccakTarget<F, D>
where
    F: RichField + Extendable<D>,
{
    pub fn new(builder: &mut CircuitBuilder<F, D>) -> Self {
        let mut result = vec![];
        for _ in 0..25 {
            result.push(U64Target::new(builder));
        }
        Self {
            words: result,
            _phantom: PhantomData,
        }
    }

    pub fn set_witness(&self, bits: Vec<bool>, pw: &mut PartialWitness<F>) {
        assert_eq!(bits.len(), 1600);
        for i in 0..25 {
            self.words[i].set_witness(bits[i * 64..(i + 1) * 64].to_vec(), pw);
        }
    }

    pub fn connect(&self, other: &Self, builder: &mut CircuitBuilder<F, D>) {
        for i in 0..25 {
            self.words[i].connect(&other.words[i], builder);
        }
    }

    pub fn from(bits: Vec<BoolTarget>) -> Self {
        let mut result = vec![];
        for i in 0..25 {
            result.push(U64Target::from(bits[i * 64..(i + 1) * 64].to_vec()));
        }
        Self {
            words: result,
            _phantom: PhantomData,
        }
    }

    pub fn keccak_round(&mut self, rc: u64, builder: &mut CircuitBuilder<F, D>) {
        // θ step
        let mut c = vec![];
        for x in 0..5 {
            let xor01 = self.words[x + 0 * 5].xor(&self.words[x + 1 * 5], builder);
            let xor012 = xor01.xor(&self.words[x + 2 * 5], builder);
            let xor0123 = xor012.xor(&self.words[x + 3 * 5], builder);
            let xor01234 = xor0123.xor(&self.words[x + 4 * 5], builder);
            c.push(xor01234);
        }
        let mut d = vec![];
        for x in 0..5 {
            let rot_c = c[(x + 1) % 5].rotl(1, builder);
            d.push(c[(x + 4) % 5].xor(&rot_c, builder));
        }
        for x in 0..5 {
            for y in 0..5 {
                self.words[x + y * 5] = self.words[x + y * 5].xor(&d[x], builder);
            }
        }
        // ρ and π steps
        let b = KeccakTarget::new(builder);
        for x in 0..5 {
            for y in 0..5 {
                let rot_self = self.words[x + y * 5].rotl(ROTR[x + y * 5], builder);
                b.words[y + ((2 * x + 3 * y) % 5) * 5].connect(&rot_self, builder);
            }
        }

        // χ step
        for x in 0..5 {
            for y in 0..5 {
                let not_b = b.words[(x + 1) % 5 + y * 5].not(builder);
                let and_not_b = not_b.and(&b.words[(x + 2) % 5 + y * 5], builder);
                self.words[x + y * 5] = b.words[x + y * 5].xor(&and_not_b, builder);
            }
        }

        let const_rc = U64Target::constant(rc, builder);
        self.words[0] = self.words[0].xor(&const_rc, builder);
    }

    pub fn keccakf(&self, builder: &mut CircuitBuilder<F, D>) -> Self {
        let mut output = Self::new(builder);
        output.connect(&self, builder);
        for i in 0..24 {
            output.keccak_round(ROUND_CONSTANTS[i], builder);
        }
        output
    }
}

pub fn keccak256_circuit<F, const D: usize>(
    input: Vec<BoolTarget>,
    builder: &mut CircuitBuilder<F, D>,
) -> Vec<BoolTarget>
where
    F: RichField + Extendable<D>,
{
    assert_eq!(input.len() % 8, 0); // input should be bytes.
    let block_size_in_bytes = 136; // in bytes
    let input_len_in_bytes = input.len() / 8;
    let num_blocks = input_len_in_bytes / block_size_in_bytes + 1;
    dbg!(num_blocks);

    let mut padded = vec![];
    for _ in 0..block_size_in_bytes * 8 * num_blocks {
        padded.push(builder.add_virtual_bool_target_safe());
    }

    // register input
    for i in 0..input_len_in_bytes * 8 {
        builder.connect(padded[i].target, input[i].target);
    }

    // append 0x01 = 1000 0000 after the last input
    let true_target = builder.constant_bool(true);
    builder.connect(padded[input_len_in_bytes * 8].target, true_target.target);

    // pad 0s
    let false_target = builder.constant_bool(false);
    let last_index = padded.len() - 1;
    for i in input_len_in_bytes * 8 + 1..last_index {
        builder.connect(padded[i].target, false_target.target);
    }

    // xor 0x80 = 0000 0001 with the last byte.
    // however the last bit is ensured to be 0, so just fill 1.
    builder.connect(padded[last_index].target, true_target.target);

    let mut m = KeccakTarget::new(builder);
    for i in 0..1600 {
        let word = i / 64;
        let bit = i % 64;
        builder.connect(m.words[word].bits[bit].target, false_target.target);
    }

    for i in 0..num_blocks {
        for j in 0..block_size_in_bytes * 8 {
            let word = j / 64;
            let bit = j % 64;
            let xor_t = xor_circuit(
                m.words[word].bits[bit],
                padded[i * block_size_in_bytes * 8 + j],
                builder,
            );
            m.words[word].bits[bit] = xor_t;
        }
        m = m.keccakf(builder);
    }

    let mut z = Vec::new();
    for i in 0..256 {
        let new_target = builder.add_virtual_bool_target_safe();
        let word = i / 64;
        let bit = i % 64;
        builder.connect(new_target.target, m.words[word].bits[bit].target);
        z.push(new_target);
    }
    z
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use anyhow::Result;
    use plonky2::{
        field::goldilocks_field::GoldilocksField,
        iop::witness::WitnessWrite,
        plonk::{circuit_data::CircuitConfig, config::PoseidonGoldilocksConfig},
    };
    use tiny_keccak::{Hasher, Keccak};

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    use super::*;

    fn u8_to_bits(num: u8) -> Vec<bool> {
        let mut result = Vec::with_capacity(8);
        let mut n = num;
        for _ in 0..8 {
            result.push(n & 1 == 1);
            n >>= 1;
        }
        result
    }

    fn hex_str_to_bits(input: &str) -> Result<Vec<bool>> {
        let input_u8 = hex::decode(input)?;
        let input_bits = input_u8
            .iter()
            .flat_map(|x| u8_to_bits(*x))
            .collect::<Vec<_>>();
        Ok(input_bits)
    }

    fn expected_keccak(input: &[u8]) -> String {
        let mut hasher = Keccak::v256();
        hasher.update(&input);
        let mut hash = [0u8; 32];
        hasher.finalize(&mut hash);
        let expected = hex::encode(hash);
        expected
    }

    #[test]
    fn test_keccakf() -> Result<()> {
        let input = "bb45f489bea73ef400b0ef4cd65dcec3565b0fd75c6eb248f1fefc84dd216650327e5a5c9b02ed7ce898f8ecb2e045cded87742a7723e7fddd9ac96c8aa70f4601000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        let expected_output = "61060054a4f8cd82609992a7604a95c9165bc95ae016a5299dd7d400dddbea9a3069922d826066fae8aad9aac3d937d6b6db11d4e3ce7663ef4236ca2f1a97a3de6259030506c8f50dcec6588ba1e7598a5f39e74f8f858f3fc04a371d52d761cb369205487758026a035dc5edd42a6bb4f1cc84c2f5a4f7915993a7b209935c40a06104fc2d4d3e337a79a6671f69fb0b3a14ccdf72f66f59828ab0f43bedab3622aa17746d3e536b9bd39974f215916563a5ed55d944d6137ce8cf03677e57bc75e502054f51b0";

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let input_t = KeccakTarget::new(&mut builder);
        let output_t = input_t.keccakf(&mut builder);

        let mut pw = PartialWitness::<F>::new();
        let input_bits = hex_str_to_bits(input)?;
        let output_bits = hex_str_to_bits(expected_output)?;
        input_t.set_witness(input_bits, &mut pw);
        output_t.set_witness(output_bits, &mut pw);

        let data = builder.build::<C>();
        let proof = data.prove(pw)?;
        data.verify(proof)?;
        Ok(())
    }

    #[test]
    fn test_keccak256_circuit() -> Result<()> {
        let input = "8f54f1c2d0eb5771cd5bf67a6689fcd6eed9444d91a39e5ef32a9b4ae5ca14ff8f54f1c2d0eb5771cd5bf67a6689fcd6eed9444d91a39e5ef32a9b4ae5ca14ff";
        let expected_output = expected_keccak(&hex::decode(input).unwrap());

        let input_bits = hex_str_to_bits(input)?;
        let exptected_output_bits = hex_str_to_bits(&expected_output)?;

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let mut input_t = vec![];
        for i in 0..input_bits.len() {
            input_t.push(builder.constant_bool(input_bits[i]));
        }
        let output_t = keccak256_circuit(input_t, &mut builder);

        let mut pw = PartialWitness::new();
        for i in 0..256 {
            pw.set_bool_target(output_t[i], exptected_output_bits[i]);
        }

        let data = builder.build::<C>();
        let now = Instant::now();
        let proof = data.prove(pw)?;

        println!("time = {} ms", now.elapsed().as_millis());
        println!(
            "degree = {}, degree_bits= {}",
            data.common.degree(),
            data.common.degree_bits()
        );

        data.verify(proof)?;
        Ok(())
    }
}
