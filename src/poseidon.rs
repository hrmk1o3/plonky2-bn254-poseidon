use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField, iop::target::BoolTarget,
    plonk::circuit_builder::CircuitBuilder,
};
use poseidon_circuit::poseidon::primitives::{P128Pow5T3, Spec};

use super::arithmetic::{Fr, FrTarget};

pub(crate) const HASH_OUT_SIZE: usize = 1;
pub const SPONGE_RATE: usize = HASH_OUT_SIZE * 2;
pub(crate) const SPONGE_CAPACITY: usize = HASH_OUT_SIZE;
pub const SPONGE_WIDTH: usize = SPONGE_RATE + SPONGE_CAPACITY;

type S = P128Pow5T3<Fr>;

pub fn permute_swapped_circuit<F: RichField + Extendable<D>, const D: usize>(
    inputs: [FrTarget; SPONGE_WIDTH],
    swap: BoolTarget,
    builder: &mut CircuitBuilder<F, D>,
) -> [FrTarget; SPONGE_WIDTH] {
    let one = FrTarget::constant(&Fr::one(), builder);
    let swap = one.mul_by_bool(swap, builder);

    // Assert that each delta wire is set properly: `delta_i = swap * (rhs - lhs)`.
    // Compute the possibly-swapped input layer.
    let mut state = [(); SPONGE_WIDTH].map(|_| FrTarget::zero(builder));
    for i in 0..HASH_OUT_SIZE {
        let input_lhs = &inputs[i];
        let input_rhs = &inputs[i + HASH_OUT_SIZE];
        let diff = input_rhs.sub(input_lhs, builder);
        let delta_i = diff.mul(&swap, builder);
        state[i] = input_lhs.add(&delta_i, builder);
        state[i + HASH_OUT_SIZE] = input_rhs.sub(&delta_i, builder);
    }

    #[allow(clippy::manual_memcpy)]
    for i in (HASH_OUT_SIZE * 2)..SPONGE_WIDTH {
        state[i] = inputs[i];
    }

    permute_circuit::<F, D>(state, builder)
}

pub fn permute_circuit<F: RichField + Extendable<D>, const D: usize>(
    mut state: [FrTarget; SPONGE_WIDTH],
    builder: &mut CircuitBuilder<F, D>,
) -> [FrTarget; SPONGE_WIDTH] {
    let mut round_ctr = 0;

    let r_f = S::full_rounds() / 2;
    let r_p = S::partial_rounds();

    // First set of full rounds.
    for _ in 0..r_f {
        full_round(&mut state, &mut round_ctr, builder);
    }

    // Partial rounds.
    for _ in 0..r_p {
        partial_round(&mut state, &mut round_ctr, builder);
    }

    // Second set of full rounds.
    for _ in 0..r_f {
        full_round(&mut state, &mut round_ctr, builder);
    }

    state
}

fn full_round<F: RichField + Extendable<D>, const D: usize>(
    state: &mut [FrTarget; SPONGE_WIDTH],
    round_ctr: &mut usize,
    builder: &mut CircuitBuilder<F, D>,
) {
    constant_layer_circuit(state, *round_ctr, builder);
    sbox_layer_circuit(state, builder);
    *state = mds_layer_circuit(state, builder);
    *round_ctr += 1;
}

fn partial_round<F: RichField + Extendable<D>, const D: usize>(
    state: &mut [FrTarget; SPONGE_WIDTH],
    round_ctr: &mut usize,
    builder: &mut CircuitBuilder<F, D>,
) {
    constant_layer_circuit(state, *round_ctr, builder);
    state[0] = sbox_monomial_circuit(&state[0], builder);
    *state = mds_layer_circuit(state, builder);
    *round_ctr += 1;
}

fn mds_layer_circuit<F: RichField + Extendable<D>, const D: usize>(
    state: &[FrTarget; SPONGE_WIDTH],
    builder: &mut CircuitBuilder<F, D>,
) -> [FrTarget; SPONGE_WIDTH] {
    let (_, mds, _) = S::constants();
    mds.iter()
        .map(|m_i| {
            m_i.iter().zip(state.iter()).fold(
                FrTarget::constant(&Fr::zero(), builder),
                |acc, (m_ij, r_j)| {
                    let m_ij = FrTarget::constant(m_ij, builder);
                    let addend = m_ij.mul(r_j, builder);
                    acc.add(&addend, builder)
                },
            )
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

fn constant_layer_circuit<F: RichField + Extendable<D>, const D: usize>(
    state: &mut [FrTarget; SPONGE_WIDTH],
    round_ctr: usize,
    builder: &mut CircuitBuilder<F, D>,
) {
    let (round_constants, _, _) = S::constants();
    for (r_i, c_i) in state.iter_mut().zip(round_constants[round_ctr].iter()) {
        let c_i = FrTarget::constant(c_i, builder);
        *r_i = r_i.add(&c_i, builder);
    }
}

fn sbox_monomial_circuit<F: RichField + Extendable<D>, const D: usize>(
    x: &FrTarget,
    builder: &mut CircuitBuilder<F, D>,
) -> FrTarget {
    x.exp_u64(5, builder)
}

fn sbox_layer_circuit<F: RichField + Extendable<D>, const D: usize>(
    state: &mut [FrTarget; SPONGE_WIDTH],
    builder: &mut CircuitBuilder<F, D>,
) {
    for state_i in state.iter_mut() {
        *state_i = sbox_monomial_circuit(state_i, builder);
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use halo2curves::FieldExt;
    use plonky2::{
        field::types::PrimeField64,
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };
    use rand::{rngs::OsRng, Rng};

    use crate::{
        arithmetic::{Fr, FrTarget},
        poseidon::permute_circuit,
    };

    #[test]
    fn test_poseidon_bn254_permute() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let mut rng = OsRng;
        let x_value = Fr::from_u128(rng.gen());
        let y_value = Fr::from_u128(rng.gen());
        let z_value = Fr::from_u128(rng.gen());
        let input_value = [x_value, y_value, z_value];
        dbg!(&input_value);

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let x = FrTarget::new(&mut builder);
        let y = FrTarget::new(&mut builder);
        let z = FrTarget::new(&mut builder);
        let input = [x, y, z];
        let output = permute_circuit(input, &mut builder);
        output[0].register_public_input(&mut builder);
        output[1].register_public_input(&mut builder);
        output[2].register_public_input(&mut builder);

        dbg!(builder.num_gates()); // 99846
        let data = builder.build::<C>();
        dbg!(data.common.degree_bits()); // 17

        let mut pw = PartialWitness::new();
        x.set_witness(&mut pw, &x_value);
        y.set_witness(&mut pw, &y_value);
        z.set_witness(&mut pw, &z_value);

        let proof = data.prove(pw).unwrap();
        let output = proof
            .public_inputs
            .iter()
            .map(|v| v.to_canonical_u64() as u32)
            .collect::<Vec<_>>()
            .chunks(8)
            .map(|v| {
                Fr::from_bytes(
                    &v.iter()
                        .flat_map(|v| v.to_le_bytes())
                        .collect::<Vec<_>>()
                        .try_into()
                        .unwrap(),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        dbg!(&output);

        // use super::{SPONGE_RATE, SPONGE_WIDTH};
        // use poseidon_circuit::poseidon::primitives::{P128Pow5T3, Spec};
        // let (round_constants, mds, _) = P128Pow5T3::<Fr>::constants();
        // let mut expected_output_value = input_value;
        // poseidon_circuit::poseidon::primitives::permute::<
        //     Fr,
        //     P128Pow5T3<Fr>,
        //     SPONGE_WIDTH,
        //     SPONGE_RATE,
        // >(&mut expected_output_value, &mds, &round_constants);
        // dbg!(&expected_output_value);
        // assert_eq!(output, expected_output_value.to_vec());

        data.verify(proof)
    }
}
