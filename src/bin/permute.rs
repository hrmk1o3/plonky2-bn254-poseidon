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

use plonky2_bn254_poseidon::{
    arithmetic::{Fr, FrTarget},
    poseidon::permute_circuit,
};

fn main() -> Result<()> {
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

    let data = builder.build::<C>();

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

    data.verify(proof)
}
