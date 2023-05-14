pub(crate) use halo2_proofs::halo2curves::bn256::Fr;
use halo2curves::{group::ff::PrimeField, FieldExt};
use num::{BigUint, Zero};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{target::BoolTarget, witness::Witness},
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_ecdsa::gadgets::biguint::{BigUintTarget, CircuitBuilderBiguint};
use plonky2_u32::{
    gadgets::arithmetic_u32::{CircuitBuilderU32, U32Target},
    witness::WitnessU32,
};

const NUM_LIMBS: usize = 8;

pub fn order_of_fr() -> BigUint {
    BigUint::from_bytes_be(&hex::decode(&Fr::MODULUS[2..]).unwrap())
}

#[derive(Copy, Clone, Debug)]
pub struct FrTarget {
    pub limbs: [U32Target; NUM_LIMBS],
}

impl FrTarget {
    pub fn num_limbs(&self) -> usize {
        self.limbs.len()
    }

    pub fn get_limb(&self, i: usize) -> U32Target {
        self.limbs[i]
    }

    pub fn order<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> BigUintTarget {
        builder.constant_biguint(&order_of_fr())
    }

    /// order - 1
    pub fn max_value<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        Self {
            limbs: builder
                .constant_biguint(&order_of_fr())
                .limbs
                .try_into()
                .unwrap(),
        }
    }
}

impl FrTarget {
    pub fn constant<F: RichField + Extendable<D>, const D: usize>(
        value: &Fr,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        // let limb_values = value.to_u32_digits();
        let value_bytes = value.to_repr();
        let limb_values = value_bytes
            .chunks(4)
            .map(|v| u32::from_le_bytes(v.try_into().unwrap()))
            .collect::<Vec<_>>();
        let limbs = limb_values
            .iter()
            .map(|&l| builder.constant_u32(l))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        Self { limbs }
    }

    pub fn zero<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        Self::constant(&Fr::zero(), builder)
    }

    pub fn connect<F: RichField + Extendable<D>, const D: usize>(
        lhs: &Self,
        rhs: &Self,
        builder: &mut CircuitBuilder<F, D>,
    ) {
        debug_assert_eq!(lhs.num_limbs(), rhs.num_limbs());
        for i in 0..NUM_LIMBS {
            builder.connect_u32(lhs.get_limb(i), rhs.get_limb(i));
        }
    }

    // pub fn le<F: RichField + Extendable<D>, const D: usize>(
    //     builder: &mut CircuitBuilder<F, D>,
    //     a: &Self,
    //     b: &Self,
    // ) -> BoolTarget {
    //     list_le_u32_circuit(builder, a.limbs.to_vec(), b.limbs.to_vec())
    // }

    pub fn to_biguint_target(&self) -> BigUintTarget {
        BigUintTarget {
            limbs: self.limbs.to_vec(),
        }
    }

    pub fn check_safety<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) {
        let target_biguint = self.to_biguint_target();
        let max_value = Self::max_value(builder);
        let max_value_biguint = max_value.to_biguint_target();

        let is_valid = builder.cmp_biguint(&target_biguint, &max_value_biguint);
        let constant_true = builder._true();
        builder.connect(is_valid.target, constant_true.target);
    }

    /// Check field's order.
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let limbs = builder
            .add_virtual_u32_targets(NUM_LIMBS)
            .try_into()
            .unwrap();

        let target = Self { limbs };

        target.check_safety(builder);

        target
    }

    pub fn new_unsafe<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let limbs = builder
            .add_virtual_u32_targets(NUM_LIMBS)
            .try_into()
            .unwrap();

        Self { limbs }
    }

    pub fn register_public_input<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) {
        builder.register_public_inputs(&self.limbs.map(|v| v.0));
    }

    /// Returns self + other
    pub fn add<F: RichField + Extendable<D>, const D: usize>(
        &self,
        other: &Self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let sum = builder.add_biguint(&self.to_biguint_target(), &other.to_biguint_target());
        let order = Self::order(builder);
        let mut r_limbs = builder.rem_biguint(&sum, &order).limbs;
        let zero_u32 = builder.zero_u32();
        r_limbs.resize(NUM_LIMBS, zero_u32);

        Self {
            limbs: r_limbs.try_into().unwrap(),
        }
    }

    /// Returns self - other
    /// The underflow occurs in the case first is larger than the second.
    pub fn sub<F: RichField + Extendable<D>, const D: usize>(
        &self,
        other: &Self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let order = Self::order(builder);
        let addend = builder.sub_biguint(&order, &other.to_biguint_target());
        let sum = builder.add_biguint(&self.to_biguint_target(), &addend);
        let order = Self::order(builder);
        let mut r_limbs = builder.rem_biguint(&sum, &order).limbs;
        let zero_u32 = builder.zero_u32();
        r_limbs.resize(NUM_LIMBS, zero_u32);

        Self {
            limbs: r_limbs.try_into().unwrap(),
        }
    }

    /// Returns self * other
    pub fn mul<F: RichField + Extendable<D>, const D: usize>(
        &self,
        other: &Self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let sum = builder.mul_biguint(&self.to_biguint_target(), &other.to_biguint_target());
        let order = Self::order(builder);
        let mut r_limbs = builder.rem_biguint(&sum, &order).limbs;
        let zero_u32 = builder.zero_u32();
        r_limbs.resize(NUM_LIMBS, zero_u32);

        Self {
            limbs: r_limbs.try_into().unwrap(),
        }
    }

    /// Returns if b { self } else { 0 }
    pub fn mul_by_bool<F: RichField + Extendable<D>, const D: usize>(
        &self,
        b: BoolTarget,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let t = b.target;

        Self {
            limbs: self.limbs.map(|limb| U32Target(builder.mul(limb.0, t))),
        }
    }

    /// Returns self * y + z. This is no more efficient than mul-then-add; it's purely for convenience (only need to call one CircuitBuilder function).
    pub fn mul_add<F: RichField + Extendable<D>, const D: usize>(
        &self,
        y: &Self,
        z: &Self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let prod = self.mul(y, builder);
        prod.add(z, builder)
    }

    pub fn exp_u64<F: RichField + Extendable<D>, const D: usize>(
        &self,
        mut exponent: u64,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let mut current = *self;
        let mut product = FrTarget::constant(&Fr::one(), builder);

        while exponent != 0 {
            if (exponent & 1) == 1 {
                product = product.mul(&current, builder);
            }
            current = current.mul(&current, builder);
            exponent >>= 1;
        }

        product
    }

    pub fn get_witness<F: RichField>(&self, pw: impl Witness<F>) -> Fr {
        let value = self
            .limbs
            .into_iter()
            .rev()
            .fold(BigUint::zero(), |acc, limb| {
                (acc << 32) + pw.get_target(limb.0).to_canonical_biguint()
            });

        let values_u32 = (value % order_of_fr()).to_u32_digits();
        let mut value_bytes = values_u32
            .iter()
            .flat_map(|v| v.to_le_bytes())
            .collect::<Vec<_>>();
        value_bytes.resize(64, 0);

        Fr::from_bytes_wide(&value_bytes.try_into().unwrap())
    }

    pub fn set_witness<F: RichField>(&self, pw: &mut impl Witness<F>, value: &Fr) {
        let value_bytes = value.to_repr();
        let mut limb_values = value_bytes
            .chunks(4)
            .map(|v| u32::from_le_bytes(v.try_into().unwrap()))
            .collect::<Vec<_>>();
        assert!(self.num_limbs() >= limb_values.len());
        limb_values.resize(self.num_limbs(), 0);
        #[allow(clippy::needless_range_loop)]
        for i in 0..self.num_limbs() {
            pw.set_u32_target(self.limbs[i], limb_values[i]);
        }
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use halo2curves::FieldExt;
    use plonky2::{
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };
    use rand::{rngs::OsRng, Rng};

    use super::{Fr, FrTarget};

    #[test]
    fn test_fr_add() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let mut rng = OsRng;
        let x_value = Fr::from_u128(rng.gen());
        let y_value = Fr::from_u128(rng.gen());
        let expected_z_value = x_value + y_value;

        let config = CircuitConfig::standard_recursion_config();
        let mut pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let x = FrTarget::new(&mut builder);
        let y = FrTarget::new(&mut builder);
        let z = x.add(&y, &mut builder);
        let expected_z = FrTarget::new(&mut builder);
        FrTarget::connect(&z, &expected_z, &mut builder);

        x.set_witness(&mut pw, &x_value);
        y.set_witness(&mut pw, &y_value);
        expected_z.set_witness(&mut pw, &expected_z_value);

        dbg!(builder.num_gates()); // 83
        let data = builder.build::<C>();
        dbg!(data.common.degree_bits()); // 7

        let proof = data.prove(pw).unwrap();
        data.verify(proof)
    }

    #[test]
    fn test_fr_mul() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let mut rng = OsRng;
        let x_value = Fr::from_u128(rng.gen());
        let y_value = Fr::from_u128(rng.gen());
        let expected_z_value = x_value * y_value;

        let config = CircuitConfig::standard_recursion_config();
        let mut pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let x = FrTarget::new(&mut builder);
        let y = FrTarget::new(&mut builder);
        let z = x.mul(&y, &mut builder);
        let expected_z = FrTarget::new(&mut builder);
        FrTarget::connect(&z, &expected_z, &mut builder);

        x.set_witness(&mut pw, &x_value);
        y.set_witness(&mut pw, &y_value);
        expected_z.set_witness(&mut pw, &expected_z_value);

        dbg!(builder.num_gates()); // 134
        let data = builder.build::<C>();
        dbg!(data.common.degree_bits()); // 8

        let proof = data.prove(pw).unwrap();
        data.verify(proof)
    }
}
