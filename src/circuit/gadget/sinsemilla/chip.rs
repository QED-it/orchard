use super::super::ecc::{
    chip::{CellValue, EccChip, EccConfig, EccPoint, OrchardFixedBases},
    EccInstructions,
};
use super::{CommitDomains, HashDomains, SinsemillaInstructions};

use crate::constants;
use crate::primitives::sinsemilla::{
    lebs2ip_k, C as SinsemillaC, K, Q_COMMIT_IVK_M_GENERATOR, Q_MERKLE_CRH,
    Q_NOTE_COMMITMENT_M_GENERATOR,
};

use ff::Field;
use group::Curve;
use halo2::{
    arithmetic::{CurveAffine, FieldExt},
    circuit::{Chip, Layouter, Region},
    plonk::{Advice, Column, ConstraintSystem, Error, Fixed, Permutation, Selector},
};

mod generator_table;
use generator_table::{get_s_by_idx, GeneratorTableChip, GeneratorTableConfig};

/// A message to be hashed.
#[derive(Clone, Debug)]
pub struct Message(Vec<CellValue<u32>>);

/// TODO: Configuration for the Sinsemilla hash chip
#[derive(Clone, Debug)]
#[allow(non_snake_case)]
pub struct SinsemillaConfig {
    q_sinsemilla: Selector,
    bits: Column<Advice>,
    x_a: Column<Advice>,
    x_p: Column<Advice>,
    lambda: (Column<Advice>, Column<Advice>),
    perm_bits: Permutation,
    perm_sum: Permutation,
    generator_table: GeneratorTableConfig,
    ecc_config: EccConfig,
}

#[derive(Clone, Debug)]
pub struct SinsemillaChip<C: CurveAffine> {
    config: SinsemillaConfig,
    loaded: <EccChip<C> as Chip<C::Base>>::Loaded,
}

impl<C: CurveAffine> Chip<C::Base> for SinsemillaChip<C> {
    type Config = SinsemillaConfig;
    type Loaded = <EccChip<C> as Chip<C::Base>>::Loaded;

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &self.loaded
    }
}

impl<C: CurveAffine> SinsemillaChip<C> {
    pub fn construct(
        config: <Self as Chip<C::Base>>::Config,
        loaded: <Self as Chip<C::Base>>::Loaded,
    ) -> Self {
        Self { config, loaded }
    }

    pub fn load(
        config: SinsemillaConfig,
        layouter: &mut impl Layouter<C::Base>,
    ) -> Result<<Self as Chip<C::Base>>::Loaded, Error> {
        // Load the lookup table.
        let generator_table_chip =
            GeneratorTableChip::<C>::construct(config.generator_table.clone());
        generator_table_chip.load(layouter)?;

        // Load the ECC fixed configuration
        Ok(EccChip::<C>::load())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn configure(
        meta: &mut ConstraintSystem<C::Base>,
        bits: Column<Advice>,
        x_a: Column<Advice>,
        x_p: Column<Advice>,
        lambda: (Column<Advice>, Column<Advice>),
        lookup: (Column<Fixed>, Column<Fixed>, Column<Fixed>),
        ecc_config: EccConfig,
    ) -> <Self as Chip<C::Base>>::Config {
        // Sinsemilla selector
        let q_sinsemilla = meta.selector();

        // Set up permutations
        let perm_bits = Permutation::new(meta, &[bits.into()]);
        let perm_sum = Permutation::new(meta, &[x_a.into(), x_p.into()]);

        // Generator table config
        let generator_table =
            GeneratorTableChip::<C>::configure(meta, q_sinsemilla, lookup, bits, x_a, x_p, lambda);

        SinsemillaConfig {
            q_sinsemilla,
            bits,
            x_a,
            x_p,
            lambda,
            perm_bits,
            perm_sum,
            generator_table,
            ecc_config,
        }
    }
}

// Impl SinsemillaInstructions for SinsemillaChip
impl<C: CurveAffine> SinsemillaInstructions<C> for SinsemillaChip<C> {
    type HashDomains = SinsemillaHashDomains;
    type CommitDomains = SinsemillaCommitDomains;

    type Q = (CellValue<C::Base>, C::Base);

    type Message = Message;

    #[allow(non_snake_case)]
    fn get_Q(
        &self,
        layouter: &mut impl Layouter<C::Base>,
        domain: &Self::HashDomains,
    ) -> Result<Self::Q, Error> {
        let q: C = domain.Q();
        let q = q.coordinates().unwrap();
        let config = self.config().clone();

        layouter.assign_region(
            || format!("{:?} Q", domain),
            |mut region: Region<'_, C::Base>| {
                let x = region.assign_advice(|| "x_q", config.x_a, 0, || Ok(*q.x()))?;
                let x = CellValue::new(x, Some(*q.x()));
                Ok((x, *q.y()))
            },
        )
    }

    fn witness_message(
        &self,
        layouter: &mut impl Layouter<C::Base>,
        message: Vec<bool>,
    ) -> Result<Self::Message, Error> {
        let config = self.config().clone();

        // Message must be at most `kc` bits
        let max_len = K * SinsemillaC;
        assert!(message.len() <= max_len);

        // Pad message to nearest multiple of `k`.
        let pad_length = K - (message.len() % K);
        let mut message = message;
        message.extend_from_slice(&vec![false; pad_length]);

        // Chunk message into `k`-bit words
        let words: Vec<_> = message.chunks_exact(K).collect();

        // Parse each chunk of boolean values (little-endian bit order) into a u64.
        let words: Vec<u32> = words.iter().map(|word| lebs2ip_k(word)).collect();

        layouter.assign_region(
            || "message",
            |mut region: Region<'_, C::Base>| {
                let mut result = Vec::with_capacity(words.len());
                for (idx, word) in words.iter().enumerate() {
                    let cell = region.assign_advice(
                        || format!("word {:?}", idx),
                        config.bits,
                        idx,
                        || Ok(C::Base::from_u64(*word as u64)),
                    )?;
                    result.push(CellValue::new(cell, Some(*word)));
                }
                Ok(Message(result))
            },
        )
    }

    fn extract(point: &Self::Point) -> Self::X {
        point.x.clone()
    }

    #[allow(non_snake_case)]
    fn hash_to_point(
        &self,
        layouter: &mut impl Layouter<C::Base>,
        Q: &Self::Q,
        message: Self::Message,
    ) -> Result<Self::Point, Error> {
        let config = self.config().clone();

        // Get (x_p, y_p) for each word. We precompute this here so that we can use `batch_normalize()`.
        let generators_projective: Vec<_> = message
            .0
            .iter()
            .map(|word| get_s_by_idx::<C>(word.value.unwrap()))
            .collect();
        let mut generators = vec![C::default(); generators_projective.len()];
        C::Curve::batch_normalize(&generators_projective, &mut generators);
        let generators: Vec<(C::Base, C::Base)> = generators
            .iter()
            .map(|gen| {
                let point = gen.coordinates().unwrap();
                (*point.x(), *point.y())
            })
            .collect();

        // Initialize `(x_a, y_a)` to be `(x_q, y_q)`

        layouter.assign_region(
            || "Assign message",
            |mut region| {
                // Copy message into this region.
                {
                    for (idx, word) in message.0.iter().enumerate() {
                        let word_copy = region.assign_advice(
                            || format!("hash message word {:?}", idx),
                            config.bits,
                            idx,
                            || {
                                word.value
                                    .map(|value| C::Base::from_u64(value.into()))
                                    .ok_or(Error::SynthesisError)
                            },
                        )?;
                        region.constrain_equal(&config.perm_bits, word.cell, word_copy)?;
                    }
                }

                for row in 0..(message.0.len() - 1) {
                    // Enable `Sinsemilla` selector
                    config.q_sinsemilla.enable(&mut region, row)?;
                }

                // Copy the `x`-coordinate of our starting `Q` base.
                let x_q_cell = region.assign_advice(
                    || "x_q",
                    config.x_a,
                    0,
                    || Q.0.value.ok_or(Error::SynthesisError),
                )?;
                region.constrain_equal(&config.perm_sum, Q.0.cell, x_q_cell)?;

                // Initialize `x_a`, `y_a` as `x_q`, `y_q`.
                let mut x_a = Q.0.value;
                let mut x_a_cell = Q.0.cell;
                let mut y_a = Some(Q.1);

                for (row, _) in message.0.iter().enumerate() {
                    let gen = generators[row];
                    let x_p = gen.0;
                    let y_p = gen.1;

                    // Assign `x_p`
                    region.assign_advice(|| "x_p", config.x_p, row, || Ok(x_p))?;

                    // Compute and assign `lambda1, lambda2`
                    let lambda1 = x_a
                        .zip(y_a)
                        .map(|(x_a, y_a)| (y_a - y_p) * (x_a - x_p).invert().unwrap());
                    let x_r = lambda1
                        .zip(x_a)
                        .map(|(lambda1, x_a)| lambda1 * lambda1 - x_a - x_p);
                    let lambda2 =
                        x_a.zip(y_a)
                            .zip(x_r)
                            .zip(lambda1)
                            .map(|(((x_a, y_a), x_r), lambda1)| {
                                C::Base::from_u64(2) * y_a * (x_a - x_r).invert().unwrap() - lambda1
                            });
                    region.assign_advice(
                        || "lambda1",
                        config.lambda.0,
                        row,
                        || lambda1.ok_or(Error::SynthesisError),
                    )?;
                    region.assign_advice(
                        || "lambda2",
                        config.lambda.1,
                        row,
                        || lambda2.ok_or(Error::SynthesisError),
                    )?;

                    // Compute and assign `x_a` for the next row
                    let x_a_new = lambda2
                        .zip(x_a)
                        .zip(x_r)
                        .map(|((lambda2, x_a), x_r)| lambda2 * lambda2 - x_a - x_r);
                    y_a =
                        lambda2.zip(x_a).zip(x_a_new).zip(y_a).map(
                            |(((lambda2, x_a), x_a_new), y_a)| lambda2 * (x_a - x_a_new) - y_a,
                        );

                    x_a_cell = region.assign_advice(
                        || "x_a",
                        config.x_a,
                        row + 1,
                        || x_a_new.ok_or(Error::SynthesisError),
                    )?;

                    x_a = x_a_new;
                }

                // Assign the final `y_a`
                let y_a_cell = region.assign_advice(
                    || "y_a",
                    config.bits,
                    message.0.len(),
                    || y_a.ok_or(Error::SynthesisError),
                )?;

                #[cfg(test)]
                if let Some((x_a, y_a)) = x_a.zip(y_a) {
                    let computed_point: C = C::from_xy(x_a, y_a).unwrap();
                    let expected_point: C = {
                        let Q = C::from_xy(Q.0.value.unwrap(), Q.1).unwrap();
                        let message: Vec<u32> =
                            message.0.iter().map(|word| word.value.unwrap()).collect();

                        use crate::primitives::sinsemilla::S_PERSONALIZATION;
                        use pasta_curves::arithmetic::CurveExt;

                        let hasher_S = C::CurveExt::hash_to_curve(S_PERSONALIZATION);
                        let S = |chunk: u32| -> C { hasher_S(&chunk.to_le_bytes()).to_affine() };

                        message
                            .iter()
                            .fold(C::CurveExt::from(Q), |acc, &chunk| (acc + S(chunk)) + acc)
                            .to_affine()
                    };
                    assert_eq!(computed_point, expected_point);
                }

                let y_a = CellValue::new(y_a_cell, y_a);
                let x_a = CellValue::new(x_a_cell, x_a);

                Ok(EccPoint { x: x_a, y: y_a })
            },
        )
    }
}

// Impl EccInstructions for SinsemillaChip
impl<C: CurveAffine> EccInstructions<C> for SinsemillaChip<C> {
    type ScalarFixed = <EccChip<C> as EccInstructions<C>>::ScalarFixed;
    type ScalarFixedShort = <EccChip<C> as EccInstructions<C>>::ScalarFixedShort;
    type Point = <EccChip<C> as EccInstructions<C>>::Point;
    type X = <EccChip<C> as EccInstructions<C>>::X;
    type FixedPoint = <EccChip<C> as EccInstructions<C>>::FixedPoint;
    type FixedPoints = <EccChip<C> as EccInstructions<C>>::FixedPoints;

    fn witness_scalar_fixed(
        &self,
        layouter: &mut impl Layouter<C::Base>,
        value: Option<C::Scalar>,
    ) -> Result<Self::ScalarFixed, Error> {
        let ecc_chip = EccChip::<C>::construct(self.config.ecc_config.clone(), self.loaded.clone());
        ecc_chip.witness_scalar_fixed(layouter, value)
    }

    fn witness_scalar_fixed_short(
        &self,
        layouter: &mut impl Layouter<C::Base>,
        value: Option<C::Scalar>,
    ) -> Result<Self::ScalarFixedShort, Error> {
        let ecc_chip = EccChip::<C>::construct(self.config.ecc_config.clone(), self.loaded.clone());
        ecc_chip.witness_scalar_fixed_short(layouter, value)
    }

    fn witness_point(
        &self,
        layouter: &mut impl Layouter<C::Base>,
        value: Option<C>,
    ) -> Result<Self::Point, Error> {
        let ecc_chip = EccChip::<C>::construct(self.config.ecc_config.clone(), self.loaded.clone());
        ecc_chip.witness_point(layouter, value)
    }

    fn extract_p(point: &Self::Point) -> &Self::X {
        EccChip::<C>::extract_p(point)
    }

    fn get_fixed(&self, fixed_point: Self::FixedPoints) -> Result<Self::FixedPoint, Error> {
        let ecc_chip = EccChip::<C>::construct(self.config.ecc_config.clone(), self.loaded.clone());
        ecc_chip.get_fixed(fixed_point)
    }

    fn add(
        &self,
        layouter: &mut impl Layouter<C::Base>,
        a: &Self::Point,
        b: &Self::Point,
    ) -> Result<Self::Point, Error> {
        let ecc_chip = EccChip::<C>::construct(self.config.ecc_config.clone(), self.loaded.clone());
        ecc_chip.add(layouter, a, b)
    }

    fn add_complete(
        &self,
        layouter: &mut impl Layouter<C::Base>,
        a: &Self::Point,
        b: &Self::Point,
    ) -> Result<Self::Point, Error> {
        let ecc_chip = EccChip::<C>::construct(self.config.ecc_config.clone(), self.loaded.clone());
        ecc_chip.add_complete(layouter, a, b)
    }

    fn mul(
        &self,
        layouter: &mut impl Layouter<C::Base>,
        scalar: C::Scalar,
        base: &Self::Point,
    ) -> Result<Self::Point, Error> {
        let ecc_chip = EccChip::<C>::construct(self.config.ecc_config.clone(), self.loaded.clone());
        ecc_chip.mul(layouter, scalar, base)
    }

    fn mul_fixed(
        &self,
        layouter: &mut impl Layouter<C::Base>,
        scalar: &Self::ScalarFixed,
        base: &Self::FixedPoint,
    ) -> Result<Self::Point, Error> {
        let ecc_chip = EccChip::<C>::construct(self.config.ecc_config.clone(), self.loaded.clone());
        ecc_chip.mul_fixed(layouter, scalar, base)
    }

    fn mul_fixed_short(
        &self,
        layouter: &mut impl Layouter<C::Base>,
        scalar: &Self::ScalarFixedShort,
        base: &Self::FixedPoint,
    ) -> Result<Self::Point, Error> {
        let ecc_chip = EccChip::<C>::construct(self.config.ecc_config.clone(), self.loaded.clone());
        ecc_chip.mul_fixed_short(layouter, scalar, base)
    }
}

#[derive(Clone, Debug)]
pub enum SinsemillaHashDomains {
    NoteCommit,
    CommitIvk,
    MerkleCrh,
}

impl<C: CurveAffine> HashDomains<C> for SinsemillaHashDomains {
    fn Q(&self) -> C {
        match self {
            SinsemillaHashDomains::CommitIvk => C::from_xy(
                C::Base::from_bytes(&Q_COMMIT_IVK_M_GENERATOR.0).unwrap(),
                C::Base::from_bytes(&Q_COMMIT_IVK_M_GENERATOR.1).unwrap(),
            )
            .unwrap(),
            SinsemillaHashDomains::NoteCommit => C::from_xy(
                C::Base::from_bytes(&Q_NOTE_COMMITMENT_M_GENERATOR.0).unwrap(),
                C::Base::from_bytes(&Q_NOTE_COMMITMENT_M_GENERATOR.1).unwrap(),
            )
            .unwrap(),
            SinsemillaHashDomains::MerkleCrh => C::from_xy(
                C::Base::from_bytes(&Q_MERKLE_CRH.0).unwrap(),
                C::Base::from_bytes(&Q_MERKLE_CRH.1).unwrap(),
            )
            .unwrap(),
        }
    }
}

#[derive(Clone, Debug)]
pub enum SinsemillaCommitDomains {
    NoteCommit,
    CommitIvk,
}

impl<C: CurveAffine> CommitDomains<C, OrchardFixedBases<C>, SinsemillaHashDomains>
    for SinsemillaCommitDomains
{
    fn r(&self) -> OrchardFixedBases<C> {
        match self {
            Self::NoteCommit => {
                OrchardFixedBases::<C>::NoteCommitR(constants::note_commit_r::generator())
            }
            Self::CommitIvk => {
                OrchardFixedBases::<C>::CommitIvkR(constants::commit_ivk_r::generator())
            }
        }
    }

    fn hash_domain(&self) -> SinsemillaHashDomains {
        match self {
            Self::NoteCommit => SinsemillaHashDomains::NoteCommit,
            Self::CommitIvk => SinsemillaHashDomains::CommitIvk,
        }
    }
}
