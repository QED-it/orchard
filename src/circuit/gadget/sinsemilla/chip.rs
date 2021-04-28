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
    bits: Column<Advice>,
    x_a: Column<Advice>,
    x_p: Column<Advice>,
    lambda: (Column<Advice>, Column<Advice>),
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

    // TODO: configure()
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
        todo!()
    }

    fn witness_message(
        &self,
        layouter: &mut impl Layouter<C::Base>,
        message: Vec<bool>,
    ) -> Result<Self::Message, Error> {
        todo!()
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
        todo!()
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
