//! Gadget and chips for the Sinsemilla hash function.
use crate::circuit::gadget::ecc::{self, EccInstructions};
use halo2::{arithmetic::CurveAffine, circuit::Layouter, plonk::Error};
use std::fmt;

pub mod chip;
pub use chip::{
    Message, SinsemillaChip, SinsemillaCommitDomains, SinsemillaConfig, SinsemillaHashDomains,
};

/// The set of circuit instructions required to use the [`Sinsemilla`](https://zcash.github.io/halo2/design/gadgets/sinsemilla.html) gadget.
pub trait SinsemillaInstructions<C: CurveAffine>: EccInstructions<C> {
    /// HashDomains used in this instruction.
    type HashDomains: HashDomains<C>;
    /// CommitDomains used in this instruction.
    type CommitDomains: CommitDomains<
        C,
        <Self as EccInstructions<C>>::FixedPoints,
        Self::HashDomains,
    >;
    /// Variable representing a Q fixed point for a HashDomain.
    type Q: Clone + fmt::Debug;

    /// Witnessed message.
    type Message: Clone + fmt::Debug;

    /// Gets the Q constant for the given domain.
    #[allow(non_snake_case)]
    fn get_Q(
        &self,
        layouter: &mut impl Layouter<C::Base>,
        domain: &Self::HashDomains,
    ) -> Result<Self::Q, Error>;

    /// Witnesses a message in the form of a bitstring.
    fn witness_message(
        &self,
        layouter: &mut impl Layouter<C::Base>,
        message: Vec<bool>,
    ) -> Result<Self::Message, Error>;

    /// Move to ECC chip
    /// Extracts the x-coordinate from a curve point.
    fn extract(point: &Self::Point) -> Self::X;

    /// Hashes a message to an ECC curve point.
    #[allow(non_snake_case)]
    fn hash_to_point(
        &self,
        layouter: &mut impl Layouter<C::Base>,
        Q: &Self::Q,
        message: Self::Message,
    ) -> Result<Self::Point, Error>;
}

/// Trait allowing circuit's Sinsemilla HashDomains to be enumerated.
#[allow(non_snake_case)]
pub trait HashDomains<C: CurveAffine>: Clone + fmt::Debug {
    fn Q(&self) -> C;
}

#[allow(non_snake_case)]
pub struct HashDomain<C: CurveAffine, SinsemillaChip: SinsemillaInstructions<C> + Clone> {
    chip: SinsemillaChip,
    pub Q: SinsemillaChip::Q,
}

impl<C: CurveAffine, SinsemillaChip: SinsemillaInstructions<C> + Clone>
    HashDomain<C, SinsemillaChip>
{
    #[allow(non_snake_case)]
    /// Constructs a new `HashDomain` for the given domain.
    pub fn new(
        chip: SinsemillaChip,
        mut layouter: impl Layouter<C::Base>,
        domain: &<SinsemillaChip as SinsemillaInstructions<C>>::HashDomains,
    ) -> Result<Self, Error> {
        chip.get_Q(&mut layouter, domain).map(|Q| HashDomain {
            chip: chip.clone(),
            Q,
        })
    }

    /// $\mathsf{SinsemillaHashToPoint}$ from [§ 5.4.1.9][concretesinsemillahash].
    ///
    /// [concretesinsemillahash]: https://zips.z.cash/protocol/nu5.pdf#concretesinsemillahash
    pub fn hash_to_point(
        &self,
        mut layouter: impl Layouter<C::Base>,
        message: Vec<bool>,
    ) -> Result<ecc::Point<C, SinsemillaChip>, Error> {
        let message = self.chip.witness_message(&mut layouter, message)?;
        self.chip
            .hash_to_point(&mut layouter, &self.Q, message)
            .map(|point| ecc::Point::from_inner(self.chip.clone(), point))
    }

    /// $\mathsf{SinsemillaHash}$ from [§ 5.4.1.9][concretesinsemillahash].
    ///
    /// [concretesinsemillahash]: https://zips.z.cash/protocol/nu5.pdf#concretesinsemillahash
    pub fn hash(
        &self,
        layouter: impl Layouter<C::Base>,
        message: Vec<bool>,
    ) -> Result<ecc::X<C, SinsemillaChip>, Error> {
        let p = self.hash_to_point(layouter, message);
        p.map(|p| p.extract_p())
    }
}

/// Trait allowing circuit's Sinsemilla CommitDomains to be enumerated.
pub trait CommitDomains<C: CurveAffine, F: ecc::FixedPoints<C>, H: HashDomains<C>>:
    Clone + fmt::Debug
{
    /// Returns the fixed point corresponding to the R constant for this CommitDomain.
    fn r(&self) -> F;

    /// Returns the HashDomain contained in this CommitDomain
    fn hash_domain(&self) -> H;
}

#[allow(non_snake_case)]
pub struct CommitDomain<C: CurveAffine, SinsemillaChip: SinsemillaInstructions<C> + Clone> {
    M: HashDomain<C, SinsemillaChip>,
    R: ecc::FixedPoint<C, SinsemillaChip>,
}

impl<C: CurveAffine, SinsemillaChip: Clone + SinsemillaInstructions<C>>
    CommitDomain<C, SinsemillaChip>
{
    /// Constructs a new `CommitDomain` for the given domain.
    pub fn new(
        chip: SinsemillaChip,
        mut layouter: impl Layouter<C::Base>,
        domain: &SinsemillaChip::CommitDomains,
    ) -> Result<Self, Error> {
        Ok(CommitDomain {
            M: HashDomain::new(
                chip.clone(),
                layouter.namespace(|| "M"),
                &domain.hash_domain(),
            )?,
            R: ecc::FixedPoint::get(chip, domain.r())?,
        })
    }

    /// $\mathsf{SinsemillaCommit}$ from [§ 5.4.8.4][concretesinsemillacommit].
    ///
    /// [concretesinsemillacommit]: https://zips.z.cash/protocol/nu5.pdf#concretesinsemillacommit
    pub fn commit(
        &self,
        mut layouter: impl Layouter<C::Base>,
        message: Vec<bool>,
        r: ecc::ScalarFixed<C, SinsemillaChip>,
    ) -> Result<ecc::Point<C, SinsemillaChip>, Error> {
        let blind = self.R.mul(layouter.namespace(|| "[r] R"), &r)?;
        self.M
            .hash_to_point(layouter.namespace(|| "M"), message)?
            .add(layouter.namespace(|| "M + [r] R"), &blind)
    }

    /// $\mathsf{SinsemillaShortCommit}$ from [§ 5.4.8.4][concretesinsemillacommit].
    ///
    /// [concretesinsemillacommit]: https://zips.z.cash/protocol/nu5.pdf#concretesinsemillacommit
    pub fn short_commit(
        &self,
        mut layouter: impl Layouter<C::Base>,
        message: Vec<bool>,
        r: ecc::ScalarFixed<C, SinsemillaChip>,
    ) -> Result<ecc::X<C, SinsemillaChip>, Error> {
        let p = self.commit(layouter.namespace(|| "commit"), message, r);
        p.map(|p| p.extract_p())
    }
}

#[cfg(test)]
mod tests {
    use halo2::{
        arithmetic::{CurveAffine, FieldExt},
        circuit::{layouter::SingleChipLayouter, Layouter},
        dev::MockProver,
        pasta::pallas,
        plonk::{Assignment, Circuit, ConstraintSystem, Error},
    };

    use super::{
        CommitDomain, HashDomain, SinsemillaChip, SinsemillaCommitDomains, SinsemillaConfig,
        SinsemillaHashDomains,
    };
    use crate::circuit::gadget::ecc::{chip::EccChip, ScalarFixed};

    struct MyCircuit<C: CurveAffine> {
        _marker: std::marker::PhantomData<C>,
    }

    impl<C: CurveAffine> Circuit<C::Base> for MyCircuit<C> {
        type Config = (SinsemillaConfig, SinsemillaConfig);

        #[allow(non_snake_case)]
        fn configure(meta: &mut ConstraintSystem<C::Base>) -> Self::Config {
            let bits = meta.advice_column();
            let P = (meta.advice_column(), meta.advice_column());
            let lambda = (meta.advice_column(), meta.advice_column());
            let extras = [
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
            ];

            let ecc_config = EccChip::<C>::configure(meta, bits, P, lambda, extras);

            // Fixed columns for the Sinsemilla generator lookup table
            let lookup = (
                meta.fixed_column(),
                meta.fixed_column(),
                meta.fixed_column(),
            );

            let config1 = SinsemillaChip::<C>::configure(
                meta,
                bits,
                P.0,
                P.1,
                lambda,
                lookup,
                ecc_config.clone(),
            );
            let config2 = SinsemillaChip::<C>::configure(
                meta,
                extras[0],
                extras[1],
                extras[2],
                (extras[3], extras[4]),
                lookup,
                ecc_config,
            );
            (config1, config2)
        }

        fn synthesize(
            &self,
            cs: &mut impl Assignment<C::Base>,
            config: Self::Config,
        ) -> Result<(), Error> {
            let mut layouter = SingleChipLayouter::new(cs)?;

            let loaded1 = SinsemillaChip::<C>::load(config.0.clone(), &mut layouter)?;
            let chip1 = SinsemillaChip::<C>::construct(config.0, loaded1);

            let merkle_crh = HashDomain::new(
                chip1.clone(),
                layouter.namespace(|| "merkle_crh"),
                &SinsemillaHashDomains::MerkleCrh,
            )?;
            merkle_crh.hash_to_point(
                layouter.namespace(|| "hash_to_point"),
                vec![
                    true, true, false, true, true, false, false, false, true, true, false, false,
                ],
            )?;

            let loaded2 = SinsemillaChip::<C>::load(config.1.clone(), &mut layouter)?;
            let chip2 = SinsemillaChip::<C>::construct(config.1, loaded2);

            let commit_ivk = CommitDomain::new(
                chip2.clone(),
                layouter.namespace(|| "commit_ivk"),
                &SinsemillaCommitDomains::CommitIvk,
            )?;
            let r = ScalarFixed::<C, SinsemillaChip<C>>::new(
                chip2.clone(),
                layouter.namespace(|| "r"),
                Some(C::Scalar::rand()),
            )?;
            commit_ivk.commit(
                layouter.namespace(|| "commit"),
                vec![
                    true, true, false, false, true, false, true, true, false, true, false, true,
                    true, false,
                ],
                r,
            )?;

            Ok(())
        }
    }

    #[test]
    fn sinsemilla_gadget() {
        let k = 11;
        let circuit = MyCircuit::<pallas::Affine> {
            _marker: std::marker::PhantomData,
        };
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()))
    }
}
