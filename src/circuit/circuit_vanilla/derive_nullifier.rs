//! Derive nullifier logic for the Orchard circuit (Vanilla variation).

pub(in crate::circuit) mod gadgets {
    use pasta_curves::pallas;

    use crate::{circuit::gadget::AddInstruction, constants::OrchardFixedBases};
    use halo2_gadgets::{
        ecc::{chip::EccPoint, EccInstructions, Point, X},
        poseidon::{
            primitives::{self as poseidon, ConstantLength},
            PoseidonSpongeInstructions,
        },
    };
    use halo2_proofs::{
        circuit::{AssignedCell, Layouter},
        plonk,
    };

    /// `DeriveNullifier` from [Section 4.16: Note Commitments and Nullifiers].
    ///
    /// [Section 4.16: Note Commitments and Nullifiers]: https://zips.z.cash/protocol/protocol.pdf#commitmentsandnullifiers
    #[allow(clippy::too_many_arguments)]
    pub(in crate::circuit) fn derive_nullifier<
        PoseidonChip: PoseidonSpongeInstructions<pallas::Base, poseidon::P128Pow5T3, ConstantLength<2>, 3, 2>,
        AddChip: AddInstruction<pallas::Base>,
        EccChip: EccInstructions<
            pallas::Affine,
            FixedPoints = OrchardFixedBases,
            Point = EccPoint,
            Var = AssignedCell<pallas::Base, pallas::Base>,
        >,
    >(
        layouter: &mut impl Layouter<pallas::Base>,
        poseidon_chip: PoseidonChip,
        add_chip: AddChip,
        ecc_chip: EccChip,
        rho: AssignedCell<pallas::Base, pallas::Base>,
        psi: &AssignedCell<pallas::Base, pallas::Base>,
        cm: &Point<pallas::Affine, EccChip>,
        nk: AssignedCell<pallas::Base, pallas::Base>,
    ) -> Result<X<pallas::Affine, EccChip>, plonk::Error> {
        crate::circuit::derive_nullifier::derive_nullifier(
            layouter,
            poseidon_chip,
            add_chip,
            ecc_chip,
            rho,
            psi,
            cm,
            nk,
        )
        .map(|res| res.extract_p())
    }
}
