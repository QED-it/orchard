//! Derive nullifier logic for the Orchard circuit (ZSA variation).

pub(in crate::circuit) mod gadgets {
    use group::Curve;
    use pasta_curves::{arithmetic::CurveExt, pallas};

    use crate::{circuit::gadget::AddInstruction, constants::OrchardFixedBases};
    use halo2_gadgets::{
        ecc::{chip::EccPoint, EccInstructions, Point, X},
        poseidon::{
            primitives::{self as poseidon, ConstantLength},
            PoseidonSpongeInstructions,
        },
        utilities::cond_swap::CondSwapChip,
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
        cond_swap_chip: CondSwapChip<pallas::Base>,
        rho: AssignedCell<pallas::Base, pallas::Base>,
        psi: &AssignedCell<pallas::Base, pallas::Base>,
        cm: &Point<pallas::Affine, EccChip>,
        nk: AssignedCell<pallas::Base, pallas::Base>,
        split_flag: AssignedCell<pallas::Base, pallas::Base>,
    ) -> Result<X<pallas::Affine, EccChip>, plonk::Error> {
        let nf = crate::circuit::gadget::derive_nullifier(
            layouter,
            poseidon_chip,
            add_chip,
            ecc_chip.clone(),
            rho,
            psi,
            cm,
            nk,
        )?;

        // Add NullifierL to nf
        // split_note_nf = NullifierL + nf
        let nullifier_l = Point::new_from_constant(
            ecc_chip.clone(),
            layouter.namespace(|| "witness NullifierL constant"),
            pallas::Point::hash_to_curve("z.cash:Orchard")(b"L").to_affine(),
        )?;
        let split_note_nf = nullifier_l.add(layouter.namespace(|| "split_note_nf"), &nf)?;

        // Select the desired nullifier according to split_flag
        Ok(Point::from_inner(
            ecc_chip,
            cond_swap_chip.mux_on_points(
                layouter.namespace(|| "mux on nf"),
                &split_flag,
                nf.inner(),
                split_note_nf.inner(),
            )?,
        )
        .extract_p())
    }
}
