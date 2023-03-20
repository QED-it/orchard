pub(in crate::circuit) mod gadgets {
    use pasta_curves::pallas;

    use crate::constants::{OrchardFixedBases, OrchardFixedBasesFull, ValueCommitV};
    use halo2_gadgets::ecc::{
        EccInstructions, FixedPoint, FixedPointShort, NonIdentityPoint, Point, ScalarFixed,
        ScalarFixedShort,
    };
    use halo2_proofs::{
        circuit::{AssignedCell, Layouter},
        plonk,
    };

    /// `ValueCommit^Orchard` from [Section 5.4.8.3 Homomorphic Pedersen commitments (Sapling and Orchard)].
    ///
    /// [Section 5.4.8.3 Homomorphic Pedersen commitments (Sapling and Orchard)]: https://zips.z.cash/protocol/protocol.pdf#concretehomomorphiccommit
    pub(in crate::circuit) fn value_commit_orchard<
        EccChip: EccInstructions<
            pallas::Affine,
            FixedPoints = OrchardFixedBases,
            Var = AssignedCell<pallas::Base, pallas::Base>,
        >,
    >(
        mut layouter: impl Layouter<pallas::Base>,
        ecc_chip: EccChip,
        v: ScalarFixedShort<pallas::Affine, EccChip>,
        rcv: ScalarFixed<pallas::Affine, EccChip>,
        _asset: NonIdentityPoint<pallas::Affine, EccChip>,
    ) -> Result<Point<pallas::Affine, EccChip>, plonk::Error> {
        // commitment = [v] ValueCommitV
        let (commitment, _) = {
            let value_commit_v = ValueCommitV;
            let value_commit_v = FixedPointShort::from_inner(ecc_chip.clone(), value_commit_v);
            value_commit_v.mul(layouter.namespace(|| "[v] ValueCommitV"), v)?
        };

        // blind = [rcv] ValueCommitR
        let (blind, _rcv) = {
            let value_commit_r = OrchardFixedBasesFull::ValueCommitR;
            let value_commit_r = FixedPoint::from_inner(ecc_chip, value_commit_r);

            // [rcv] ValueCommitR
            value_commit_r.mul(layouter.namespace(|| "[rcv] ValueCommitR"), rcv)?
        };

        // [v] ValueCommitV + [rcv] ValueCommitR
        commitment.add(layouter.namespace(|| "cv"), &blind)
    }
}
