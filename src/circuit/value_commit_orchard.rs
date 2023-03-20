pub(in crate::circuit) mod gadgets {
    use pasta_curves::pallas;

    use crate::constants::{
        OrchardCommitDomains, OrchardFixedBases, OrchardFixedBasesFull, OrchardHashDomains,
        ValueCommitV,
    };
    use halo2_gadgets::{
        ecc::{
            EccInstructions, FixedPoint, FixedPointShort, NonIdentityPoint, Point, ScalarFixed,
            ScalarFixedShort,
        },
        sinsemilla::{self, chip::SinsemillaChip},
    };
    use halo2_proofs::{
        circuit::{AssignedCell, Chip, Layouter},
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
        sinsemilla_chip: SinsemillaChip<
            OrchardHashDomains,
            OrchardCommitDomains,
            OrchardFixedBases,
        >,
        ecc_chip: EccChip,
        v_net_magnitude_sign: (
            AssignedCell<pallas::Base, pallas::Base>,
            AssignedCell<pallas::Base, pallas::Base>,
        ),
        // TODO to remove v
        v: ScalarFixedShort<pallas::Affine, EccChip>,
        rcv: ScalarFixed<pallas::Affine, EccChip>,
        _asset: NonIdentityPoint<pallas::Affine, EccChip>,
    ) -> Result<Point<pallas::Affine, EccChip>, plonk::Error> {
        // Check that v.magnitude is 64 bits.
        {
            let lookup_config = sinsemilla_chip.config().lookup_config();
            let (magnitude_words, magnitude_extra_bits) = (6, 4);
            assert_eq!(
                magnitude_words * sinsemilla::primitives::K + magnitude_extra_bits,
                64
            );
            let magnitude_zs = lookup_config.copy_check(
                layouter.namespace(|| "magnitude lowest 60 bits"),
                v_net_magnitude_sign.0.clone(),
                magnitude_words, // 6 windows of 10 bits.
                false,           // Do not constrain the result here.
            )?;
            assert_eq!(magnitude_zs.len(), magnitude_words + 1);
            lookup_config.copy_short_check(
                layouter.namespace(|| "magnitude highest 4 bits"),
                magnitude_zs[magnitude_words].clone(),
                magnitude_extra_bits, // The 7th window must be a 4 bits value.
            )?;
        }

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
