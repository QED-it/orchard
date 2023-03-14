//! Gadgets used in the Orchard circuit.

use ff::Field;
use pasta_curves::pallas;

use super::{commit_ivk::CommitIvkChip, note_commit::NoteCommitChip};
use crate::constants::{
    NullifierK, OrchardCommitDomains, OrchardFixedBases, OrchardFixedBasesFull, OrchardHashDomains,
};
use halo2_gadgets::ecc::NonIdentityPoint;
use halo2_gadgets::{
    ecc::{
        chip::EccChip, EccInstructions, FixedPoint, FixedPointBaseField, Point, ScalarFixed,
        ScalarFixedShort, X,
    },
    poseidon::{
        primitives::{self as poseidon, ConstantLength},
        Hash as PoseidonHash, PoseidonSpongeInstructions, Pow5Chip as PoseidonChip,
    },
    sinsemilla::{chip::SinsemillaChip, merkle::chip::MerkleChip},
};
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{AssignedCell, Chip, Layouter, Value},
    plonk::{self, Advice, Assigned, Column},
};

pub(in crate::circuit) mod add_chip;

impl super::Config {
    pub(super) fn add_chip(&self) -> add_chip::AddChip {
        add_chip::AddChip::construct(self.add_config.clone())
    }

    pub(super) fn commit_ivk_chip(&self) -> CommitIvkChip {
        CommitIvkChip::construct(self.commit_ivk_config.clone())
    }

    pub(super) fn ecc_chip(&self) -> EccChip<OrchardFixedBases> {
        EccChip::construct(self.ecc_config.clone())
    }

    pub(super) fn sinsemilla_chip_1(
        &self,
    ) -> SinsemillaChip<OrchardHashDomains, OrchardCommitDomains, OrchardFixedBases> {
        SinsemillaChip::construct(self.sinsemilla_config_1.clone())
    }

    pub(super) fn sinsemilla_chip_2(
        &self,
    ) -> SinsemillaChip<OrchardHashDomains, OrchardCommitDomains, OrchardFixedBases> {
        SinsemillaChip::construct(self.sinsemilla_config_2.clone())
    }

    pub(super) fn merkle_chip_1(
        &self,
    ) -> MerkleChip<OrchardHashDomains, OrchardCommitDomains, OrchardFixedBases> {
        MerkleChip::construct(self.merkle_config_1.clone())
    }

    pub(super) fn merkle_chip_2(
        &self,
    ) -> MerkleChip<OrchardHashDomains, OrchardCommitDomains, OrchardFixedBases> {
        MerkleChip::construct(self.merkle_config_2.clone())
    }

    pub(super) fn poseidon_chip(&self) -> PoseidonChip<pallas::Base, 3, 2> {
        PoseidonChip::construct(self.poseidon_config.clone())
    }

    pub(super) fn note_commit_chip_new(&self) -> NoteCommitChip {
        NoteCommitChip::construct(self.new_note_commit_config.clone())
    }

    pub(super) fn note_commit_chip_old(&self) -> NoteCommitChip {
        NoteCommitChip::construct(self.old_note_commit_config.clone())
    }
}

/// An instruction set for adding two circuit words (field elements).
pub(in crate::circuit) trait AddInstruction<F: FieldExt>: Chip<F> {
    /// Constraints `a + b` and returns the sum.
    fn add(
        &self,
        layouter: impl Layouter<F>,
        a: &AssignedCell<F, F>,
        b: &AssignedCell<F, F>,
    ) -> Result<AssignedCell<F, F>, plonk::Error>;
}

/// Witnesses the given value in a standalone region.
///
/// Usages of this helper are technically superfluous, as the single-cell region is only
/// ever used in equality constraints. We could eliminate them with a
/// [write-on-copy abstraction](https://github.com/zcash/halo2/issues/334).
pub(in crate::circuit) fn assign_free_advice<F: Field, V: Copy>(
    mut layouter: impl Layouter<F>,
    column: Column<Advice>,
    value: Value<V>,
) -> Result<AssignedCell<V, F>, plonk::Error>
where
    for<'v> Assigned<F>: From<&'v V>,
{
    layouter.assign_region(
        || "load private",
        |mut region| region.assign_advice(|| "load private", column, 0, || value),
    )
}

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
    asset: NonIdentityPoint<pallas::Affine, EccChip>,
) -> Result<Point<pallas::Affine, EccChip>, plonk::Error> {
    // commitment = [v] asset
    let (commitment, _) = asset.mul_short(layouter.namespace(|| "[v] asset"), v)?;

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
        Var = AssignedCell<pallas::Base, pallas::Base>,
    >,
>(
    mut layouter: impl Layouter<pallas::Base>,
    poseidon_chip: PoseidonChip,
    add_chip: AddChip,
    ecc_chip: EccChip,
    rho: AssignedCell<pallas::Base, pallas::Base>,
    psi: &AssignedCell<pallas::Base, pallas::Base>,
    cm: &Point<pallas::Affine, EccChip>,
    nk: AssignedCell<pallas::Base, pallas::Base>,
) -> Result<X<pallas::Affine, EccChip>, plonk::Error> {
    // hash = poseidon_hash(nk, rho)
    let hash = {
        let poseidon_message = [nk, rho];
        let poseidon_hasher =
            PoseidonHash::init(poseidon_chip, layouter.namespace(|| "Poseidon init"))?;
        poseidon_hasher.hash(
            layouter.namespace(|| "Poseidon hash (nk, rho)"),
            poseidon_message,
        )?
    };

    // Add hash output to psi.
    // `scalar` = poseidon_hash(nk, rho) + psi.
    let scalar = add_chip.add(
        layouter.namespace(|| "scalar = poseidon_hash(nk, rho) + psi"),
        &hash,
        psi,
    )?;

    // Multiply scalar by NullifierK
    // `product` = [poseidon_hash(nk, rho) + psi] NullifierK.
    //
    let product = {
        let nullifier_k = FixedPointBaseField::from_inner(ecc_chip, NullifierK);
        nullifier_k.mul(
            layouter.namespace(|| "[poseidon_output + psi] NullifierK"),
            scalar,
        )?
    };

    // Add cm to multiplied fixed base to get nf
    // cm + [poseidon_output + psi] NullifierK
    cm.add(layouter.namespace(|| "nf"), &product)
        .map(|res| res.extract_p())
}

pub(in crate::circuit) use crate::circuit::commit_ivk::gadgets::commit_ivk;
pub(in crate::circuit) use crate::circuit::note_commit::gadgets::note_commit;

#[cfg(test)]
mod tests {
    use crate::{
        circuit::gadget::{assign_free_advice, value_commit_orchard},
        circuit::K,
        constants::{OrchardCommitDomains, OrchardFixedBases, OrchardHashDomains},
        keys::{IssuanceAuthorizingKey, IssuanceValidatingKey, SpendingKey},
        note::AssetBase,
        value::{NoteValue, ValueCommitTrapdoor, ValueCommitment},
    };
    use halo2_gadgets::{
        ecc::{
            chip::{EccChip, EccConfig},
            NonIdentityPoint, ScalarFixed, ScalarFixedShort,
        },
        sinsemilla::chip::{SinsemillaChip, SinsemillaConfig},
        utilities::lookup_range_check::LookupRangeCheckConfig,
    };

    use group::Curve;
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner, Value},
        dev::MockProver,
        plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance},
    };
    use pasta_curves::pallas;

    use rand::{rngs::OsRng, RngCore};

    #[test]
    fn test_value_commit_orchard() {
        #[derive(Clone, Debug)]
        pub struct MyConfig {
            primary: Column<Instance>,
            advices: [Column<Advice>; 10],
            ecc_config: EccConfig<OrchardFixedBases>,
            // Sinsemilla  config is only used to initialize the table_idx lookup table in the same
            // way as in the Orchard circuit
            sinsemilla_config:
                SinsemillaConfig<OrchardHashDomains, OrchardCommitDomains, OrchardFixedBases>,
        }
        #[derive(Default)]
        struct MyCircuit {
            v_old: Value<NoteValue>,
            v_new: Value<NoteValue>,
            rcv: Value<ValueCommitTrapdoor>,
            asset: Value<AssetBase>,
            split_flag: Value<bool>,
        }

        impl Circuit<pallas::Base> for MyCircuit {
            type Config = MyConfig;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                Self::default()
            }

            fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self::Config {
                let advices = [
                    meta.advice_column(),
                    meta.advice_column(),
                    meta.advice_column(),
                    meta.advice_column(),
                    meta.advice_column(),
                    meta.advice_column(),
                    meta.advice_column(),
                    meta.advice_column(),
                    meta.advice_column(),
                    meta.advice_column(),
                ];

                for advice in advices.iter() {
                    meta.enable_equality(*advice);
                }

                // Instance column used for public inputs
                let primary = meta.instance_column();
                meta.enable_equality(primary);

                let table_idx = meta.lookup_table_column();
                let lookup = (
                    table_idx,
                    meta.lookup_table_column(),
                    meta.lookup_table_column(),
                );

                let lagrange_coeffs = [
                    meta.fixed_column(),
                    meta.fixed_column(),
                    meta.fixed_column(),
                    meta.fixed_column(),
                    meta.fixed_column(),
                    meta.fixed_column(),
                    meta.fixed_column(),
                    meta.fixed_column(),
                ];
                meta.enable_constant(lagrange_coeffs[0]);

                let range_check = LookupRangeCheckConfig::configure(meta, advices[9], table_idx);

                let sinsemilla_config = SinsemillaChip::configure(
                    meta,
                    advices[..5].try_into().unwrap(),
                    advices[6],
                    lagrange_coeffs[0],
                    lookup,
                    range_check,
                );

                MyConfig {
                    primary,
                    advices,
                    ecc_config: EccChip::<OrchardFixedBases>::configure(
                        meta,
                        advices,
                        lagrange_coeffs,
                        range_check,
                    ),
                    sinsemilla_config,
                }
            }

            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<pallas::Base>,
            ) -> Result<(), Error> {
                // Load the Sinsemilla generator lookup table.
                SinsemillaChip::load(config.sinsemilla_config.clone(), &mut layouter)?;

                // Construct an ECC chip
                let ecc_chip = EccChip::construct(config.ecc_config);

                // Witness the magnitude and sign of v_net = v_old - v_new
                let v_net = {
                    // v_net is equal to
                    //   (-v_new) if split_flag = true
                    //   v_old - v_new if split_flag = false
                    let v_net = self.split_flag.and_then(|split_flag| {
                        if split_flag {
                            Value::known(crate::value::NoteValue::zero()) - self.v_new
                        } else {
                            self.v_old - self.v_new
                        }
                    });

                    let magnitude_sign = v_net.map(|v_net| {
                        let (magnitude, sign) = v_net.magnitude_sign();
                        (
                            // magnitude is guaranteed to be an unsigned 64-bit value.
                            // Therefore, we can move it into the base field.
                            pallas::Base::from(magnitude),
                            match sign {
                                crate::value::Sign::Positive => pallas::Base::one(),
                                crate::value::Sign::Negative => -pallas::Base::one(),
                            },
                        )
                    });

                    let magnitude = assign_free_advice(
                        layouter.namespace(|| "v_net magnitude"),
                        config.advices[9],
                        magnitude_sign.map(|m_s| m_s.0),
                    )?;
                    let sign = assign_free_advice(
                        layouter.namespace(|| "v_net sign"),
                        config.advices[9],
                        magnitude_sign.map(|m_s| m_s.1),
                    )?;
                    let v_net_magnitude_sign = (magnitude, sign);

                    let v_net = ScalarFixedShort::new(
                        ecc_chip.clone(),
                        layouter.namespace(|| "v_net"),
                        v_net_magnitude_sign,
                    )?;
                    v_net
                };

                // Witness rcv
                let rcv = ScalarFixed::new(
                    ecc_chip.clone(),
                    layouter.namespace(|| "rcv"),
                    self.rcv.as_ref().map(|rcv| rcv.inner()),
                )?;

                // Witness asset
                let asset = NonIdentityPoint::new(
                    ecc_chip.clone(),
                    layouter.namespace(|| "witness asset"),
                    self.asset.map(|asset| asset.cv_base().to_affine()),
                )?;

                // Evaluate cv_net with value_commit_orchard
                let cv_net = value_commit_orchard(
                    layouter.namespace(|| "cv_net = ValueCommit^Orchard_rcv(v_net)"),
                    ecc_chip,
                    v_net,
                    rcv,
                    asset,
                )?;

                // Constrain cv_net to equal public input
                layouter.constrain_instance(cv_net.inner().x().cell(), config.primary, 0)?;
                layouter.constrain_instance(cv_net.inner().y().cell(), config.primary, 1)
            }
        }

        // Test different circuits
        let mut rng = OsRng;
        let mut circuits = vec![];
        let mut instances = vec![];
        let native_asset = AssetBase::native();
        let random_asset = {
            let sk = SpendingKey::random(&mut rng);
            let isk = IssuanceAuthorizingKey::from(&sk);
            let ik = IssuanceValidatingKey::from(&isk);
            let asset_descr = "zsa_asset";
            AssetBase::derive(&ik, asset_descr)
        };
        for split_flag in [false, true] {
            for asset in [native_asset, random_asset] {
                let v_old = NoteValue::from_raw(rng.next_u64());
                let v_new = NoteValue::from_raw(rng.next_u64());
                let rcv = ValueCommitTrapdoor::random(&mut rng);
                let v_net = if split_flag {
                    NoteValue::zero() - v_new
                } else {
                    v_old - v_new
                };
                circuits.push(MyCircuit {
                    v_old: Value::known(v_old),
                    v_new: Value::known(v_new),
                    rcv: Value::known(rcv),
                    asset: Value::known(asset),
                    split_flag: Value::known(split_flag),
                });
                let expected_cv_net = ValueCommitment::derive(v_net, rcv, asset);
                instances.push([[expected_cv_net.x(), expected_cv_net.y()]]);
            }
        }

        for (circuit, instance) in circuits.iter().zip(instances.iter()) {
            let prover = MockProver::<pallas::Base>::run(
                K,
                circuit,
                instance.iter().map(|p| p.to_vec()).collect(),
            )
            .unwrap();
            assert_eq!(prover.verify(), Ok(()));
        }
    }
}
