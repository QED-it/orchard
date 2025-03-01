//! Value commitment logic for the Orchard circuit.

use pasta_curves::pallas;

use crate::constants::{OrchardCommitDomains, OrchardFixedBases, OrchardHashDomains};

use halo2_gadgets::utilities::lookup_range_check::PallasLookupRangeCheck;
use halo2_gadgets::{
    ecc::{chip::EccChip, NonIdentityPoint},
    sinsemilla::chip::SinsemillaChip,
};

pub struct ZsaValueCommitParams<Lookup: PallasLookupRangeCheck> {
    pub sinsemilla_chip:
        SinsemillaChip<OrchardHashDomains, OrchardCommitDomains, OrchardFixedBases, Lookup>,
    pub asset: NonIdentityPoint<pallas::Affine, EccChip<OrchardFixedBases, Lookup>>,
}

pub(in crate::circuit) mod gadgets {
    use super::*;

    use crate::constants::{OrchardFixedBasesFull, ValueCommitV};

    use halo2_gadgets::{
        ecc::{FixedPoint, FixedPointShort, Point, ScalarFixed, ScalarFixedShort, ScalarVar},
        sinsemilla,
        utilities::lookup_range_check::PallasLookupRangeCheck,
    };

    use halo2_proofs::{
        circuit::{AssignedCell, Chip, Layouter},
        plonk,
    };

    /// `ValueCommit^Orchard` from [ZIP-226: Transfer and Burn of Zcash Shielded Assets][zip226].
    ///
    /// [zip226]: https://zips.z.cash/zip-0226#value-commitment-correctness
    pub(in crate::circuit) fn value_commit_orchard<Lookup: PallasLookupRangeCheck>(
        mut layouter: impl Layouter<pallas::Base>,
        ecc_chip: EccChip<OrchardFixedBases, Lookup>,
        v_net_magnitude_sign: (
            AssignedCell<pallas::Base, pallas::Base>,
            AssignedCell<pallas::Base, pallas::Base>,
        ),
        rcv: ScalarFixed<pallas::Affine, EccChip<OrchardFixedBases, Lookup>>,
        zsa_params: Option<ZsaValueCommitParams<Lookup>>,
    ) -> Result<Point<pallas::Affine, EccChip<OrchardFixedBases, Lookup>>, plonk::Error> {
        // Evaluate commitment = [v_net_magnitude_sign] asset
        let commitment = match zsa_params {
            None => {
                let v_net = ScalarFixedShort::new(
                    ecc_chip.clone(),
                    layouter.namespace(|| "v_net"),
                    v_net_magnitude_sign,
                )?;

                // commitment = [v_net] ValueCommitV
                let (commitment, _) = {
                    let value_commit_v = ValueCommitV;
                    let value_commit_v =
                        FixedPointShort::from_inner(ecc_chip.clone(), value_commit_v);
                    value_commit_v.mul(layouter.namespace(|| "[v] ValueCommitV"), v_net)?
                };
                commitment
            }
            Some(params) => {
                // Check that magnitude is 64 bits
                // Note: if zsa_params is not provided, this check will be performed inside the
                // fixed-base short scalar multiplication.
                {
                    let lookup_config = params.sinsemilla_chip.config().lookup_config();
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

                // Multiply asset by magnitude, using the long scalar mul.
                // TODO: implement a new variable base multiplication which is optimized for 64-bit scalar
                // (the long scalar mul is optimized for pallas::Base scalar (~255-bits))
                //
                // magnitude_asset = [magnitude] asset
                let magnitude_asset = {
                    let magnitude_scalar = ScalarVar::from_base(
                        ecc_chip.clone(),
                        layouter.namespace(|| "magnitude"),
                        &v_net_magnitude_sign.0,
                    )?;
                    let (magnitude_asset, _) = params
                        .asset
                        .mul(layouter.namespace(|| "[magnitude] asset"), magnitude_scalar)?;
                    magnitude_asset
                };

                // commitment = [sign] magnitude_asset = [v_net_magnitude_sign] asset
                magnitude_asset.mul_sign(
                    layouter.namespace(|| "[sign] commitment"),
                    &v_net_magnitude_sign.1,
                )?
            }
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

#[cfg(test)]
mod tests {
    use crate::{
        circuit::gadget::assign_free_advice,
        circuit::value_commit_orchard::gadgets::value_commit_orchard,
        circuit::K,
        constants::{OrchardCommitDomains, OrchardFixedBases, OrchardHashDomains},
        note::AssetBase,
        value::{NoteValue, ValueCommitTrapdoor, ValueCommitment},
    };
    use halo2_gadgets::{
        ecc::{
            chip::{EccChip, EccConfig},
            NonIdentityPoint, ScalarFixed,
        },
        sinsemilla::chip::{SinsemillaChip, SinsemillaConfig},
        utilities::lookup_range_check::{
            LookupRangeCheck4_5BConfig, PallasLookupRangeCheck4_5BConfig,
        },
    };

    use group::Curve;
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner, Value},
        dev::MockProver,
        plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance},
    };
    use pasta_curves::pallas;

    use crate::circuit::value_commit_orchard::ZsaValueCommitParams;
    use rand::{rngs::OsRng, RngCore};

    #[test]
    fn test_value_commit_orchard() {
        #[derive(Clone, Debug)]
        pub struct MyConfig {
            primary: Column<Instance>,
            advices: [Column<Advice>; 10],
            ecc_config: EccConfig<OrchardFixedBases, PallasLookupRangeCheck4_5BConfig>,
            // Sinsemilla  config is only used to initialize the table_idx lookup table in the same
            // way as in the Orchard circuit
            sinsemilla_config: SinsemillaConfig<
                OrchardHashDomains,
                OrchardCommitDomains,
                OrchardFixedBases,
                PallasLookupRangeCheck4_5BConfig,
            >,
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
                let table_range_check_tag = meta.lookup_table_column();
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

                let range_check = LookupRangeCheck4_5BConfig::configure_with_tag(
                    meta,
                    advices[9],
                    table_idx,
                    table_range_check_tag,
                );

                let sinsemilla_config = SinsemillaChip::configure(
                    meta,
                    advices[..5].try_into().unwrap(),
                    advices[6],
                    lagrange_coeffs[0],
                    lookup,
                    range_check,
                    true,
                );

                MyConfig {
                    primary,
                    advices,
                    ecc_config:
                        EccChip::<OrchardFixedBases, PallasLookupRangeCheck4_5BConfig>::configure(
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

                let sinsemilla_chip = SinsemillaChip::construct(config.sinsemilla_config.clone());

                // Witness the magnitude and sign of v_net = v_old - v_new
                let v_net_magnitude_sign = {
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
                    (magnitude, sign)
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
                    v_net_magnitude_sign,
                    rcv,
                    Some(ZsaValueCommitParams {
                        sinsemilla_chip,
                        asset,
                    }),
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
        let random_asset = AssetBase::random();
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
