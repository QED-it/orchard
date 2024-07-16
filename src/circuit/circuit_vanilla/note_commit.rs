//! Note commitment logic for the Orchard circuit (Vanilla variation).

use halo2_proofs::{
    circuit::{AssignedCell, Chip, Layouter},
    plonk::Error,
};
use pasta_curves::pallas;

use crate::{
    circuit::note_commit::{DecomposeB, DecomposeD, DecomposeE, DecomposeG, DecomposeHVanilla},
    constants::{OrchardCommitDomains, OrchardFixedBases, OrchardHashDomains},
    value::NoteValue,
};
use halo2_gadgets::{
    ecc::{
        chip::{EccChip, NonIdentityEccPoint},
        Point, ScalarFixed,
    },
    sinsemilla::{chip::SinsemillaChip, CommitDomain, Message, MessagePiece},
    utilities::{lookup_range_check::PallasLookupRangeCheckConfig, RangeConstrained},
};

/*
    <https://zips.z.cash/protocol/nu5.pdf#concretesinsemillacommit>
    We need to hash g★_d || pk★_d || i2lebsp_{64}(v) || rho || psi,
    where
        - g★_d is the representation of the point g_d, with 255 bits used for the
          x-coordinate and 1 bit used for the y-coordinate;
        - pk★_d is the representation of the point pk_d, with 255 bits used for the
          x-coordinate and 1 bit used for the y-coordinate;
        - v is a 64-bit value;
        - rho is a base field element (255 bits); and
        - psi is a base field element (255 bits).
*/

pub(in crate::circuit) mod gadgets {

    use super::*;

    use crate::circuit::note_commit::gadgets::{
        canon_bitshift_130, pkd_asset_x_canonicity, psi_canonicity, rho_canonicity, y_canonicity,
    };
    use crate::circuit::note_commit::{NoteCommitChip, SpecificConfigForCircuit};

    #[allow(clippy::many_single_char_names)]
    #[allow(clippy::type_complexity)]
    #[allow(clippy::too_many_arguments)]
    pub(in crate::circuit) fn note_commit(
        mut layouter: impl Layouter<pallas::Base>,
        chip: SinsemillaChip<OrchardHashDomains, OrchardCommitDomains, OrchardFixedBases>,
        ecc_chip: EccChip<OrchardFixedBases>,
        note_commit_chip: NoteCommitChip<PallasLookupRangeCheckConfig>,
        g_d: &NonIdentityEccPoint,
        pk_d: &NonIdentityEccPoint,
        value: AssignedCell<NoteValue, pallas::Base>,
        rho: AssignedCell<pallas::Base, pallas::Base>,
        psi: AssignedCell<pallas::Base, pallas::Base>,
        rcm: ScalarFixed<pallas::Affine, EccChip<OrchardFixedBases>>,
    ) -> Result<Point<pallas::Affine, EccChip<OrchardFixedBases>>, Error> {
        let vanilla_config = match &note_commit_chip.config.specific_config_for_circuit {
            SpecificConfigForCircuit::Zsa(_) => {
                panic!("Incorrect NoteCommitChip")
            }
            SpecificConfigForCircuit::Vanilla(specific_config) => specific_config.clone(),
        };

        let lookup_config = chip.config().lookup_config();

        // `a` = bits 0..=249 of `x(g_d)`
        let a = MessagePiece::from_subpieces(
            chip.clone(),
            layouter.namespace(|| "a"),
            [RangeConstrained::bitrange_of(g_d.x().value(), 0..250)],
        )?;

        // b = b_0 || b_1 || b_2 || b_3
        //   = (bits 250..=253 of x(g_d)) || (bit 254 of x(g_d)) || (ỹ bit of g_d) || (bits 0..=3 of pk★_d)
        let (b, b_0, b_1, b_2, b_3) =
            DecomposeB::decompose(&lookup_config, chip.clone(), &mut layouter, g_d, pk_d)?;

        // c = bits 4..=253 of pk★_d
        let c = MessagePiece::from_subpieces(
            chip.clone(),
            layouter.namespace(|| "c"),
            [RangeConstrained::bitrange_of(pk_d.x().value(), 4..254)],
        )?;

        // d = d_0 || d_1 || d_2 || d_3
        //   = (bit 254 of x(pk_d)) || (ỹ bit of pk_d) || (bits 0..=7 of v) || (bits 8..=57 of v)
        let (d, d_0, d_1, d_2) =
            DecomposeD::decompose(&lookup_config, chip.clone(), &mut layouter, pk_d, &value)?;

        // e = e_0 || e_1 = (bits 58..=63 of v) || (bits 0..=3 of rho)
        let (e, e_0, e_1) =
            DecomposeE::decompose(&lookup_config, chip.clone(), &mut layouter, &value, &rho)?;

        // f = bits 4..=253 inclusive of rho
        let f = MessagePiece::from_subpieces(
            chip.clone(),
            layouter.namespace(|| "f"),
            [RangeConstrained::bitrange_of(rho.value(), 4..254)],
        )?;

        // g = g_0 || g_1 || g_2
        //   = (bit 254 of rho) || (bits 0..=8 of psi) || (bits 9..=248 of psi)
        let (g, g_0, g_1) =
            DecomposeG::decompose(&lookup_config, chip.clone(), &mut layouter, &rho, &psi)?;

        // h = h_0 || h_1 || h_2
        //   = (bits 249..=253 of psi) || (bit 254 of psi) || 4 zero bits
        let (h, h_0, h_1) =
            DecomposeHVanilla::decompose(&lookup_config, chip.clone(), &mut layouter, &psi)?;

        // Check decomposition of `y(g_d)`.
        let b_2 = y_canonicity(
            &lookup_config,
            &note_commit_chip.config.y_canon,
            layouter.namespace(|| "y(g_d) decomposition"),
            g_d.y(),
            b_2,
        )?;
        // Check decomposition of `y(pk_d)`.
        let d_1 = y_canonicity(
            &lookup_config,
            &note_commit_chip.config.y_canon,
            layouter.namespace(|| "y(pk_d) decomposition"),
            pk_d.y(),
            d_1,
        )?;

        // cm = NoteCommit^Orchard_rcm(g★_d || pk★_d || i2lebsp_{64}(v) || rho || psi)
        //
        // `cm = ⊥` is handled internally to `CommitDomain::commit`: incomplete addition
        // constraints allows ⊥ to occur, and then during synthesis it detects these edge
        // cases and raises an error (aborting proof creation).
        //
        // https://p.z.cash/ZKS:action-cm-old-integrity?partial
        // https://p.z.cash/ZKS:action-cmx-new-integrity?partial
        let (cm, zs) = {
            let message = Message::from_pieces(
                chip.clone(),
                vec![
                    a.clone(),
                    b.clone(),
                    c.clone(),
                    d.clone(),
                    e.clone(),
                    f.clone(),
                    g.clone(),
                    h.clone(),
                ],
            );
            let domain = CommitDomain::new(chip, ecc_chip, &OrchardCommitDomains::NoteCommit);
            domain.commit(
                layouter.namespace(|| "Process NoteCommit inputs"),
                message,
                rcm,
            )?
        };

        // `CommitDomain::commit` returns the running sum for each `MessagePiece`. Grab
        // the outputs that we will need for canonicity checks.
        let z13_a = zs[0][13].clone();
        let z13_c = zs[2][13].clone();
        let z1_d = zs[3][1].clone();
        let z13_f = zs[5][13].clone();
        let z1_g = zs[6][1].clone();
        let g_2 = z1_g.clone();
        let z13_g = zs[6][13].clone();

        // Witness and constrain the bounds we need to ensure canonicity.
        let (a_prime, z13_a_prime) = canon_bitshift_130(
            &lookup_config,
            layouter.namespace(|| "x(g_d) canonicity"),
            a.inner().cell_value(),
        )?;

        let (b3_c_prime, z14_b3_c_prime) = pkd_asset_x_canonicity(
            &lookup_config,
            layouter.namespace(|| "x(pk_d) canonicity"),
            b_3.clone(),
            c.inner().cell_value(),
        )?;

        let (e1_f_prime, z14_e1_f_prime) = rho_canonicity(
            &lookup_config,
            layouter.namespace(|| "rho canonicity"),
            e_1.clone(),
            f.inner().cell_value(),
        )?;

        let (g1_g2_prime, z13_g1_g2_prime) = psi_canonicity(
            &lookup_config,
            layouter.namespace(|| "psi canonicity"),
            g_1.clone(),
            g_2,
        )?;

        // Finally, assign values to all of the NoteCommit regions.
        let cfg = note_commit_chip.config;

        let b_1 = cfg
            .b
            .assign(&mut layouter, b, b_0.clone(), b_1, b_2, b_3.clone())?;

        let d_0 = cfg
            .d
            .assign(&mut layouter, d, d_0, d_1, d_2.clone(), z1_d.clone())?;

        cfg.e.assign(&mut layouter, e, e_0.clone(), e_1.clone())?;

        let g_0 = cfg
            .g
            .assign(&mut layouter, g, g_0, g_1.clone(), z1_g.clone())?;

        let h_1 = vanilla_config
            .h_vanilla
            .assign(&mut layouter, h, h_0.clone(), h_1)?;

        cfg.g_d
            .assign(&mut layouter, g_d, a, b_0, b_1, a_prime, z13_a, z13_a_prime)?;

        cfg.pk_d_asset.assign(
            &mut layouter,
            pk_d,
            b_3,
            c,
            d_0,
            b3_c_prime,
            z13_c,
            z14_b3_c_prime,
        )?;

        cfg.value.assign(&mut layouter, value, d_2, z1_d, e_0)?;

        cfg.rho.assign(
            &mut layouter,
            rho,
            e_1,
            f,
            g_0,
            e1_f_prime,
            z13_f,
            z14_e1_f_prime,
        )?;

        cfg.psi.assign(
            &mut layouter,
            psi,
            g_1,
            z1_g,
            h_0,
            h_1,
            g1_g2_prime,
            z13_g,
            z13_g1_g2_prime,
        )?;

        Ok(cm)
    }
}

#[cfg(test)]
mod tests {
    use core::iter;

    use crate::{
        circuit::circuit_vanilla::note_commit::gadgets,
        circuit::gadget::assign_free_advice,
        circuit::note_commit::{NoteCommitChip, NoteCommitConfig},
        constants::{
            fixed_bases::NOTE_COMMITMENT_PERSONALIZATION, OrchardCommitDomains, OrchardFixedBases,
            OrchardHashDomains, L_ORCHARD_BASE, L_VALUE, T_Q,
        },
        value::NoteValue,
    };
    use halo2_gadgets::{
        ecc::{
            chip::{EccChip, EccConfig},
            NonIdentityPoint, ScalarFixed,
        },
        sinsemilla::chip::SinsemillaChip,
        sinsemilla::primitives::CommitDomain,
        utilities::lookup_range_check::{
            LookupRangeCheck, LookupRangeCheckConfig, PallasLookupRangeCheckConfig,
        },
    };

    use ff::{Field, PrimeField, PrimeFieldBits};
    use group::Curve;
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner, Value},
        dev::MockProver,
        plonk::{Circuit, ConstraintSystem, Error},
    };
    use pasta_curves::{arithmetic::CurveAffine, pallas};

    use rand::{rngs::OsRng, RngCore};

    #[test]
    fn note_commit() {
        #[derive(Default)]
        struct MyCircuit {
            gd_x: Value<pallas::Base>,
            gd_y_lsb: Value<pallas::Base>,
            pkd_x: Value<pallas::Base>,
            pkd_y_lsb: Value<pallas::Base>,
            rho: Value<pallas::Base>,
            psi: Value<pallas::Base>,
        }

        impl Circuit<pallas::Base> for MyCircuit {
            type Config = (
                NoteCommitConfig<PallasLookupRangeCheckConfig>,
                EccConfig<OrchardFixedBases>,
            );
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

                // Shared fixed column for loading constants.
                let constants = meta.fixed_column();
                meta.enable_constant(constants);

                for advice in advices.iter() {
                    meta.enable_equality(*advice);
                }

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

                let range_check = LookupRangeCheckConfig::configure(meta, advices[9], table_idx);
                let sinsemilla_config = SinsemillaChip::<
                    OrchardHashDomains,
                    OrchardCommitDomains,
                    OrchardFixedBases,
                >::configure(
                    meta,
                    advices[..5].try_into().unwrap(),
                    advices[2],
                    lagrange_coeffs[0],
                    lookup,
                    range_check,
                    false,
                );
                let note_commit_config =
                    NoteCommitChip::configure(meta, advices, sinsemilla_config, false);

                let ecc_config = EccChip::<OrchardFixedBases>::configure(
                    meta,
                    advices,
                    lagrange_coeffs,
                    range_check,
                );

                (note_commit_config, ecc_config)
            }

            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<pallas::Base>,
            ) -> Result<(), Error> {
                let (note_commit_config, ecc_config) = config;

                // Load the Sinsemilla generator lookup table used by the whole circuit.
                SinsemillaChip::<
                OrchardHashDomains,
                OrchardCommitDomains,
                OrchardFixedBases,
            >::load(note_commit_config.sinsemilla_config.clone(), &mut layouter)?;

                // Construct a Sinsemilla chip
                let sinsemilla_chip =
                    SinsemillaChip::construct(note_commit_config.sinsemilla_config.clone());

                // Construct an ECC chip
                let ecc_chip = EccChip::construct(ecc_config);

                // Construct a NoteCommit chip
                let note_commit_chip = NoteCommitChip::construct(note_commit_config.clone());

                // Witness g_d
                let g_d = {
                    let g_d = self.gd_x.zip(self.gd_y_lsb).map(|(x, y_lsb)| {
                        // Calculate y = (x^3 + 5).sqrt()
                        let mut y = (x.square() * x + pallas::Affine::b()).sqrt().unwrap();
                        if bool::from(y.is_odd() ^ y_lsb.is_odd()) {
                            y = -y;
                        }
                        pallas::Affine::from_xy(x, y).unwrap()
                    });

                    NonIdentityPoint::new(
                        ecc_chip.clone(),
                        layouter.namespace(|| "witness g_d"),
                        g_d,
                    )?
                };

                // Witness pk_d
                let pk_d = {
                    let pk_d = self.pkd_x.zip(self.pkd_y_lsb).map(|(x, y_lsb)| {
                        // Calculate y = (x^3 + 5).sqrt()
                        let mut y = (x.square() * x + pallas::Affine::b()).sqrt().unwrap();
                        if bool::from(y.is_odd() ^ y_lsb.is_odd()) {
                            y = -y;
                        }
                        pallas::Affine::from_xy(x, y).unwrap()
                    });

                    NonIdentityPoint::new(
                        ecc_chip.clone(),
                        layouter.namespace(|| "witness pk_d"),
                        pk_d,
                    )?
                };

                // Witness a random non-negative u64 note value
                // A note value cannot be negative.
                let value = {
                    let mut rng = OsRng;
                    NoteValue::from_raw(rng.next_u64())
                };
                let value_var = {
                    assign_free_advice(
                        layouter.namespace(|| "witness value"),
                        note_commit_config.advices[0],
                        Value::known(value),
                    )?
                };

                // Witness rho
                let rho = assign_free_advice(
                    layouter.namespace(|| "witness rho"),
                    note_commit_config.advices[0],
                    self.rho,
                )?;

                // Witness psi
                let psi = assign_free_advice(
                    layouter.namespace(|| "witness psi"),
                    note_commit_config.advices[0],
                    self.psi,
                )?;

                let rcm = pallas::Scalar::random(OsRng);
                let rcm_gadget = ScalarFixed::new(
                    ecc_chip.clone(),
                    layouter.namespace(|| "rcm"),
                    Value::known(rcm),
                )?;

                let cm = gadgets::note_commit(
                    layouter.namespace(|| "Hash NoteCommit pieces"),
                    sinsemilla_chip,
                    ecc_chip.clone(),
                    note_commit_chip,
                    g_d.inner(),
                    pk_d.inner(),
                    value_var,
                    rho,
                    psi,
                    rcm_gadget,
                )?;
                let expected_cm = {
                    let domain = CommitDomain::new(NOTE_COMMITMENT_PERSONALIZATION);
                    // Hash g★_d || pk★_d || i2lebsp_{64}(v) || rho || psi
                    let lsb = |y_lsb: pallas::Base| y_lsb == pallas::Base::one();
                    let point = self
                        .gd_x
                        .zip(self.gd_y_lsb)
                        .zip(self.pkd_x.zip(self.pkd_y_lsb))
                        .zip(self.rho.zip(self.psi))
                        .map(|(((gd_x, gd_y_lsb), (pkd_x, pkd_y_lsb)), (rho, psi))| {
                            domain
                                .commit(
                                    iter::empty()
                                        .chain(
                                            gd_x.to_le_bits().iter().by_vals().take(L_ORCHARD_BASE),
                                        )
                                        .chain(Some(lsb(gd_y_lsb)))
                                        .chain(
                                            pkd_x
                                                .to_le_bits()
                                                .iter()
                                                .by_vals()
                                                .take(L_ORCHARD_BASE),
                                        )
                                        .chain(Some(lsb(pkd_y_lsb)))
                                        .chain(value.to_le_bits().iter().by_vals().take(L_VALUE))
                                        .chain(
                                            rho.to_le_bits().iter().by_vals().take(L_ORCHARD_BASE),
                                        )
                                        .chain(
                                            psi.to_le_bits().iter().by_vals().take(L_ORCHARD_BASE),
                                        ),
                                    &rcm,
                                )
                                .unwrap()
                                .to_affine()
                        });
                    NonIdentityPoint::new(ecc_chip, layouter.namespace(|| "witness cm"), point)?
                };
                cm.constrain_equal(layouter.namespace(|| "cm == expected cm"), &expected_cm)
            }
        }

        let two_pow_254 = pallas::Base::from_u128(1 << 127).square();
        // Test different values of `ak`, `nk`
        let circuits = [
            // `gd_x` = -1, `pkd_x` = -1 (these have to be x-coordinates of curve points)
            // `rho` = 0, `psi` = 0
            MyCircuit {
                gd_x: Value::known(-pallas::Base::one()),
                gd_y_lsb: Value::known(pallas::Base::one()),
                pkd_x: Value::known(-pallas::Base::one()),
                pkd_y_lsb: Value::known(pallas::Base::one()),
                rho: Value::known(pallas::Base::zero()),
                psi: Value::known(pallas::Base::zero()),
            },
            // `rho` = T_Q - 1, `psi` = T_Q - 1
            MyCircuit {
                gd_x: Value::known(-pallas::Base::one()),
                gd_y_lsb: Value::known(pallas::Base::zero()),
                pkd_x: Value::known(-pallas::Base::one()),
                pkd_y_lsb: Value::known(pallas::Base::zero()),
                rho: Value::known(pallas::Base::from_u128(T_Q - 1)),
                psi: Value::known(pallas::Base::from_u128(T_Q - 1)),
            },
            // `rho` = T_Q, `psi` = T_Q
            MyCircuit {
                gd_x: Value::known(-pallas::Base::one()),
                gd_y_lsb: Value::known(pallas::Base::one()),
                pkd_x: Value::known(-pallas::Base::one()),
                pkd_y_lsb: Value::known(pallas::Base::zero()),
                rho: Value::known(pallas::Base::from_u128(T_Q)),
                psi: Value::known(pallas::Base::from_u128(T_Q)),
            },
            // `rho` = 2^127 - 1, `psi` = 2^127 - 1
            MyCircuit {
                gd_x: Value::known(-pallas::Base::one()),
                gd_y_lsb: Value::known(pallas::Base::zero()),
                pkd_x: Value::known(-pallas::Base::one()),
                pkd_y_lsb: Value::known(pallas::Base::one()),
                rho: Value::known(pallas::Base::from_u128((1 << 127) - 1)),
                psi: Value::known(pallas::Base::from_u128((1 << 127) - 1)),
            },
            // `rho` = 2^127, `psi` = 2^127
            MyCircuit {
                gd_x: Value::known(-pallas::Base::one()),
                gd_y_lsb: Value::known(pallas::Base::zero()),
                pkd_x: Value::known(-pallas::Base::one()),
                pkd_y_lsb: Value::known(pallas::Base::zero()),
                rho: Value::known(pallas::Base::from_u128(1 << 127)),
                psi: Value::known(pallas::Base::from_u128(1 << 127)),
            },
            // `rho` = 2^254 - 1, `psi` = 2^254 - 1
            MyCircuit {
                gd_x: Value::known(-pallas::Base::one()),
                gd_y_lsb: Value::known(pallas::Base::one()),
                pkd_x: Value::known(-pallas::Base::one()),
                pkd_y_lsb: Value::known(pallas::Base::one()),
                rho: Value::known(two_pow_254 - pallas::Base::one()),
                psi: Value::known(two_pow_254 - pallas::Base::one()),
            },
            // `rho` = 2^254, `psi` = 2^254
            MyCircuit {
                gd_x: Value::known(-pallas::Base::one()),
                gd_y_lsb: Value::known(pallas::Base::one()),
                pkd_x: Value::known(-pallas::Base::one()),
                pkd_y_lsb: Value::known(pallas::Base::zero()),
                rho: Value::known(two_pow_254),
                psi: Value::known(two_pow_254),
            },
        ];

        for circuit in circuits.iter() {
            let prover = MockProver::<pallas::Base>::run(11, circuit, vec![]).unwrap();
            assert_eq!(prover.verify(), Ok(()));
        }
    }
}
