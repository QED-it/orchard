//! Note commitment logic for the Orchard circuit (ZSA variation).

use group::ff::PrimeField;
use halo2_proofs::{
    circuit::{AssignedCell, Chip, Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression},
};
use pasta_curves::pallas;

use crate::{
    circuit::note_commit::{
        DecomposeB, DecomposeD, DecomposeE, DecomposeG, DecomposeHZsa, DecomposeJ, GdCanonicity,
        PkdAssetCanonicity, PsiCanonicity, RhoCanonicity, ValueCanonicity, YCanonicity,
    },
    constants::{OrchardCommitDomains, OrchardFixedBases, OrchardHashDomains, T_P},
    value::NoteValue,
};
use halo2_gadgets::{
    ecc::{
        chip::{EccChip, NonIdentityEccPoint},
        NonIdentityPoint, Point, ScalarFixed,
    },
    sinsemilla::{
        chip::{SinsemillaChip, SinsemillaConfig},
        CommitDomain, Message, MessagePiece,
    },
    utilities::{
        cond_swap::CondSwapChip,
        lookup_range_check::{PallasLookupRangeCheck, PallasLookupRangeCheck45BConfig},
        RangeConstrained,
    },
};

/*
    <https://zips.z.cash/protocol/nu5.pdf#concretesinsemillacommit>
    We need to hash g★_d || pk★_d || i2lebsp_{64}(v) || rho || psi || asset,
    where
        - g★_d is the representation of the point g_d, with 255 bits used for the
          x-coordinate and 1 bit used for the y-coordinate;
        - pk★_d is the representation of the point pk_d, with 255 bits used for the
          x-coordinate and 1 bit used for the y-coordinate;
        - v is a 64-bit value;
        - rho is a base field element (255 bits);
        - psi is a base field element (255 bits); and
        - asset is the representation of the asset point, with 255 bits used for the
          x-coordinate and 1 bit used for the y-coordinate.
*/

#[allow(non_snake_case)]
#[derive(Clone, Debug)]
pub struct NoteCommitConfig<Lookup: PallasLookupRangeCheck> {
    b: DecomposeB<Lookup>,
    d: DecomposeD<Lookup>,
    e: DecomposeE<Lookup>,
    g: DecomposeG<Lookup>,
    h: DecomposeHZsa<Lookup>,
    j: DecomposeJ<Lookup>,
    g_d: GdCanonicity<Lookup>,
    pk_d_asset: PkdAssetCanonicity<Lookup>,
    value: ValueCanonicity,
    rho: RhoCanonicity<Lookup>,
    psi: PsiCanonicity,
    y_canon: YCanonicity,
    advices: [Column<Advice>; 10],
    sinsemilla_config:
        SinsemillaConfig<OrchardHashDomains, OrchardCommitDomains, OrchardFixedBases, Lookup>,
}

#[derive(Clone, Debug)]
pub struct NoteCommitChip<Lookup: PallasLookupRangeCheck> {
    config: NoteCommitConfig<Lookup>,
}

impl<Lookup: PallasLookupRangeCheck> NoteCommitChip<Lookup> {
    #[allow(non_snake_case)]
    #[allow(clippy::many_single_char_names)]
    pub(in crate::circuit) fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        advices: [Column<Advice>; 10],
        sinsemilla_config: SinsemillaConfig<
            OrchardHashDomains,
            OrchardCommitDomains,
            OrchardFixedBases,
            Lookup,
        >,
    ) -> NoteCommitConfig<Lookup> {
        // Useful constants
        let two = pallas::Base::from(2);
        let two_pow_2 = pallas::Base::from(1 << 2);
        let two_pow_4 = two_pow_2.square();
        let two_pow_5 = two_pow_4 * two;
        let two_pow_6 = two_pow_5 * two;
        let two_pow_8 = two_pow_4.square();
        let two_pow_9 = two_pow_8 * two;
        let two_pow_10 = two_pow_9 * two;
        let two_pow_58 = pallas::Base::from(1 << 58);
        let two_pow_130 = Expression::Constant(pallas::Base::from_u128(1 << 65).square());
        let two_pow_140 = Expression::Constant(pallas::Base::from_u128(1 << 70).square());
        let two_pow_249 = pallas::Base::from_u128(1 << 124).square() * two;
        let two_pow_250 = two_pow_249 * two;
        let two_pow_254 = pallas::Base::from_u128(1 << 127).square();

        let t_p = Expression::Constant(pallas::Base::from_u128(T_P));

        // Columns used for MessagePiece and message input gates.
        let col_l = advices[6];
        let col_m = advices[7];
        let col_r = advices[8];
        let col_z = advices[9];

        let b = DecomposeB::configure(meta, col_l, col_m, col_r, two_pow_4, two_pow_5, two_pow_6);
        let d = DecomposeD::configure(meta, col_l, col_m, col_r, two, two_pow_2, two_pow_10);
        let e = DecomposeE::configure(meta, col_l, col_m, col_r, two_pow_6);
        let g = DecomposeG::configure(meta, col_l, col_m, two, two_pow_10);
        let h = DecomposeHZsa::configure(meta, col_l, col_m, col_r, two_pow_5, two_pow_6);
        let j = DecomposeJ::configure(meta, col_l, col_m, col_r, two);

        let g_d = GdCanonicity::configure(
            meta,
            col_l,
            col_m,
            col_r,
            col_z,
            two_pow_130.clone(),
            two_pow_250,
            two_pow_254,
            t_p.clone(),
        );

        let pk_d_asset = PkdAssetCanonicity::configure(
            meta,
            col_l,
            col_m,
            col_r,
            col_z,
            two_pow_4,
            two_pow_140.clone(),
            two_pow_254,
            t_p.clone(),
        );

        let value =
            ValueCanonicity::configure(meta, col_l, col_m, col_r, col_z, two_pow_8, two_pow_58);

        let rho = RhoCanonicity::configure(
            meta,
            col_l,
            col_m,
            col_r,
            col_z,
            two_pow_4,
            two_pow_140,
            two_pow_254,
            t_p.clone(),
        );

        let psi = PsiCanonicity::configure(
            meta,
            col_l,
            col_m,
            col_r,
            col_z,
            two_pow_9,
            two_pow_130.clone(),
            two_pow_249,
            two_pow_254,
            t_p.clone(),
        );

        let y_canon = YCanonicity::configure(
            meta,
            advices,
            two,
            two_pow_10,
            two_pow_130,
            two_pow_250,
            two_pow_254,
            t_p,
        );

        NoteCommitConfig {
            b,
            d,
            e,
            g,
            h,
            j,
            g_d,
            pk_d_asset,
            value,
            rho,
            psi,
            y_canon,
            advices,
            sinsemilla_config,
        }
    }

    pub(in crate::circuit) fn construct(config: NoteCommitConfig<Lookup>) -> Self {
        Self { config }
    }
}

pub(in crate::circuit) mod gadgets {
    use crate::circuit::note_commit::gadgets::{
        canon_bitshift_130, pkd_asset_x_canonicity, psi_canonicity, rho_canonicity, y_canonicity,
    };

    use super::*;

    #[allow(clippy::many_single_char_names)]
    #[allow(clippy::type_complexity)]
    #[allow(clippy::too_many_arguments)]
    pub(in crate::circuit) fn note_commit(
        mut layouter: impl Layouter<pallas::Base>,
        chip: SinsemillaChip<
            OrchardHashDomains,
            OrchardCommitDomains,
            OrchardFixedBases,
            PallasLookupRangeCheck45BConfig,
        >,
        ecc_chip: EccChip<OrchardFixedBases, PallasLookupRangeCheck45BConfig>,
        note_commit_chip: NoteCommitChip<PallasLookupRangeCheck45BConfig>,
        cond_swap_chip: CondSwapChip<pallas::Base>,
        g_d: &NonIdentityEccPoint,
        pk_d: &NonIdentityEccPoint,
        value: AssignedCell<NoteValue, pallas::Base>,
        rho: AssignedCell<pallas::Base, pallas::Base>,
        psi: AssignedCell<pallas::Base, pallas::Base>,
        asset: &NonIdentityEccPoint,
        rcm: ScalarFixed<
            pallas::Affine,
            EccChip<OrchardFixedBases, PallasLookupRangeCheck45BConfig>,
        >,
        is_native_asset: AssignedCell<pallas::Base, pallas::Base>,
    ) -> Result<
        Point<pallas::Affine, EccChip<OrchardFixedBases, PallasLookupRangeCheck45BConfig>>,
        Error,
    > {
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

        // h_zec = h_0 || h_1 || h_2_zec
        //   = (bits 249..=253 of psi) || (bit 254 of psi) || 4 zero bits
        // h_zsa = h_0 || h_1 || h_2_zsa
        //   = (bits 249..=253 of psi) || (bit 254 of psi) || (bits 0..=3 of x(asset))
        let (h_zec, h_zsa, h_0, h_1, h_2_zsa) =
            DecomposeHZsa::decompose(&lookup_config, chip.clone(), &mut layouter, &psi, asset)?;

        // i = bits 4..=253 of asset
        let i = MessagePiece::from_subpieces(
            chip.clone(),
            layouter.namespace(|| "i"),
            [RangeConstrained::bitrange_of(asset.x().value(), 4..254)],
        )?;

        // j = j_0 || j_1 || j_2 = (bit 254 of x(asset)) || (ỹ bit of asset) || 8 zero bits
        let (j, j_0, j_1) = DecomposeJ::decompose(chip.clone(), &mut layouter, asset)?;

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
        // Check decomposition of `y(asset)`.
        let j_1 = y_canonicity(
            &lookup_config,
            &note_commit_chip.config.y_canon,
            layouter.namespace(|| "y(asset) decomposition"),
            asset.y(),
            j_1,
        )?;

        // cm = NoteCommit^Orchard_rcm(g★_d || pk★_d || i2lebsp_{64}(v) || rho || psi)
        //
        // `cm = ⊥` is handled internally to `CommitDomain::commit`: incomplete addition
        // constraints allows ⊥ to occur, and then during synthesis it detects these edge
        // cases and raises an error (aborting proof creation).
        //
        // https://p.z.cash/ZKS:action-cm-old-integrity?partial
        // https://p.z.cash/ZKS:action-cmx-new-integrity?partial
        let (cm, zs_common, zs_zsa_suffix) = {
            let message_common_prefix = Message::from_pieces(
                chip.clone(),
                vec![
                    a.clone(),
                    b.clone(),
                    c.clone(),
                    d.clone(),
                    e.clone(),
                    f.clone(),
                    g.clone(),
                ],
            );

            let message_suffix_zec = Message::from_pieces(chip.clone(), vec![h_zec.clone()]);

            let message_suffix_zsa =
                Message::from_pieces(chip.clone(), vec![h_zsa.clone(), i.clone(), j.clone()]);

            // We will evaluate
            // - `hash_point_zec = hash(Q_ZEC, message_common_prefix || message_suffix_zec)`, and
            // - `hash_point_zsa = hash(Q_ZSA, message_common_prefix || message_suffix_zsa)`.
            // by sharing a portion of the hash evaluation process between `hash_point_zec` and
            // `hash_point_zsa`:
            // 1. Q = if (is_native_asset == 0) {Q_ZSA} else {Q_ZEC}
            // 2. common_hash = hash(Q, message_common_prefix) // this part is shared
            // 3. hash_point_zec = hash(common_hash, message_suffix_zec)
            // 4. hash_point_zsa = hash(common_hash, message_suffix_zsa)
            // 5. hash_point = if (is_native_asset == 0) {hash_point_zsa} else {hash_point_zec}
            let zec_domain = CommitDomain::new(
                chip.clone(),
                ecc_chip.clone(),
                &OrchardCommitDomains::NoteCommit,
            );
            let zsa_domain =
                CommitDomain::new(chip, ecc_chip.clone(), &OrchardCommitDomains::NoteZsaCommit);

            // Perform a MUX to select the desired initial Q point
            // q_init = q_init_zec if is_native_asset is true
            // q_init = q_init_zsa if is_native_asset is false
            let q_init = {
                let q_init_zec = NonIdentityPoint::new(
                    ecc_chip.clone(),
                    layouter.namespace(|| "q_init_zec"),
                    Value::known(zec_domain.q_init()),
                )?;

                let q_init_zsa = NonIdentityPoint::new(
                    ecc_chip.clone(),
                    layouter.namespace(|| "q_init_zsa"),
                    Value::known(zsa_domain.q_init()),
                )?;

                cond_swap_chip.mux_on_non_identity_points(
                    layouter.namespace(|| "mux on hash point"),
                    &is_native_asset,
                    q_init_zsa.inner(),
                    q_init_zec.inner(),
                )?
            };

            // common_hash = hash(q_init, message_common_prefix)
            //
            // To evaluate the different hash, we could use either zec_domain or zsa_domain
            // because we use a private initial point.
            let (common_hash, zs_common) = zec_domain.hash_with_private_init(
                layouter.namespace(|| "hash common prefix note"),
                &q_init,
                message_common_prefix,
            )?;

            // hash_point_zec = hash(common_hash, message_suffix_zec) = hash(q_init, message_zec)
            let (hash_point_zec, _zs_zec) = zec_domain.hash_with_private_init(
                layouter.namespace(|| "hash suffix ZEC note"),
                common_hash.inner(),
                message_suffix_zec,
            )?;

            // hash_point_zsa = hash(common_hash, message_suffix_zsa) = hash(q_init, message_zsa)
            let (hash_point_zsa, zs_zsa) = zec_domain.hash_with_private_init(
                layouter.namespace(|| "hash suffix ZSA note"),
                common_hash.inner(),
                message_suffix_zsa,
            )?;

            // Perform a MUX to select the desired hash point
            // hash_point = hash_zec if is_native_asset is true
            // hash_point = hash_zsa if is_native_asset is false
            let hash_point = Point::from_inner(
                ecc_chip,
                cond_swap_chip.mux_on_points(
                    layouter.namespace(|| "mux on hash point"),
                    &is_native_asset,
                    &(hash_point_zsa.inner().clone().into()),
                    &(hash_point_zec.inner().clone().into()),
                )?,
            );

            // To evaluate the blinding factor, we could use either zec_domain or zsa_domain
            // because they have both the same `R` constant.
            let blinding_factor =
                zec_domain.blinding_factor(layouter.namespace(|| "[r] R"), rcm)?;
            let commitment =
                hash_point.add(layouter.namespace(|| "M + [r] R"), &blinding_factor)?;

            (commitment, zs_common, zs_zsa)
        };

        // `CommitDomain::hash` returns the running sum for each `MessagePiece`. Grab
        // the outputs that we will need for canonicity checks.
        let z13_a = zs_common[0][13].clone();
        let z13_c = zs_common[2][13].clone();
        let z1_d = zs_common[3][1].clone();
        let z13_f = zs_common[5][13].clone();
        let z1_g = zs_common[6][1].clone();
        let g_2 = z1_g.clone();
        let z13_g = zs_common[6][13].clone();
        let z13_i = zs_zsa_suffix[1][13].clone();

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

        let (h2_i_prime, z14_h2_i_prime) = pkd_asset_x_canonicity(
            &lookup_config,
            layouter.namespace(|| "x(asset) canonicity"),
            h_2_zsa.clone(),
            i.inner().cell_value(),
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

        let h_1 = cfg.h.assign(
            &mut layouter,
            h_zec,
            h_zsa,
            h_0.clone(),
            h_1,
            h_2_zsa.clone(),
        )?;

        let j_0 = cfg.j.assign(&mut layouter, j, j_0, j_1)?;

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

        cfg.pk_d_asset.assign(
            &mut layouter,
            asset,
            h_2_zsa,
            i,
            j_0,
            h2_i_prime,
            z13_i,
            z14_h2_i_prime,
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
    use super::NoteCommitConfig;
    use crate::{
        circuit::circuit_zsa::note_commit::{gadgets, NoteCommitChip},
        circuit::gadget::{assign_free_advice, assign_is_native_asset},
        constants::{OrchardCommitDomains, OrchardFixedBases, OrchardHashDomains, T_Q},
        note::{commitment::NoteCommitTrapdoor, AssetBase, NoteCommitment},
        value::NoteValue,
    };
    use halo2_gadgets::{
        ecc::{
            chip::{EccChip, EccConfig},
            NonIdentityPoint, ScalarFixed,
        },
        sinsemilla::chip::SinsemillaChip,
        utilities::{
            cond_swap::{CondSwapChip, CondSwapConfig},
            lookup_range_check::PallasLookupRangeCheck45BConfig,
        },
    };

    use ff::{Field, PrimeField};
    use group::{Curve, Group, GroupEncoding};
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner, Value},
        dev::MockProver,
        plonk::{Circuit, ConstraintSystem, Error},
    };
    use pasta_curves::{arithmetic::CurveAffine, pallas, EpAffine};

    use rand::{rngs::OsRng, RngCore};

    #[test]
    fn note_commit() {
        #[derive(Default)]
        struct MyCircuit {
            g_d: Value<EpAffine>,
            pk_d: Value<EpAffine>,
            rho: Value<pallas::Base>,
            psi: Value<pallas::Base>,
            asset: Value<AssetBase>,
        }

        impl Circuit<pallas::Base> for MyCircuit {
            type Config = (
                NoteCommitConfig<PallasLookupRangeCheck45BConfig>,
                EccConfig<OrchardFixedBases, PallasLookupRangeCheck45BConfig>,
                CondSwapConfig,
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

                let range_check = PallasLookupRangeCheck45BConfig::configure_with_tag(
                    meta,
                    advices[9],
                    table_idx,
                    table_range_check_tag,
                );
                let sinsemilla_config = SinsemillaChip::<
                    OrchardHashDomains,
                    OrchardCommitDomains,
                    OrchardFixedBases,
                    PallasLookupRangeCheck45BConfig,
                >::configure(
                    meta,
                    advices[..5].try_into().unwrap(),
                    advices[2],
                    lagrange_coeffs[0],
                    lookup,
                    range_check,
                    true,
                );
                let note_commit_config =
                    NoteCommitChip::configure(meta, advices, sinsemilla_config);

                let ecc_config =
                    EccChip::<OrchardFixedBases, PallasLookupRangeCheck45BConfig>::configure(
                        meta,
                        advices,
                        lagrange_coeffs,
                        range_check,
                    );

                let cond_swap_config =
                    CondSwapChip::configure(meta, advices[0..5].try_into().unwrap());

                (note_commit_config, ecc_config, cond_swap_config)
            }

            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<pallas::Base>,
            ) -> Result<(), Error> {
                let (note_commit_config, ecc_config, cond_swap_config) = config;

                // Load the Sinsemilla generator lookup table used by the whole circuit.
                SinsemillaChip::<
                    OrchardHashDomains,
                    OrchardCommitDomains,
                    OrchardFixedBases,
                    PallasLookupRangeCheck45BConfig,
                >::load(
                    note_commit_config.sinsemilla_config.clone(), &mut layouter
                )?;

                // Construct a Sinsemilla chip
                let sinsemilla_chip =
                    SinsemillaChip::construct(note_commit_config.sinsemilla_config.clone());

                // Construct an ECC chip
                let ecc_chip = EccChip::construct(ecc_config);

                // Construct a NoteCommit chip
                let note_commit_chip = NoteCommitChip::construct(note_commit_config.clone());

                // Construct a CondSwap chip
                let cond_swap_chip = CondSwapChip::construct(cond_swap_config);

                // Witness g_d
                let g_d = NonIdentityPoint::new(
                    ecc_chip.clone(),
                    layouter.namespace(|| "witness g_d"),
                    self.g_d,
                )?;

                // Witness pk_d
                let pk_d = NonIdentityPoint::new(
                    ecc_chip.clone(),
                    layouter.namespace(|| "witness pk_d"),
                    self.pk_d,
                )?;

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

                let asset = NonIdentityPoint::new(
                    ecc_chip.clone(),
                    layouter.namespace(|| "witness asset"),
                    self.asset.map(|asset| asset.cv_base().to_affine()),
                )?;

                let is_native_asset = assign_is_native_asset(
                    layouter.namespace(|| "witness is_native_asset"),
                    note_commit_config.advices[0],
                    self.asset,
                )?;
                let cm = gadgets::note_commit(
                    layouter.namespace(|| "Hash NoteCommit pieces"),
                    sinsemilla_chip,
                    ecc_chip.clone(),
                    note_commit_chip,
                    cond_swap_chip,
                    g_d.inner(),
                    pk_d.inner(),
                    value_var,
                    rho,
                    psi,
                    asset.inner(),
                    rcm_gadget,
                    is_native_asset,
                )?;
                let expected_cm = {
                    // Hash g★_d || pk★_d || i2lebsp_{64}(v) || rho || psi
                    let point = self
                        .g_d
                        .zip(self.pk_d)
                        .zip(self.rho.zip(self.psi))
                        .zip(self.asset)
                        .map(|(((g_d, pk_d), (rho, psi)), asset)| {
                            NoteCommitment::derive(
                                g_d.to_bytes(),
                                pk_d.to_bytes(),
                                value,
                                asset,
                                rho,
                                psi,
                                NoteCommitTrapdoor(rcm),
                            )
                            .unwrap()
                            .inner()
                            .to_affine()
                        });
                    NonIdentityPoint::new(ecc_chip, layouter.namespace(|| "witness cm"), point)?
                };
                cm.constrain_equal(layouter.namespace(|| "cm == expected cm"), &expected_cm)
            }
        }

        fn affine_point_from_coordinates(x_coord: pallas::Base, y_lsb: pallas::Base) -> EpAffine {
            // Calculate y = (x^3 + 5).sqrt()
            let mut y = (x_coord.square() * x_coord + pallas::Affine::b())
                .sqrt()
                .unwrap();
            if bool::from(y.is_odd() ^ y_lsb.is_odd()) {
                y = -y;
            }
            pallas::Affine::from_xy(x_coord, y).unwrap()
        }

        let two_pow_254 = pallas::Base::from_u128(1 << 127).square();
        let mut rng = OsRng;
        let random_asset = AssetBase::random();

        // Test different values of `ak`, `nk`
        let mut circuits = vec![];
        for asset in [random_asset, AssetBase::native()] {
            // `gd_x` = -1, `pkd_x` = -1 (these have to be x-coordinates of curve points)
            // `rho` = 0, `psi` = 0
            circuits.push(MyCircuit {
                g_d: Value::known(affine_point_from_coordinates(
                    -pallas::Base::one(),
                    pallas::Base::one(),
                )),
                pk_d: Value::known(affine_point_from_coordinates(
                    -pallas::Base::one(),
                    pallas::Base::one(),
                )),
                rho: Value::known(pallas::Base::zero()),
                psi: Value::known(pallas::Base::zero()),
                asset: Value::known(asset),
            });
            // `rho` = T_Q - 1, `psi` = T_Q - 1
            circuits.push(MyCircuit {
                g_d: Value::known(affine_point_from_coordinates(
                    -pallas::Base::one(),
                    pallas::Base::zero(),
                )),
                pk_d: Value::known(affine_point_from_coordinates(
                    -pallas::Base::one(),
                    pallas::Base::zero(),
                )),
                rho: Value::known(pallas::Base::from_u128(T_Q - 1)),
                psi: Value::known(pallas::Base::from_u128(T_Q - 1)),
                asset: Value::known(asset),
            });
            // `rho` = T_Q, `psi` = T_Q
            circuits.push(MyCircuit {
                g_d: Value::known(affine_point_from_coordinates(
                    -pallas::Base::one(),
                    pallas::Base::one(),
                )),
                pk_d: Value::known(affine_point_from_coordinates(
                    -pallas::Base::one(),
                    pallas::Base::zero(),
                )),
                rho: Value::known(pallas::Base::from_u128(T_Q)),
                psi: Value::known(pallas::Base::from_u128(T_Q)),
                asset: Value::known(asset),
            });
            // `rho` = 2^127 - 1, `psi` = 2^127 - 1
            circuits.push(MyCircuit {
                g_d: Value::known(affine_point_from_coordinates(
                    -pallas::Base::one(),
                    pallas::Base::zero(),
                )),
                pk_d: Value::known(affine_point_from_coordinates(
                    -pallas::Base::one(),
                    pallas::Base::one(),
                )),
                rho: Value::known(pallas::Base::from_u128((1 << 127) - 1)),
                psi: Value::known(pallas::Base::from_u128((1 << 127) - 1)),
                asset: Value::known(asset),
            });
            // `rho` = 2^127, `psi` = 2^127
            circuits.push(MyCircuit {
                g_d: Value::known(affine_point_from_coordinates(
                    -pallas::Base::one(),
                    pallas::Base::zero(),
                )),
                pk_d: Value::known(affine_point_from_coordinates(
                    -pallas::Base::one(),
                    pallas::Base::zero(),
                )),
                rho: Value::known(pallas::Base::from_u128(1 << 127)),
                psi: Value::known(pallas::Base::from_u128(1 << 127)),
                asset: Value::known(asset),
            });
            // `rho` = 2^254 - 1, `psi` = 2^254 - 1
            circuits.push(MyCircuit {
                g_d: Value::known(affine_point_from_coordinates(
                    -pallas::Base::one(),
                    pallas::Base::one(),
                )),
                pk_d: Value::known(affine_point_from_coordinates(
                    -pallas::Base::one(),
                    pallas::Base::one(),
                )),
                rho: Value::known(two_pow_254 - pallas::Base::one()),
                psi: Value::known(two_pow_254 - pallas::Base::one()),
                asset: Value::known(asset),
            });
            // `rho` = 2^254, `psi` = 2^254
            circuits.push(MyCircuit {
                g_d: Value::known(affine_point_from_coordinates(
                    -pallas::Base::one(),
                    pallas::Base::one(),
                )),
                pk_d: Value::known(affine_point_from_coordinates(
                    -pallas::Base::one(),
                    pallas::Base::zero(),
                )),
                rho: Value::known(two_pow_254),
                psi: Value::known(two_pow_254),
                asset: Value::known(asset),
            });
            // Random values
            circuits.push(MyCircuit {
                g_d: Value::known(pallas::Point::random(rng).to_affine()),
                pk_d: Value::known(pallas::Point::random(rng).to_affine()),
                rho: Value::known(pallas::Base::random(&mut rng)),
                psi: Value::known(pallas::Base::random(&mut rng)),
                asset: Value::known(asset),
            });
        }

        for circuit in circuits.iter() {
            let prover = MockProver::<pallas::Base>::run(11, circuit, vec![]).unwrap();
            assert_eq!(prover.verify(), Ok(()));
        }
    }
}
