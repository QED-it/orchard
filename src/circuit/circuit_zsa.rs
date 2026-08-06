//! The Orchard Action circuit implementation for the ZSA variation of the Orchard protocol.
//!
//! Includes the configuration, synthesis, and proof verification logic.

use ff::Field;

use group::Curve;

use pasta_curves::{arithmetic::CurveAffine, pallas};

use halo2_gadgets::{
    ecc::{chip::EccChip, FixedPoint, NonIdentityPoint, Point, ScalarFixed, ScalarVar},
    poseidon::{primitives as poseidon, Pow5Chip as PoseidonChip},
    sinsemilla::{
        chip::SinsemillaChip,
        merkle::{chip::MerkleChip, MerklePath},
    },
    utilities::{
        bool_check,
        lookup_range_check::{LookupRangeCheck4_5BConfig, PallasLookupRangeCheck4_5BConfig},
    },
};

use halo2_proofs::{
    circuit::{floor_planner, Layouter, Value},
    plonk::{self, Constraints, Expression},
    poly::Rotation,
};

use crate::{
    builder::SpendInfo,
    circuit::{
        commit_ivk::{gadgets::commit_ivk, CommitIvkChip},
        derive_nullifier::{gadgets::derive_nullifier, ZsaNullifierParams},
        gadget::{
            add_chip::AddChip, assign_free_advice, assign_is_zatoshi_asset, assign_split_flag,
        },
        note_commit::{gadgets::note_commit, NoteCommitChip, ZsaNoteCommitParams},
        value_commit_orchard::{gadgets::value_commit_orchard, ZsaValueCommitParams},
        AddressPoints, CircuitVanilla, Config, OrchardCircuitVersion, ANCHOR, CMX, CV_NET_X,
        CV_NET_Y, DISABLE_CROSS_ADDRESS, ENABLE_OUTPUT, ENABLE_SPEND, ENABLE_ZSA, NF_OLD, RK_X,
        RK_Y,
    },
    constants::{OrchardFixedBases, OrchardFixedBasesFull, OrchardHashDomains},
    note::{AssetBase, Note},
    value::ValueCommitTrapdoor,
};

/// The ZSA-specific witnesses.
#[derive(Clone, Debug)]
pub(crate) struct AdditionalZsaWitnesses {
    pub(crate) psi_nf: pallas::Base,
    pub(crate) asset: AssetBase,
    pub(crate) split_flag: bool,
}

fn unpack(
    zsa_values: Value<AdditionalZsaWitnesses>,
) -> (Value<pallas::Base>, Value<AssetBase>, Value<bool>) {
    (
        zsa_values.clone().map(|values| values.psi_nf),
        zsa_values.clone().map(|values| values.asset),
        zsa_values.map(|values| values.split_flag),
    )
}

/// The OrchardZSA Action circuit.
#[derive(Clone, Debug)]
pub struct CircuitZsa {
    pub(crate) common_witnesses: CircuitVanilla,

    // The ZSA-specific witnesses.
    pub(crate) additional_zsa_witnesses: Value<AdditionalZsaWitnesses>,
}

impl CircuitZsa {
    /// Returns an empty circuit with all private witnesses unknown.
    ///
    /// This is used for circuit shape-dependent operations, such as generating keys
    /// or rendering the circuit layout, where witness values are not required.
    pub(crate) fn empty() -> Self {
        CircuitZsa {
            common_witnesses: CircuitVanilla::empty(OrchardCircuitVersion::ZSA),
            additional_zsa_witnesses: Value::unknown(),
        }
    }

    /// Constructs a `CircuitZsa` from the following components:
    /// - `spend`: [`SpendInfo`] of the note spent in scope of the action
    /// - `output_note`: a note created in scope of the action
    /// - `alpha`: a scalar used for randomization of the action spend validating key
    /// - `rcv`: trapdoor for the action value commitment
    ///
    /// # Panics
    ///
    /// Panics if `circuit_version` is not ZSA.
    pub(crate) fn from_action_context_unchecked(
        spend: SpendInfo,
        output_note: Note,
        alpha: pallas::Scalar,
        rcv: ValueCommitTrapdoor,
        circuit_version: OrchardCircuitVersion,
    ) -> Self {
        if !circuit_version.is_zsa() {
            panic!("circuit version must be ZSA in OrchardZSA circuit");
        }

        let (common_witnesses, psi_nf) = CircuitVanilla::from_action_context_common(
            &spend,
            &output_note,
            alpha,
            rcv,
            circuit_version,
        );

        CircuitZsa {
            common_witnesses,
            additional_zsa_witnesses: Value::known(AdditionalZsaWitnesses {
                psi_nf,
                asset: spend.note.asset(),
                split_flag: spend.split_flag,
            }),
        }
    }
}

impl plonk::Circuit<pallas::Base> for CircuitZsa {
    type Config = Config<PallasLookupRangeCheck4_5BConfig>;
    type FloorPlanner = floor_planner::V1;

    fn without_witnesses(&self) -> Self {
        CircuitZsa::empty()
    }

    fn configure(meta: &mut plonk::ConstraintSystem<pallas::Base>) -> Self::Config {
        // Advice columns used in the Orchard circuit.
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

        // The new or updated constraints for OrchardZSA are explained in
        // [ZIP-226: Transfer and Burn of Zcash Shielded Assets][circuitstatement].
        //
        // All OrchardZSA constraints:
        // Constrain split_flag to be boolean
        // Constrain v_old * (1 - split_flag) - v_new = magnitude * sign
        // Constrain (v_old = 0 and is_zatoshi_asset = 1) or (calculated root = anchor)
        // Constrain v_old = 0 or enable_spend = 1
        // Constrain v_new = 0 or enable_output = 1
        // Constrain is_zatoshi_asset to be boolean
        // Constrain if is_zatoshi_asset = 1 then asset = zatoshi_asset else asset != zatoshi_asset
        // Constrain if split_flag = 0 then psi_old = psi_nf
        // Constrain if split_flag = 1, then is_zatoshi_asset = 0
        // Constrain if enable_zsa = 0, then is_zatoshi_asset = 1
        // Constrain if disable_cross_address = 1, then split_flag = 0
        //
        // [circuitstatement]: https://zips.z.cash/zip-0226#circuit-statement
        let q_orchard = meta.selector();
        meta.create_gate("Orchard circuit checks", |meta| {
            let q_orchard = meta.query_selector(q_orchard);
            let v_old = meta.query_advice(advices[0], Rotation::cur());
            let v_new = meta.query_advice(advices[1], Rotation::cur());
            let magnitude = meta.query_advice(advices[2], Rotation::cur());
            let sign = meta.query_advice(advices[3], Rotation::cur());

            let root = meta.query_advice(advices[4], Rotation::cur());
            let anchor = meta.query_advice(advices[5], Rotation::cur());

            let enable_spend = meta.query_advice(advices[6], Rotation::cur());
            let enable_output = meta.query_advice(advices[7], Rotation::cur());

            let split_flag = meta.query_advice(advices[8], Rotation::cur());

            let is_zatoshi_asset = meta.query_advice(advices[9], Rotation::cur());
            let asset_x = meta.query_advice(advices[0], Rotation::next());
            let asset_y = meta.query_advice(advices[1], Rotation::next());
            let diff_asset_x_inv = meta.query_advice(advices[2], Rotation::next());
            let diff_asset_y_inv = meta.query_advice(advices[3], Rotation::next());

            let one = Expression::Constant(pallas::Base::one());

            let zatoshi_asset = AssetBase::zatoshi()
                .cv_base()
                .to_affine()
                .coordinates()
                .unwrap();

            let diff_asset_x = asset_x - Expression::Constant(*zatoshi_asset.x());
            let diff_asset_y = asset_y - Expression::Constant(*zatoshi_asset.y());

            let psi_old = meta.query_advice(advices[4], Rotation::next());
            let psi_nf = meta.query_advice(advices[5], Rotation::next());

            let enable_zsa = meta.query_advice(advices[6], Rotation::next());
            let disable_cross_address = meta.query_advice(advices[7], Rotation::next());

            Constraints::with_selector(
                q_orchard,
                [
                    ("bool_check split_flag", bool_check(split_flag.clone())),
                    (
                        "v_old * (1 - split_flag) - v_new = magnitude * sign",
                        v_old.clone() * (one.clone() - split_flag.clone())
                            - v_new.clone()
                            - magnitude * sign,
                    ),
                    // We already checked that
                    // * is_zatoshi_asset is boolean (just below), and
                    // * v_old is a 64 bit unsigned integer (in the note commitment evaluation).
                    // So, 1 - is_zatoshi_asset + v_old = 0 only when (is_zatoshi_asset = 1 and v_old = 0), no overflow can occur.
                    (
                        "(v_old = 0 and is_zatoshi_asset = 1) or (root = anchor)",
                        (v_old.clone() + one.clone() - is_zatoshi_asset.clone()) * (root - anchor),
                    ),
                    (
                        "v_old = 0 or enable_spend = 1",
                        v_old * (one.clone() - enable_spend),
                    ),
                    (
                        "v_new = 0 or enable_output = 1",
                        v_new * (one.clone() - enable_output),
                    ),
                    (
                        "bool_check is_zatoshi_asset",
                        bool_check(is_zatoshi_asset.clone()),
                    ),
                    (
                        "(is_zatoshi_asset = 1) =>  (asset_x = zatoshi_asset_x)",
                        is_zatoshi_asset.clone() * diff_asset_x.clone(),
                    ),
                    (
                        "(is_zatoshi_asset = 1) => (asset_y = zatoshi_asset_y)",
                        is_zatoshi_asset.clone() * diff_asset_y.clone(),
                    ),
                    // To prove that `asset` is not equal to `zatoshi_asset`, we will prove that at
                    // least one of `x(asset) - x(zatoshi_asset)` or `y(asset) - y(zatoshi_asset)` is
                    // not equal to zero.
                    // To prove that `x(asset) - x(zatoshi_asset)` (resp `y(asset) - y(zatoshi_asset)`)
                    // is not equal to zero, we will prove that it is invertible.
                    (
                        "(is_zatoshi_asset = 0) => (asset != zatoshi_asset)",
                        (one.clone() - is_zatoshi_asset.clone())
                            * (diff_asset_x * diff_asset_x_inv - one.clone())
                            * (diff_asset_y * diff_asset_y_inv - one.clone()),
                    ),
                    (
                        "(split_flag = 0) => (psi_old = psi_nf)",
                        (one.clone() - split_flag.clone()) * (psi_old - psi_nf),
                    ),
                    (
                        "(split_flag = 1) => (is_zatoshi_asset = 0)",
                        split_flag.clone() * is_zatoshi_asset.clone(),
                    ),
                    (
                        "(enable_zsa = 0) => (is_zatoshi_asset = 1)",
                        (one.clone() - enable_zsa) * (one - is_zatoshi_asset),
                    ),
                    // `split_flag` and `cross_address_disabled` cannot both be enabled at the
                    // same time. A split note's output is forced to a negative net value, which
                    // is not a meaningful self-transfer.
                    (
                        "(disable_cross_address = 1) => (split_flag = 0)",
                        split_flag * disable_cross_address,
                    ),
                ],
            )
        });

        // Addition of two field elements.
        let add_config = AddChip::configure(meta, advices[7], advices[8], advices[6]);

        // Fixed columns for the Sinsemilla generator lookup table
        let table_idx = meta.lookup_table_column();
        let table_range_check_tag = meta.lookup_table_column();
        let lookup = (
            table_idx,
            meta.lookup_table_column(),
            meta.lookup_table_column(),
        );

        // Instance column used for public inputs
        let primary = meta.instance_column();
        meta.enable_equality(primary);

        // Permutation over all advice columns.
        for advice in advices.iter() {
            meta.enable_equality(*advice);
        }

        // Poseidon requires four advice columns, while ECC incomplete addition requires
        // six, so we could choose to configure them in parallel. However, we only use a
        // single Poseidon invocation, and we have the rows to accommodate it serially.
        // Instead, we reduce the proof size by sharing fixed columns between the ECC and
        // Poseidon chips.
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
        let rc_a = lagrange_coeffs[2..5].try_into().unwrap();
        let rc_b = lagrange_coeffs[5..8].try_into().unwrap();

        // Also use the first Lagrange coefficient column for loading global constants.
        // It's free real estate :)
        meta.enable_constant(lagrange_coeffs[0]);

        // We have a lot of free space in the right-most advice columns; use one of them
        // for all of our range checks.
        let range_check = LookupRangeCheck4_5BConfig::configure_with_tag(
            meta,
            advices[9],
            table_idx,
            table_range_check_tag,
        );

        // Configuration for curve point operations.
        // This uses 10 advice columns and spans the whole circuit.
        let ecc_config = EccChip::<OrchardFixedBases, PallasLookupRangeCheck4_5BConfig>::configure(
            meta,
            advices,
            lagrange_coeffs,
            range_check,
        );

        // Configuration for the Poseidon hash.
        let poseidon_config = PoseidonChip::configure::<poseidon::P128Pow5T3>(
            meta,
            // We place the state columns after the partial_sbox column so that the
            // pad-and-add region can be laid out more efficiently.
            advices[6..9].try_into().unwrap(),
            advices[5],
            rc_a,
            rc_b,
        );

        // Configuration for a Sinsemilla hash instantiation and a
        // Merkle hash instantiation using this Sinsemilla instance.
        // Since the Sinsemilla config uses only 5 advice columns,
        // we can fit two instances side-by-side.
        let (sinsemilla_config_1, merkle_config_1) = {
            let sinsemilla_config_1 = SinsemillaChip::configure(
                meta,
                advices[..5].try_into().unwrap(),
                advices[6],
                lagrange_coeffs[0],
                lookup,
                range_check,
                true,
            );
            let merkle_config_1 = MerkleChip::configure(meta, sinsemilla_config_1.clone());

            (sinsemilla_config_1, merkle_config_1)
        };

        // Configuration for a Sinsemilla hash instantiation and a
        // Merkle hash instantiation using this Sinsemilla instance.
        // Since the Sinsemilla config uses only 5 advice columns,
        // we can fit two instances side-by-side.
        let (sinsemilla_config_2, merkle_config_2) = {
            let sinsemilla_config_2 = SinsemillaChip::configure(
                meta,
                advices[5..].try_into().unwrap(),
                advices[7],
                lagrange_coeffs[1],
                lookup,
                range_check,
                true,
            );
            let merkle_config_2 = MerkleChip::configure(meta, sinsemilla_config_2.clone());

            (sinsemilla_config_2, merkle_config_2)
        };

        // Configuration to handle decomposition and canonicity checking
        // for CommitIvk.
        let commit_ivk_config = CommitIvkChip::configure(meta, advices);

        // Configuration to handle decomposition and canonicity checking
        // for NoteCommit_old.
        let old_note_commit_config =
            NoteCommitChip::configure(meta, advices, sinsemilla_config_1.clone(), true);

        // Configuration to handle decomposition and canonicity checking
        // for NoteCommit_new.
        let new_note_commit_config =
            NoteCommitChip::configure(meta, advices, sinsemilla_config_2.clone(), true);

        Config {
            primary,
            q_orchard,
            advices,
            add_config,
            ecc_config,
            poseidon_config,
            merkle_config_1,
            merkle_config_2,
            sinsemilla_config_1,
            sinsemilla_config_2,
            commit_ivk_config,
            old_note_commit_config,
            new_note_commit_config,
        }
    }

    #[allow(non_snake_case)]
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<(), plonk::Error> {
        if !self.common_witnesses.circuit_version.is_zsa() {
            return Err(plonk::Error::Synthesis);
        }

        // Load the Sinsemilla generator lookup table used by the whole circuit.
        SinsemillaChip::load(config.sinsemilla_config_1.clone(), &mut layouter)?;

        // Unpack the ZSA witnesses.
        let (psi_nf_value, asset_value, split_flag_value) =
            unpack(self.additional_zsa_witnesses.clone());

        // Construct the ECC chip.
        let ecc_chip = config.ecc_chip(self.common_witnesses.circuit_version.halo2_version());

        // Witness private inputs that are used across multiple checks.
        let (psi_nf, psi_old, rho_old, cm_old, g_d_old, ak_P, nk, v_old, v_new, asset) = {
            // Witness psi_nf
            let psi_nf = assign_free_advice(
                layouter.namespace(|| "witness psi_nf"),
                config.advices[0],
                psi_nf_value,
            )?;

            // Witness psi_old
            let psi_old = assign_free_advice(
                layouter.namespace(|| "witness psi_old"),
                config.advices[0],
                self.common_witnesses.psi_old,
            )?;

            // Witness rho_old
            let rho_old = assign_free_advice(
                layouter.namespace(|| "witness rho_old"),
                config.advices[0],
                self.common_witnesses.rho_old.map(|rho| rho.into_inner()),
            )?;

            // Witness cm_old
            let cm_old = Point::new(
                ecc_chip.clone(),
                layouter.namespace(|| "cm_old"),
                self.common_witnesses
                    .cm_old
                    .as_ref()
                    .map(|cm| cm.inner().to_affine()),
            )?;

            // Witness g_d_old
            let g_d_old = NonIdentityPoint::new(
                ecc_chip.clone(),
                layouter.namespace(|| "gd_old"),
                self.common_witnesses
                    .g_d_old
                    .as_ref()
                    .map(|gd| gd.to_affine()),
            )?;

            // Witness ak_P.
            let ak_P: Value<pallas::Point> = self.common_witnesses.ak.as_ref().map(|ak| ak.into());
            let ak_P = NonIdentityPoint::new(
                ecc_chip.clone(),
                layouter.namespace(|| "witness ak_P"),
                ak_P.map(|ak_P| ak_P.to_affine()),
            )?;

            // Witness nk.
            let nk = assign_free_advice(
                layouter.namespace(|| "witness nk"),
                config.advices[0],
                self.common_witnesses.nk.map(|nk| nk.inner()),
            )?;

            // Witness v_old.
            let v_old = assign_free_advice(
                layouter.namespace(|| "witness v_old"),
                config.advices[0],
                self.common_witnesses.v_old,
            )?;

            // Witness v_new.
            let v_new = assign_free_advice(
                layouter.namespace(|| "witness v_new"),
                config.advices[0],
                self.common_witnesses.v_new,
            )?;

            // Witness asset
            let asset = NonIdentityPoint::new(
                ecc_chip.clone(),
                layouter.namespace(|| "witness asset"),
                asset_value.map(|asset| asset.cv_base().to_affine()),
            )?;

            (
                psi_nf, psi_old, rho_old, cm_old, g_d_old, ak_P, nk, v_old, v_new, asset,
            )
        };

        // Witness split_flag
        let split_flag = assign_split_flag(
            layouter.namespace(|| "witness split_flag"),
            config.advices[0],
            split_flag_value,
        )?;

        // Witness is_zatoshi_asset which is equal to
        // 1 if asset is equal to zatoshi asset, and
        // 0 if asset is not equal to zatoshi asset.
        let is_zatoshi_asset = assign_is_zatoshi_asset(
            layouter.namespace(|| "witness is_zatoshi_asset"),
            config.advices[0],
            asset_value,
        )?;

        // Merkle path validity check.
        let root = {
            let path = self
                .common_witnesses
                .path
                .map(|typed_path| typed_path.map(|node| node.inner()));
            let merkle_inputs = MerklePath::construct(
                [config.merkle_chip_1(), config.merkle_chip_2()],
                OrchardHashDomains::MerkleCrh,
                self.common_witnesses.pos,
                path,
            );
            let leaf = cm_old.extract_p().inner().clone();
            merkle_inputs.calculate_root(layouter.namespace(|| "Merkle path"), leaf)?
        };

        // Value commitment integrity.
        // See [ZIP-226: Transfer and Burn of Zcash Shielded Assets][valuecommitcorrectness] for more details.
        //
        // [valuecommitcorrectness]: https://zips.z.cash/zip-0226#value-commitment-correctness
        let v_net_magnitude_sign = {
            // Witness the magnitude and sign of v_net = v_old - v_new
            let v_net_magnitude_sign = {
                // v_net is equal to
                //   (-v_new) if split_flag = true
                //   v_old - v_new if split_flag = false
                let v_net = split_flag_value.and_then(|split_flag| {
                    if split_flag {
                        Value::known(crate::value::NoteValue::ZERO) - self.common_witnesses.v_new
                    } else {
                        self.common_witnesses.v_old - self.common_witnesses.v_new
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

            let rcv = ScalarFixed::new(
                ecc_chip.clone(),
                layouter.namespace(|| "rcv"),
                self.common_witnesses.rcv.as_ref().map(|rcv| rcv.inner()),
            )?;

            let cv_net = value_commit_orchard(
                layouter.namespace(|| "cv_net = ValueCommit^Orchard_rcv(v_net_magnitude_sign)"),
                ecc_chip.clone(),
                v_net_magnitude_sign.clone(),
                rcv,
                Some(ZsaValueCommitParams {
                    sinsemilla_chip: config.sinsemilla_chip_1(),
                    asset_base: asset.clone(),
                }),
            )?;

            // Constrain cv_net to equal public input
            layouter.constrain_instance(cv_net.inner().x().cell(), config.primary, CV_NET_X)?;
            layouter.constrain_instance(cv_net.inner().y().cell(), config.primary, CV_NET_Y)?;

            // Return the magnitude and sign so we can use them in the Orchard gate.
            v_net_magnitude_sign
        };

        // Nullifier integrity.
        // See [ZIP-226: Transfer and Burn of Zcash Shielded Assets][zip226] for more details.
        //
        // [zip226]: https://zips.z.cash/zip-0226
        let nf_old = {
            let nf_old = derive_nullifier(
                layouter.namespace(|| "nf_old = DeriveNullifier_nk(rho_old, psi_nf, cm_old)"),
                config.poseidon_chip(),
                config.add_chip(),
                ecc_chip.clone(),
                rho_old.clone(),
                &psi_nf,
                &cm_old,
                nk.clone(),
                Some(ZsaNullifierParams {
                    cond_swap_chip: config.cond_swap_chip(),
                    split_flag: split_flag.clone(),
                }),
            )?;

            // Constrain nf_old to equal public input
            layouter.constrain_instance(nf_old.inner().cell(), config.primary, NF_OLD)?;

            nf_old
        };

        // Spend authority
        {
            let alpha = ScalarFixed::new(
                ecc_chip.clone(),
                layouter.namespace(|| "alpha"),
                self.common_witnesses.alpha,
            )?;

            // alpha_commitment = [alpha] SpendAuthG
            let (alpha_commitment, _) = {
                let spend_auth_g = OrchardFixedBasesFull::SpendAuthG;
                let spend_auth_g = FixedPoint::from_inner(ecc_chip.clone(), spend_auth_g);
                spend_auth_g.mul(layouter.namespace(|| "[alpha] SpendAuthG"), alpha)?
            };

            // [alpha] SpendAuthG + ak_P
            let rk = alpha_commitment.add(layouter.namespace(|| "rk"), &ak_P)?;

            // Constrain rk to equal public input
            layouter.constrain_instance(rk.inner().x().cell(), config.primary, RK_X)?;
            layouter.constrain_instance(rk.inner().y().cell(), config.primary, RK_Y)?;
        }

        // Diversified address integrity.
        let pk_d_old = {
            let ivk = {
                let ak = ak_P.extract_p().inner().clone();
                let rivk = ScalarFixed::new(
                    ecc_chip.clone(),
                    layouter.namespace(|| "rivk"),
                    self.common_witnesses.rivk.map(|rivk| rivk.inner()),
                )?;

                commit_ivk(
                    config.sinsemilla_chip_1(),
                    ecc_chip.clone(),
                    config.commit_ivk_chip(),
                    layouter.namespace(|| "CommitIvk"),
                    ak,
                    nk,
                    rivk,
                )?
            };
            let ivk =
                ScalarVar::from_base(ecc_chip.clone(), layouter.namespace(|| "ivk"), ivk.inner())?;

            // [ivk] g_d_old
            // The scalar value is passed through and discarded.
            let (derived_pk_d_old, _ivk) =
                g_d_old.mul(layouter.namespace(|| "[ivk] g_d_old"), ivk)?;

            // Constrain derived pk_d_old to equal witnessed pk_d_old
            //
            // This equality constraint is technically superfluous, because the assigned
            // value of `derived_pk_d_old` is an equivalent witness. But it's nice to see
            // an explicit connection between circuit-synthesized values, and explicit
            // prover witnesses. We could get the best of both worlds with a write-on-copy
            // abstraction (https://github.com/zcash/halo2/issues/334).
            let pk_d_old = NonIdentityPoint::new(
                ecc_chip.clone(),
                layouter.namespace(|| "witness pk_d_old"),
                self.common_witnesses
                    .pk_d_old
                    .map(|pk_d_old| pk_d_old.inner().to_affine()),
            )?;
            derived_pk_d_old
                .constrain_equal(layouter.namespace(|| "pk_d_old equality"), &pk_d_old)?;

            pk_d_old
        };

        // Old note commitment integrity.
        // See [ZIP-226: Transfer and Burn of Zcash Shielded Assets][notecommit] for more details.
        //
        // [notecommit]: https://zips.z.cash/zip-0226#note-structure-commitment.
        {
            let rcm_old = ScalarFixed::new(
                ecc_chip.clone(),
                layouter.namespace(|| "rcm_old"),
                self.common_witnesses
                    .rcm_old
                    .as_ref()
                    .map(|rcm_old| rcm_old.inner()),
            )?;

            // g★_d || pk★_d || i2lebsp_{64}(v) || i2lebsp_{255}(rho) || i2lebsp_{255}(psi)
            let derived_cm_old = note_commit(
                layouter.namespace(|| {
                    "g★_d || pk★_d || i2lebsp_{64}(v) || i2lebsp_{255}(rho) || i2lebsp_{255}(psi)"
                }),
                config.sinsemilla_chip_1(),
                config.ecc_chip(self.common_witnesses.circuit_version.halo2_version()),
                config.note_commit_chip_old(),
                g_d_old.inner(),
                pk_d_old.inner(),
                v_old.clone(),
                rho_old,
                psi_old.clone(),
                rcm_old,
                Some(ZsaNoteCommitParams {
                    cond_swap_chip: config.cond_swap_chip(),
                    asset: asset.inner().clone(),
                    is_zatoshi_asset: is_zatoshi_asset.clone(),
                }),
            )?;

            // Constrain derived cm_old to equal witnessed cm_old
            derived_cm_old.constrain_equal(layouter.namespace(|| "cm_old equality"), &cm_old)?;
        }

        // Witness g_d_new
        let g_d_new = {
            let g_d_new = self
                .common_witnesses
                .g_d_new
                .map(|g_d_new| g_d_new.to_affine());
            NonIdentityPoint::new(
                ecc_chip.clone(),
                layouter.namespace(|| "witness g_d_new_star"),
                g_d_new,
            )?
        };

        // Witness pk_d_new
        let pk_d_new = {
            let pk_d_new = self
                .common_witnesses
                .pk_d_new
                .map(|pk_d_new| pk_d_new.inner().to_affine());
            NonIdentityPoint::new(
                ecc_chip.clone(),
                layouter.namespace(|| "witness pk_d_new"),
                pk_d_new,
            )?
        };

        // New note commitment integrity.
        // See [ZIP-226: Transfer and Burn of Zcash Shielded Assets][notecommit] for more details.
        //
        // [notecommit]: https://zips.z.cash/zip-0226#note-structure-commitment.
        {
            // ρ^new = nf^old
            let rho_new = nf_old.inner().clone();

            // Witness psi_new
            let psi_new = assign_free_advice(
                layouter.namespace(|| "witness psi_new"),
                config.advices[0],
                self.common_witnesses.psi_new,
            )?;

            let rcm_new = ScalarFixed::new(
                ecc_chip,
                layouter.namespace(|| "rcm_new"),
                self.common_witnesses
                    .rcm_new
                    .as_ref()
                    .map(|rcm_new| rcm_new.inner()),
            )?;

            // g★_d || pk★_d || i2lebsp_{64}(v) || i2lebsp_{255}(rho) || i2lebsp_{255}(psi)
            let cm_new = note_commit(
                layouter.namespace(|| {
                    "g★_d || pk★_d || i2lebsp_{64}(v) || i2lebsp_{255}(rho) || i2lebsp_{255}(psi)"
                }),
                config.sinsemilla_chip_2(),
                config.ecc_chip(self.common_witnesses.circuit_version.halo2_version()),
                config.note_commit_chip_new(),
                g_d_new.inner(),
                pk_d_new.inner(),
                v_new.clone(),
                rho_new,
                psi_new,
                rcm_new,
                Some(ZsaNoteCommitParams {
                    cond_swap_chip: config.cond_swap_chip(),
                    asset: asset.inner().clone(),
                    is_zatoshi_asset: is_zatoshi_asset.clone(),
                }),
            )?;

            let cmx = cm_new.extract_p();

            // Constrain cmx to equal public input
            layouter.constrain_instance(cmx.inner().cell(), config.primary, CMX)?;
        }

        // Constrain the remaining Orchard circuit checks.
        layouter.assign_region(
            || "Orchard circuit checks",
            |mut region| {
                v_old.copy_advice(|| "v_old", &mut region, config.advices[0], 0)?;
                v_new.copy_advice(|| "v_new", &mut region, config.advices[1], 0)?;
                v_net_magnitude_sign.0.copy_advice(
                    || "v_net magnitude",
                    &mut region,
                    config.advices[2],
                    0,
                )?;
                v_net_magnitude_sign.1.copy_advice(
                    || "v_net sign",
                    &mut region,
                    config.advices[3],
                    0,
                )?;

                root.copy_advice(|| "calculated root", &mut region, config.advices[4], 0)?;
                region.assign_advice_from_instance(
                    || "pub input anchor",
                    config.primary,
                    ANCHOR,
                    config.advices[5],
                    0,
                )?;

                region.assign_advice_from_instance(
                    || "enable spend",
                    config.primary,
                    ENABLE_SPEND,
                    config.advices[6],
                    0,
                )?;

                region.assign_advice_from_instance(
                    || "enable output",
                    config.primary,
                    ENABLE_OUTPUT,
                    config.advices[7],
                    0,
                )?;

                split_flag.copy_advice(|| "split_flag", &mut region, config.advices[8], 0)?;

                is_zatoshi_asset.copy_advice(
                    || "is_zatoshi_asset",
                    &mut region,
                    config.advices[9],
                    0,
                )?;
                asset
                    .inner()
                    .x()
                    .copy_advice(|| "asset_x", &mut region, config.advices[0], 1)?;
                asset
                    .inner()
                    .y()
                    .copy_advice(|| "asset_y", &mut region, config.advices[1], 1)?;

                // `diff_asset_x_inv` and `diff_asset_y_inv` will be used to prove that
                // if is_zatoshi_asset = 0, then asset != zatoshi_asset.
                region.assign_advice(
                    || "diff_asset_x_inv",
                    config.advices[2],
                    1,
                    || {
                        asset_value.map(|asset| {
                            let asset_x = *asset.cv_base().to_affine().coordinates().unwrap().x();
                            let zatoshi_asset_x = *AssetBase::zatoshi()
                                .cv_base()
                                .to_affine()
                                .coordinates()
                                .unwrap()
                                .x();

                            let diff_asset_x = asset_x - zatoshi_asset_x;

                            if diff_asset_x == pallas::Base::zero() {
                                pallas::Base::zero()
                            } else {
                                diff_asset_x.invert().unwrap()
                            }
                        })
                    },
                )?;
                region.assign_advice(
                    || "diff_asset_y_inv",
                    config.advices[3],
                    1,
                    || {
                        asset_value.map(|asset| {
                            let asset_y = *asset.cv_base().to_affine().coordinates().unwrap().y();
                            let zatoshi_asset_y = *AssetBase::zatoshi()
                                .cv_base()
                                .to_affine()
                                .coordinates()
                                .unwrap()
                                .y();

                            let diff_asset_y = asset_y - zatoshi_asset_y;

                            if diff_asset_y == pallas::Base::zero() {
                                pallas::Base::zero()
                            } else {
                                diff_asset_y.invert().unwrap()
                            }
                        })
                    },
                )?;

                psi_old.copy_advice(|| "psi_old", &mut region, config.advices[4], 1)?;
                psi_nf.copy_advice(|| "psi_nf", &mut region, config.advices[5], 1)?;

                region.assign_advice_from_instance(
                    || "enable zsa",
                    config.primary,
                    ENABLE_ZSA,
                    config.advices[6],
                    1,
                )?;

                region.assign_advice_from_instance(
                    || "disable_cross_address",
                    config.primary,
                    DISABLE_CROSS_ADDRESS,
                    config.advices[7],
                    1,
                )?;

                config.q_orchard.enable(&mut region, 0)
            },
        )?;

        let addrs = AddressPoints {
            g_d_old,
            pk_d_old,
            g_d_new,
            pk_d_new,
        };

        synthesize_cross_address_checks(&config, &mut layouter, &addrs)?;

        Ok(())
    }
}

/// Enforces the ZSA cross-address restriction for one action: when
/// `disableCrossAddress` is nonzero, the spent note and output note must be
/// addressed to the same expanded receiver, meaning equal `(g_d, pk_d)`.
///
/// This reuses the existing "Orchard circuit checks" gate instead of adding a
/// new gate. The gate already has a product constraint,
/// `(v_old + 1 - is_zatoshi_asset) * (root - anchor) = 0`, with exactly the shape needed for
/// `disableCrossAddress * (old_coord - new_coord) = 0` when `is_zatoshi_asset = 1`.
///
/// The ZSA circuit enables that gate on eight extra rows, two per affine coordinate of
/// `(g_d, pk_d)`, with:
///
/// ```text
/// First row:
/// v_old            <- disableCrossAddress
/// v_new            <- 0 (constant)
/// magnitude        <- disableCrossAddress
/// sign             <- 1 (constant)
/// root             <- old coordinate
/// anchor           <- new coordinate
/// enable_spend     <- 1 (constant)
/// enable_output    <- 1 (constant)
/// split_flag       <- 0 (constant)
/// is_zatoshi_asset <- 1 (constant)
///
/// Second row
/// asset_x          <- zatoshi_asset.x()
/// asset_y          <- zatoshi_asset.y()
/// diff_asset_x_inv <- 0 (constant)
/// diff_asset_y_inv <- 0 (constant)
/// psi_old          <- 0 (constant)
/// psi_nf           <- 0 (constant)
/// enable_zsa       <- 1 (constant)
/// disable_cross_address <- disableCrossAddress
/// ```
///
/// With this layout, the gate constraints become:
///
/// ```text
/// split_flag * (1 - split_flag) = 0
///     ->  0 * (1-0) = 0
/// v_old * (1 - split_flag) - v_new = magnitude * sign
///     -> disableCrossAddress * (1-0) - 0 = disableCrossAddress * 1
/// (v_old + 1 - is_zatoshi_asset) * (root - anchor) = 0
///     ->  (disableCrossAddress + 1 - 1) * (old_coord - new_coord) = 0
/// v_old * (1 - enable_spend) = 0
///     ->  disableCrossAddress * (1 - 1) = 0
/// v_new * (1 - enable_output) = 0
///     ->  0 * (1 - 1) = 0
/// is_zatoshi_asset * (1 - is_zatoshi_asset) = 0
///     -> 1 * (1-1) = 0
/// is_zatoshi_asset * diff_asset_x = 0
///     -> 1 * (zatoshi_asset.x() - zatoshi_asset.x()) = 0
/// is_zatoshi_asset * diff_asset_y = 0
///     -> 1 * (zatoshi_asset_y() - zatoshi_asset.y()) = 0
/// (1 - is_zatoshi_asset) * (diff_asset_x * diff_asset_x_inv - 1) * (diff_asset_y * diff_asset_y_inv - 1) = 0
///     -> (1 - 1) * (diff_asset_x * 0 - 1) * (diff_asset_y * 0 - 1) = 0
/// (1 - split_flag)*(psi_old - psi_nf) = 0
///     -> (1 - 0) * (0 - 0) = 0
/// split_flag * is_zatoshi_asset = 0
///     -> 0 * 1 = 0
/// (1 - enable_zsa) * (1 - is_zatoshi_asset) = 0
///     -> (1 - 1) * (1 - 1) = 0
/// disable_cross_address * split_flag = 0
///     -> disableCrossAddress * 0 = 0
/// ```
///
/// The second line is the actual cross-address check. Any nonzero
/// `disableCrossAddress` value forces each old coordinate to equal the
/// corresponding new coordinate. The public API encodes `disableCrossAddress`
/// as 0 or 1, but this algebra does not rely on a boolean constraint.
fn synthesize_cross_address_checks(
    config: &Config<PallasLookupRangeCheck4_5BConfig>,
    layouter: &mut impl Layouter<pallas::Base>,
    addrs: &AddressPoints<PallasLookupRangeCheck4_5BConfig>,
) -> Result<(), plonk::Error> {
    let AddressPoints {
        g_d_old,
        pk_d_old,
        g_d_new,
        pk_d_new,
    } = addrs;

    layouter.assign_region(
        || "ZSA cross-address checks",
        |mut region| {
            let coordinate_checks = [
                ("g_d x", g_d_old.inner().x(), g_d_new.inner().x()),
                ("g_d y", g_d_old.inner().y(), g_d_new.inner().y()),
                ("pk_d x", pk_d_old.inner().x(), pk_d_new.inner().x()),
                ("pk_d y", pk_d_old.inner().y(), pk_d_new.inner().y()),
            ];

            let mut offset = 0;

            for (label, old_coord, new_coord) in coordinate_checks.into_iter() {
                config.q_orchard.enable(&mut region, offset)?;

                // Copy disableCrossAddress from the public input at
                // primary[DISABLE_CROSS_ADDRESS] into advices[0] for this
                // coordinate-check row.
                let cross_address_disabled = region.assign_advice_from_instance(
                    || "v_old <- disableCrossAddress",
                    config.primary,
                    DISABLE_CROSS_ADDRESS,
                    config.advices[0],
                    offset,
                )?;

                // Fill the v_new, magnitude, sign and split_flag cells so the reused
                // value-balance constraint reads:
                // disableCrossAddress * (1-0) - 0 = disableCrossAddress * 1.
                region.assign_advice_from_constant(
                    || "v_new <- zero",
                    config.advices[1],
                    offset,
                    pallas::Base::zero(),
                )?;
                cross_address_disabled.copy_advice(
                    || "magnitude <- disableCrossAddress",
                    &mut region,
                    config.advices[2],
                    offset,
                )?;
                region.assign_advice_from_constant(
                    || "sign <- one",
                    config.advices[3],
                    offset,
                    pallas::Base::one(),
                )?;
                region.assign_advice_from_constant(
                    || "split_flag <- zero",
                    config.advices[8],
                    offset,
                    pallas::Base::zero(),
                )?;

                // Copy the old coordinate into the gate's root cell and the
                // new coordinate into its anchor cell for the equality check.
                old_coord.copy_advice(
                    || format!("root <- {label}"),
                    &mut region,
                    config.advices[4],
                    offset,
                )?;
                new_coord.copy_advice(
                    || format!("anchor <- {label}"),
                    &mut region,
                    config.advices[5],
                    offset,
                )?;

                // Set both enable flags to one so the unrelated enable checks
                // in q_orchard are neutralized on these rows.
                region.assign_advice_from_constant(
                    || "one (neutralize enable_spend check)",
                    config.advices[6],
                    offset,
                    pallas::Base::one(),
                )?;
                region.assign_advice_from_constant(
                    || "one (neutralize enable_output check)",
                    config.advices[7],
                    offset,
                    pallas::Base::one(),
                )?;

                // Set `is_zatoshi_asset` to 1.
                region.assign_advice_from_constant(
                    || "is_zatoshi_asset <- 1",
                    config.advices[9],
                    offset,
                    pallas::Base::one(),
                )?;

                // Second row
                offset += 1;

                // Set `(asset_x, asset_y) = AssetBase::zatoshi()`.
                let zatoshi_asset = AssetBase::zatoshi()
                    .cv_base()
                    .to_affine()
                    .coordinates()
                    .unwrap();
                region.assign_advice_from_constant(
                    || "asset_x <- zatoshi_asset.x()",
                    config.advices[0],
                    offset,
                    *zatoshi_asset.x(),
                )?;
                region.assign_advice_from_constant(
                    || "asset_y <- zatoshi_asset.y()",
                    config.advices[1],
                    offset,
                    *zatoshi_asset.y(),
                )?;

                // Set `diff_asset_x_inv` and `diff_asset_y_inv` to 0.
                region.assign_advice_from_constant(
                    || "diff_asset_x_inv <- 0",
                    config.advices[2],
                    offset,
                    pallas::Base::zero(),
                )?;
                region.assign_advice_from_constant(
                    || "diff_asset_y_inv <- 0",
                    config.advices[3],
                    offset,
                    pallas::Base::zero(),
                )?;

                // Set `psi_old` and `psi_nf` to 0 to satisfy the following constraint (split_flag=0):
                // (1 - split_flag)*(psi_old - psi_nf) = 0
                region.assign_advice_from_constant(
                    || "psi_old <- 0",
                    config.advices[4],
                    offset,
                    pallas::Base::zero(),
                )?;
                region.assign_advice_from_constant(
                    || "psi_nf <- 0",
                    config.advices[5],
                    offset,
                    pallas::Base::zero(),
                )?;

                // Set `enable_zsa` to 1 to satisfy the following constraint:
                // (1 - enable_zsa) * (1 - is_zatoshi_asset) = 0
                region.assign_advice_from_constant(
                    || "enable_zsa <- 1",
                    config.advices[6],
                    offset,
                    pallas::Base::one(),
                )?;

                cross_address_disabled.copy_advice(
                    || "disable_cross_address <- disableCrossAddress",
                    &mut region,
                    config.advices[7],
                    offset,
                )?;

                // Occupy the otherwise-unused rightmost advice columns so the
                // floor planner cannot lay out another region (and enable its
                // gate) on these rows.
                cross_address_disabled.copy_advice(
                    || "disableCrossAddress padding",
                    &mut region,
                    config.advices[8],
                    offset,
                )?;
                cross_address_disabled.copy_advice(
                    || "disableCrossAddress padding",
                    &mut region,
                    config.advices[9],
                    offset,
                )?;

                offset += 1;
            }

            Ok(())
        },
    )
}

// TODO ZSA: add tests once ZSA bundle is implemented
