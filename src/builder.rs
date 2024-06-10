//! Logic for building Orchard components of transactions.

use core::fmt;
use core::iter;
use std::collections::HashMap;
use std::fmt::Display;

use ff::Field;
use nonempty::NonEmpty;
use pasta_curves::pallas;
use rand::{prelude::SliceRandom, CryptoRng, RngCore};

use zcash_note_encryption_zsa::NoteEncryption;

use crate::builder::BuildError::{BurnErrorNative, BurnErrorZero};
use crate::{
    action::Action,
    address::Address,
    bundle::{derive_bvk, Authorization, Authorized, Bundle, Flags, OrchardHash},
    circuit::{CircuitBase, Instance, OrchardCircuit, Proof, ProvingKey},
    keys::{
        FullViewingKey, OutgoingViewingKey, Scope, SpendAuthorizingKey, SpendValidatingKey,
        SpendingKey,
    },
    note::{AssetBase, Note, Rho, TransmittedNoteCiphertext},
    note_encryption::{OrchardDomain, OrchardDomainBase},
    primitives::redpallas::{self, Binding, SpendAuth},
    tree::{Anchor, MerklePath},
    value::{self, NoteValue, OverflowError, ValueCommitTrapdoor, ValueCommitment, ValueSum},
};

const MIN_ACTIONS: usize = 2;

/// An enumeration of rules for Orchard bundle construction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BundleType {
    /// A transactional bundle will be padded if necessary to contain at least 2 actions,
    /// irrespective of whether any genuine actions are required.
    Transactional {
        /// The flags that control whether spends and/or outputs are enabled for the bundle.
        flags: Flags,
        /// A flag that, when set to `true`, indicates that a bundle should be produced even if no
        /// spends or outputs have been added to the bundle; in such a circumstance, all of the
        /// actions in the resulting bundle will be dummies.
        bundle_required: bool,
    },
    /// A coinbase bundle is required to have no non-dummy spends. No padding is performed.
    Coinbase,
}

impl BundleType {
    /// The default bundle type has all flags enabled, ZSA disabled, and does not require a bundle
    /// to be produced.
    pub const DEFAULT_VANILLA: BundleType = BundleType::Transactional {
        flags: Flags::ENABLED_WITHOUT_ZSA,
        bundle_required: false,
    };

    /// The default bundle with all flags enabled, including ZSA.
    pub const DEFAULT_ZSA: BundleType = BundleType::Transactional {
        flags: Flags::ENABLED_WITH_ZSA,
        bundle_required: false,
    };

    /// The DISABLED bundle type does not permit any bundle to be produced, and when used in the
    /// builder will prevent any spends or outputs from being added.
    pub const DISABLED: BundleType = BundleType::Transactional {
        flags: Flags::from_parts(false, false, false),
        bundle_required: false,
    };

    /// Returns the number of logical actions that builder will produce in constructing a bundle
    /// of this type, given the specified numbers of spends and outputs.
    ///
    /// Returns an error if the specified number of spends and outputs is incompatible with
    /// this bundle type.
    pub fn num_actions(
        &self,
        num_spends: usize,
        num_outputs: usize,
    ) -> Result<usize, &'static str> {
        let num_requested_actions = core::cmp::max(num_spends, num_outputs);

        match self {
            BundleType::Transactional {
                flags,
                bundle_required,
            } => {
                if !flags.spends_enabled() && num_spends > 0 {
                    Err("Spends are disabled, so num_spends must be zero")
                } else if !flags.outputs_enabled() && num_outputs > 0 {
                    Err("Outputs are disabled, so num_outputs must be zero")
                } else {
                    Ok(if *bundle_required || num_requested_actions > 0 {
                        core::cmp::max(num_requested_actions, MIN_ACTIONS)
                    } else {
                        0
                    })
                }
            }
            BundleType::Coinbase => {
                if num_spends > 0 {
                    Err("Coinbase bundles have spends disabled, so num_spends must be zero")
                } else {
                    Ok(num_outputs)
                }
            }
        }
    }

    /// Returns the set of flags and the anchor that will be used for bundle construction.
    pub fn flags(&self) -> Flags {
        match self {
            BundleType::Transactional { flags, .. } => *flags,
            BundleType::Coinbase => Flags::SPENDS_DISABLED,
        }
    }
}

/// An error type for the kinds of errors that can occur during bundle construction.
#[derive(Debug)]
pub enum BuildError {
    /// Spends are disabled for the provided bundle type.
    SpendsDisabled,
    /// Spends are disabled for the provided bundle type.
    OutputsDisabled,
    /// The anchor provided to this builder doesn't match the Merkle path used to add a spend.
    AnchorMismatch,
    /// A bundle could not be built because required signatures were missing.
    MissingSignatures,
    /// An error occurred in the process of producing a proof for a bundle.
    Proof(halo2_proofs::plonk::Error),
    /// An overflow error occurred while attempting to construct the value
    /// for a bundle.
    ValueSum(value::OverflowError),
    /// External signature is not valid.
    InvalidExternalSignature,
    /// A signature is valid for more than one input. This should never happen if `alpha`
    /// is sampled correctly, and indicates a critical failure in randomness generation.
    DuplicateSignature,
    /// The bundle being constructed violated the construction rules for the requested bundle type.
    BundleTypeNotSatisfiable,
    /// Native asset cannot be burned
    BurnErrorNative,
    /// The value to be burned cannot be zero
    BurnErrorZero,
}

impl Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use BuildError::*;
        match self {
            MissingSignatures => f.write_str("Required signatures were missing during build"),
            Proof(e) => f.write_str(&format!("Could not create proof: {}", e)),
            ValueSum(_) => f.write_str("Overflow occurred during value construction"),
            InvalidExternalSignature => f.write_str("External signature was invalid"),
            DuplicateSignature => f.write_str("Signature valid for more than one input"),
            BundleTypeNotSatisfiable => {
                f.write_str("Bundle structure did not conform to requested bundle type.")
            }
            SpendsDisabled => f.write_str("Spends are not enabled for the requested bundle type."),
            OutputsDisabled => f.write_str("Spends are not enabled for the requested bundle type."),
            AnchorMismatch => {
                f.write_str("All spends must share the anchor requested for the transaction.")
            }
            BurnErrorNative => f.write_str("Burning is only possible for non-native assets"),
            BurnErrorZero => f.write_str("Burning is not possible for zero values"),
        }
    }
}

impl std::error::Error for BuildError {}

impl From<halo2_proofs::plonk::Error> for BuildError {
    fn from(e: halo2_proofs::plonk::Error) -> Self {
        BuildError::Proof(e)
    }
}

impl From<value::OverflowError> for BuildError {
    fn from(e: value::OverflowError) -> Self {
        BuildError::ValueSum(e)
    }
}

/// An error type for adding a spend to the builder.
#[derive(Debug, PartialEq, Eq)]
pub enum SpendError {
    /// Spends aren't enabled for this builder.
    SpendsDisabled,
    /// The anchor provided to this builder doesn't match the merkle path used to add a spend.
    AnchorMismatch,
    /// The full viewing key provided didn't match the note provided
    FvkMismatch,
}

impl Display for SpendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use SpendError::*;
        f.write_str(match self {
            SpendsDisabled => "Spends are not enabled for this builder",
            AnchorMismatch => "All anchors must be equal.",
            FvkMismatch => "FullViewingKey does not correspond to the given note",
        })
    }
}

impl std::error::Error for SpendError {}

/// The only error that can occur here is if outputs are disabled for this builder.
#[derive(Debug, PartialEq, Eq)]
pub struct OutputError;

impl Display for OutputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Outputs are not enabled for this builder")
    }
}

impl std::error::Error for OutputError {}

/// Information about a specific note to be spent in an [`Action`].
#[derive(Debug, Clone)]
pub struct SpendInfo {
    pub(crate) dummy_sk: Option<SpendingKey>,
    pub(crate) fvk: FullViewingKey,
    pub(crate) scope: Scope,
    pub(crate) note: Note,
    pub(crate) merkle_path: MerklePath,
    // a flag to indicate whether the value of the note will be counted in the `ValueSum` of the action.
    pub(crate) split_flag: bool,
}

impl SpendInfo {
    /// This constructor is public to enable creation of custom builders.
    /// If you are not creating a custom builder, use [`Builder::add_spend`] instead.
    ///
    /// Creates a `SpendInfo` from note, full viewing key owning the note,
    /// and merkle path witness of the note.
    ///
    /// Returns `None` if the `fvk` does not own the `note`.
    ///
    /// [`Builder::add_spend`]: Builder::add_spend
    pub fn new(
        fvk: FullViewingKey,
        note: Note,
        merkle_path: MerklePath,
        split_flag: bool,
    ) -> Option<Self> {
        let scope = fvk.scope_for_address(&note.recipient())?;
        Some(SpendInfo {
            dummy_sk: None,
            fvk,
            scope,
            note,
            merkle_path,
            split_flag,
        })
    }

    /// Defined in [Zcash Protocol Spec § 4.8.3: Dummy Notes (Orchard)][orcharddummynotes].
    ///
    /// [orcharddummynotes]: https://zips.z.cash/protocol/nu5.pdf#orcharddummynotes
    fn dummy(asset: AssetBase, rng: &mut impl RngCore) -> Self {
        let (sk, fvk, note) = Note::dummy(rng, None, asset);
        let merkle_path = MerklePath::dummy(rng);

        SpendInfo {
            dummy_sk: Some(sk),
            fvk,
            // We use external scope to avoid unnecessary derivations, because the dummy
            // note's spending key is random and thus scoping is irrelevant.
            scope: Scope::External,
            note,
            merkle_path,
            split_flag: false,
        }
    }

    /// Creates a split spend, which is identical to origin normal spend except that
    /// `rseed_split_note` contains a random seed. In addition, the split_flag is raised.
    ///
    /// Defined in [Transfer and Burn of Zcash Shielded Assets ZIP-0226 § Split Notes (DRAFT PR)][TransferZSA].
    ///
    /// [TransferZSA]: https://qed-it.github.io/zips/zip-0226.html#split-notes
    fn create_split_spend(&self, rng: &mut impl RngCore) -> Self {
        SpendInfo {
            dummy_sk: None,
            fvk: self.fvk.clone(),
            // We use external scope to avoid unnecessary derivations
            scope: Scope::External,
            note: self.note.create_split_note(rng),
            merkle_path: self.merkle_path.clone(),
            split_flag: true,
        }
    }

    fn has_matching_anchor(&self, anchor: &Anchor) -> bool {
        if self.note.value() == NoteValue::zero() {
            true
        } else {
            let cm = self.note.commitment();
            let path_root = self.merkle_path.root(cm.into());
            &path_root == anchor
        }
    }
}

/// Information about a specific output to receive funds in an [`Action`].
#[derive(Debug, Clone)]
pub struct OutputInfo {
    ovk: Option<OutgoingViewingKey>,
    recipient: Address,
    value: NoteValue,
    asset: AssetBase,
    memo: [u8; 512],
}

impl OutputInfo {
    /// Constructs a new OutputInfo from its constituent parts.
    pub fn new(
        ovk: Option<OutgoingViewingKey>,
        recipient: Address,
        value: NoteValue,
        asset: AssetBase,
        memo: Option<[u8; 512]>,
    ) -> Self {
        Self {
            ovk,
            recipient,
            value,
            asset,
            memo: memo.unwrap_or_else(|| {
                let mut memo = [0; 512];
                memo[0] = 0xf6;
                memo
            }),
        }
    }

    /// Defined in [Zcash Protocol Spec § 4.8.3: Dummy Notes (Orchard)][orcharddummynotes].
    ///
    /// [orcharddummynotes]: https://zips.z.cash/protocol/nu5.pdf#orcharddummynotes
    pub fn dummy(rng: &mut impl RngCore, asset: AssetBase) -> Self {
        let fvk: FullViewingKey = (&SpendingKey::random(rng)).into();
        let recipient = fvk.address_at(0u32, Scope::External);

        Self::new(None, recipient, NoteValue::zero(), asset, None)
    }
}

/// Information about a specific [`Action`] we plan to build.
#[derive(Debug)]
struct ActionInfo {
    spend: SpendInfo,
    output: OutputInfo,
    rcv: ValueCommitTrapdoor,
}

impl ActionInfo {
    fn new(spend: SpendInfo, output: OutputInfo, rng: impl RngCore) -> Self {
        ActionInfo {
            spend,
            output,
            rcv: ValueCommitTrapdoor::random(rng),
        }
    }

    /// Returns the value sum for this action.
    /// Split notes do not contribute to the value sum.
    fn value_sum(&self) -> ValueSum {
        let spent_value = if self.spend.split_flag {
            NoteValue::zero()
        } else {
            self.spend.note.value()
        };

        spent_value - self.output.value
    }

    /// Builds the action.
    ///
    /// Defined in [Zcash Protocol Spec § 4.7.3: Sending Notes (Orchard)][orchardsend].
    ///
    /// [orchardsend]: https://zips.z.cash/protocol/nu5.pdf#orchardsend
    ///
    /// # Panics
    ///
    /// Panics if the asset types of the spent and output notes do not match.
    fn build<D: OrchardDomain>(
        self,
        mut rng: impl RngCore,
    ) -> (Action<SigningMetadata, D>, CircuitBase<D>) {
        assert_eq!(
            self.spend.note.asset(),
            self.output.asset,
            "spend and recipient note types must be equal"
        );

        let v_net = self.value_sum();
        let asset = self.output.asset;
        let cv_net = ValueCommitment::derive(v_net, self.rcv, asset);

        let nf_old = self.spend.note.nullifier(&self.spend.fvk);
        let rho = Rho::from_nf_old(nf_old);
        let ak: SpendValidatingKey = self.spend.fvk.clone().into();
        let alpha = pallas::Scalar::random(&mut rng);
        let rk = ak.randomize(&alpha);

        let note = Note::new(
            self.output.recipient,
            self.output.value,
            self.output.asset,
            rho,
            &mut rng,
        );
        let cm_new = note.commitment();
        let cmx = cm_new.into();

        let encryptor =
            NoteEncryption::<OrchardDomainBase<D>>::new(self.output.ovk, note, self.output.memo);

        let encrypted_note = TransmittedNoteCiphertext {
            epk_bytes: encryptor.epk().to_bytes().0,
            enc_ciphertext: encryptor.encrypt_note_plaintext(),
            out_ciphertext: encryptor.encrypt_outgoing_plaintext(&cv_net, &cmx, &mut rng),
        };

        (
            Action::from_parts(
                nf_old,
                rk,
                cmx,
                encrypted_note,
                cv_net,
                SigningMetadata {
                    dummy_ask: self.spend.dummy_sk.as_ref().map(SpendAuthorizingKey::from),
                    parts: SigningParts { ak, alpha },
                },
            ),
            CircuitBase::<D>::from_action_context_unchecked(self.spend, note, alpha, self.rcv),
        )
    }
}

/// Type alias for an in-progress bundle that has no proofs or signatures.
///
/// This is returned by [`Builder::build`].
pub type UnauthorizedBundle<V, D> = Bundle<InProgress<Unproven<D>, Unauthorized>, V, D>;

/// Metadata about a bundle created by [`bundle`] or [`Builder::build`] that is not
/// necessarily recoverable from the bundle itself.
///
/// This includes information about how [`Action`]s within the bundle are ordered (after
/// padding and randomization) relative to the order in which spends and outputs were
/// provided (to [`bundle`]), or the order in which [`Builder`] mutations were performed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleMetadata {
    spend_indices: Vec<usize>,
    output_indices: Vec<usize>,
}

impl BundleMetadata {
    fn new(num_requested_spends: usize, num_requested_outputs: usize) -> Self {
        BundleMetadata {
            spend_indices: vec![0; num_requested_spends],
            output_indices: vec![0; num_requested_outputs],
        }
    }

    /// Returns the metadata for a [`Bundle`] that contains only dummy actions, if any.
    pub fn empty() -> Self {
        Self::new(0, 0)
    }

    /// Returns the index within the bundle of the [`Action`] corresponding to the `n`-th
    /// spend specified in bundle construction. If a [`Builder`] was used, this refers to
    /// the spend added by the `n`-th call to [`Builder::add_spend`].
    ///
    /// For the purpose of improving indistinguishability, actions are padded and note
    /// positions are randomized when building bundles. This means that the bundle
    /// consumer cannot assume that e.g. the first spend they added corresponds to the
    /// first action in the bundle.
    pub fn spend_action_index(&self, n: usize) -> Option<usize> {
        self.spend_indices.get(n).copied()
    }

    /// Returns the index within the bundle of the [`Action`] corresponding to the `n`-th
    /// output specified in bundle construction. If a [`Builder`] was used, this refers to
    /// the output added by the `n`-th call to [`Builder::add_output`].
    ///
    /// For the purpose of improving indistinguishability, actions are padded and note
    /// positions are randomized when building bundles. This means that the bundle
    /// consumer cannot assume that e.g. the first output they added corresponds to the
    /// first action in the bundle.
    pub fn output_action_index(&self, n: usize) -> Option<usize> {
        self.output_indices.get(n).copied()
    }
}

/// A builder that constructs a [`Bundle`] from a set of notes to be spent, and outputs
/// to receive funds.
#[derive(Debug)]
pub struct Builder {
    spends: Vec<SpendInfo>,
    outputs: Vec<OutputInfo>,
    burn: HashMap<AssetBase, ValueSum>,
    bundle_type: BundleType,
    anchor: Anchor,
}

impl Builder {
    /// Constructs a new empty builder for an Orchard bundle.
    pub fn new(bundle_type: BundleType, anchor: Anchor) -> Self {
        Builder {
            spends: vec![],
            outputs: vec![],
            burn: HashMap::new(),
            bundle_type,
            anchor,
        }
    }

    /// Adds a note to be spent in this transaction.
    ///
    /// - `note` is a spendable note, obtained by trial-decrypting an [`Action`] using the
    ///   [`zcash_note_encryption_zsa`] crate instantiated with [`OrchardDomain`].
    /// - `merkle_path` can be obtained using the [`incrementalmerkletree`] crate
    ///   instantiated with [`MerkleHashOrchard`].
    ///
    /// Returns an error if the given Merkle path does not have the required anchor for
    /// the given note.
    ///
    /// [`OrchardDomain`]: crate::note_encryption::OrchardDomain
    /// [`MerkleHashOrchard`]: crate::tree::MerkleHashOrchard
    pub fn add_spend(
        &mut self,
        fvk: FullViewingKey,
        note: Note,
        merkle_path: MerklePath,
    ) -> Result<(), SpendError> {
        let flags = self.bundle_type.flags();
        if !flags.spends_enabled() {
            return Err(SpendError::SpendsDisabled);
        }

        let spend = SpendInfo::new(fvk, note, merkle_path, false).ok_or(SpendError::FvkMismatch)?;

        // Consistency check: all anchors must be equal.
        if !spend.has_matching_anchor(&self.anchor) {
            return Err(SpendError::AnchorMismatch);
        }

        self.spends.push(spend);

        Ok(())
    }

    /// Adds an address which will receive funds in this transaction.
    pub fn add_output(
        &mut self,
        ovk: Option<OutgoingViewingKey>,
        recipient: Address,
        value: NoteValue,
        asset: AssetBase,
        memo: Option<[u8; 512]>,
    ) -> Result<(), OutputError> {
        let flags = self.bundle_type.flags();
        if !flags.outputs_enabled() {
            return Err(OutputError);
        }

        self.outputs
            .push(OutputInfo::new(ovk, recipient, value, asset, memo));

        Ok(())
    }

    /// Add an instruction to burn a given amount of a specific asset.
    pub fn add_burn(&mut self, asset: AssetBase, value: NoteValue) -> Result<(), BuildError> {
        if asset.is_native().into() {
            return Err(BurnErrorNative);
        }

        if value.inner() == 0 {
            return Err(BurnErrorZero);
        }

        let cur = *self.burn.get(&asset).unwrap_or(&ValueSum::zero());
        let sum = (cur + value).ok_or(OverflowError)?;
        self.burn.insert(asset, sum);
        Ok(())
    }

    /// Returns the action spend components that will be produced by the
    /// transaction being constructed
    pub fn spends(&self) -> &Vec<impl InputView<()>> {
        &self.spends
    }

    /// Returns the action output components that will be produced by the
    /// transaction being constructed
    pub fn outputs(&self) -> &Vec<impl OutputView> {
        &self.outputs
    }

    /// The net value of the bundle to be built. The value of all spends,
    /// minus the value of all outputs.
    ///
    /// Useful for balancing a transaction, as the value balance of an individual bundle
    /// can be non-zero. Each bundle's value balance is [added] to the transparent
    /// transaction value pool, which [must not have a negative value]. (If it were
    /// negative, the transaction would output more value than it receives in inputs.)
    ///
    /// [added]: https://zips.z.cash/protocol/protocol.pdf#orchardbalance
    /// [must not have a negative value]: https://zips.z.cash/protocol/protocol.pdf#transactions
    pub fn value_balance<V: TryFrom<i64>>(&self) -> Result<V, value::OverflowError> {
        let value_balance = self
            .spends
            .iter()
            .map(|spend| spend.note.value() - NoteValue::zero())
            .chain(
                self.outputs
                    .iter()
                    .map(|output| NoteValue::zero() - output.value),
            )
            .try_fold(ValueSum::zero(), |acc, note_value| acc + note_value)
            .ok_or(OverflowError)?;
        i64::try_from(value_balance).and_then(|i| V::try_from(i).map_err(|_| value::OverflowError))
    }

    /// Builds a bundle containing the given spent notes and outputs.
    ///
    /// The returned bundle will have no proof or signatures; these can be applied with
    /// [`Bundle::create_proof`] and [`Bundle::apply_signatures`] respectively.
    // FIXME: Consider factoring parts of the return type into `type` definitions
    #[allow(clippy::type_complexity)]
    pub fn build<V: TryFrom<i64>, D: OrchardDomain + OrchardCircuit + OrchardHash>(
        self,
        rng: impl RngCore,
    ) -> Result<Option<(UnauthorizedBundle<V, D>, BundleMetadata)>, BuildError> {
        bundle(
            rng,
            self.anchor,
            self.bundle_type,
            self.spends,
            self.outputs,
            self.burn,
        )
    }
}

/// The index of the attached spend or output in the bundle.
/// None indicates a dummy note.
/// The index is used to track the position of the note in the bundle.
type MetadataIdx = Option<usize>;

/// Partition a list of spends and outputs by note types.
/// Method creates single dummy ZEC note if spends and outputs are both empty.
#[allow(clippy::type_complexity)]
fn partition_by_asset(
    spends: &[SpendInfo],
    outputs: &[OutputInfo],
    rng: &mut impl RngCore,
) -> HashMap<
    AssetBase,
    (
        Vec<(SpendInfo, MetadataIdx)>,
        Vec<(OutputInfo, MetadataIdx)>,
    ),
> {
    let mut hm = HashMap::new();

    for (i, s) in spends.iter().enumerate() {
        hm.entry(s.note.asset())
            .or_insert((vec![], vec![]))
            .0
            .push((s.clone(), Some(i)));
    }

    for (i, o) in outputs.iter().enumerate() {
        hm.entry(o.asset)
            .or_insert((vec![], vec![]))
            .1
            .push((o.clone(), Some(i)));
    }

    if hm.is_empty() {
        let dummy_spend = pad_spend(None, AssetBase::native(), rng);
        // dummy_spend should not be included in the indexing and marked as None.
        hm.insert(
            dummy_spend.note.asset(),
            (vec![(dummy_spend, None)], vec![]),
        );
    }

    hm
}

/// Returns the appropriate SpendInfo for padding.
fn pad_spend(spend: Option<&SpendInfo>, asset: AssetBase, mut rng: impl RngCore) -> SpendInfo {
    if asset.is_native().into() {
        // For native asset, extends with dummy notes
        SpendInfo::dummy(asset, &mut rng)
    } else {
        // For ZSA asset, extends with
        // - dummy note if SpendInfo is None
        // - split notes otherwise.
        let dummy = SpendInfo::dummy(asset, &mut rng);
        spend.map_or_else(|| dummy, |s| s.create_split_spend(&mut rng))
    }
}

/// Builds a bundle containing the given spent notes and outputs.
///
/// The returned bundle will have no proof or signatures; these can be applied with
/// [`Bundle::create_proof`] and [`Bundle::apply_signatures`] respectively.
#[allow(clippy::type_complexity)]
pub fn bundle<V: TryFrom<i64>, D: OrchardDomain + OrchardCircuit + OrchardHash>(
    mut rng: impl RngCore,
    anchor: Anchor,
    bundle_type: BundleType,
    spends: Vec<SpendInfo>,
    outputs: Vec<OutputInfo>,
    burn: HashMap<AssetBase, ValueSum>,
) -> Result<Option<(UnauthorizedBundle<V, D>, BundleMetadata)>, BuildError> {
    let flags = bundle_type.flags();

    let num_requested_spends = spends.len();
    if !flags.spends_enabled() && num_requested_spends > 0 {
        return Err(BuildError::SpendsDisabled);
    }

    for spend in &spends {
        if !spend.has_matching_anchor(&anchor) {
            return Err(BuildError::AnchorMismatch);
        }
    }

    let num_requested_outputs = outputs.len();
    if !flags.outputs_enabled() && num_requested_outputs > 0 {
        return Err(BuildError::OutputsDisabled);
    }

    // Pair up the spends and outputs, extending with dummy values as necessary.
    let (pre_actions, bundle_meta) = {
        // Use Vec::with_capacity().extend(...) instead of .collect() to avoid reallocations,
        // as we can estimate the vector size beforehand.
        let mut indexed_spends_outputs =
            Vec::with_capacity(spends.len().max(outputs.len()).max(MIN_ACTIONS));

        indexed_spends_outputs.extend(
            partition_by_asset(&spends, &outputs, &mut rng)
                .into_iter()
                .flat_map(|(asset, (spends, outputs))| {
                    let num_asset_pre_actions = spends.len().max(outputs.len());

                    let first_spend = spends.first().map(|(s, _)| s.clone());

                    let mut indexed_spends = spends
                        .into_iter()
                        .chain(iter::repeat_with(|| {
                            (pad_spend(first_spend.as_ref(), asset, &mut rng), None)
                        }))
                        .take(num_asset_pre_actions)
                        .collect::<Vec<_>>();

                    let mut indexed_outputs = outputs
                        .into_iter()
                        .chain(iter::repeat_with(|| {
                            (OutputInfo::dummy(&mut rng, asset), None)
                        }))
                        .take(num_asset_pre_actions)
                        .collect::<Vec<_>>();

                    // Shuffle the spends and outputs, so that learning the position of a
                    // specific spent note or output note doesn't reveal anything on its own about
                    // the meaning of that note in the transaction context.
                    indexed_spends.shuffle(&mut rng);
                    indexed_outputs.shuffle(&mut rng);

                    assert_eq!(indexed_spends.len(), indexed_outputs.len());

                    indexed_spends.into_iter().zip(indexed_outputs)
                }),
        );

        indexed_spends_outputs.extend(
            iter::repeat_with(|| {
                (
                    (pad_spend(None, AssetBase::native(), &mut rng), None),
                    (OutputInfo::dummy(&mut rng, AssetBase::native()), None),
                )
            })
            .take(MIN_ACTIONS.saturating_sub(indexed_spends_outputs.len())),
        );

        let mut bundle_meta = BundleMetadata::new(num_requested_spends, num_requested_outputs);
        let pre_actions = indexed_spends_outputs
            .into_iter()
            .enumerate()
            .map(|(action_idx, ((spend, spend_idx), (output, out_idx)))| {
                // Record the post-randomization spend location
                if let Some(spend_idx) = spend_idx {
                    bundle_meta.spend_indices[spend_idx] = action_idx;
                }

                // Record the post-randomization output location
                if let Some(out_idx) = out_idx {
                    bundle_meta.output_indices[out_idx] = action_idx;
                }

                ActionInfo::new(spend, output, &mut rng)
            })
            .collect::<Vec<_>>();

        (pre_actions, bundle_meta)
    };

    // Determine the value balance for this bundle, ensuring it is valid.
    let native_value_balance: i64 = pre_actions
        .iter()
        .filter(|action| action.spend.note.asset().is_native().into())
        .fold(Some(ValueSum::zero()), |acc, action| {
            acc? + action.value_sum()
        })
        .ok_or(OverflowError)?
        .into()?;

    let result_value_balance = V::try_from(native_value_balance)
        .map_err(|_| BuildError::ValueSum(value::OverflowError))?;

    // Compute the transaction binding signing key.
    let bsk = pre_actions
        .iter()
        .map(|a| &a.rcv)
        .sum::<ValueCommitTrapdoor>()
        .into_bsk();

    // Create the actions.
    let (actions, circuits): (Vec<_>, Vec<_>) =
        pre_actions.into_iter().map(|a| a.build(&mut rng)).unzip();

    // Verify that bsk and bvk are consistent.
    let bvk = derive_bvk(
        &actions,
        native_value_balance,
        burn.iter()
            .flat_map(|(asset, value)| -> Result<_, BuildError> { Ok((*asset, (*value).into()?)) }),
    );
    assert_eq!(redpallas::VerificationKey::from(&bsk), bvk);

    let burn = burn
        .into_iter()
        .map(|(asset, value)| Ok((asset, value.into()?)))
        .collect::<Result<Vec<(AssetBase, V)>, BuildError>>()?;

    Ok(NonEmpty::from_vec(actions).map(|actions| {
        (
            Bundle::from_parts(
                actions,
                flags,
                result_value_balance,
                burn,
                anchor,
                InProgress {
                    proof: Unproven { circuits },
                    sigs: Unauthorized { bsk },
                },
            ),
            bundle_meta,
        )
    }))
}

/// Marker trait representing bundle signatures in the process of being created.
pub trait InProgressSignatures: fmt::Debug {
    /// The authorization type of an Orchard action in the process of being authorized.
    type SpendAuth: fmt::Debug;
}

/// Marker for a bundle in the process of being built.
#[derive(Clone, Debug)]
pub struct InProgress<P, S: InProgressSignatures> {
    proof: P,
    sigs: S,
}

impl<P, S: InProgressSignatures> InProgress<P, S> {
    /// Changes this authorization from one proof type to another.
    pub fn map_proof<F, P2>(self, f: F) -> InProgress<P2, S>
    where
        F: FnOnce(P) -> P2,
    {
        InProgress {
            proof: f(self.proof),
            sigs: self.sigs,
        }
    }
}

impl<P: fmt::Debug, S: InProgressSignatures> Authorization for InProgress<P, S> {
    type SpendAuth = S::SpendAuth;
}

/// Marker for a bundle without a proof.
///
/// This struct contains the private data needed to create a [`Proof`] for a [`Bundle`].
#[derive(Clone, Debug)]
pub struct Unproven<D: OrchardCircuit> {
    circuits: Vec<CircuitBase<D>>,
}

impl<S: InProgressSignatures, D: OrchardCircuit> InProgress<Unproven<D>, S> {
    /// Creates the proof for this bundle.
    pub fn create_proof(
        &self,
        pk: &ProvingKey,
        instances: &[Instance],
        rng: impl RngCore,
    ) -> Result<Proof, halo2_proofs::plonk::Error> {
        Proof::create(pk, &self.proof.circuits, instances, rng)
    }
}

impl<S: InProgressSignatures, V, D: OrchardDomain + OrchardCircuit>
    Bundle<InProgress<Unproven<D>, S>, V, D>
{
    /// Creates the proof for this bundle.
    pub fn create_proof(
        self,
        pk: &ProvingKey,
        mut rng: impl RngCore,
    ) -> Result<Bundle<InProgress<Proof, S>, V, D>, BuildError> {
        let instances: Vec<_> = self
            .actions()
            .iter()
            .map(|a| a.to_instance(*self.flags(), *self.anchor()))
            .collect();
        self.try_map_authorization(
            &mut (),
            |_, _, a| Ok(a),
            |_, auth| {
                let proof = auth.create_proof(pk, &instances, &mut rng)?;
                Ok(InProgress {
                    proof,
                    sigs: auth.sigs,
                })
            },
        )
    }
}

/// The parts needed to sign an [`Action`].
#[derive(Clone, Debug)]
pub struct SigningParts {
    /// The spend validating key for this action. Used to match spend authorizing keys to
    /// actions they can create signatures for.
    ak: SpendValidatingKey,
    /// The randomization needed to derive the actual signing key for this note.
    alpha: pallas::Scalar,
}

/// Marker for an unauthorized bundle with no signatures.
#[derive(Clone, Debug)]
pub struct Unauthorized {
    bsk: redpallas::SigningKey<Binding>,
}

impl InProgressSignatures for Unauthorized {
    type SpendAuth = SigningMetadata;
}

/// Container for metadata needed to sign an [`Action`].
#[derive(Clone, Debug)]
pub struct SigningMetadata {
    /// If this action is spending a dummy note, this field holds that note's spend
    /// authorizing key.
    ///
    /// These keys are used automatically in [`Bundle<Unauthorized>::prepare`] or
    /// [`Bundle<Unauthorized>::apply_signatures`] to sign dummy spends.
    dummy_ask: Option<SpendAuthorizingKey>,
    parts: SigningParts,
}

/// Marker for a partially-authorized bundle, in the process of being signed.
#[derive(Debug)]
pub struct PartiallyAuthorized {
    binding_signature: redpallas::Signature<Binding>,
    sighash: [u8; 32],
}

impl InProgressSignatures for PartiallyAuthorized {
    type SpendAuth = MaybeSigned;
}

/// A heisen[`Signature`] for a particular [`Action`].
///
/// [`Signature`]: redpallas::Signature
#[derive(Debug)]
pub enum MaybeSigned {
    /// The information needed to sign this [`Action`].
    SigningMetadata(SigningParts),
    /// The signature for this [`Action`].
    Signature(redpallas::Signature<SpendAuth>),
}

impl MaybeSigned {
    fn finalize(self) -> Result<redpallas::Signature<SpendAuth>, BuildError> {
        match self {
            Self::Signature(sig) => Ok(sig),
            _ => Err(BuildError::MissingSignatures),
        }
    }
}

impl<P: fmt::Debug, V, D: OrchardDomain> Bundle<InProgress<P, Unauthorized>, V, D> {
    /// Loads the sighash into this bundle, preparing it for signing.
    ///
    /// This API ensures that all signatures are created over the same sighash.
    pub fn prepare<R: RngCore + CryptoRng>(
        self,
        mut rng: R,
        sighash: [u8; 32],
    ) -> Bundle<InProgress<P, PartiallyAuthorized>, V, D> {
        self.map_authorization(
            &mut rng,
            |rng, _, SigningMetadata { dummy_ask, parts }| {
                // We can create signatures for dummy spends immediately.
                dummy_ask
                    .map(|ask| ask.randomize(&parts.alpha).sign(rng, &sighash))
                    .map(MaybeSigned::Signature)
                    .unwrap_or(MaybeSigned::SigningMetadata(parts))
            },
            |rng, auth| InProgress {
                proof: auth.proof,
                sigs: PartiallyAuthorized {
                    binding_signature: auth.sigs.bsk.sign(rng, &sighash),
                    sighash,
                },
            },
        )
    }
}

impl<V, D: OrchardDomain> Bundle<InProgress<Proof, Unauthorized>, V, D> {
    /// Applies signatures to this bundle, in order to authorize it.
    ///
    /// This is a helper method that wraps [`Bundle::prepare`], [`Bundle::sign`], and
    /// [`Bundle::finalize`].
    pub fn apply_signatures<R: RngCore + CryptoRng>(
        self,
        mut rng: R,
        sighash: [u8; 32],
        signing_keys: &[SpendAuthorizingKey],
    ) -> Result<Bundle<Authorized, V, D>, BuildError> {
        signing_keys
            .iter()
            .fold(self.prepare(&mut rng, sighash), |partial, ask| {
                partial.sign(&mut rng, ask)
            })
            .finalize()
    }
}

impl<P: fmt::Debug, V, D: OrchardDomain> Bundle<InProgress<P, PartiallyAuthorized>, V, D> {
    /// Signs this bundle with the given [`SpendAuthorizingKey`].
    ///
    /// This will apply signatures for all notes controlled by this spending key.
    pub fn sign<R: RngCore + CryptoRng>(self, mut rng: R, ask: &SpendAuthorizingKey) -> Self {
        let expected_ak = ask.into();
        self.map_authorization(
            &mut rng,
            |rng, partial, maybe| match maybe {
                MaybeSigned::SigningMetadata(parts) if parts.ak == expected_ak => {
                    MaybeSigned::Signature(
                        ask.randomize(&parts.alpha).sign(rng, &partial.sigs.sighash),
                    )
                }
                s => s,
            },
            |_, partial| partial,
        )
    }
    /// Appends externally computed [`Signature`]s.
    ///
    /// Each signature will be applied to the one input for which it is valid. An error
    /// will be returned if the signature is not valid for any inputs, or if it is valid
    /// for more than one input.
    ///
    /// [`Signature`]: redpallas::Signature
    pub fn append_signatures(
        self,
        signatures: &[redpallas::Signature<SpendAuth>],
    ) -> Result<Self, BuildError> {
        signatures.iter().try_fold(self, Self::append_signature)
    }

    fn append_signature(
        self,
        signature: &redpallas::Signature<SpendAuth>,
    ) -> Result<Self, BuildError> {
        let mut signature_valid_for = 0usize;
        let bundle = self.map_authorization(
            &mut signature_valid_for,
            |valid_for, partial, maybe| match maybe {
                MaybeSigned::SigningMetadata(parts) => {
                    let rk = parts.ak.randomize(&parts.alpha);
                    if rk.verify(&partial.sigs.sighash[..], signature).is_ok() {
                        *valid_for += 1;
                        MaybeSigned::Signature(signature.clone())
                    } else {
                        // Signature isn't for this input.
                        MaybeSigned::SigningMetadata(parts)
                    }
                }
                s => s,
            },
            |_, partial| partial,
        );
        match signature_valid_for {
            0 => Err(BuildError::InvalidExternalSignature),
            1 => Ok(bundle),
            _ => Err(BuildError::DuplicateSignature),
        }
    }
}

impl<V, D: OrchardDomain> Bundle<InProgress<Proof, PartiallyAuthorized>, V, D> {
    /// Finalizes this bundle, enabling it to be included in a transaction.
    ///
    /// Returns an error if any signatures are missing.
    pub fn finalize(self) -> Result<Bundle<Authorized, V, D>, BuildError> {
        self.try_map_authorization(
            &mut (),
            |_, _, maybe| maybe.finalize(),
            |_, partial| {
                Ok(Authorized::from_parts(
                    partial.proof,
                    partial.sigs.binding_signature,
                ))
            },
        )
    }
}

/// A trait that provides a minimized view of an Orchard input suitable for use in
/// fee and change calculation.
pub trait InputView<NoteRef> {
    /// An identifier for the input being spent.
    fn note_id(&self) -> &NoteRef;
    /// The value of the input being spent.
    fn value<V: From<u64>>(&self) -> V;
}

impl InputView<()> for SpendInfo {
    fn note_id(&self) -> &() {
        // The builder does not make use of note identifiers, so we can just return the unit value.
        &()
    }

    fn value<V: From<u64>>(&self) -> V {
        V::from(self.note.value().inner())
    }
}

/// A trait that provides a minimized view of an Orchard output suitable for use in
/// fee and change calculation.
pub trait OutputView {
    /// The value of the output being produced.
    fn value<V: From<u64>>(&self) -> V;
}

impl OutputView for OutputInfo {
    fn value<V: From<u64>>(&self) -> V {
        V::from(self.value.inner())
    }
}

/// Generators for property testing.
#[cfg(any(test, feature = "test-dependencies"))]
#[cfg_attr(docsrs, doc(cfg(feature = "test-dependencies")))]
pub mod testing {
    use core::fmt::Debug;
    use incrementalmerkletree::{frontier::Frontier, Hashable};
    use rand::{rngs::StdRng, CryptoRng, SeedableRng};

    use proptest::collection::vec;
    use proptest::prelude::*;

    use crate::note::AssetBase;
    use crate::{
        address::testing::arb_address,
        bundle::{Authorized, Bundle, OrchardHash},
        circuit::{OrchardCircuit, ProvingKey},
        keys::{testing::arb_spending_key, FullViewingKey, SpendAuthorizingKey, SpendingKey},
        note::testing::arb_note,
        note_encryption::OrchardDomain,
        tree::{Anchor, MerkleHashOrchard, MerklePath},
        value::{testing::arb_positive_note_value, NoteValue, MAX_NOTE_VALUE},
        Address, Note,
    };

    use super::{Builder, BundleType};

    /// An intermediate type used for construction of arbitrary
    /// bundle values. This type is required because of a limitation
    /// of the proptest prop_compose! macro which does not correctly
    /// handle polymorphic generator functions. Instead of generating
    /// a bundle directly, we generate the bundle inputs, and then
    /// are able to use the `build` function to construct the bundle
    /// from these inputs, but using a `ValueBalance` implementation that
    /// is defined by the end user.
    #[derive(Debug)]
    struct ArbitraryBundleInputs<R> {
        rng: R,
        sk: SpendingKey,
        anchor: Anchor,
        notes: Vec<(Note, MerklePath)>,
        output_amounts: Vec<(Address, NoteValue, AssetBase)>,
    }

    impl<R: RngCore + CryptoRng> ArbitraryBundleInputs<R> {
        /// Create a bundle from the set of arbitrary bundle inputs.
        fn into_bundle<
            V: TryFrom<i64> + Copy + Into<i64>,
            D: OrchardDomain + OrchardCircuit + OrchardHash,
        >(
            mut self,
        ) -> Bundle<Authorized, V, D> {
            let fvk = FullViewingKey::from(&self.sk);
            let mut builder = Builder::new(BundleType::DEFAULT_ZSA, self.anchor);

            for (note, path) in self.notes.into_iter() {
                builder.add_spend(fvk.clone(), note, path).unwrap();
            }

            for (addr, value, asset) in self.output_amounts.into_iter() {
                let scope = fvk.scope_for_address(&addr).unwrap();
                let ovk = fvk.to_ovk(scope);

                builder
                    .add_output(Some(ovk.clone()), addr, value, asset, None)
                    .unwrap();
            }

            let pk = ProvingKey::build::<D>();
            builder
                .build(&mut self.rng)
                .unwrap()
                .unwrap()
                .0
                .create_proof(&pk, &mut self.rng)
                .unwrap()
                .prepare(&mut self.rng, [0; 32])
                .sign(&mut self.rng, &SpendAuthorizingKey::from(&self.sk))
                .finalize()
                .unwrap()
        }
    }

    /// `BuilderArb` adapts `arb_...` functions for both Vanilla and ZSA Orchard protocol variations
    /// in property-based testing, addressing proptest crate limitations.    
    #[derive(Debug)]
    pub struct BuilderArb<D: OrchardDomain> {
        phantom: std::marker::PhantomData<D>,
    }

    impl<D: OrchardDomain + OrchardCircuit + OrchardHash> BuilderArb<D> {
        prop_compose! {
            /// Produce a random valid Orchard bundle.
            fn arb_bundle_inputs(sk: SpendingKey)
            (
                n_notes in 1usize..30,
                n_outputs in 1..30,
            )
            (
                // generate note values that we're certain won't exceed MAX_NOTE_VALUE in total
                notes in vec(
                    arb_positive_note_value(MAX_NOTE_VALUE / n_notes as u64).prop_flat_map(arb_note),
                    n_notes
                ),
                output_amounts in vec(
                    arb_address().prop_flat_map(move |a| {
                        arb_positive_note_value(MAX_NOTE_VALUE / n_outputs as u64)
                            .prop_map(move |v| {
                                (a,v, AssetBase::native())
                            })
                    }),
                    n_outputs as usize,
                ),
                rng_seed in prop::array::uniform32(prop::num::u8::ANY)
            ) -> ArbitraryBundleInputs<StdRng> {
                use crate::constants::MERKLE_DEPTH_ORCHARD;
                let mut frontier = Frontier::<MerkleHashOrchard, { MERKLE_DEPTH_ORCHARD as u8 }>::empty();
                let mut notes_and_auth_paths: Vec<(Note, MerklePath)> = Vec::new();

                for note in notes.iter() {
                    let leaf = MerkleHashOrchard::from_cmx(&note.commitment().into());
                    frontier.append(leaf);

                    let path = frontier
                        .witness(|addr| Some(<MerkleHashOrchard as Hashable>::empty_root(addr.level())))
                        .ok()
                        .flatten()
                        .expect("we can always construct a correct Merkle path");
                    notes_and_auth_paths.push((*note, path.into()));
                }

                ArbitraryBundleInputs {
                    rng: StdRng::from_seed(rng_seed),
                    sk,
                    anchor: frontier.root().into(),
                    notes: notes_and_auth_paths,
                    output_amounts
                }
            }
        }

        /// Produce an arbitrary valid Orchard bundle using a random spending key.
        pub fn arb_bundle<V: TryFrom<i64> + Debug + Copy + Into<i64>>(
        ) -> impl Strategy<Value = Bundle<Authorized, V, D>> {
            arb_spending_key()
                .prop_flat_map(BuilderArb::<D>::arb_bundle_inputs)
                .prop_map(|inputs| inputs.into_bundle::<V, D>())
        }

        /// Produce an arbitrary valid Orchard bundle using a specified spending key.
        pub fn arb_bundle_with_key<V: TryFrom<i64> + Debug + Copy + Into<i64>>(
            k: SpendingKey,
        ) -> impl Strategy<Value = Bundle<Authorized, V, D>> {
            BuilderArb::<D>::arb_bundle_inputs(k).prop_map(|inputs| inputs.into_bundle::<V, D>())
        }
    }
}

#[cfg(test)]
mod tests {
    use rand::rngs::OsRng;

    use crate::{
        builder::BundleType,
        bundle::{Authorized, Bundle},
        circuit::ProvingKey,
        constants::MERKLE_DEPTH_ORCHARD,
        keys::{FullViewingKey, Scope, SpendingKey},
        note::AssetBase,
        orchard_flavors::OrchardZSA,
        tree::EMPTY_ROOTS,
        value::NoteValue,
    };

    use super::Builder;

    #[test]
    fn shielding_bundle() {
        // FIXME: consider adding test for OrchardVanilla as well
        let pk = ProvingKey::build::<OrchardZSA>();
        let mut rng = OsRng;

        let sk = SpendingKey::random(&mut rng);
        let fvk = FullViewingKey::from(&sk);
        let recipient = fvk.address_at(0u32, Scope::External);

        let mut builder = Builder::new(
            BundleType::DEFAULT_VANILLA,
            EMPTY_ROOTS[MERKLE_DEPTH_ORCHARD].into(),
        );

        builder
            .add_output(
                None,
                recipient,
                NoteValue::from_raw(5000),
                AssetBase::native(),
                None,
            )
            .unwrap();
        let balance: i64 = builder.value_balance().unwrap();
        assert_eq!(balance, -5000);

        let bundle: Bundle<Authorized, i64, OrchardZSA> = builder
            .build(&mut rng)
            .unwrap()
            .unwrap()
            .0
            .create_proof(&pk, &mut rng)
            .unwrap()
            .prepare(rng, [0; 32])
            .finalize()
            .unwrap();
        assert_eq!(bundle.value_balance(), &(-5000))
    }
}
