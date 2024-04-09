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

use crate::{
    action::Action,
    address::Address,
    bundle::{Authorization, Authorized, Bundle, Flags},
    circuit::{Circuit, Instance, OrchardCircuit, Proof, ProvingKey},
    keys::{
        FullViewingKey, OutgoingViewingKey, Scope, SpendAuthorizingKey, SpendValidatingKey,
        SpendingKey,
    },
    note::{AssetBase, Note, TransmittedNoteCiphertext},
    note_encryption::{OrchardDomain, OrchardDomainContext},
    primitives::redpallas::{self, Binding, SpendAuth},
    tree::{Anchor, MerklePath},
    value::{self, NoteValue, OverflowError, ValueCommitTrapdoor, ValueCommitment, ValueSum},
};

const MIN_ACTIONS: usize = 2;

/// An error type for the kinds of errors that can occur during bundle construction.
#[derive(Debug)]
pub enum BuildError {
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
        }
    }
}

impl std::error::Error for BuildError {}

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
}

/// Information about a specific recipient to receive funds in an [`Action`].
#[derive(Debug, Clone)]
struct RecipientInfo {
    ovk: Option<OutgoingViewingKey>,
    recipient: Address,
    value: NoteValue,
    asset: AssetBase,
    memo: Option<[u8; 512]>,
}

impl RecipientInfo {
    /// Defined in [Zcash Protocol Spec § 4.8.3: Dummy Notes (Orchard)][orcharddummynotes].
    ///
    /// [orcharddummynotes]: https://zips.z.cash/protocol/nu5.pdf#orcharddummynotes
    fn dummy(rng: &mut impl RngCore, asset: AssetBase) -> Self {
        let fvk: FullViewingKey = (&SpendingKey::random(rng)).into();
        let recipient = fvk.address_at(0u32, Scope::External);

        RecipientInfo {
            ovk: None,
            recipient,
            value: NoteValue::zero(),
            asset,
            memo: None,
        }
    }
}

/// Information about a specific [`Action`] we plan to build.
#[derive(Debug)]
struct ActionInfo {
    spend: SpendInfo,
    output: RecipientInfo,
    rcv: ValueCommitTrapdoor,
}

impl ActionInfo {
    fn new(spend: SpendInfo, output: RecipientInfo, rng: impl RngCore) -> Self {
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
    ) -> (Action<SigningMetadata, D>, Circuit<D>) {
        assert_eq!(
            self.spend.note.asset(),
            self.output.asset,
            "spend and recipient note types must be equal"
        );

        let v_net = self.value_sum();
        let asset = self.output.asset;
        let cv_net = ValueCommitment::derive(v_net, self.rcv, asset);

        let nf_old = self.spend.note.nullifier(&self.spend.fvk);
        let ak: SpendValidatingKey = self.spend.fvk.clone().into();
        let alpha = pallas::Scalar::random(&mut rng);
        let rk = ak.randomize(&alpha);

        let note = Note::new(
            self.output.recipient,
            self.output.value,
            self.output.asset,
            nf_old,
            &mut rng,
        );
        let cm_new = note.commitment();
        let cmx = cm_new.into();

        let encryptor = NoteEncryption::<OrchardDomainContext<D>>::new(
            self.output.ovk,
            note,
            self.output.memo.unwrap_or_else(|| {
                let mut memo = [0; 512];
                memo[0] = 0xf6;
                memo
            }),
        );

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
            Circuit::<D>::from_action_context_unchecked(self.spend, note, alpha, self.rcv),
        )
    }
}

/// A builder that constructs a [`Bundle`] from a set of notes to be spent, and recipients
/// to receive funds.
#[derive(Debug)]
pub struct Builder {
    spends: Vec<SpendInfo>,
    recipients: Vec<RecipientInfo>,
    burn: HashMap<AssetBase, ValueSum>,
    flags: Flags,
    anchor: Anchor,
}

type UnauthorizedBundle<V, D> = Bundle<InProgress<Unproven<D>, Unauthorized>, V, D>;

impl Builder {
    /// Constructs a new empty builder for an Orchard bundle.
    pub fn new(flags: Flags, anchor: Anchor) -> Self {
        Builder {
            spends: vec![],
            recipients: vec![],
            burn: HashMap::new(),
            flags,
            anchor,
        }
    }

    // FIXME: fix the doc, this line was removed from the doc:
    // [`OrchardDomain`]: crate::note_encryption_zsa::OrchardZSADomain

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
    /// [`MerkleHashOrchard`]: crate::tree::MerkleHashOrchard
    pub fn add_spend(
        &mut self,
        fvk: FullViewingKey,
        note: Note,
        merkle_path: MerklePath,
    ) -> Result<(), SpendError> {
        if !self.flags.spends_enabled() {
            return Err(SpendError::SpendsDisabled);
        }

        // Consistency check: all anchors must be equal.
        let cm = note.commitment();
        let path_root = merkle_path.root(cm.into());
        if path_root != self.anchor {
            return Err(SpendError::AnchorMismatch);
        }

        // Check if note is internal or external.
        let scope = fvk
            .scope_for_address(&note.recipient())
            .ok_or(SpendError::FvkMismatch)?;

        self.spends.push(SpendInfo {
            dummy_sk: None,
            fvk,
            scope,
            note,
            merkle_path,
            split_flag: false,
        });

        Ok(())
    }

    /// Adds an address which will receive funds in this transaction.
    pub fn add_recipient(
        &mut self,
        ovk: Option<OutgoingViewingKey>,
        recipient: Address,
        value: NoteValue,
        asset: AssetBase,
        memo: Option<[u8; 512]>,
    ) -> Result<(), OutputError> {
        if !self.flags.outputs_enabled() {
            return Err(OutputError);
        }

        self.recipients.push(RecipientInfo {
            ovk,
            recipient,
            value,
            asset,
            memo,
        });

        Ok(())
    }

    /// Add an instruction to burn a given amount of a specific asset.
    pub fn add_burn(&mut self, asset: AssetBase, value: NoteValue) -> Result<(), &'static str> {
        if asset.is_native().into() {
            return Err("Burning is only possible for non-native assets");
        }

        if value.inner() == 0 {
            return Err("Burning is not possible for zero values");
        }

        let cur = *self.burn.get(&asset).unwrap_or(&ValueSum::zero());
        let sum = (cur + value).ok_or("Orchard ValueSum operation overflowed")?;
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
        &self.recipients
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
                self.recipients
                    .iter()
                    .map(|recipient| NoteValue::zero() - recipient.value),
            )
            .fold(Some(ValueSum::zero()), |acc, note_value| acc? + note_value)
            .ok_or(OverflowError)?;
        i64::try_from(value_balance).and_then(|i| V::try_from(i).map_err(|_| value::OverflowError))
    }

    /// Returns the number of actions to add to this bundle in order to contain at least MIN_ACTION actions.
    fn num_missing_actions(&self) -> usize {
        let num_actions = [self.spends.len(), self.recipients.len()]
            .iter()
            .max()
            .cloned()
            .unwrap();
        if num_actions < MIN_ACTIONS {
            MIN_ACTIONS - num_actions
        } else {
            0
        }
    }

    /// Builds a bundle containing the given spent notes and recipients.
    ///
    /// The returned bundle will have no proof or signatures; these can be applied with
    /// [`Bundle::create_proof`] and [`Bundle::apply_signatures`] respectively.
    pub fn build<V: TryFrom<i64> + Copy + Into<i64>, D: OrchardDomain + OrchardCircuit>(
        self,
        mut rng: impl RngCore,
    ) -> Result<UnauthorizedBundle<V, D>, BuildError> {
        let mut pre_actions: Vec<_> = Vec::new();

        // Pair up the spends and recipients, extending with dummy values as necessary.
        for (asset, (mut spends, mut recipients)) in
            partition_by_asset(&self.spends, &self.recipients, &mut rng)
        {
            let num_spends = spends.len();
            let num_recipients = recipients.len();
            let mut num_actions = [num_spends, num_recipients].iter().max().cloned().unwrap();
            // We might have to add dummy/split actions only for the first asset to reach MIN_ACTIONS.
            pre_actions
                .is_empty()
                .then(|| num_actions += self.num_missing_actions());

            let first_spend = spends.first().cloned();

            spends.extend(
                iter::repeat_with(|| pad_spend(first_spend.as_ref(), asset, &mut rng))
                    .take(num_actions - num_spends),
            );

            // Extend the recipients with dummy values.
            recipients.extend(
                iter::repeat_with(|| RecipientInfo::dummy(&mut rng, asset))
                    .take(num_actions - num_recipients),
            );

            // Shuffle the spends and recipients, so that learning the position of a
            // specific spent note or output note doesn't reveal anything on its own about
            // the meaning of that note in the transaction context.
            spends.shuffle(&mut rng);
            recipients.shuffle(&mut rng);

            assert_eq!(spends.len(), recipients.len());
            pre_actions.extend(
                spends
                    .into_iter()
                    .zip(recipients.into_iter())
                    .map(|(spend, recipient)| ActionInfo::new(spend, recipient, &mut rng)),
            );
        }

        // Move some things out of self that we will need.
        let flags = self.flags;
        let anchor = self.anchor;

        // Determine the value balance for this bundle, ensuring it is valid.
        let native_value_balance: V = pre_actions
            .iter()
            .filter(|action| action.spend.note.asset().is_native().into())
            .fold(Some(ValueSum::zero()), |acc, action| {
                acc? + action.value_sum()
            })
            .ok_or(OverflowError)?
            .into()?;

        // Compute the transaction binding signing key.
        let bsk = pre_actions
            .iter()
            .map(|a| &a.rcv)
            .sum::<ValueCommitTrapdoor>()
            .into_bsk();

        // Create the actions.
        let (actions, circuits): (Vec<_>, Vec<_>) = pre_actions
            .into_iter()
            .map(|a| a.build::<D>(&mut rng))
            .unzip();

        let bundle = Bundle::from_parts(
            NonEmpty::from_vec(actions).unwrap(),
            flags,
            native_value_balance,
            self.burn
                .into_iter()
                .map(|(asset, value)| Ok((asset, value.into()?)))
                .collect::<Result<_, BuildError>>()?,
            anchor,
            InProgress {
                proof: Unproven { circuits },
                sigs: Unauthorized { bsk },
            },
        );

        assert_eq!(
            redpallas::VerificationKey::from(&bundle.authorization().sigs.bsk),
            bundle.binding_validating_key()
        );
        Ok(bundle)
    }
}

/// Partition a list of spends and recipients by note types.
/// Method creates single dummy ZEC note if spends and recipients are both empty.
fn partition_by_asset(
    spends: &[SpendInfo],
    recipients: &[RecipientInfo],
    rng: &mut impl RngCore,
) -> HashMap<AssetBase, (Vec<SpendInfo>, Vec<RecipientInfo>)> {
    let mut hm = HashMap::new();

    for s in spends {
        hm.entry(s.note.asset())
            .or_insert((vec![], vec![]))
            .0
            .push(s.clone());
    }

    for r in recipients {
        hm.entry(r.asset)
            .or_insert((vec![], vec![]))
            .1
            .push(r.clone())
    }

    if hm.is_empty() {
        let dummy_spend = SpendInfo::dummy(AssetBase::native(), rng);
        hm.insert(dummy_spend.note.asset(), (vec![dummy_spend], vec![]));
    }

    hm
}

/// Returns a dummy/split notes to extend the spends.
fn pad_spend(spend: Option<&SpendInfo>, asset: AssetBase, mut rng: impl RngCore) -> SpendInfo {
    if asset.is_native().into() {
        // For native asset, extends with dummy notes
        SpendInfo::dummy(asset, &mut rng)
    } else {
        // For ZSA asset, extends with
        // - dummy notes if first spend is empty
        // - split notes otherwise.
        let dummy = SpendInfo::dummy(asset, &mut rng);
        spend.map_or_else(|| dummy, |s| s.create_split_spend(&mut rng))
    }
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

impl<P: fmt::Debug, S: InProgressSignatures> Authorization for InProgress<P, S> {
    type SpendAuth = S::SpendAuth;
}

/// Marker for a bundle without a proof.
///
/// This struct contains the private data needed to create a [`Proof`] for a [`Bundle`].
#[derive(Clone, Debug)]
pub struct Unproven<D: OrchardCircuit> {
    circuits: Vec<Circuit<D>>,
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

impl OutputView for RecipientInfo {
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
        bundle::{Authorized, Bundle, Flags},
        circuit::{OrchardCircuit, ProvingKey},
        keys::{testing::arb_spending_key, FullViewingKey, SpendAuthorizingKey, SpendingKey},
        note::testing::arb_note,
        note_encryption::OrchardDomain,
        tree::{Anchor, MerkleHashOrchard, MerklePath},
        value::{testing::arb_positive_note_value, NoteValue, MAX_NOTE_VALUE},
        Address, Note,
    };

    use super::Builder;

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
        recipient_amounts: Vec<(Address, NoteValue, AssetBase)>,
    }

    impl<R: RngCore + CryptoRng> ArbitraryBundleInputs<R> {
        /// Create a bundle from the set of arbitrary bundle inputs.
        fn into_bundle<V: TryFrom<i64> + Copy + Into<i64>, D: OrchardDomain + OrchardCircuit>(
            mut self,
        ) -> Bundle<Authorized, V, D> {
            let fvk = FullViewingKey::from(&self.sk);
            let flags = Flags::from_parts(true, true, true);
            let mut builder = Builder::new(flags, self.anchor);

            for (note, path) in self.notes.into_iter() {
                builder.add_spend(fvk.clone(), note, path).unwrap();
            }

            for (addr, value, asset) in self.recipient_amounts.into_iter() {
                let scope = fvk.scope_for_address(&addr).unwrap();
                let ovk = fvk.to_ovk(scope);

                builder
                    .add_recipient(Some(ovk.clone()), addr, value, asset, None)
                    .unwrap();
            }

            let pk = ProvingKey::build::<D>();
            builder
                .build(&mut self.rng)
                .unwrap()
                .create_proof(&pk, &mut self.rng)
                .unwrap()
                .prepare(&mut self.rng, [0; 32])
                .sign(&mut self.rng, &SpendAuthorizingKey::from(&self.sk))
                .finalize()
                .unwrap()
        }
    }

    /// FIXME: add a proper doc
    #[derive(Debug)]
    pub struct BuilderArb<D: OrchardDomain> {
        phantom: std::marker::PhantomData<D>,
    }

    impl<D: OrchardDomain + OrchardCircuit> BuilderArb<D> {
        prop_compose! {
            /// Produce a random valid Orchard bundle.
            fn arb_bundle_inputs(sk: SpendingKey)
            (
                n_notes in 1usize..30,
                n_recipients in 1..30,

            )
            (
                // generate note values that we're certain won't exceed MAX_NOTE_VALUE in total
                notes in vec(
                    arb_positive_note_value(MAX_NOTE_VALUE / n_notes as u64).prop_flat_map(arb_note),
                    n_notes
                ),
                recipient_amounts in vec(
                    arb_address().prop_flat_map(move |a| {
                        arb_positive_note_value(MAX_NOTE_VALUE / n_recipients as u64)
                            .prop_map(move |v| {
                                (a,v, AssetBase::native())
                            })
                    }),
                    n_recipients as usize,
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
                    recipient_amounts
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

    use super::Builder;
    use crate::note::AssetBase;
    use crate::{
        bundle::{Authorized, Bundle, Flags},
        circuit::ProvingKey,
        constants::MERKLE_DEPTH_ORCHARD,
        keys::{FullViewingKey, Scope, SpendingKey},
        note_encryption_zsa::OrchardDomainZSA,
        tree::EMPTY_ROOTS,
        value::NoteValue,
    };

    #[test]
    fn shielding_bundle() {
        // FIXME: consider adding test for OrchardDomainVanilla as well
        let pk = ProvingKey::build::<OrchardDomainZSA>();
        let mut rng = OsRng;

        let sk = SpendingKey::random(&mut rng);
        let fvk = FullViewingKey::from(&sk);
        let recipient = fvk.address_at(0u32, Scope::External);

        let mut builder = Builder::new(
            Flags::from_parts(true, true, false),
            EMPTY_ROOTS[MERKLE_DEPTH_ORCHARD].into(),
        );

        builder
            .add_recipient(
                None,
                recipient,
                NoteValue::from_raw(5000),
                AssetBase::native(),
                None,
            )
            .unwrap();
        let balance: i64 = builder.value_balance().unwrap();
        assert_eq!(balance, -5000);

        let bundle: Bundle<Authorized, i64, OrchardDomainZSA> = builder
            .build(&mut rng)
            .unwrap()
            .create_proof(&pk, &mut rng)
            .unwrap()
            .prepare(rng, [0; 32])
            .finalize()
            .unwrap();
        assert_eq!(bundle.value_balance(), &(-5000))
    }
}
