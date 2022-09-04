//! Structs related to issuance bundles and the associated logic.

use memuse::DynamicUsage;
use nonempty::NonEmpty;
use rand::{CryptoRng, RngCore};
use std::fmt;

use crate::keys::IssuerValidatingKey;
use crate::note::note_type::MAX_ASSET_DESCRIPTION_SIZE;
use crate::note::{NoteType, Nullifier};
use crate::value::NoteValue;
use crate::{
    primitives::redpallas::{self, SpendAuth},
    Address, Note,
};

impl IssueAction<Unauthorized> {
    /// Constructs a new `IssueAction`.
    pub fn new(ik: IssuerValidatingKey, asset_desc: String, note: &Note) -> Self {
        IssueAction {
            ik,
            asset_desc,
            notes: NonEmpty {
                head: *note,
                tail: vec![],
            },
            finalize: false,
            authorization: Unauthorized,
        }
    }

    /// inject the `sighash` for signature into the bundle.
    pub fn prepare(self, sighash: [u8; 32]) -> IssueAction<Prepared> {
        return IssueAction {
            ik: self.ik,
            asset_desc: self.asset_desc,
            notes: self.notes,
            finalize: self.finalize,
            authorization: Prepared { sighash },
        };
    }
}

impl<T: IssueAuth> IssueAction<T> {
    /// Constructs an `IssueAction` from its constituent parts.
    pub fn from_parts(
        ik: IssuerValidatingKey,
        asset_desc: String,
        notes: NonEmpty<Note>,
        finalize: bool,
        authorization: T,
    ) -> Self {
        IssueAction {
            ik,
            asset_desc,
            notes,
            finalize,
            authorization,
        }
    }

    /// Returns the issuer verification key for the note being created.
    pub fn ik(&self) -> &IssuerValidatingKey {
        &self.ik
    }

    /// Returns the asset description for the note being created.
    pub fn asset_desc(&self) -> &str {
        &self.asset_desc
    }

    /// Returns the issued notes.
    pub fn notes(&self) -> &NonEmpty<Note> {
        &self.notes
    }

    /// Returns the authorization for this action.
    pub fn authorization(&self) -> &T {
        &self.authorization
    }

    /// Returns whether the asset type was finalized in this action.
    pub fn is_finalized(&self) -> bool {
        self.finalize
    }

    /// Transitions this issue action from one authorization state to another.
    pub fn map<U>(self, step: impl FnOnce(T) -> U) -> IssueAction<U> {
        IssueAction {
            ik: self.ik,
            asset_desc: self.asset_desc,
            notes: self.notes,
            finalize: self.finalize,
            authorization: step(self.authorization),
        }
    }

    /// Transitions this issue action from one authorization state to another.
    pub fn try_map<U, E>(self, step: impl FnOnce(T) -> Result<U, E>) -> Result<IssueAction<U>, E> {
        Ok(IssueAction {
            ik: self.ik,
            asset_desc: self.asset_desc,
            notes: self.notes,
            finalize: self.finalize,
            authorization: step(self.authorization)?,
        })
    }
}

impl DynamicUsage for IssueAction<redpallas::Signature<SpendAuth>> {
    #[inline(always)]
    fn dynamic_usage(&self) -> usize {
        0
    }

    #[inline(always)]
    fn dynamic_usage_bounds(&self) -> (usize, Option<usize>) {
        (0, Some(0))
    }
}

/// Generators for property testing.
#[cfg(any(test, feature = "test-dependencies"))]
#[cfg_attr(docsrs, doc(cfg(feature = "test-dependencies")))]
pub(crate) mod testing {
    use nonempty::NonEmpty;
    use proptest::prelude::*;
    use rand::{rngs::StdRng, SeedableRng};

    use crate::{note::testing::arb_note, value::NoteValue};

    use super::{IssueAction, Signed};

    use crate::keys::{testing::arb_spending_key, IssuerAuthorizingKey, IssuerValidatingKey};

    prop_compose! {
        /// Generate an issue action with a single note and without authorization data.
        pub fn arb_unauthorized_issue_action(output_value: NoteValue)(
            sk in arb_spending_key(),
            vec in prop::collection::vec(any::<u8>(), 0..=255),
            note in arb_note(output_value),
        ) -> IssueAction<()> {
            let isk: IssuerAuthorizingKey = (&sk).into();
            let ik: IssuerValidatingKey = (&isk).into();
            let asset_desc = String::from_utf8(vec).unwrap();

            IssueAction {
                ik,
                asset_desc,
                notes:NonEmpty::new(note), //todo: replace note type
                finalize: false,
                authorization: (),
            }
        }
    }

    prop_compose! {
        /// Generate an issue action with invalid (random) authorization data.
        pub fn arb_issue_action(output_value: NoteValue)(
            sk in arb_spending_key(),
            vec in prop::collection::vec(any::<u8>(), 0..=255),
            note in arb_note(output_value),
            rng_seed in prop::array::uniform32(prop::num::u8::ANY),
            fake_sighash in prop::array::uniform32(prop::num::u8::ANY),
        ) -> IssueAction<Signed> {

            let mut rng = StdRng::from_seed(rng_seed);
            let isk: IssuerAuthorizingKey = (&sk).into();
            let ik: IssuerValidatingKey = (&isk).into();

            IssueAction {
                ik,
                asset_desc: String::from_utf8(vec).unwrap(),
                notes: NonEmpty::new(note), //todo: replace note type
                finalize: false,
                authorization: Signed {
                    signature: isk.sign(&mut rng, &fake_sighash),
                }
            }
        }
    }
}

/// An issue action applied to the global ledger.
///
/// Externally, this creates new zsa notes (adding a commitment to the global ledger).
#[derive(Debug, Clone)]
pub struct IssueAction<A> {
    /// The issuer key for the note being created.
    //ik: redpallas::VerificationKey<SpendAuth>,
    ik: IssuerValidatingKey,
    /// Asset description for verification.
    asset_desc: String,
    /// The newly issued notes.
    notes: NonEmpty<Note>,
    /// Finalize will prevent further issuance of the same asset.
    finalize: bool,
    /// The authorization for this action.
    authorization: A,
}

/// A bundle of actions to be applied to the ledger.
#[derive(Debug)]
pub struct IssueBundle<T: IssueAuth> {
    /// The list of issue actions that make up this bundle.
    actions: Vec<IssueAction<T>>,
}

/// Defines the authorization type of an Issue bundle.
pub trait IssueAuth: fmt::Debug {}

/// Marker for an unauthorized bundle with no proofs or signatures.
#[derive(Debug)]
pub struct Unauthorized;

/// Marker for an unauthorized bundle with injected sighash.
#[derive(Debug)]
pub struct Prepared {
    sighash: [u8; 32],
}

/// Marker for an authorized bundle.
#[derive(Debug)]
pub struct Signed {
    signature: redpallas::Signature<SpendAuth>,
}

impl IssueAuth for Unauthorized {}
impl IssueAuth for Prepared {}
impl IssueAuth for Signed {}

impl IssueBundle<Unauthorized> {
    /// Constructs a new `IssueBundle`.
    pub fn new() -> IssueBundle<Unauthorized> {
        IssueBundle {
            actions: Vec::new(),
        }
    }
}

impl Default for IssueBundle<Unauthorized> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: IssueAuth> IssueBundle<T> {
    /// Return the actions for a given `IssueBundle`.
    pub fn actions(&self) -> &Vec<IssueAction<T>> {
        &self.actions
    }

    /// Find an action by `ik` and `asset_desc` for a given `IssueBundle`.
    pub fn get_action(
        &self,
        ik: IssuerValidatingKey,
        asset_desc: String,
    ) -> Option<&IssueAction<T>> {
        self.actions
            .iter()
            .find(|a| a.ik.eq(&ik) && a.asset_desc.eq(&asset_desc))
    }

    /// Find an action by `note_type` for a given `IssueBundle`.
    pub fn get_action_by_type(&self, note_type: NoteType) -> Option<&IssueAction<T>> {
        let action = self
            .actions
            .iter()
            .find(|a| NoteType::derive(&a.ik, &a.asset_desc).eq(&note_type));
        action
    }
}

impl IssueBundle<Unauthorized> {
    /// Add a new note to the `IssueBundle`.
    ///
    /// Rho will be randomly sampled, similar to dummy note generation.
    ///
    /// # Panics
    ///
    /// Panics if `asset_desc` is empty or longer than 512 bytes.
    pub fn add_recipient(
        &mut self,
        ik: IssuerValidatingKey,
        asset_desc: String,
        recipient: Address,
        value: NoteValue,
        finalize: bool,
        // memo: Option<[u8; 512]>,
        mut rng: impl RngCore,
    ) -> Result<NoteType, Error> {
        assert!(!asset_desc.is_empty() && asset_desc.bytes().len() <= MAX_ASSET_DESCRIPTION_SIZE);

        let note_type = NoteType::derive(&ik, &asset_desc);

        let note = Note::new(
            recipient,
            value,
            note_type,
            Nullifier::dummy(&mut rng),
            &mut rng,
        );

        match self
            .actions
            .iter_mut()
            .find(|issue_action| issue_action.ik.eq(&ik) && issue_action.asset_desc.eq(&asset_desc))
        {
            // Append to an existing IssueAction.
            Some(action) => {
                if action.finalize {
                    return Err(Error::IssueActionAlreadyFinalized);
                };
                action.notes.push(note);
                finalize.then(|| action.finalize = true);
            }
            // Insert a new IssueAction.
            None => {
                let mut action = IssueAction::new(ik.clone(), asset_desc, &note);
                finalize.then(|| action.finalize = true);
                self.actions.push(action);
            }
        }

        Ok(note_type)
    }

    /// Finalizes a given `IssueAction`
    ///
    /// # Panics
    ///
    /// Panics if `asset_desc` is empty or longer than 512 bytes.
    pub fn finalize_action(
        &mut self,
        ik: IssuerValidatingKey,
        asset_desc: String,
    ) -> Result<(), Error> {
        assert!(!asset_desc.is_empty() && asset_desc.bytes().len() <= MAX_ASSET_DESCRIPTION_SIZE);

        match self
            .actions
            .iter_mut()
            .find(|issue_action| issue_action.ik.eq(&ik) && issue_action.asset_desc.eq(&asset_desc))
        {
            Some(issue_action) => {
                issue_action.finalize = true;
            }
            None => {
                return Err(Error::IssueActionNotFound);
            }
        }

        Ok(())
    }

    /// Loads the sighash into this bundle, preparing it for signing.
    ///
    /// This API ensures that all signatures are created over the same sighash.
    /// pub fn prepare<R: RngCore + CryptoRng>(
    //         self,
    //         mut rng: R,
    pub fn prepare(self, sighash: [u8; 32]) -> IssueBundle<Prepared> {
        IssueBundle {
            actions: self
                .actions
                .into_iter()
                .map(|a| a.prepare(sighash))
                .collect(),
        }
    }
}

/// Errors produced during the issuance process
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// Unable to add note to the IssueAction since it has already been finalized.
    IssueActionAlreadyFinalized,
    /// The requested IssueAction not exists in the bundle.
    IssueActionNotFound,
}

#[cfg(test)]
mod tests {
    use super::IssueBundle;
    use crate::issuance::Error::{IssueActionAlreadyFinalized, IssueActionNotFound};
    use crate::keys::{
        FullViewingKey, IssuerAuthorizingKey, IssuerValidatingKey, Scope, SpendingKey,
    };
    use crate::value::NoteValue;
    use rand::rngs::OsRng;

    #[test]
    fn issue_bundle_basic() {
        let mut rng = OsRng;
        let sk = SpendingKey::random(&mut rng);
        let isk: IssuerAuthorizingKey = (&sk).into();
        let ik: IssuerValidatingKey = (&isk).into();

        let fvk = FullViewingKey::from(&sk);
        let recipient = fvk.address_at(0u32, Scope::External);

        let mut bundle = IssueBundle::new();

        let str = String::from("Halo");
        let str2 = String::from("Halo2");

        let note_type = bundle
            .add_recipient(
                ik.clone(),
                str.clone(),
                recipient,
                NoteValue::from_raw(5),
                false,
                rng,
            )
            .unwrap();

        let another_note_type = bundle
            .add_recipient(
                ik.clone(),
                str,
                recipient,
                NoteValue::from_raw(10),
                false,
                rng,
            )
            .unwrap();
        assert_eq!(note_type, another_note_type);

        let third_note_type = bundle
            .add_recipient(
                ik.clone(),
                str2.clone(),
                recipient,
                NoteValue::from_raw(15),
                false,
                rng,
            )
            .unwrap();
        assert_ne!(note_type, third_note_type);

        let actions = bundle.actions();
        assert_eq!(actions.len(), 2);

        let action = bundle.get_action_by_type(note_type).unwrap();
        assert_eq!(action.notes.len(), 2);
        assert_eq!(action.notes.first().value().inner(), 5);
        assert_eq!(action.notes.first().note_type(), note_type);
        assert_eq!(action.notes.first().recipient(), recipient);

        assert_eq!(action.notes.tail().first().unwrap().value().inner(), 10);
        assert_eq!(action.notes.tail().first().unwrap().note_type(), note_type);
        assert_eq!(action.notes.tail().first().unwrap().recipient(), recipient);

        let action2 = bundle.get_action(ik, str2).unwrap();
        assert_eq!(action2.notes.len(), 1);
        assert_eq!(action2.notes().first().value().inner(), 15);
        assert_eq!(action2.notes().first().note_type(), third_note_type);
    }

    #[test]
    fn issue_bundle_finalize_asset() {
        let mut rng = OsRng;
        let sk = SpendingKey::random(&mut rng);
        let isk: IssuerAuthorizingKey = (&sk).into();
        let ik: IssuerValidatingKey = (&isk).into();

        let fvk = FullViewingKey::from(&sk);
        let recipient = fvk.address_at(0u32, Scope::External);

        let mut bundle = IssueBundle::new();

        bundle
            .add_recipient(
                ik.clone(),
                String::from("Precious NFT"),
                recipient,
                NoteValue::from_raw(u64::MIN),
                false,
                rng,
            )
            .expect("Should properly add recipient");

        bundle
            .finalize_action(ik.clone(), String::from("Precious NFT"))
            .expect("Should finalize properly");

        assert_eq!(
            bundle
                .add_recipient(
                    ik.clone(),
                    String::from("Precious NFT"),
                    recipient,
                    NoteValue::from_raw(u64::MIN),
                    false,
                    rng,
                )
                .unwrap_err(),
            IssueActionAlreadyFinalized
        );

        assert_eq!(
            bundle
                .finalize_action(ik.clone(), String::from("Another precious NFT"))
                .unwrap_err(),
            IssueActionNotFound
        );

        bundle
            .add_recipient(
                ik.clone(),
                String::from("Another precious NFT"),
                recipient,
                NoteValue::from_raw(u64::MIN),
                true,
                rng,
            )
            .expect("should add and finalize");

        assert_eq!(
            bundle
                .add_recipient(
                    ik,
                    String::from("Another precious NFT"),
                    recipient,
                    NoteValue::from_raw(u64::MIN),
                    true,
                    rng,
                )
                .unwrap_err(),
            IssueActionAlreadyFinalized
        );
    }

    #[test]
    fn issue_bundle_prepare() {
        let mut rng = OsRng;
        let sk = SpendingKey::random(&mut rng);
        let isk: IssuerAuthorizingKey = (&sk).into();
        let ik: IssuerValidatingKey = (&isk).into();

        let fvk = FullViewingKey::from(&sk);
        let recipient = fvk.address_at(0u32, Scope::External);

        let mut bundle = IssueBundle::new();

        bundle
            .add_recipient(
                ik.clone(),
                String::from("Frost"),
                recipient,
                NoteValue::from_raw(5),
                false,
                rng,
            )
            .unwrap();

        let fake_sighash = [1; 32];
        let prepared = bundle.prepare(fake_sighash);

        let action = prepared
            .get_action(ik.clone(), String::from("Frost"))
            .unwrap();
        let auth = action.authorization();
        assert_eq!(auth.sighash, fake_sighash);
    }
}

// mod tests {
//     use rand::rngs::OsRng;
//
//     use super::Builder;
//     // use crate::keys::{IssuerAuthorizingKey, IssuerValidatingKey};
//     use crate::note::NoteType;
//     use crate::{
//         bundle::{Authorized, Bundle, Flags},
//         circuit::ProvingKey,
//         constants::MERKLE_DEPTH_ORCHARD,
//         keys::{FullViewingKey, Scope, SpendingKey},
//         tree::EMPTY_ROOTS,
//         value::NoteValue,
//     };
//     use crate::builder::Builder;
//
//     #[test]
//     fn shielding_bundle() {
//         let pk = ProvingKey::build();
//         let mut rng = OsRng;
//
//         let sk = SpendingKey::random(&mut rng);
//         let fvk = FullViewingKey::from(&sk);
//         let recipient = fvk.address_at(0u32, Scope::External);
//
//         let mut builder = Builder::new(
//             Flags::from_parts(true, true),
//             EMPTY_ROOTS[MERKLE_DEPTH_ORCHARD].into(),
//         );
//
//         builder
//             .add_recipient(
//                 None,
//                 recipient,
//                 NoteValue::from_raw(5000),
//                 NoteType::native(),
//                 None,
//             )
//             .unwrap();
//
//
//         let bundle: Bundle<Authorized, i64> = builder
//             .build(&mut rng)
//             .unwrap()
//             .create_proof(&pk, &mut rng)
//             .unwrap()
//             .prepare(&mut rng, [0; 32])
//             .sign()
//             .finalize()
//             .unwrap();
//         assert_eq!(bundle.value_balance(), &(-5000));
//
//         verify_bundle(&bundle, &vk)
//     }
// }
