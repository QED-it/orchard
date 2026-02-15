# PR #471 - Changelog-Related Comments

Extracted from https://github.com/zcash/orchard/pull/471

## Review-Level Comments

### Review by **str4d** (CHANGES_REQUESTED) - 2025-11-21T18:42:25Z
**Link:** https://github.com/zcash/orchard/pull/471#pullrequestreview-3412925415

Flushing comments from my in-progress review of a02fdf1f873d58167887abe23a8a7e0b9c1a0a36.

The changelog-related comments are non-blocking for now; I'm making them to help track what needs to go in as of the reviewed commit, but given that it might significantly change prior to this PR being merged, we don't need to make the changes until nearer the end of the review process (but they *must* be made before the `orchard` crate release containing this PR).

### Review by **str4d** (CHANGES_REQUESTED) - 2025-12-09T15:02:28Z
**Link:** https://github.com/zcash/orchard/pull/471#pullrequestreview-3527051205

Flushing the remainder of my review of a02fdf1f873d58167887abe23a8a7e0b9c1a0a36 (which included review of circuit changes with @daira). Caveats:
- I have not reviewed ZSA-specific changes in this review, and have noted which files this affects.
- I have not yet reviewed the non-ZSA changes to the note commitment circuit logic.

---

## Inline Comments Mentioning Changelog

### Comment 1

### str4d on `src/circuit.rs` (line 269)
**Date:** 2025-11-03T21:59:42Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2487968253
```diff
         config.advices[6],
-                    0,
-                )?;
-
-                region.assign_advice_from_instance(
-                    || "enable outputs",
-                    config.primary,
-                    ENABLE_OUTPUT,
-                    config.advices[7],
-                    0,
-                )?;
-
-                config.q_orchard.enable(&mut region, 0)
-            },
-        )?;
-
-        Ok(())
     }
 }
 
 /// The verifying key for the Orchard Action circuit.
```

This documentation needs to be updated reflect the fact that in the current type system, this could be a verifying key for either the original Orchard Action circuit, or the OrchardZSA circuit.

The changelog also needs a "Changed" entry saying that the semantics of `VerifyingKey` have changed in this way.

We may also want to consider whether `VerifyingKey` should instead have the generic parameter `<C: OrchardCircuit>`, but IDK right now what the wider implications of this are.

> **PaulLaux** replied at 2026-01-29T19:50:10Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2743250960
> 
> updated comment in https://github.com/QED-it/orchard/pull/216/commits/bda4fe0665eb811480dd551499f1807b0d0f3f3a

---

### Comment 2

### str4d on `src/circuit.rs` (line 291)
**Date:** 2025-11-03T21:59:56Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2487968899
```diff
@@ -776,17 +286,17 @@ impl VerifyingKey {
 }
 
 /// The proving key for the Orchard Action circuit.
```

This documentation needs to be updated reflect the fact that in the current type system, this could be a proving key for either the original Orchard Action circuit, or the OrchardZSA circuit.

The changelog also needs a "Changed" entry saying that the semantics of `ProvingKey` have changed in this way.

We may also want to consider whether`ProvingKey` should instead have the generic parameter `<C: OrchardCircuit>`, but IDK right now what the wider implications of this are.

> **PaulLaux** replied at 2026-01-29T19:50:19Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2743251550
> 
> updated comment in https://github.com/QED-it/orchard/pull/216/commits/bda4fe0665eb811480dd551499f1807b0d0f3f3a

---

### Comment 3

### str4d on `src/circuit.rs` (line 281)
**Date:** 2025-11-03T22:01:41Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2487972759
```diff
  config.q_orchard.enable(&mut region, 0)
-            },
-        )?;
-
-        Ok(())
     }
 }
 
 /// The verifying key for the Orchard Action circuit.
-#[derive(Debug)]
+#[derive(Debug, Clone)]
 pub struct VerifyingKey {
     pub(crate) params: halo2_proofs::poly::commitment::Params<vesta::Affine>,
     pub(crate) vk: plonk::VerifyingKey<vesta::Affine>,
 }
 
 impl VerifyingKey {
     /// Builds the verifying key.
-    pub fn build() -> Self {
+    pub fn build<C: OrchardCircuit>() -> Self {
```

Document this change to the public API in the changelog.

---

### Comment 4

### str4d on `src/circuit.rs` (line 346)
**Date:** 2025-11-03T22:04:37Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2487977836
```diff
@@ -821,22 +332,22 @@ impl Instance {
         nf_old: Nullifier,
         rk: VerificationKey<SpendAuth>,
         cmx: ExtractedNoteCommitment,
-        enable_spend: bool,
-        enable_output: bool,
+        flags: Flags,
```

Document this change to the public API in the changelog.

---

### Comment 5

### str4d on `src/circuit.rs` (line 303)
**Date:** 2025-11-04T00:11:57Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2488216689
```diff
@@ -776,17 +286,17 @@ impl VerifyingKey {
 }
 
 /// The proving key for the Orchard Action circuit.
-#[derive(Debug)]
+#[derive(Debug, Clone)]
 pub struct ProvingKey {
     params: halo2_proofs::poly::commitment::Params<vesta::Affine>,
     pk: plonk::ProvingKey<vesta::Affine>,
 }
 
 impl ProvingKey {
     /// Builds the proving key.
-    pub fn build() -> Self {
+    pub fn build<C: OrchardCircuit>() -> Self {
```

Document this change to the public API in the changelog.

---

### Comment 6

### str4d on `src/circuit.rs` (line 392)
**Date:** 2025-11-04T00:12:07Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2488217193
```diff
-854,16 +365,17 @@ impl Instance {
         instance[CMX] = self.cmx.inner();
         instance[ENABLE_SPEND] = vesta::Scalar::from(u64::from(self.enable_spend));
         instance[ENABLE_OUTPUT] = vesta::Scalar::from(u64::from(self.enable_output));
+        instance[ENABLE_ZSA] = vesta::Scalar::from(u64::from(self.enable_zsa));
 
         [instance]
     }
 }
 
 impl Proof {
     /// Creates a proof for the given circuits and instances.
-    pub fn create(
+    pub fn create<C: OrchardCircuit>(
```

Document this change to the public API in the changelog.

---

### Comment 7

### str4d on `Cargo.toml` (line 12)
**Date:** 2025-11-19T14:45:03Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2542333126
```diff
@@ -9,7 +9,7 @@ authors = [
     "Kris Nuttycombe <kris@electriccoin.co>",
 ]
 edition = "2021"
-rust-version = "1.70"
+rust-version = "1.71"
```

What 1.71 functionality made this MSRV bump necessary?

If it is indeed necessary, document the MSRV bump in the changelog.

> **PaulLaux** replied at 2026-01-29T20:11:33Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2743335223
> 
> reverted bump back to 1.70 in https://github.com/QED-it/orchard/pull/216/commits/b5518f1b2688889b7eab8a92a773e1655ba5f95f

---

### Comment 8

### str4d on `src/lib.rs` (line 37)
**Date:** 2025-11-19T14:53:08Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2542371427
```diff
@@ -32,9 +32,13 @@ pub mod bundle;
 #[cfg(feature = "circuit")]
 pub mod circuit;
 mod constants;
+pub mod issuance;
+pub mod issuance_auth;
+pub mod issuance_sighash_versioning;
```

- These should not be three separate modules. Move `crate::issuance_auth` to `crate::issuance::auth` (and similarly for the other).
- Place the `issuance` module behind the same feature flag that is added to gate the `secp256k1` dependency (maybe `zsa-issuance`).
- Document the addition of the `issuance` module in the changelog.

> **PaulLaux** replied at 2026-02-02T18:51:48Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2755773933
> 
> issuance-related modules were moved under `crate::issuance::*` in https://github.com/QED-it/orchard/pull/216/commits/b5518f1b2688889b7eab8a92a773e1655ba5f95f and `#[cfg(feature = "zsa-issuance")]` added in https://github.com/QED-it/orchard/pull/216/commits/f85cc4027f172c35007ff3774184892af3eba885

---

### Comment 9

### str4d on `src/lib.rs` (line 41)
**Date:** 2025-11-19T14:57:47Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2542392826
```diff
@@ -32,9 +32,13 @@ pub mod bundle;
 #[cfg(feature = "circuit")]
 pub mod circuit;
 mod constants;
+pub mod issuance;
+pub mod issuance_auth;
+pub mod issuance_sighash_versioning;
 pub mod keys;
 pub mod note;
-pub mod note_encryption;
+pub mod orchard_flavor;
+pub mod orchard_sighash_versioning;
```

Remove the redundant module prefixes; these are already in the `orchard` crate namespace, and `orchard::orchard_signash_versioning::OrchardSighashVersion` is unnecessary duplicative.
```suggestion
pub mod flavor;
pub mod sighash_versioning;
```
(or `protocol_flavor` if `orchard::flavor` is not sufficiently clear).

Also, document the addition of these modules in the changelog.

> **PaulLaux** replied at 2026-02-02T18:58:48Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2755797303
> 
> done in https://github.com/QED-it/orchard/pull/216/commits/b5518f1b2688889b7eab8a92a773e1655ba5f95f

---

### Comment 10

### str4d on `src/keys.rs` (line 33)
**Date:** 2025-11-19T15:49:54Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2542599948
```diff
@@ -28,7 +28,9 @@ use crate::{
     zip32::{self, ExtendedSpendingKey},
 };
 
-pub use ::zip32::{DiversifierIndex, Scope};
+// Preserve '::' which specifies the EXTERNAL 'zip32' crate
+#[rustfmt::skip]
+pub use ::zip32::{AccountId, ChildIndex, DiversifierIndex, Scope, hardened_only};
```

- Remove `ChildIndex` from the re-export; it is unused in this module's public API.
- Remove `hardened_only` from the re-export; it will be unused in this module's public API after my other comment is addressed.
- Document the addition of `AccountId` in the changelog.

> **PaulLaux** replied at 2026-01-29T20:53:57Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2743511180
> 
> done in https://github.com/QED-it/orchard/pull/216/commits/b5518f1b2688889b7eab8a92a773e1655ba5f95f

---

### Comment 11

### str4d on `src/value.rs` (line 116)
**Date:** 2025-11-19T16:28:04Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2542747848
```diff
@@ -107,11 +110,13 @@ impl NoteValue {
         NoteValue(value)
     }
 
-    pub(crate) fn from_bytes(bytes: [u8; 8]) -> Self {
+    /// Creates a note value from a byte array.
+    pub fn from_bytes(bytes: [u8; 8]) -> Self {
         NoteValue(u64::from_le_bytes(bytes))
     }
 
-    pub(crate) fn to_bytes(self) -> [u8; 8] {
+    /// Converts the note value to a byte array.
+    pub fn to_bytes(self) -> [u8; 8] {
```

Where are you needing to use these outside the `orchard` crate?

If a canonical byte encoding of `NoteValue` needs to be exposed, document these additions in the changelog.

> **PaulLaux** replied at 2026-02-02T19:16:43Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2755848784
> 
> As defined in ZIP 230 for TXv6, we need to serialize and deserialize the issued notes as part of the issuance bundle (used in librustzcash and zebra).

---

### Comment 12

### str4d on `src/value.rs` (line 376)
**Date:** 2025-11-19T16:53:27Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2542839935
```diff
@@ -344,9 +394,8 @@ impl ValueCommitment {
     ///
     /// [concretehomomorphiccommit]: https://zips.z.cash/protocol/nu5.pdf#concretehomomorphiccommit
     #[allow(non_snake_case)]
-    pub fn derive(value: ValueSum, rcv: ValueCommitTrapdoor) -> Self {
+    pub fn derive(value: ValueSum, rcv: ValueCommitTrapdoor, asset: AssetBase) -> Self {
```

Document this change to the public API in the changelog.

---

### Comment 13

### str4d on `src/note.rs` (line 203)
**Date:** 2025-11-19T18:39:32Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2543154752
```diff
@@ -169,14 +200,17 @@ impl Note {
     pub fn from_parts(
         recipient: Address,
         value: NoteValue,
+        asset: AssetBase,
```

Document this change to the public API in the changelog.

---

### Comment 14

### str4d on `src/note.rs` (line 337)
**Date:** 2025-11-19T20:26:22Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2543456692
```diff
@@ -233,11 +276,25 @@ impl Note {
         self.value
     }
 
+    /// Returns the asset of this note.
+    pub fn asset(&self) -> AssetBase {
```

Document this addition in the changelog.

---

### Comment 15

### str4d on `src/note.rs` (line 404)
**Date:** 2025-11-19T21:26:04Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2543616642
```diff
ISSUE_NOTE_RHO_PERSONALIZATION)
+            .to_state()
+            .update(&nullifier.to_bytes())
+            .update(&[0x84])
+            .update(index_action.to_le_bytes().as_ref())
+            .update(index_note.to_le_bytes().as_ref())
+            .finalize()
+            .as_bytes()
+            .try_into()
+            .unwrap(),
+    ))
 }
 
 /// An encrypted note.
 #[derive(Clone)]
-pub struct TransmittedNoteCiphertext {
+pub struct TransmittedNoteCiphertext<P: OrchardPrimitives> {
```

Document the changes to this struct in the changelog.

---

### Comment 16

### str4d on `src/action.rs` (line 16)
**Date:** 2025-11-21T15:24:52Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2550122674
```diff
@@ -11,30 +13,30 @@ use crate::{
 /// This both creates a note (adding a commitment to the global ledger), and consumes
 /// some note created prior to this action (adding a nullifier to the global ledger).
 #[derive(Debug, Clone)]
-pub struct Action<A> {
+pub struct Action<A, P: OrchardPrimitives> {
```

Document the change to this struct in the changelog.

---

### Comment 17

### str4d on `src/primitives.rs` (line 21)
**Date:** 2025-11-21T15:54:42Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2550223729
```diff
es.
+//!
+//! It includes functionality for handling both the standard "Vanilla" variation and the ZSA
+//! variation, with different implementations for each. The different implementations are
+//! organized into separate submodules.
 
+mod compact_action;
+mod orchard_domain;
+mod orchard_primitives;
+mod orchard_primitives_vanilla;
+mod orchard_primitives_zsa;
 pub mod redpallas;
+mod zcash_note_encryption_domain;
+
+pub use {
+    compact_action::CompactAction, orchard_domain::OrchardDomain,
```

It feels very wrong for a `CompactAction` to be considered an "Orchard primitive", when it is actually derived from a more fundamental value (`Action`). This is a misunderstanding of the `primitives` module, and gets to a complaint I raised with you months ago that I didn't think the deletion of the `note_encryption` module was the right way to approach the refactor.

Non-blocking because it doesn't affect the correctness of the PR (and the history of this PR is more valuable to me than ease of introspecting the history of the note encryption logic), but be warned that I will likely go through after this PR is merged (and maybe after the corresponding `librustzcash` PR is merged) and undo a bunch of your refactoring (with the effect of having logically reduced the diff of this PR, even if it doesn't reduce the actual diff that gets merged).

In the meantime:
- Document these additions to the `primitives` module in the changelog.

> **PaulLaux** replied at 2026-02-04T09:42:33Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2763098203
> 
> Your concern is understandable, but each of the other restructuring options has its own pros and cons. We chose the approach that we believe is clearest for readability and easy to modify in the future, and we’ll adopt any changes that you or other core developers introduce after the merge.

---

### Comment 18

### str4d on `src/bundle.rs` (line 159)
**Date:** 2025-12-03T15:20:19Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2585543059
```diff
@@ -117,6 +149,14 @@ impl Flags {
         self.outputs_enabled
     }
 
+    /// Flag denoting whether ZSA transaction is enabled.
+    ///
+    /// If `false`,  all notes within [`Action`]s in the transaction's [`Bundle`] are
+    /// guaranteed to be notes with native asset.
+    pub fn zsa_enabled(&self) -> bool {
```

Document this addition in the changelog.

---

### Comment 19

### str4d on `src/bundle.rs` (line 201)
**Date:** 2025-12-03T15:23:39Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2585555720
```diff
@@ -154,31 +198,38 @@ impl Flags {
 /// Defines the authorization type of an Orchard bundle.
 pub trait Authorization: fmt::Debug {
     /// The authorization type of an Orchard action.
-    type SpendAuth: fmt::Debug;
+    type SpendAuth: fmt::Debug + Clone;
```

What requires this to be `Clone` generically?

If this is actually necessary, document this change in the changelog.

> **PaulLaux** replied at 2026-02-04T20:45:54Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2765910811
> 
> removed `clone` in https://github.com/QED-it/orchard/pull/216/commits/dc861afa2d8257687f5a3082d107a7afe817b063
> 
> We used it in librustzcash but found a way to avoid (similar to the current Orchard/spendAuth approach)

---

### Comment 20

### str4d on `src/bundle.rs` (line 206)
**Date:** 2025-12-03T15:24:27Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2585558588
```diff
@@ -154,31 +198,38 @@ impl Flags {
 /// Defines the authorization type of an Orchard bundle.
 pub trait Authorization: fmt::Debug {
     /// The authorization type of an Orchard action.
-    type SpendAuth: fmt::Debug;
+    type SpendAuth: fmt::Debug + Clone;
 }
 
 /// A bundle of actions to be applied to the ledger.
 #[derive(Clone)]
-pub struct Bundle<T: Authorization, V> {
+pub struct Bundle<A: Authorization, V, P: OrchardPrimitives> {
```

Document the change to this struct in the changelog.

---

### Comment 21

### str4d on `src/bundle.rs` (line 252)
**Date:** 2025-12-03T15:39:15Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2585613936
```diff
@@ -194,26 +245,30 @@ impl<T: Authorization, V: fmt::Debug> fmt::Debug for Bundle<T, V> {
     }
 }
 
-impl<T: Authorization, V> Bundle<T, V> {
+impl<A: Authorization, V, P: OrchardPrimitives> Bundle<A, V, P> {
     /// Constructs a `Bundle` from its constituent parts.
     pub fn from_parts(
-        actions: NonEmpty<Action<T::SpendAuth>>,
+        actions: NonEmpty<Action<A::SpendAuth, P>>,
         flags: Flags,
         value_balance: V,
+        burn: Vec<(AssetBase, NoteValue)>,
```

Document this change in the changelog.

---

### Comment 22

### str4d on `src/bundle.rs` (line 284)
**Date:** 2025-12-03T15:39:32Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2585615091
```diff
@@ -229,15 +284,25 @@ impl<T: Authorization, V> Bundle<T, V> {
         &self.value_balance
     }
 
+    /// Returns assets intended for burning
+    pub fn burn(&self) -> &Vec<(AssetBase, NoteValue)> {
```

Document this addition in the changelog.

---

### Comment 23

### str4d on `src/bundle.rs` (line 534)
**Date:** 2025-12-03T15:48:34Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2585656869
```diff
redpallas::Signature<Binding>,
+    binding_signature: VerBindingSig,
 }
 
 impl Authorization for Authorized {
-    type SpendAuth = redpallas::Signature<SpendAuth>;
+    type SpendAuth = VerSpendAuthSig;
 }
 
 impl Authorized {
     /// Constructs the authorizing data for a bundle of actions from its constituent parts.
-    pub fn from_parts(proof: Proof, binding_signature: redpallas::Signature<Binding>) -> Self {
+    pub fn from_parts(proof: Proof, binding_signature: VerBindingSig) -> Self {
```

Document this change in the changelog.

---

### Comment 24

### str4d on `src/bundle.rs` (line 547)
**Date:** 2025-12-03T15:48:42Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2585657409
```diff
@@ -453,18 +543,24 @@ impl Authorized {
         &self.proof
     }
 
-    /// Return the binding signature.
-    pub fn binding_signature(&self) -> &redpallas::Signature<Binding> {
+    /// Return the versioned binding signature.
+    pub fn binding_signature(&self) -> &VerBindingSig {
```

Document this change in the changelog.

---

### Comment 25

### str4d on `src/builder.rs` (line 70)
**Date:** 2025-12-09T12:11:16Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2602380774
```diff
FAULT: BundleType = BundleType::Transactional {
-        flags: Flags::ENABLED,
+    /// The default bundle type has all flags enabled, ZSA disabled, and does not require a bundle
+    /// to be produced.
+    pub const DEFAULT_VANILLA: BundleType = BundleType::Transactional {
+        flags: Flags::ENABLED_WITHOUT_ZSA,
+        bundle_required: false,
+    };
+
+    /// The default bundle with all flags enabled, including ZSA.
+    pub const DEFAULT_ZSA: BundleType = BundleType::Transactional {
```

Document this addition in the changelog.

---

### Comment 26

### str4d on `src/builder.rs` (line 162)
**Date:** 2025-12-09T12:12:47Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2602385534
```diff
@@ -139,6 +152,14 @@ pub enum BuildError {
     DuplicateSignature,
     /// The bundle being constructed violated the construction rules for the requested bundle type.
     BundleTypeNotSatisfiable,
+    /// Native asset cannot be burned
+    BurnNative,
+    /// The value to be burned cannot be zero
+    BurnZero,
+    /// The asset to be burned is duplicated.
+    BurnDuplicateAsset,
+    /// There is no available split note for this asset.
+    NoSplitNoteAvailable,
```

- Instead of having three separate `Burn*` variants that directly mirror `BurnError` variants, have a single `Burn(BurnError)` variant.
- Document the resulting addition in the changelog. (Previously they would have been changes, but after #473 this error enum is non-exhaustive.)

> **PaulLaux** replied at 2026-02-05T19:28:09Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2770791218
> 
> Consolidated three error variants into one in https://github.com/QED-it/orchard/pull/216/commits/f0cf7ea231d340809bf6530bd5c900bf8b86a876#diff-e4f794ca308aa712cbad31feb714df7cada1bbe453a30e232e45891571430263

---

### Comment 27

### str4d on `src/builder.rs` (line 239)
**Date:** 2025-12-09T12:15:11Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2602394332
```diff
@@ -218,41 +243,49 @@ impl fmt::Display for OutputError {
 impl std::error::Error for OutputError {}
 
 /// Information about a specific note to be spent in an [`Action`].
-#[derive(Debug)]
+#[derive(Debug, Clone)]
```

Document this impl addition in the changelog.

---

### Comment 28

### str4d on `src/builder.rs` (line 271)
**Date:** 2025-12-09T12:15:40Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2602395934
```diff
 of the note.
+    /// Creates a `SpendInfo` from note, full viewing key owning the note, merkle path witness of
+    /// the note, and split flag.
     ///
     /// Returns `None` if the `fvk` does not own the `note`.
     ///
     /// [`Builder::add_spend`]: Builder::add_spend
-    pub fn new(fvk: FullViewingKey, note: Note, merkle_path: MerklePath) -> Option<Self> {
+    pub fn new(
+        fvk: FullViewingKey,
+        note: Note,
+        merkle_path: MerklePath,
+        split_flag: bool,
```

- Do we need this change in the public API constructor, or could we instead have a `SpendInfo::split_note` constructor (like we do `SpendInfo::dummy`) or use `SpendInfo::create_split_spend`?
- If it is needed, document this change in the changelog.

> **PaulLaux** replied at 2026-02-05T19:46:31Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2770855043
> 
> Reverted change to public API in https://github.com/QED-it/orchard/pull/216/commits/5f8eb1212d8a7fd716b1ea28213fd9d7f07fde49
> 
> The API change was redundant. External callers don't need to worry about split notes since it is handled by the builder.

---

### Comment 29

### str4d on `src/builder.rs` (line 366)
**Date:** 2025-12-09T12:19:05Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2602406286
```diff
@@ -320,11 +375,12 @@ impl SpendInfo {
 }
 
 /// Information about a specific output to receive funds in an [`Action`].
-#[derive(Debug)]
+#[derive(Debug, Clone)]
```

Document this impl addition in the changelog.

---

### Comment 30

### str4d on `src/builder.rs` (line 381)
**Date:** 2025-12-09T12:19:37Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2602407984
```diff
@@ -334,43 +390,45 @@ impl OutputInfo {
         ovk: Option<OutgoingViewingKey>,
         recipient: Address,
         value: NoteValue,
+        asset: AssetBase,
```

Document this change in the changelog.

---

### Comment 31

### str4d on `src/builder.rs` (line 396)
**Date:** 2025-12-09T12:19:46Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2602408431
```diff
 AssetBase,
         memo: [u8; 512],
     ) -> Self {
         Self {
             ovk,
             recipient,
             value,
+            asset,
             memo,
         }
     }
 
     /// Defined in [Zcash Protocol Spec § 4.8.3: Dummy Notes (Orchard)][orcharddummynotes].
     ///
     /// [orcharddummynotes]: https://zips.z.cash/protocol/nu5.pdf#orcharddummynotes
-    pub fn dummy(rng: &mut impl RngCore) -> Self {
+    pub fn dummy(rng: &mut impl RngCore, asset: AssetBase) -> Self {
```

Document this change in the changelog.

---

### Comment 32

### str4d on `src/builder.rs` (line 603)
**Date:** 2025-12-09T12:23:54Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2602420507
```diff
@@ -528,12 +613,18 @@ impl BundleMetadata {
     }
 }
 
-/// A builder that constructs a [`Bundle`] from a set of notes to be spent, and outputs
-/// to receive funds.
+/// A tuple containing an in-progress bundle with no proofs or signatures, and its associated metadata.
+#[cfg(feature = "circuit")]
+pub type UnauthorizedBundleWithMetadata<V, FL> = (UnauthorizedBundle<V, FL>, BundleMetadata);
```

Document this addition in the changelog.

---

### Comment 33

### str4d on `src/builder.rs` (line 671)
**Date:** 2025-12-09T12:25:05Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2602424474
```diff
@@ -590,6 +682,7 @@ impl Builder {
         ovk: Option<OutgoingViewingKey>,
         recipient: Address,
         value: NoteValue,
+        asset: AssetBase,
```

Document this change in the changelog.

---

### Comment 34

### str4d on `src/builder.rs` (line 686)
**Date:** 2025-12-09T12:25:29Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2602425870
```diff
@@ -598,11 +691,32 @@ impl Builder {
         }
 
         self.outputs
-            .push(OutputInfo::new(ovk, recipient, value, memo));
+            .push(OutputInfo::new(ovk, recipient, value, asset, memo));
 
         Ok(())
     }
 
+    /// Add an instruction to burn a given amount of a specific asset.
+    pub fn add_burn(&mut self, asset: AssetBase, value: NoteValue) -> Result<(), BuildError> {
```

Document this addition in the changelog.

---

### Comment 35

### str4d on `src/builder.rs` (line 877)
**Date:** 2025-12-09T12:40:32Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2602477131
```diff
 have no proof or signatures; these can be applied with
 /// [`Bundle::create_proof`] and [`Bundle::apply_signatures`] respectively.
 #[cfg(feature = "circuit")]
-pub fn bundle<V: TryFrom<i64>>(
+pub fn bundle<V: TryFrom<i64>, FL: OrchardFlavor>(
     rng: impl RngCore,
     anchor: Anchor,
     bundle_type: BundleType,
     spends: Vec<SpendInfo>,
     outputs: Vec<OutputInfo>,
-) -> Result<Option<(UnauthorizedBundle<V>, BundleMetadata)>, BuildError> {
+    burn: BTreeMap<AssetBase, NoteValue>,
```

Document this change in the changelog.

---

### Comment 36

### str4d on `src/builder.rs` (line 1087)
**Date:** 2025-12-09T13:01:40Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2602558531
```diff
t::<Result<Vec<(AssetBase, NoteValue)>, BuildError>>()?;
+
+    finisher(
+        pre_actions,
+        flags,
+        native_value_balance,
+        burn_vec,
+        bundle_meta,
+        rng,
+    )
 }
 
 /// Marker trait representing bundle signatures in the process of being created.
 pub trait InProgressSignatures: fmt::Debug {
     /// The authorization type of an Orchard action in the process of being authorized.
-    type SpendAuth: fmt::Debug;
+    type SpendAuth: fmt::Debug + Clone;
```

What makes this change necessary? If it is, document this change in the changelog.

> **PaulLaux** replied at 2026-02-05T20:18:24Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2770979380
> 
> removed `Clone` in https://github.com/QED-it/orchard/pull/216/commits/dc861afa2d8257687f5a3082d107a7afe817b063#diff-e4f794ca308aa712cbad31feb714df7cada1bbe453a30e232e45891571430263 and adjusted the librustzcash approach

---

### Comment 37

### str4d on `src/builder.rs` (line 1208)
**Date:** 2025-12-09T13:02:52Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2602563105
```diff
@@ -949,54 +1204,63 @@ impl InProgressSignatures for PartiallyAuthorized {
 
 /// A heisen[`Signature`] for a particular [`Action`].
 ///
-/// [`Signature`]: redpallas::Signature
-#[derive(Debug)]
+/// [`Signature`]: VerSpendAuthSig
+#[derive(Debug, Clone)]
```

Document this impl addition in the changelog.

---

### Comment 38

### str4d on `src/builder.rs` (line 1213)
**Date:** 2025-12-09T13:02:59Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2602563639
```diff
artiallyAuthorized {
 
 /// A heisen[`Signature`] for a particular [`Action`].
 ///
-/// [`Signature`]: redpallas::Signature
-#[derive(Debug)]
+/// [`Signature`]: VerSpendAuthSig
+#[derive(Debug, Clone)]
 pub enum MaybeSigned {
     /// The information needed to sign this [`Action`].
     SigningMetadata(SigningParts),
-    /// The signature for this [`Action`].
-    Signature(redpallas::Signature<SpendAuth>),
+    /// The versioned signature for this [`Action`].
+    Signature(VerSpendAuthSig),
```

Document this change in the changelog.

---

### Comment 39

### str4d on `src/builder.rs` (line 1217)
**Date:** 2025-12-09T13:03:17Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2602564851
```diff
ndAuthSig
+#[derive(Debug, Clone)]
 pub enum MaybeSigned {
     /// The information needed to sign this [`Action`].
     SigningMetadata(SigningParts),
-    /// The signature for this [`Action`].
-    Signature(redpallas::Signature<SpendAuth>),
+    /// The versioned signature for this [`Action`].
+    Signature(VerSpendAuthSig),
 }
 
 impl MaybeSigned {
-    fn finalize(self) -> Result<redpallas::Signature<SpendAuth>, BuildError> {
+    fn finalize(self) -> Result<VerSpendAuthSig, BuildError> {
```

Document this change in the changelog.

---

### Comment 40

### str4d on `src/builder.rs` (line 1312)
**Date:** 2025-12-09T14:36:02Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2602943087
```diff
ut for which it is valid. An error
+    /// will be returned if the versioned signature is not valid for any inputs, or if it is valid
     /// for more than one input.
     ///
-    /// [`Signature`]: redpallas::Signature
-    pub fn append_signatures(
-        self,
-        signatures: &[redpallas::Signature<SpendAuth>],
-    ) -> Result<Self, BuildError> {
+    /// [`Signature`]: VerSpendAuthSig
+    pub fn append_signatures(self, signatures: &[VerSpendAuthSig]) -> Result<Self, BuildError> {
```

Document this change in the changelog.

---


**Total changelog-related comments: 41**