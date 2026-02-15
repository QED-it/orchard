# PR #471: Add OrchardZSA
**URL:** https://github.com/zcash/orchard/pull/471
**Author:** ConstanceBeguier
**Created:** 2025-09-09T07:44:26Z
**State:** open

## Description
This PR implements [ZIP 226](https://zips.z.cash/zip-0226) (Transfer and Burn of Zcash Shielded Assets), [ZIP 227](https://zips.z.cash/zip-0227) (Issuance of Zcash Shielded Assets), and [ZIP 246](https://zips.z.cash/zip-0246) (Digests for the Version 6 Transaction Format).

Main changes:
- Support issuance of ZSAs.
- Support transfer of ZSAs (with circuit changes).
- Support public burning of ZSAs.
- Introduce versioned sighash to accommodate protocol evolution.
- Update test vectors.
- Maintain backward compatibility for vanilla Orchard bundles.

---

## Reviews

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

## Inline Review Comments

### str4d on `.circleci/config.yml` (line 1)
**Date:** 2025-11-03T21:04:36Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2487849124

We do not use CircleCI, and this workflow references various private qedit Slack workflows. Either remove this file from your `zsa1` integration branch before the PR is merged, or open a dedicated PR for merging your ongoing work that removes it (if you want to keep this CI config around for your own testing).

> **PaulLaux** replied at 2026-02-11T21:11:58Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2795553701
> 
> removed in https://github.com/QED-it/orchard/pull/216/commits/6fbb8ce73c98f263bb6557a80e41726ed505571a

---

### str4d on `.github/workflows/ci.yml` (line 16)
**Date:** 2025-11-03T21:05:40Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2487851383
```diff
@@ -1,18 +1,24 @@
 name: CI checks
 
-on: [push, pull_request]
+#on: [push, pull_request]
+on:
+  push:
+    branches: [ main ]  # Only runs on push to main
+  pull_request:       # Runs on any PR to any branch
 
 jobs:
   test:
     name: Test on ${{ matrix.os }}
     runs-on: ${{ matrix.os }}
     strategy:
       matrix:
-        os: [ubuntu-latest, windows-latest, macOS-latest]
+        os: [ ubuntu-latest, windows-latest ]
+    #        os: [ubuntu-latest, windows-latest, macOS-latest]
```

Revert this change; we need to be testing on `macOS-latest`.

> **PaulLaux** replied at 2026-01-29T13:58:11Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2741794573
> 
> done in https://github.com/QED-it/orchard/pull/216/commits/b5518f1b2688889b7eab8a92a773e1655ba5f95f

---

### str4d on `.github/workflows/ci.yml` (line 120)
**Date:** 2025-11-03T21:07:53Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2487857002
```diff
@@ -111,7 +117,7 @@ jobs:
     steps:
       - uses: actions/checkout@v4
       - name: Generate coverage report
-        run: cargo tarpaulin --engine llvm --all-features --release --timeout 600 --out xml
+        run: timeout --preserve-status 300s cargo tarpaulin --engine llvm --timeout 600 --out xml --skip-clean || true
```

Undo this change.

> **PaulLaux** replied at 2026-01-29T13:58:52Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2741797809
> 
> done in https://github.com/QED-it/orchard/pull/216/commits/b5518f1b2688889b7eab8a92a773e1655ba5f95f

---

### str4d on `.github/workflows/ci.yml` (line 3)
**Date:** 2025-11-03T21:08:20Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2487858123
```diff
@@ -1,18 +1,24 @@
 name: CI checks
 
-on: [push, pull_request]
+#on: [push, pull_request]
```

```suggestion
```

> **PaulLaux** replied at 2026-01-29T13:59:03Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2741798537
> 
> done in https://github.com/QED-it/orchard/pull/216/commits/b5518f1b2688889b7eab8a92a773e1655ba5f95f

---

### str4d on `src/circuit.rs` (line 270)
**Date:** 2025-11-03T21:57:28Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2487964032
```diff
      0,
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
-#[derive(Debug)]
+#[derive(Debug, Clone)]
```

Note to self: check whether it is fine to clone this (and in particular, why it was not `Clone` before).

> **PaulLaux** replied at 2026-02-15T11:11:56Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2809050455
> 
> We remove this clone in https://github.com/QED-it/orchard/commit/4f0357336d94b670259a71d4034f9fbb002dac1e#diff-a62026d10aabe43041a05aa22b6b426fe55ab3e7b21e6bfa7d5a13351c84b521L272 

---

### str4d on `src/circuit.rs` (line 289)
**Date:** 2025-11-03T21:57:33Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2487964195
```diff
@@ -776,17 +286,17 @@ impl VerifyingKey {
 }
 
 /// The proving key for the Orchard Action circuit.
-#[derive(Debug)]
+#[derive(Debug, Clone)]
```

Note to self: check whether it is fine to clone this (and in particular, why it was not `Clone` before).

> **PaulLaux** replied at 2026-02-15T11:12:03Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2809050534
> 
> We remove this clone in https://github.com/QED-it/orchard/commit/4f0357336d94b670259a71d4034f9fbb002dac1e#diff-a62026d10aabe43041a05aa22b6b426fe55ab3e7b21e6bfa7d5a13351c84b521L272

---

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

### str4d on `src/circuit.rs` (line 365)
**Date:** 2025-11-03T22:14:10Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2488006245
```diff
          anchor,
             cv_net,
             nf_old,
             rk,
             cmx,
-            enable_spend,
-            enable_output,
+            enable_spend: flags.spends_enabled(),
+            enable_output: flags.outputs_enabled(),
+            enable_zsa: flags.zsa_enabled(),
         }
     }
 
-    fn to_halo2_instance(&self) -> [[vesta::Scalar; 9]; 1] {
-        let mut instance = [vesta::Scalar::zero(); 9];
+    fn to_halo2_instance(&self) -> [[vesta::Scalar; 10]; 1] {
```

Possible consensus bug: this method now returns an additional entry in the instance vector for vanilla Orchard.

In `Proof::create` and `Proof::verify` below, this extra value is passed through to `halo2_proofs` in both cases, which might mean that it happens that created proofs validate because they are providing the same instances, and the actually-checked values within those instances are also consistent with vanilla Orchard (the new value won't be checked by the circuit logic itself).

However, if a proof is created with the current `orchard` crate (e.g. current Zashi wallets) that *doesn't* append the extra instance value, will those proofs validate with this PR's vanilla Orchard verifier (or vice versa)? This likely depends on whether or not `halo2_proofs` is committing to the instance vector anywhere; if it does (which seems likely), then this is a consensus bug.

It might just happen that this is fine for two reasons:
- `halo2_proofs` zero-extends the instance vectors when converting to polynomials.
- The added instance value in this method is a boolean flag converted to an integer and then to a `vesta::Scalar`, so as long as `self.enable_zsa` is always set to `false` for vanilla Orchard, then given the semantics of Rust, this would always append a zero to the instance vector.

If this happens to be the case, this behaviour needs to be clearly documented both on this method, and on the `enable_zsa` fields of both `Flags` and `Instance`.

> **PaulLaux** replied at 2026-01-29T13:36:29Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2741691584
> 
> As discussed during the call, the implementation is correct: 
> 
> > However, if a proof is created with the current orchard crate (e.g. current Zashi wallets) that doesn't append the extra instance value, will those proofs validate with this PR's vanilla Orchard verifier (or vice versa)? This likely depends on whether or not halo2_proofs is committing to the instance vector anywhere; if it does (which seems likely), then this is a consensus bug.
> 
> The vanilla proof serialization has not been updated (the file src/circuit/circuit_proof_test_case_vanilla.bin has not been updated in our [PR](https://github.com/zcash/orchard/pull/471)).
> If a proof is created with the current orchard crate, we could validate it with this PR’s vanilla Orchard verifier([link](https://github.com/QED-it/orchard/blob/a02fdf1f873d58167887abe23a8a7e0b9c1a0a36/src/circuit/circuit_vanilla.rs#L853)).
> 
> > It might just happen that this is fine for two reasons:
> > - halo2_proofs zero-extends the instance vectors when converting to polynomials.
> > - The added instance value in this method is a boolean flag converted to an integer and then to a vesta::Scalar, so as long as self.enable_zsa is always set to false for vanilla Orchard, then given the semantics of Rust, this would always append a zero to the instance vector.
> 
> This is indeed the case for both items.
> 
> Added the requested comments in https://github.com/QED-it/orchard/pull/216/commits/4f0357336d94b670259a71d4034f9fbb002dac1e

---

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

### str4d on `benches/circuit.rs` (line 35)
**Date:** 2025-11-19T14:34:09Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2542276487
```diff
::from_bytes([7; 32]).unwrap();
     let recipient = FullViewingKey::from(&sk).address_at(0u32, Scope::External);
 
-    let vk = VerifyingKey::build();
-    let pk = ProvingKey::build();
+    let vk = VerifyingKey::build::<FL>();
+    let pk = ProvingKey::build::<FL>();
 
     let create_bundle = |num_recipients| {
-        let mut builder = Builder::new(BundleType::DEFAULT, Anchor::from_bytes([0; 32]).unwrap());
+        let mut builder = Builder::new(
+            BundleType::DEFAULT_VANILLA,
```

Bug: you are using `BundleType::DEFAULT_VANILLA` for all `FL`, which means that the ZSA constraints are disabled when benchmarking `OrchardZSA`. While that won't have an effect on the circuit complexity itself, we should be benchmarking the intended default configuration for actual usage (in case there are additional prover or verifier codepaths that are disabled when the ZSA flag is false).

> **PaulLaux** replied at 2026-01-29T19:54:07Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2743267983
> 
> fixed in https://github.com/QED-it/orchard/pull/216/commits/b5518f1b2688889b7eab8a92a773e1655ba5f95f

---

### str4d on `benches/note_decryption.rs` (line 54)
**Date:** 2025-11-19T14:36:35Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2542288774
```diff
@@ -44,16 +50,31 @@ fn bench_note_decryption(c: &mut Criterion) {
         .collect();
 
     let bundle = {
-        let mut builder = Builder::new(BundleType::DEFAULT, Anchor::from_bytes([0; 32]).unwrap());
+        let mut builder = Builder::new(
+            BundleType::DEFAULT_VANILLA,
```

Bug: same issue here.

> **PaulLaux** replied at 2026-01-29T19:54:26Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2743269383
> 
> fixed in https://github.com/QED-it/orchard/pull/216/commits/b5518f1b2688889b7eab8a92a773e1655ba5f95f

---

### str4d on `book/src/design/actions.md` (line 24)
**Date:** 2025-11-19T14:39:45Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2542305679
```diff
we define an Orchard transaction as containing a
 bundle of actions, where each action is both a spend and an output. This provides the same
 inherent arity-hiding as multi-JoinSplit Sprout, but using Sapling value commitments to
 balance the transaction without doubling its size.
 
+## Dummy notes for Orchard
+
+For Orchard, a transaction is a bundle of actions. Each action is composed of one spend and one output.
+This means we have the same amount of "spends" and "outputs" in one transaction.
```

These sentences are fully duplicative of the previous paragraph.
```suggestion
```

> **PaulLaux** replied at 2026-01-29T20:09:30Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2743328541
> 
> fixed in https://github.com/QED-it/orchard/pull/216/commits/5da1dbc4fead9b6b02b71ff6b543c06702a48a84

---

### str4d on `book/src/design/actions.md` (line 35)
**Date:** 2025-11-19T14:41:20Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2542313926
```diff
 output is a note with a value of zero and a random recipient address.
+In the ZK proof, when the value of the spent note is zero,
+we do not verify that the corresponding spent note commitment is part of the Merkle tree.
+
+## Split notes for OrchardZSA
+
+For OrchardZSA, if the number of inputs exceeds the number of outputs,
+we use dummy output notes (as in Orchard) to fill all actions.
+Conversely, if the number of outputs exceeds the number of inputs, we use split notes to fill the actions.
```

Unnecessary repetition of content above and below.
```suggestion
```

> **PaulLaux** replied at 2026-01-29T20:09:38Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2743328909
> 
> fixed in https://github.com/QED-it/orchard/pull/216/commits/5da1dbc4fead9b6b02b71ff6b543c06702a48a84

---

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

### str4d on `Cargo.toml` (line 33)
**Date:** 2025-11-19T14:48:55Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2542352311
```diff
@@ -30,6 +30,7 @@ ff = { version = "0.13", default-features = false }
 fpe = { version = "0.6", default-features = false, features = ["alloc"] }
 group = "0.13"
 hex = { version = "0.4", default-features = false, features = ["alloc"] }
+k256 = { version = "0.13.0", default-features = false, features = ["arithmetic", "schnorr"] }
```

We use the `secp256k1` crate in our ecosystem, not the `k256` crate. Replace this dependency.

Additionally, the dependency **must** be optional, behind a default-disabled feature flag, because it is only required for issuers (which will almost certainly not be all wallets), or issuance verifiers (i.e. full nodes). An Orchard-only wallet must not be required to depend on it.

> **PaulLaux** replied at 2026-01-29T20:21:31Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2743373078
> 
> Replaced to `secp256k1` in https://github.com/QED-it/orchard/pull/216/commits/0e9729add7cafc19f3c1429ea2c04dbba7bf9029 and removed from default in Cargo.toml in https://github.com/QED-it/orchard/pull/216/commits/61ab6486dfd4cfa72c186a5e7b9290968edff277

---

### str4d on `Cargo.toml` (line 116)
**Date:** 2025-11-19T14:49:54Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2542357168
```diff
@@ -109,5 +110,7 @@ debug = true
 debug = true
 
 [patch.crates-io]
+sinsemilla = { git = "https://github.com/zcash/sinsemilla", rev = "aabb707e862bc3d7b803c77d14e5a771bcee3e8c" }
+zcash_note_encryption = { git = "https://github.com/zcash/zcash_note_encryption", rev = "9f7e93d42cef839d02b9d75918117941d453f8cb" }
```

I checked these revisions.

---

### str4d on `README.md` (line 1)
**Date:** 2025-11-19T14:50:20Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2542359143
```diff
@@ -1,6 +1,7 @@
-# orchard [![Crates.io](https://img.shields.io/crates/v/orchard.svg)](https://crates.io/crates/orchard) #
+# orchard [![Crates.io](https://img.shields.io/crates/v/orchard.svg)](https://crates.io/crates/orchard) [![CI checks](https://github.com/QED-it/orchard/actions/workflows/ci.yml/badge.svg?branch=zsa1)](https://github.com/QED-it/orchard/actions/workflows/ci.yml)
```

Undo this change.

> **PaulLaux** replied at 2026-01-29T20:22:39Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2743376994
> 
> done in https://github.com/QED-it/orchard/pull/216/commits/b5518f1b2688889b7eab8a92a773e1655ba5f95f

---

### str4d on `README.md` (line 4)
**Date:** 2025-11-19T14:50:47Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2542360991
```diff
@@ -1,6 +1,7 @@
-# orchard [![Crates.io](https://img.shields.io/crates/v/orchard.svg)](https://crates.io/crates/orchard) #
+# orchard [![Crates.io](https://img.shields.io/crates/v/orchard.svg)](https://crates.io/crates/orchard) [![CI checks](https://github.com/QED-it/orchard/actions/workflows/ci.yml/badge.svg?branch=zsa1)](https://github.com/QED-it/orchard/actions/workflows/ci.yml)
+#
 
-Requires Rust 1.66+.
+Requires Rust 1.71+.
```

If the MSRV bump is not necessary and is undone:
```suggestion
Requires Rust 1.70+.
```

> **PaulLaux** replied at 2026-01-29T20:22:53Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2743377880
> 
> done in https://github.com/QED-it/orchard/pull/216/commits/b5518f1b2688889b7eab8a92a773e1655ba5f95f

---

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

### str4d on `src/lib.rs` (line 58)
**Date:** 2025-11-19T15:01:06Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2542406328
```diff
@@ -48,8 +52,12 @@ mod test_vectors;
 pub use action::Action;
 pub use address::Address;
 pub use bundle::Bundle;
+pub use constants::reference_keys::ReferenceKeys;
 pub use constants::MERKLE_DEPTH_ORCHARD as NOTE_COMMITMENT_TREE_DEPTH;
-pub use note::Note;
+pub use note::{
+    commitment::{ExtractedNoteCommitment, NoteCommitment},
```

Undo this change; these are already re-exported from the `note` module.

> **PaulLaux** replied at 2026-01-29T20:27:46Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2743394180
> 
> done in https://github.com/QED-it/orchard/pull/216/commits/b5518f1b2688889b7eab8a92a773e1655ba5f95f

---

### str4d on `src/constants/reference_keys.rs` (line 49)
**Date:** 2025-11-19T15:06:04Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2542428312
```diff
n recipient() -> Address {
+        Address::from_raw_address_bytes(&RAW_REFERENCE_RECIPIENT).unwrap()
+    }
+
+    /// Returns the full viewing key for reference notes.
+    pub fn fvk() -> FullViewingKey {
+        FullViewingKey::from(&Self::sk())
+    }
+}
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+    use crate::keys::{FullViewingKey, Scope};
+
+    #[test]
+    fn recipient() {
+        let sk = SpendingKey::from_bytes([0; 32]).unwrap();
+        let fvk = FullViewingKey::from(&sk);
```

This test should be checking that `ReferenceKeys` is self-consistent. And because it is only checking the recipient, we can just fetch the FVK instead of deriving it in parallel (which would enable bugs in the actual code to go undetected):
```suggestion
        let fvk = ReferenceKeys::fvk();
```

> **PaulLaux** replied at 2026-01-29T20:28:37Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2743396767
> 
> done in https://github.com/QED-it/orchard/pull/216/commits/b5518f1b2688889b7eab8a92a773e1655ba5f95f

---

### str4d on `src/lib.rs` (line 55)
**Date:** 2025-11-19T15:10:32Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2542447228
```diff
@@ -48,8 +52,12 @@ mod test_vectors;
 pub use action::Action;
 pub use address::Address;
 pub use bundle::Bundle;
+pub use constants::reference_keys::ReferenceKeys;
```

I'm not convinced that `ReferenceKeys` is important enough to go into the root namespace. Expose it as `orchard::issuance::ReferenceKeys` instead, and remove it here:
```suggestion
```

> **PaulLaux** replied at 2026-01-29T20:49:25Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2743488932
> 
> Removed and exposed from `issuance.rs` in https://github.com/QED-it/orchard/pull/216/commits/fcd1a0b059e437e05b1fb875a75ac526746419f8

---

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

### str4d on `src/zip32.rs` (line 152)
**Date:** 2025-11-19T16:03:31Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2542655700
```diff
P32_ORCHARD_ISSUANCE_PERSONALIZATION;
+    const CKD_DOMAIN: PrfExpand<([u8; 32], [u8; 4], [u8; 1], VariableLengthSlice)> =
+        PrfExpand::ORCHARD_ZIP32_CHILD;
+}
+
 /// An Orchard extended spending key.
 ///
 /// Defined in [ZIP32: Orchard extended keys][orchardextendedkeys].
 ///
 /// [orchardextendedkeys]: https://zips.z.cash/zip-0032#orchard-extended-keys
 #[derive(Debug, Clone)]
-pub(crate) struct ExtendedSpendingKey {
+pub(crate) struct ExtendedSpendingKey<C: hardened_only::Context> {
```

Bug: This generalisation is incorrect.
- `orchard::zip32::ExtendedSpendingKey` is very specifically a root of Orchard spend authority, and exposes an `orchard::keys::SpendingKey` via `ExtendedSpendingKey::sk`, from which RedPallas etc. keys can be derived.
- By contrast, an issuance authorizing key `isk` is (for the version 0 scheme) a BIP 340 private key.

If your aim was just to reuse some of the `ExtendedSpendingKey` code, then you need to do so without altering the public API of `ExtendedSpendingKey` in any way. But also consider whether you actually need to share any of its code; most of the work is handled for you by `HardenedOnlyKey`, and half of the custom parts in `ExtendedSpendingKey` (that confirm a valid `SpendingKey` can be derived at each child) would need to be specialised away.

So I think you should just undo all of the changes in this file, and instead define your own `IssuanceAuthorizingKey` type that wraps `HardenedOnlyKey<Issuance>` (which is how the latter is intended to be used).

> **PaulLaux** replied at 2026-01-29T20:56:40Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2743520657
> 
> done in https://github.com/QED-it/orchard/pull/216/commits/c3469736cb61a563457ce10f958a3120f4e2e25a

---

### str4d on `src/keys.rs` (line 326)
**Date:** 2025-11-19T16:07:17Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2542668676
```diff
@@ -321,8 +323,8 @@ impl From<&SpendingKey> for FullViewingKey {
     }
 }
 
-impl From<&ExtendedSpendingKey> for FullViewingKey {
-    fn from(extsk: &ExtendedSpendingKey) -> Self {
+impl<C: hardened_only::Context> From<&ExtendedSpendingKey<C>> for FullViewingKey {
```

Bug: this conversion is completely incorrect for an issuance authorizing key.

If I hadn't already said to undo all of the changes to `ExtendedSpendingKey`, I would be saying here to restrict this to `ExtendedSpendingKey<Orchard>`. As it is, these changes will be reverted.

> **PaulLaux** replied at 2026-01-29T20:59:09Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2743527896
> 
> fixed in https://github.com/QED-it/orchard/pull/216/commits/c3469736cb61a563457ce10f958a3120f4e2e25a

---

### str4d on `src/keys.rs` (line 190)
**Date:** 2025-11-19T16:08:08Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2542671834
```diff
@@ -185,7 +187,7 @@ impl SpendValidatingKey {
         self.0.randomize(randomizer)
     }
 
-    /// Converts this spend validating key to its serialized form,
+    /// Converts this spend key to its serialized form,
```

Why was this valid comment on `SpendValidatingKey` altered? Undo the change.

> **PaulLaux** replied at 2026-01-29T21:00:09Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2743530866
> 
> undone in https://github.com/QED-it/orchard/pull/216/commits/b5518f1b2688889b7eab8a92a773e1655ba5f95f

---

### str4d on `src/keys.rs` (line 1042)
**Date:** 2025-11-19T16:19:25Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2542714951
```diff
@@ -1027,15 +1030,20 @@ mod tests {
 
     #[test]
     fn test_vectors() {
-        for tv in crate::test_vectors::keys::test_vectors() {
+        for tv in crate::test_vectors::keys::TEST_VECTORS {
             let sk = SpendingKey::from_bytes(tv.sk).unwrap();
 
             let ask: SpendAuthorizingKey = (&sk).into();
             assert_eq!(<[u8; 32]>::from(&ask.0), tv.ask);
 
+            let isk = IssueAuthKey::<ZSASchnorr>::from_bytes(&tv.isk).unwrap();
```

I'm not convinced that the ZSA issuance test vectors should be merged with the Orchard key tree test vectors. But any changes here should be a result of review comments on https://github.com/zcash/zcash-test-vectors/pull/108 once they are made.

> **PaulLaux** replied at 2026-02-02T19:00:27Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2755802286
> 
> Noted. No action until https://github.com/zcash/zcash-test-vectors/pull/108 is reviewed.

---

### str4d on `src/value.rs` (line 162)
**Date:** 2025-11-19T16:23:33Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2542731689
```diff
@@ -141,6 +152,14 @@ impl Sub for NoteValue {
     }
 }
 
+impl Add for NoteValue {
+    type Output = Option<NoteValue>;
+
+    fn add(self, rhs: Self) -> Self::Output {
+        self.0.checked_add(rhs.0).map(NoteValue)
+    }
+}
+
```

Where is this being used? `NoteValue` intentionally only exposed `Sub<NoteValue> for NoteValue` because the only consensus-correct way to combine `NoteValue`s is to take a `(spend, output)` pair and compute the difference to get a `ValueSum`.

Unless there is a good motivation for it, remove this:
```suggestion
```

> **PaulLaux** replied at 2026-01-29T21:02:33Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2743538030
> 
> Replaced `Add` with
> ```rust
> pub(crate) fn add(self, rhs: Self) -> Option<Self> {..}
> ```
> as discussed in the call
> 
> in https://github.com/QED-it/orchard/pull/216/commits/a80b5faf590add72ddf2feb40e045937f9cb1d40

---

### str4d on `src/value.rs` (line 140)
**Date:** 2025-11-19T16:26:14Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2542741081
```diff
@@ -127,6 +132,12 @@ impl From<&NoteValue> for Assigned<pallas::Base> {
     }
 }
 
+impl From<NoteValue> for i128 {
+    fn from(value: NoteValue) -> Self {
+        value.0 as i128
+    }
+}
+
```

I do not want this in the public API. We already have `NoteValue::inner()` returning a `u64`, and it is *very* incorrect to treat a `NoteValue` as signed, much less have `value.into()` default to returning a signed value. Remove this:
```suggestion
```
Anywhere you were relying on `value.into()` or `i128::from(value)` can be updated with `value.inner().into()` or `i128::from(value.inner())`.

> **PaulLaux** replied at 2026-01-29T21:19:58Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2743594609
> 
> done in https://github.com/QED-it/orchard/pull/216/commits/27e682400a82e8a425cf5d6d480446a900ec7166

---

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

### str4d on `src/value.rs` (line 221)
**Date:** 2025-11-19T16:30:42Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2542756837
```diff
@@ -198,15 +217,34 @@ impl ValueSum {
             sign,
         )
     }
+
+    pub(crate) fn into<V: TryFrom<i64>>(self) -> Result<V, BuildError> {
```

Rename this; we should never have a manual `into()` method that aliases the `Into` trait while using a different method signature (which is closer to `TryInto::try_into`).

```suggestion
    pub(crate) fn into_value_balance<V: TryFrom<i64>>(self) -> Result<V, BuildError> {
```

> **str4d** replied at 2025-11-19T22:01:30Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2543702226
> 
> In a pairing with @daira, we also noted that currently [ZIP 230](https://zips.z.cash/zip-0230#orchardzsa-asset-burn-description) defines `valueBurn: u64`, but allowing that full range now is annoying because every other value balance is an `i64`, and it would force us to add a bunch of extra handling logic that would only be used for burns (and would be incompatible with future asset-specific value balances when we eventually have a subsequent pool that supports ZSAs via a turnstile).
> 
> For simplicity, we should update ZIP 230 to only allow burn amounts that fit into both a `u64` and an `i64`, i.e. `u63`.

> **PaulLaux** replied at 2026-02-02T19:23:26Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2755867464
> 
> renamed to `into_value_balance<>()` in https://github.com/QED-it/orchard/pull/216/commits/b5518f1b2688889b7eab8a92a773e1655ba5f95f

> **PaulLaux** replied at 2026-02-02T19:47:11Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2755924676
> 
> We added `MAX_BURN_VALUE` and a check in https://github.com/QED-it/orchard/pull/216/commits/49f5939cbd341a7024575f828ecd3bca2eceffa4.
> 
> ZIP 230 will be updated separately. 

> **vivek-arte** replied at 2026-02-04T14:45:12Z:
> 
> The update to ZIP 230 is done in https://github.com/zcash/zips/pull/1168.

---

### str4d on `src/value.rs` (line 228)
**Date:** 2025-11-19T16:33:02Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2542764684
```diff
@@ -198,15 +217,34 @@ impl ValueSum {
             sign,
         )
     }
+
+    pub(crate) fn into<V: TryFrom<i64>>(self) -> Result<V, BuildError> {
+        i64::try_from(self)
+            .map_err(BuildError::ValueSum)
+            .and_then(|i| V::try_from(i).map_err(|_| BuildError::ValueSum(OverflowError)))
+    }
 }
 
-impl Add for ValueSum {
+impl<T: Into<i128>> Add<T> for ValueSum {
```

Undo this generalisation. It is an intentional part of the crate's type safety that `ValueSum` types can only be added to themselves.

> **PaulLaux** replied at 2026-02-02T20:00:12Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2755959692
> 
> Removed generalization in https://github.com/QED-it/orchard/pull/216/commits/27e682400a82e8a425cf5d6d480446a900ec7166
> 
> Also, removed `#[allow(clippy::suspicious_arithmetic_impl)]` that does not seem to be needed in https://github.com/QED-it/orchard/pull/216/commits/1d93e5f2d42ea746465995ab479c3e5df66738ca

---

### str4d on `src/value.rs` (line 241)
**Date:** 2025-11-19T16:37:40Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2542782876
```diff
(|_| BuildError::ValueSum(OverflowError)))
+    }
 }
 
-impl Add for ValueSum {
+impl<T: Into<i128>> Add<T> for ValueSum {
     type Output = Option<ValueSum>;
 
     #[allow(clippy::suspicious_arithmetic_impl)]
-    fn add(self, rhs: Self) -> Self::Output {
+    fn add(self, rhs: T) -> Self::Output {
+        self.0
+            .checked_add(rhs.into())
+            .filter(|v| VALUE_SUM_RANGE.contains(v))
+            .map(ValueSum)
+    }
+}
+
+#[cfg(feature = "std")]
+impl Neg for ValueSum {
```

- Where is this being used?
- Why is it gated on `feature = "std"` instead of using `core::ops::Neg` (like the other ops impls do)?

> **PaulLaux** replied at 2026-02-02T20:05:10Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2755972888
> 
> The `impl Neg for ValueSum` was removed entirely in https://github.com/QED-it/orchard/pull/216/commits/27e682400a82e8a425cf5d6d480446a900ec7166
> Upon review, it was not being used anywhere in the codebase (a leftover from an old version).

---

### str4d on `src/value.rs` (line 280)
**Date:** 2025-11-19T16:42:04Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2542800703
```diff
@@ -234,8 +272,20 @@ impl TryFrom<ValueSum> for i64 {
     }
 }
 
+impl From<ValueSum> for i128 {
+    fn from(value: ValueSum) -> Self {
+        value.0
+    }
+}
+
```

Where is this being used? I'm not keen on having it in the public API; we already have `ValueSum::magnitude_sign` which is documented as requiring care to use, and that is no less true of this conversion which is both undocumented and very easy to accidentally use.

If the conversion is a hard requirement somewhere in the ZSA stack outside of the `orchard` crate that can't use `ValueSum::magnitude_sign` (which I would think is unlikely), then it should instead be a concrete method on `ValueSum` like `magnitude_sum`.
```suggestion
```

> **PaulLaux** replied at 2026-02-02T20:09:07Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2755983383
> 
> removed entirely in https://github.com/QED-it/orchard/pull/216/commits/27e682400a82e8a425cf5d6d480446a900ec7166

---

### str4d on `src/value.rs` (line 286)
**Date:** 2025-11-19T16:43:54Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2542807405
```diff
@@ -234,8 +272,20 @@ impl TryFrom<ValueSum> for i64 {
     }
 }
 
+impl From<ValueSum> for i128 {
+    fn from(value: ValueSum) -> Self {
+        value.0
+    }
+}
+
+impl From<NoteValue> for ValueSum {
+    fn from(value: NoteValue) -> Self {
+        Self(value.into())
+    }
+}
+
```

Where is this being used? I don't think it should be in the public API, because this silently assumes the `NoteValue` is part of an `Action` that spends either a dummy note or split note, and I think that at the level of the `orchard` crate this should be explicit.
```suggestion
```

> **PaulLaux** replied at 2026-02-02T20:10:50Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2755987630
> 
> Agreed. We removed it in https://github.com/QED-it/orchard/pull/216/commits/27e682400a82e8a425cf5d6d480446a900ec7166

---

### str4d on `src/value.rs` (line 288)
**Date:** 2025-11-19T16:46:47Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2542817988
```diff
@@ -234,8 +272,20 @@ impl TryFrom<ValueSum> for i64 {
     }
 }
 
+impl From<ValueSum> for i128 {
+    fn from(value: ValueSum) -> Self {
+        value.0
+    }
+}
+
+impl From<NoteValue> for ValueSum {
+    fn from(value: NoteValue) -> Self {
+        Self(value.into())
+    }
+}
+
 /// The blinding factor for a [`ValueCommitment`].
-#[derive(Clone, Debug)]
+#[derive(Clone, Copy, Debug)]
```

`ValueCommitTrapdoor` is a blinding factor that we shouldn't allow to be arbitrarily copied around the stack.
```suggestion
#[derive(Clone, Debug)]
```

> **PaulLaux** replied at 2026-02-02T20:14:49Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2755997442
> 
> we removed `copy` in https://github.com/QED-it/orchard/pull/216/commits/b5518f1b2688889b7eab8a92a773e1655ba5f95f

---

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

### str4d on `src/value.rs` (line 410)
**Date:** 2025-11-19T16:55:25Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2542846302
```diff
@@ -356,7 +405,9 @@ impl ValueCommitment {
             pallas::Scalar::from(abs_value)
         };
 
-        ValueCommitment(V * value + R * rcv.0)
+        let V_zsa = asset.cv_base();
+
+        ValueCommitment(V_zsa * value + R * rcv.0)
```

This is not necessarily `V_zsa` in this context; we should continue to use the existing naming to match the protocol spec.
```suggestion
        ValueCommitment(V * value + R * rcv.0)
```

> **PaulLaux** replied at 2026-02-02T20:17:16Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2756003331
> 
> renamed `V_zsa` to `V` to match protocol spec in https://github.com/QED-it/orchard/pull/216/commits/b5518f1b2688889b7eab8a92a773e1655ba5f95f

---

### str4d on `src/value.rs` (line 379)
**Date:** 2025-11-19T16:55:27Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2542846450
```diff
itment {
     ///
     /// [concretehomomorphiccommit]: https://zips.z.cash/protocol/nu5.pdf#concretehomomorphiccommit
     #[allow(non_snake_case)]
-    pub fn derive(value: ValueSum, rcv: ValueCommitTrapdoor) -> Self {
+    pub fn derive(value: ValueSum, rcv: ValueCommitTrapdoor, asset: AssetBase) -> Self {
         let hasher = pallas::Point::hash_to_curve(VALUE_COMMITMENT_PERSONALIZATION);
-        let V = hasher(&VALUE_COMMITMENT_V_BYTES);
         let R = hasher(&VALUE_COMMITMENT_R_BYTES);
```

```suggestion
        let V = asset.cv_base();
        let R = hasher(&VALUE_COMMITMENT_R_BYTES);
```

> **PaulLaux** replied at 2026-02-02T20:18:55Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2756007473
> 
> done in https://github.com/QED-it/orchard/pull/216/commits/b5518f1b2688889b7eab8a92a773e1655ba5f95f

---

### str4d on `src/value.rs` (line 526)
**Date:** 2025-11-19T17:08:41Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2542892451
```diff
vec::Vec;
     use proptest::prelude::*;
 
     use super::{
         testing::{arb_note_value_bounded, arb_trapdoor, arb_value_sum_bounded},
         OverflowError, ValueCommitTrapdoor, ValueCommitment, ValueSum, MAX_NOTE_VALUE,
     };
-    use crate::primitives::redpallas;
+    use crate::{
+        note::asset_base::testing::arb_asset_base, note::AssetBase, primitives::redpallas,
+    };
+
+    fn check_binding_signature(
+        native_values: &[(ValueSum, ValueCommitTrapdoor, AssetBase)],
```

If these are all meant to be native values, this shouldn't be taking `AssetBase` in the tuple. Either remove `AssetBase` from the argument, or merge `native_values` into `arb_values`.

> **PaulLaux** replied at 2026-02-02T20:35:55Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2756049391
> 
>  Addressed in two commits:
> 
>   https://github.com/QED-it/orchard/pull/216/commits/f0cf7ea231d340809bf6530bd5c900bf8b86a876: Removed `AssetBase` from the `native_values` tuple as suggested.
> 
>   https://github.com/QED-it/orchard/pull/216/commits/dc861afa2d8257687f5a3082d107a7afe817b063: Further simplified the test by:
>   - Removing neg_trapdoors parameter and the neg_arb_values construction
>   - Replacing the manual negation logic with arb_asset_values_balanced_per_asset() which directly generates values that sum to zero per custom asset
> 
>   Final signature:
> ```rust
>   fn check_binding_signature(
>       zatoshi_values: &[(ValueSum, ValueCommitTrapdoor)],
>       arb_values: &[(ValueSum, ValueCommitTrapdoor, AssetBase)],
>       arb_values_to_burn: &[(ValueSum, ValueCommitTrapdoor, AssetBase)],
>   )
> ```
> 
>   The native_values was also renamed to `zatoshi_values` for clarity
>   (https://github.com/QED-it/orchard/pull/216/commits/d8caa76a5c49300db35f7a4d80077dfaeb7295ca).

---

### str4d on `src/value.rs` (line 532)
**Date:** 2025-11-19T17:13:48Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2542907997
```diff
rb_asset_base, note::AssetBase, primitives::redpallas,
+    };
+
+    fn check_binding_signature(
+        native_values: &[(ValueSum, ValueCommitTrapdoor, AssetBase)],
+        arb_values: &[(ValueSum, ValueCommitTrapdoor, AssetBase)],
+        neg_trapdoors: &[ValueCommitTrapdoor],
+        arb_values_to_burn: &[(ValueSum, ValueCommitTrapdoor, AssetBase)],
+    ) {
+        // for each arb value, create a negative value with a different trapdoor
+        let neg_arb_values: Vec<_> = arb_values
```

Instead of manually cancelling out the "unburned" values (which embeds the assumption that they shouldn't affect the proptest) and then generating a separate set of `arb_values_to_burn`, it would be better to calculate the expected value balances for each `AssetBase` within `arb_values`, the same way that is already done for `native_value_balance`. Then both positive and negative value balances are being tested for custom assets, which both need to work (negative value balances are used in issuance transactions).

> **PaulLaux** replied at 2026-02-02T21:03:15Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2756115373
> 
> Continued from https://github.com/zcash/orchard/pull/471#discussion_r2756049391
> 
> The test now covers:
>   - Zero value balance for custom assets (transfer case)
>   - Positive value balance for custom assets (burn case)
> 
> > Then both positive and negative value balances are being tested for custom assets, which both need to work (negative value balances are used in issuance transactions).
> 
> Regarding negative value balances for custom assets: per ZIP 226, Custom Assets are contained within the shielded pool and cannot be unshielded via regular transfer. The value balance verification equation shows that for Custom Assets:
> 
>   - Transfers: net value per asset = 0 (no entry in `assetBurn`)
>   - Burns: net value per asset > 0 (amount appears in `assetBurn` and is subtracted from `bvk`)
> 
> Issuance of new Custom Assets is handled by the separate `IssueBundle` (ZIP 227) with its own `IssueAuth` authorization, not through the Orchard value balance mechanism. Therefore, negative value balance only applies to ZEC (shielding from transparent pool via `v^balanceOrchard`), not to Custom Assets.

---

### str4d on `src/constants/fixed_bases.rs` (line 32)
**Date:** 2025-11-19T17:19:14Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2542924422
```diff
@@ -28,15 +28,21 @@ pub const ORCHARD_PERSONALIZATION: &str = "z.cash:Orchard";
 /// SWU hash-to-curve personalization for the value commitment generator
 pub const VALUE_COMMITMENT_PERSONALIZATION: &str = "z.cash:Orchard-cv";
 
+/// SWU hash-to-curve personalization for the ZSA asset base generator
+pub const ZSA_ASSET_BASE_PERSONALIZATION: &str = "z.cash:OrchardZSA";
```

I checked this matches https://zips.z.cash/zip-0227#orchardzsa-asset-bases

---

### str4d on `src/constants/fixed_bases.rs` (line 44)
**Date:** 2025-11-19T17:22:06Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2542932802
```diff
1] = *b"v";
+pub const NATIVE_ASSET_BASE_V_BYTES: [u8; 1] = *b"v";
 
 /// SWU hash-to-curve value for the value commitment generator
 pub const VALUE_COMMITMENT_R_BYTES: [u8; 1] = *b"r";
 
 /// SWU hash-to-curve personalization for the note commitment generator
 pub const NOTE_COMMITMENT_PERSONALIZATION: &str = "z.cash:Orchard-NoteCommit";
 
+/// SWU hash-to-curve personalization for the ZSA note commitment generator
+pub const NOTE_ZSA_COMMITMENT_PERSONALIZATION: &str = "z.cash:ZSA-NoteCommit";
```

I checked this matches https://zips.z.cash/zip-0226#note-structure-and-commitment (there it appears with its `-M` suffix due to using `SinsemillaHashToPoint` directly, but in the `sinsemilla` crate we retain the `SinsemillaCommit` abstraction as much as possible, so we pass it in like this).

---

### str4d on `src/constants/sinsemilla.rs` (line 227)
**Date:** 2025-11-19T17:32:34Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2542967008
```diff
@@ -197,6 +222,22 @@ mod tests {
         );
     }
 
+    #[test]
+    fn q_note_zsa_commitment_m() {
+        let domain = CommitDomain::new(NOTE_ZSA_COMMITMENT_PERSONALIZATION);
```

This should use `CommitDomain::new_with_separate_domains` to ensure it exactly matches the `CommitDomain` used in production. The fact that only the hash domain influences `Q` should not be something that the constant-checking test relies on.
```suggestion
        let domain = CommitDomain::new_with_separate_domains(
            NOTE_ZSA_COMMITMENT_PERSONALIZATION,
            NOTE_COMMITMENT_PERSONALIZATION,
        );
```

> **PaulLaux** replied at 2026-02-03T19:48:48Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2760724051
> 
> done in https://github.com/QED-it/orchard/pull/216/commits/b5518f1b2688889b7eab8a92a773e1655ba5f95f

---

### str4d on `src/note.rs` (line 398)
**Date:** 2025-11-19T18:29:10Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2543127484
```diff

+    index_action: u32,
+    index_note: u32,
+) -> Rho {
+    Rho(to_base(
+        Params::new()
+            .hash_length(64)
+            .personal(ZSA_ISSUE_NOTE_RHO_PERSONALIZATION)
+            .to_state()
+            .update(&nullifier.to_bytes())
+            .update(&[0x84])
+            .update(index_action.to_le_bytes().as_ref())
+            .update(index_note.to_le_bytes().as_ref())
+            .finalize()
+            .as_bytes()
+            .try_into()
+            .unwrap(),
```

Consensus bug: this is an incorrect instantiation of `PRF^expand` (it uses a different personalization), and does not match the specification in https://zips.z.cash/zip-0227#computation-of

Instead, https://github.com/zcash/zcash_spec/blob/main/src/prf_expand.rs should be updated to add the new 2-input `PRF^expand` domain, and then that constant should be used here.

> **PaulLaux** replied at 2026-01-29T09:58:30Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2740843948
> 
> Moved to the `zcash_spec` repo, PR: https://github.com/zcash/zcash_spec/pull/13 . 
> 
> Now it is imported.

---

### str4d on `src/note.rs` (line 28)
**Date:** 2025-11-19T18:29:20Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2543127880
```diff
@@ -21,6 +24,8 @@ pub use self::commitment::{ExtractedNoteCommitment, NoteCommitment};
 pub(crate) mod nullifier;
 pub use self::nullifier::Nullifier;
 
+const ZSA_ISSUE_NOTE_RHO_PERSONALIZATION: &[u8; 16] = b"ZSA_IssueNoteRho";
+
```

```suggestion
```

> **PaulLaux** replied at 2026-02-03T20:02:35Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2760773940
> 
> Done, moved to the `zcash_spec` repo, PR: https://github.com/zcash/zcash_spec/pull/13 . 

---

### str4d on `src/note.rs` (line 3)
**Date:** 2025-11-19T18:29:35Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2543128465
```diff
@@ -1,15 +1,18 @@
 //! Data structures used for note construction.
+use alloc::vec::Vec;
+use blake2b_simd::Params;
```

```suggestion
```

> **PaulLaux** replied at 2026-02-03T20:05:31Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2760784114
> 
> done in https://github.com/QED-it/orchard/pull/216/commits/7aafdc0b8cc51657fce04f27d9cd93566dca7331

---

### str4d on `src/note.rs` (line 75)
**Date:** 2025-11-19T18:36:48Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2543147318
```diff
@@ -57,8 +62,17 @@ impl Rho {
     pub(crate) fn into_inner(self) -> pallas::Base {
         self.0
     }
+
+    /// When creating an issuance note, the rho value is initialized with the Pallas base element zero.
+    /// This value will be updated later by calling `update_rho` method on the `IssueBundle`.
+    pub(crate) fn zero() -> Self {
+        Rho(pallas::Base::zero())
+    }
 }
 
+pub(crate) mod asset_base;
+pub use self::asset_base::AssetBase;
+
```

Move this to around line 20, next to the other module definitions (and above them so they remain in alphabetical order).

> **PaulLaux** replied at 2026-02-03T20:08:03Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2760792205
> 
> done in https://github.com/QED-it/orchard/pull/216/commits/b5518f1b2688889b7eab8a92a773e1655ba5f95f

---

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

### str4d on `src/note.rs` (line 297)
**Date:** 2025-11-19T20:38:32Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2543502871
```diff
(&self) -> AssetBase {
+        self.asset
+    }
+
     /// Returns the rseed value of this note.
     pub fn rseed(&self) -> &RandomSeed {
         &self.rseed
     }
 
+    /// Returns the rseed_split_note value of this note.
+    pub fn rseed_split_note(&self) -> CtOption<RandomSeed> {
+        self.rseed_split_note
+    }
+
+    pub(crate) fn set_rseed_split_note(&mut self, rseed_split_note: RandomSeed) {
+        self.rseed_split_note = CtOption::new(rseed_split_note, 1u8.into());
+    }
+
```

It looks like the only place this is used is in the proposed PCZT v2 changes (see https://github.com/QED-it/orchard/pull/195 and https://github.com/QED-it/orchard/pull/196 for context). I think it would be clearer to have a `pub(crate) fn from_parts_internal()` method on `Note` that takes an extra `rseed_split_note` argument:
```suggestion
```

> **PaulLaux** replied at 2026-02-03T20:16:27Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2760819637
> 
> done in https://github.com/QED-it/orchard/pull/216/commits/b5518f1b2688889b7eab8a92a773e1655ba5f95f

---

### str4d on `src/note.rs` (line 206)
**Date:** 2025-11-19T20:39:53Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2543506591
```diff
@@ -169,14 +200,17 @@ impl Note {
     pub fn from_parts(
         recipient: Address,
         value: NoteValue,
+        asset: AssetBase,
         rho: Rho,
         rseed: RandomSeed,
     ) -> CtOption<Self> {
```

```suggestion
    ) -> CtOption<Self> {
        Self::from_parts_internal(
            recipient,
            value,
            asset,
            rho,
            rseed,
            CtOption::new(rseed, 0u8.into()),
        )
    }

    /// Creates a `Note` from its component parts.
    ///
    /// This additionally permits constructing a [Split Input note], which is necessary
    /// for constructing certain patterns of bundles containing ZSA outputs. It is used by
    /// the PCZT code, which is the only place where these notes are serialized.
    ///
    /// Returns `None` if a valid [`NoteCommitment`] cannot be derived from the note.
    ///
    /// # Caveats
    ///
    /// See [`Self::from_parts`].
    ///
    /// [Split Input note]: https://zips.z.cash/zip-0226#split-notes
    pub(crate) fn from_parts_internal(
        recipient: Address,
        value: NoteValue,
        asset: AssetBase,
        rho: Rho,
        rseed: RandomSeed,
        rseed_split_note: CtOption<RandomSeed>,
    ) -> CtOption<Self> {
```

> **PaulLaux** replied at 2026-02-03T20:17:23Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2760822791
> 
> done in https://github.com/QED-it/orchard/pull/216/commits/b5518f1b2688889b7eab8a92a773e1655ba5f95f
> 
> Continued from https://github.com/zcash/orchard/pull/471#discussion_r2543502871

---

### str4d on `src/note.rs` (line 213)
**Date:** 2025-11-19T20:48:49Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2543527521
```diff
@@ -169,14 +200,17 @@ impl Note {
     pub fn from_parts(
         recipient: Address,
         value: NoteValue,
+        asset: AssetBase,
         rho: Rho,
         rseed: RandomSeed,
     ) -> CtOption<Self> {
         let note = Note {
             recipient,
             value,
+            asset,
             rho,
             rseed,
+            rseed_split_note: CtOption::new(rseed, 0u8.into()),
```

```suggestion
            rseed_split_note,
```

> **PaulLaux** replied at 2026-02-03T20:19:42Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2760829754
> 
> done in https://github.com/QED-it/orchard/pull/216/commits/b5518f1b2688889b7eab8a92a773e1655ba5f95f

---

### str4d on `src/note.rs` (line 290)
**Date:** 2025-11-19T20:55:27Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2543542313
```diff
@@ -233,11 +276,25 @@ impl Note {
         self.value
     }
 
+    /// Returns the asset of this note.
+    pub fn asset(&self) -> AssetBase {
+        self.asset
+    }
+
     /// Returns the rseed value of this note.
     pub fn rseed(&self) -> &RandomSeed {
         &self.rseed
     }
 
+    /// Returns the rseed_split_note value of this note.
+    pub fn rseed_split_note(&self) -> CtOption<RandomSeed> {
```

Does this need to be in the public API? If the APIs that take this value to recreate the note (currently `Note::set_rseed_split_note`, after my suggestion `Note::from_parts_internal`) are crate-private, then presumably this can also be crate-private:
```suggestion
    pub(crate) fn rseed_split_note(&self) -> CtOption<RandomSeed> {
```

> **PaulLaux** replied at 2026-02-03T20:21:38Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2760835919
> 
> right. Done in https://github.com/QED-it/orchard/pull/216/commits/b5518f1b2688889b7eab8a92a773e1655ba5f95f

---

### str4d on `src/note.rs` (line 355)
**Date:** 2025-11-19T21:05:33Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2543565714
```diff
ey) -> Nullifier {
+        let selected_rseed = self.rseed_split_note.unwrap_or(self.rseed);
+
         Nullifier::derive(
             fvk.nk(),
             self.rho.0,
-            self.rseed.psi(&self.rho),
+            selected_rseed.psi(&self.rho),
             self.commitment(),
+            self.rseed_split_note.is_some(),
         )
     }
+
+    /// Create a split note which has the same values than the input note except for
+    /// `rseed_split_note` which is equal to a random seed.
```

If my previous comment is actioned, then `rseed_split_note` won't be anywhere in the public API of `Note`, so this documentation should be reworded.

Additionally, this method should only be valid to call on Custom Assets (for native assets, dummy notes should be used instead). Given that this method is rather low-level, I think it's fine to panic on incorrect usage rather than returning `Option<Self>`.

```suggestion
    /// Creates a [Split Input note] from a Custom Asset note, for use on the Spend side
    /// of an Output-only Action.
    ///
    /// # Panics
    ///
    /// Panics if `self.asset().is_native()`.
    ///
    /// [Split Input note]: https://zips.z.cash/zip-0226#split-notes
```

I'm also wondering whether this method should be public or not. We need this when preparing the final set of spends and outputs within the Action (roughly encompassed by the Constructor and IO Finalizer roles in PCZTs), and presumably this can currently all be handled internally to `Builder`?

> **PaulLaux** replied at 2026-02-03T20:47:18Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2760923857
> 
>   1. Documentation reworded — Updated to match your suggested doc comment, removing reference to `rseed_split_note` which is now `pub(crate)`. https://github.com/QED-it/orchard/pull/216/commits/b5518f1b2688889b7eab8a92a773e1655ba5f95f
> 
>   2. Panic on native assets — Added `assert!(bool::from(!self.asset().is_zatoshi()))` at the start of the method. https://github.com/QED-it/orchard/pull/216/commits/f0cf7ea231d340809bf6530bd5c900bf8b86a876
> 
>   > I'm also wondering whether this method should be public or not.
> 
>   3. Changed to `pub(crate)` — You're correct that split note creation is handled internally by `Builder` through `SpendInfo::create_split_spend()`. Wallets add spends and outputs to the Builder, which internally decides when split notes are needed. https://github.com/QED-it/orchard/pull/216/commits/9d2960c8ec018d62e2be2d0df91549097ce0229c

---

### str4d on `src/note.rs` (line 356)
**Date:** 2025-11-19T21:09:40Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2543575888
```diff
.unwrap_or(self.rseed);
+
         Nullifier::derive(
             fvk.nk(),
             self.rho.0,
-            self.rseed.psi(&self.rho),
+            selected_rseed.psi(&self.rho),
             self.commitment(),
+            self.rseed_split_note.is_some(),
         )
     }
+
+    /// Create a split note which has the same values than the input note except for
+    /// `rseed_split_note` which is equal to a random seed.
+    pub fn create_split_note(self, rng: &mut impl RngCore) -> Self {
```

```suggestion
    pub fn create_split_note(self, rng: &mut impl RngCore) -> Self {
        assert!(bool::from(!self.asset().is_native()));
```

> **PaulLaux** replied at 2026-02-03T20:55:42Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2760961653
> 
> Added `assert!(bool::from(!self.asset().is_zatoshi()))` at the start of the method. https://github.com/QED-it/orchard/pull/216/commits/f0cf7ea231d340809bf6530bd5c900bf8b86a876

---

### str4d on `src/note.rs` (line 166)
**Date:** 2025-11-19T21:24:04Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2543612212
```diff
@@ -139,6 +166,10 @@ pub struct Note {
     rho: Rho,
```

Non-blocking: I think I'd prefer this to be
```suggestion
    rho: Option<Rho>,
```
and then remove `Rho::zero`, rather than opening up the possibility that `rho` accidentally gets used as zero in some codepath where `Note::update_rho_for_issuance_note` accidentally hasn't been called. We can then replace internal `self.rho` usage with `self.rho.expect("must call Note::update_rho_for_issuance_note first")` (panics are fine here as this is a programming error that should always be fixed if it occurs).

> **PaulLaux** replied at 2026-02-03T21:05:37Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2761004556
> 
> Addressed in https://github.com/QED-it/orchard/pull/216/commits/b10dd2bd85e533bf1551059c1aa38bc10df8c91e.
> 
>   - Changed `rho: Rho` to `rho: Option<Rho>`
>   - Removed `Rho::zero()`
>   - `rho()` accessor now panics with `"must call Note::update_rho_for_issuance_note first"`
>   - Added `Note::new_issue_note()` for issuance notes with uninitialized rho
>   - Fix: `rseed` is now resampled after `rho` is set to ensure valid note commitments

---

### str4d on `src/note.rs` (line 70)
**Date:** 2025-11-19T21:25:22Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2543614980
```diff
@@ -57,8 +62,17 @@ impl Rho {
     pub(crate) fn into_inner(self) -> pallas::Base {
         self.0
     }
+
+    /// When creating an issuance note, the rho value is initialized with the Pallas base element zero.
+    /// This value will be updated later by calling `update_rho` method on the `IssueBundle`.
+    pub(crate) fn zero() -> Self {
+        Rho(pallas::Base::zero())
+    }
```

Non-blocking: if my other comment is actioned:
```suggestion
```

> **PaulLaux** replied at 2026-02-03T21:06:05Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2761006404
> 
> done, as described in https://github.com/zcash/orchard/pull/471#discussion_r2761004556

---

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

### str4d on `src/primitives/redpallas.rs` (line 26)
**Date:** 2025-11-21T14:28:09Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2549938764
```diff
@@ -23,7 +23,7 @@ pub type Binding = reddsa::orchard::Binding;
 impl SigType for Binding {}
 
 /// A RedPallas signing key.
-#[derive(Clone, Debug)]
+#[derive(Clone, Copy, Debug)]
```

We shouldn't allow signing keys to be arbitrarily copied around the stack.
```suggestion
#[derive(Clone, Debug)]
```

> **PaulLaux** replied at 2026-02-03T21:08:26Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2761014630
> 
> done in https://github.com/QED-it/orchard/pull/216/commits/b5518f1b2688889b7eab8a92a773e1655ba5f95f

---

### str4d on `src/pczt/tx_extractor.rs` (line 151)
**Date:** 2025-11-21T14:39:31Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2549980740
```diff
{
             Some(self.map_authorization(
                 &mut (),
-                |_, _, a| a,
-                |_, Unbound { proof, bsk }| Authorized::from_parts(proof, bsk.sign(rng, &sighash)),
+                |_, _, a| VerSpendAuthSig::new(OrchardSighashVersion::V0, a),
+                |_, Unbound { proof, bsk }| {
+                    Authorized::from_parts(
+                        proof,
+                        VerBindingSig::new(OrchardSighashVersion::V0, bsk.sign(rng, &sighash)),
```

Non-blocking: The sighash version needs to be passed into the method, because it is a property of the sighash (and only the caller knows which version was used). Given that this will need an API refactor across several crates to ensure consistency, let's not do it in this PR (which is complicated enough as it is).

---

### str4d on `src/orchard_sighash_versioning.rs` (line 16)
**Date:** 2025-11-21T15:09:36Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2550076032
```diff
for Orchard signatures.
+
+use crate::primitives::redpallas::{Binding, SigType, Signature, SpendAuth};
+
+/// The Orchard Sighash version.
+/// Represented as a `u8` for compatibility with the PCZT encoding.
+#[repr(u8)]
+#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord)]
+pub enum OrchardSighashVersion {
+    /// Version V0.
+    V0 = 0,
+
+    /// No version (used for Orchard and TXv5 compatibility).
+    /// TXv5 does not require the sighash versioning bytes.
+    NoVersion = u8::MAX,
+}
```

A `repr(u8)` enum with unique values matching the `sighashVersion`s cannnot work here, because:
- The v0 sighash for tx v6 will almost certainly be different from the v0 sighash for tx v7.
- No PCZT encoding has been defined yet.
- We do not know in the `orchard` crate what the actual encoding of the sighash version will be; it requires knowledge of the transaction version in which the sighash is used (in addition to the sighash algorithm).
- Future sighash versions may have `associatedData`, which cannot be conveyed in an enum like this.

Instead of using version numbers for the enum variants, they should be the semantic digest operation that is expected here; the mapping from that to actual serialized version numbers should happen in `zcash_primitives`. This also means the `NoVersion` variant is unnecessary (the difference is handled by the tx serializer).
```suggestion
/// The kind of data that a sighash commits to.
///
/// This is used to implement [sighash versioning] for transactions containing Orchard
/// bundles.
///
/// [sighash versioning]: https://zips.z.cash/zip-0246#sighash-versioning
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum OrchardSighashKind {
    /// The "default" sighash that commits to all effecting data of the transaction.
    ///
    /// Corresponds to the Orchard parts of the following specifications:
    /// - [ZIP 244](https://zips.z.cash/zip-0244#s-4-orchard-digest)
    /// - [ZIP 246](https://zips.z.cash/zip-0246#s-4-orchard-digest)
    AllEffecting,
}
```

(Then when a new digest algorithm is defined for a given tx version that commits to a subset of data, we'd add a new variant here representing the commitment to the subset of Orchard; likewise if a bug is found in a given tx version's `AllEffecting` committed data, we'd add a new variant representing the fixed commitment strategy.)

As a result, this entire module should be rewritten to avoid mentioning "versioning" (other than by motivating reference in documentation like above) as that is a transaction-level concern, not an Orchard bundle-level concern.

> **PaulLaux** replied at 2026-02-04T09:11:41Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2762968194
> 
> Done in https://github.com/QED-it/orchard/pull/216/commits/57c33af24665829d6c1e756ad157d6fddc6205a0 as described in the comment.

---

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

### str4d on `src/action.rs` (line 181)
**Date:** 2025-11-21T15:29:28Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2550138371
```diff
aintext(),
+                out_ciphertext: encryptor.encrypt_outgoing_plaintext(cv_net, cmx, rng),
+            }
+        }
+
+        prop_compose! {
+            /// Generate an action without authorization data.
+            pub fn arb_unauthorized_action(spend_value: NoteValue, output_value: NoteValue)(
+                nf in arb_nullifier(),
+                rk in arb_spendauth_verification_key(),
+                note in arb_note(output_value),
+                asset in arb_asset_base(),
```

This is in the wrong place. The asset for the action should be an argument of `arb_unauthorized_action` alongside the spend and output values, otherwise the caller cannot leverage those existing arguments in any meaningful way.
```suggestion
```

> **PaulLaux** replied at 2026-02-04T09:19:15Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2762997690
> 
> added `asset` as an argument to `arb_action()` and `arb_unauthorized_action()` in https://github.com/QED-it/orchard/pull/216/commits/accdd2f6bcc101607bd7b1569a0410ccdc6aa0c1

---

### str4d on `src/action.rs` (line 214)
**Date:** 2025-11-21T15:30:13Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2550140892
```diff
ose! {
+            /// Generate an action with invalid (random) authorization data.
+            pub fn arb_action(spend_value: NoteValue, output_value: NoteValue)(
+                nf in arb_nullifier(),
+                sk in arb_spendauth_signing_key(),
+                note in arb_note(output_value),
+                rng_seed in prop::array::uniform32(prop::num::u8::ANY),
+                fake_sighash in prop::array::uniform32(prop::num::u8::ANY),
+                asset in arb_asset_base(),
```

Ditto:
```suggestion
```

> **PaulLaux** replied at 2026-02-04T09:22:27Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2763011050
> 
> done in https://github.com/QED-it/orchard/commit/accdd2f6bcc101607bd7b1569a0410ccdc6aa0c1

---

### str4d on `src/circuit/gadget/add_chip.rs` (line 1)
**Date:** 2025-11-21T15:33:23Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2550151848
```diff
@@ -1,3 +1,5 @@
+//! `Add` chip implemetation.
```

```suggestion
//! `Add` chip implementation.
```

> **PaulLaux** replied at 2026-02-04T09:23:58Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2763017694
> 
> fixed in https://github.com/QED-it/orchard/pull/216/commits/b5518f1b2688889b7eab8a92a773e1655ba5f95f

---

### str4d on `src/issuance_sighash_versioning.rs` (line 9)
**Date:** 2025-11-21T15:40:52Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2550178094
```diff
@@ -0,0 +1,37 @@
+//! This module defines the versioning for issuance authorization signatures.
+
+use crate::issuance_auth::{IssueAuthSig, IssueAuthSigScheme, ZSASchnorr};
+
+/// The Issuance Sighash version.
+#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
+pub enum IssueSighashVersion {
+    /// Version V0.
+    V0,
```

I think most of the same rationale applies here as for the Orchard sighash kind, i.e. this should be `AllEffecting` instead of `V0`.

I agree that it should be a separate enum from the Orchard sighash kind, at least for the current approach. This would in theory allow a `TransactionData` to be constructed that claimed to use incompatible `OrchardSighashKind` and `IssueSighashKind` values, but that *should* be detected and rejected at tx serialization time. I'll see if I can think of a cleaner approach...

> **PaulLaux** replied at 2026-02-04T09:27:12Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2763030419
> 
> done in https://github.com/QED-it/orchard/pull/216/commits/57c33af24665829d6c1e756ad157d6fddc6205a0 as a continuation of the approach described in https://github.com/zcash/orchard/pull/471#discussion_r2550076032

---

### str4d on `src/note/commitment.rs` (line 43)
**Date:** 2025-11-21T15:43:25Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2550187398
```diff
29 +38,52 @@ impl NoteCommitment {
 impl NoteCommitment {
     /// $NoteCommit^Orchard$.
     ///
-    /// Defined in [Zcash Protocol Spec § 5.4.8.4: Sinsemilla commitments][concretesinsemillacommit].
+    /// Defined in [ZIP-226: Transfer and Burn of Zcash Shielded Assets][notecommit].
     ///
-    /// [concretesinsemillacommit]: https://zips.z.cash/protocol/nu5.pdf#concretesinsemillacommit
-    pub(super) fn derive(
+    /// [notecommit]: https://zips.z.cash/zip-0226#note-structure-commitment
```

```suggestion
    /// [notecommit]: https://zips.z.cash/zip-0226#note-structure-and-commitment
```

> **PaulLaux** replied at 2026-02-04T09:33:35Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2763061136
> 
> Improved doc in https://github.com/QED-it/orchard/pull/216/commits/f0cf7ea231d340809bf6530bd5c900bf8b86a876
> and fixed concretely in https://github.com/QED-it/orchard/pull/216/commits/ec35bccfc1e67a974f34463871162aa00d385113

---

### str4d on `src/note/commitment.rs` (line 41)
**Date:** 2025-11-21T15:46:43Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2550196973
```diff
@@ -33,29 +38,52 @@ impl NoteCommitment {
 impl NoteCommitment {
     /// $NoteCommit^Orchard$.
     ///
-    /// Defined in [Zcash Protocol Spec § 5.4.8.4: Sinsemilla commitments][concretesinsemillacommit].
+    /// Defined in [ZIP-226: Transfer and Burn of Zcash Shielded Assets][notecommit].
```

Do not remove the existing reference; it is the correct reference for `$NoteCommit^Orchard$`. Instead reference both locations, and also mention `$NoteCommit^OrchardZSA$` in the docstring.

> **PaulLaux** replied at 2026-02-04T09:34:02Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2763063353
> 
> done in https://github.com/QED-it/orchard/commit/f0cf7ea231d340809bf6530bd5c900bf8b86a876

---

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

### str4d on `src/note/asset_base.rs` (line 34)
**Date:** 2025-11-21T16:12:47Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2550276814
```diff
ve(Clone, Copy, Debug, Eq)]
+pub struct AssetBase(pallas::Point);
+
+// AssetBase must implement PartialOrd and Ord to be used as a key in BTreeMap.
+impl PartialOrd for AssetBase {
+    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
+        Some(self.cmp(other))
+    }
+}
+
+impl Ord for AssetBase {
+    fn cmp(&self, other: &Self) -> Ordering {
+        let self_coord = self.0.to_affine().coordinates().unwrap();
+        let other_coord = other.0.to_affine().coordinates().unwrap();
```

Even though `self.0` cannot be the identity, I do not like that the `.unwrap()`s here. We should instead just compare the byte representations of `self` and `other`.

> **PaulLaux** replied at 2026-02-04T13:06:06Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2763932764
> 
> done in https://github.com/QED-it/orchard/pull/216/commits/b5518f1b2688889b7eab8a92a773e1655ba5f95f

---

### str4d on `src/note/asset_base.rs` (line 78)
**Date:** 2025-11-21T16:16:21Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2550287842
```diff
  asset_desc_hash: &[u8; 32],
+) -> Vec<u8> {
+    let ik_encoding = ik.encode();
+    let mut asset_id = Vec::with_capacity(1 + ik_encoding.len() + asset_desc_hash.len());
+    asset_id.push(version);
+    asset_id.extend(ik_encoding);
+    asset_id.extend_from_slice(&asset_desc_hash[..]);
+    asset_id
+}
+
+impl AssetBase {
+    /// Deserialize the AssetBase from a byte array.
+    pub fn from_bytes(bytes: &[u8; 32]) -> CtOption<Self> {
+        pallas::Point::from_bytes(bytes).map(AssetBase)
```

Bug: this needs to reject the identity, in order to correctly enforce the requirements on `AssetBase` specified in [ZIP 226](https://zips.z.cash/zip-0226#note-structure-and-commitment) when parsing note plaintexts.

> **PaulLaux** replied at 2026-02-04T13:08:50Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2763945818
> 
> done + doc in https://github.com/QED-it/orchard/pull/216/commits/dc861afa2d8257687f5a3082d107a7afe817b063

---

### str4d on `src/note/asset_base.rs` (line 49)
**Date:** 2025-11-21T16:38:03Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2550352041
```diff
       .x()
+            .cmp(other_coord.x())
+            .then_with(|| self_coord.y().cmp(other_coord.y()))
+    }
+}
+
+/// Personalization for the ZSA asset digest generator
+pub const ZSA_ASSET_DIGEST_PERSONALIZATION: &[u8; 16] = b"ZSA-Asset-Digest";
+
+///    AssetDigest for the ZSA asset
+///
+///    Defined in [ZIP-227: Issuance of Zcash Shielded Assets][assetdigest].
+///
+///    [assetdigest]: https://zips.z.cash/zip-0227.html#specification-asset-identifier-asset-digest-and-asset-base
```

```suggestion
/// Derives the Asset Digest for the given ZSA asset.
///
/// Defined in [ZIP-227: Issuance of Zcash Shielded Assets][assetdigest].
///
/// [assetdigest]: https://zips.z.cash/zip-0227#asset-digests
```

> **PaulLaux** replied at 2026-02-04T13:09:58Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2763951071
> 
> done in https://github.com/QED-it/orchard/pull/216/commits/b5518f1b2688889b7eab8a92a773e1655ba5f95f

---

### str4d on `src/note/asset_base.rs` (line 66)
**Date:** 2025-11-21T16:45:40Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2550373804
```diff
:new()
+        .hash_length(64)
+        .personal(ZSA_ASSET_DIGEST_PERSONALIZATION)
+        .to_state()
+        .update(encode_asset_id)
+        .finalize()
+}
+
+/// Encoding the Asset Identifier, as defined in [ZIP 227][assetidentifier].
+///
+/// [assetidentifier]: https://zips.z.cash/zip-0227.html#specification-asset-identifier-asset-digest-and-asset-base
+pub fn encode_asset_id(
+    version: u8,
+    ik: &IssueValidatingKey<ZSASchnorr>,
+    asset_desc_hash: &[u8; 32],
+) -> Vec<u8> {
```

This function mis-represents the relationship between its arguments. `version` is not an arbitrary parameter independent from `ik` and `asset_desc_hash`: by definition, if `version != 0`, the `ik` and `asset_desc_hash` parameters might not exist.

Either remove the `version` parameter and internally hard-code it to 0 (making this function solely for the version 0 protocol), or replace all of the arguments with an `AssetId` enum:
```rust
pub enum AssetId {
    V0 {
        ik: IssueValidatingKey<ZSASchnorr>,
        asset_desc_hash: [u8; 32],
    },
}
```
and then make this function a method of `AssetId` (as well as `asset_digest`).

> **PaulLaux** replied at 2026-02-04T13:15:17Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2763972589
> 
> We opt into replacing the args with `AssetId` enum, as suggested.
> Done in https://github.com/QED-it/orchard/pull/216/commits/382f31921f0382743a9d96ae6a0003a28ab5dc5c

---

### str4d on `src/note/asset_base.rs` (line 70)
**Date:** 2025-11-21T16:47:38Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2550380193
```diff
Identifier, as defined in [ZIP 227][assetidentifier].
+///
+/// [assetidentifier]: https://zips.z.cash/zip-0227.html#specification-asset-identifier-asset-digest-and-asset-base
+pub fn encode_asset_id(
+    version: u8,
+    ik: &IssueValidatingKey<ZSASchnorr>,
+    asset_desc_hash: &[u8; 32],
+) -> Vec<u8> {
+    let ik_encoding = ik.encode();
+    let mut asset_id = Vec::with_capacity(1 + ik_encoding.len() + asset_desc_hash.len());
+    asset_id.push(version);
+    asset_id.extend(ik_encoding);
```

While you're making changes here, update the variable names to match ZIP 227:
```suggestion
    let issuer = ik.encode();
    let mut asset_id = Vec::with_capacity(1 + issuer.len() + asset_desc_hash.len());
    asset_id.push(version);
    asset_id.extend(issuer);
```

> **PaulLaux** replied at 2026-02-04T13:17:04Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2763979830
> 
> done in https://github.com/QED-it/orchard/pull/216/commits/382f31921f0382743a9d96ae6a0003a28ab5dc5c

---

### str4d on `src/note/asset_base.rs` (line 50)
**Date:** 2025-11-21T16:50:07Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2550386724
```diff
hen_with(|| self_coord.y().cmp(other_coord.y()))
+    }
+}
+
+/// Personalization for the ZSA asset digest generator
+pub const ZSA_ASSET_DIGEST_PERSONALIZATION: &[u8; 16] = b"ZSA-Asset-Digest";
+
+///    AssetDigest for the ZSA asset
+///
+///    Defined in [ZIP-227: Issuance of Zcash Shielded Assets][assetdigest].
+///
+///    [assetdigest]: https://zips.z.cash/zip-0227.html#specification-asset-identifier-asset-digest-and-asset-base
+pub fn asset_digest(encode_asset_id: &[u8]) -> Blake2bHash {
```

I don't like this being a public method and taking an arbitrary unconstrained slice. If you take my earlier suggestion of introducing an `AssetId` enum with this as one of its methods, then this would instead take `&self` which is fine.

> **PaulLaux** replied at 2026-02-04T13:19:21Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2763988711
> 
> Indeed, after the changes in https://github.com/QED-it/orchard/pull/216/commits/382f31921f0382743a9d96ae6a0003a28ab5dc5c, it takes `&self`

---

### str4d on `src/note/asset_base.rs` (line 101)
**Date:** 2025-11-21T16:56:25Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2550403709
```diff
ml#asset-identifiers
+    ///
+    /// # Panics
+    ///
+    /// Panics if the derived AssetBase is the identity point.
+    #[allow(non_snake_case)]
+    pub fn derive(ik: &IssueValidatingKey<ZSASchnorr>, asset_desc_hash: &[u8; 32]) -> Self {
+        let version_byte: u8 = 0x00;
+
+        // EncodeAssetId(ik, asset_desc_hash) = version_byte || ik || asset_desc_hash
+        let asset_id = encode_asset_id(version_byte, ik, asset_desc_hash);
+        let asset_digest = asset_digest(&asset_id);
```

This should be named `AssetBase::custom` rather than `AssetBase::derive`, to match the "Custom Asset" terminology from ZIP 227.

If my enum suggestion is taken:
```suggestion
    pub fn custom(asset_id: &AssetId) -> Self 
        let asset_digest = asset_id.asset_digest();
```

> **PaulLaux** replied at 2026-02-04T13:19:52Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2763990697
> 
> done in https://github.com/QED-it/orchard/pull/216/commits/382f31921f0382743a9d96ae6a0003a28ab5dc5c

---

### str4d on `src/note/asset_base.rs` (line 90)
**Date:** 2025-11-21T16:57:34Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2550407188
```diff
om a byte array.
+    pub fn from_bytes(bytes: &[u8; 32]) -> CtOption<Self> {
+        pallas::Point::from_bytes(bytes).map(AssetBase)
+    }
+
+    /// Serialize the AssetBase to its canonical byte representation.
+    pub fn to_bytes(self) -> [u8; 32] {
+        self.0.to_bytes()
+    }
+
+    /// Note type derivation.
+    ///
+    /// Defined in [ZIP-226: Transfer and Burn of Zcash Shielded Assets][assetbase].
+    ///
+    /// [assetbase]: https://zips.z.cash/zip-0226.html#asset-identifiers
```

```suggestion
    /// Defined in [ZIP 227: Issuance of Zcash Shielded Assets][assetbase].
    ///
    /// [assetbase]: https://zips.z.cash/zip-0227#asset-bases
```

> **PaulLaux** replied at 2026-02-04T13:20:33Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2763993319
> 
> done in https://github.com/QED-it/orchard/pull/216/commits/382f31921f0382743a9d96ae6a0003a28ab5dc5c

---

### str4d on `src/note/asset_base.rs` (line 117)
**Date:** 2025-11-21T18:21:34Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2550615705
```diff
SET_BASE_PERSONALIZATION)(asset_digest.as_bytes());
+
+        // this will happen with negligible probability.
+        assert!(
+            bool::from(!asset_base.is_identity()),
+            "The Asset Base is the identity point, which is invalid."
+        );
+
+        // AssetBase = ZSAValueBase(AssetDigest)
+        AssetBase(asset_base)
+    }
+
+    /// Note type for the "native" currency (zec), maintains backward compatibility with Orchard untyped notes.
+    pub fn native() -> Self {
```

I just noticed that ZIP 227's terminology section defines "Native Asset" as "a Custom Asset with issuance defined on the Zcash blockchain" (first introduced in https://github.com/QED-it/zips/commit/97eacabbef9377ede457bf6faff92cc53513cd9f), where "Custom Asset" is "any Asset other than ZEC and TAZ" (first introduced in https://github.com/QED-it/zips/commit/8ed51c2444418e5eb675d94e7290bd9476fef138). Thus the entire usage of `native` / `is_native` in this PR is inconsistent with ZIP 227, and should be reworked to use a different term.

Non-blocking for this PR, but blocking the first `orchard` release containing this PR; open an issue for addressing this.

> **daira** replied at 2025-12-08T19:04:34Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2599795093
> 
> The definitions in ZIP 227 don't make sense to me (I think I have mentioned this but not loudly enough). For reference here they are:
> 
> > * Asset: A type of note that can be transferred on the Zcash blockchain. [...]
> >
> >   * ZEC is the default (and currently the only defined) Asset for the Zcash mainnet.
> >   * TAZ is the default (and currently the only defined) Asset for the Zcash testnet.
> >   * We use the term "Custom Asset" to refer to any Asset other than ZEC and TAZ.
> >
> > * Native Asset: a Custom Asset with issuance defined on the Zcash blockchain.
> > * Wrapped Asset: a Custom Asset with native issuance defined outside the Zcash blockchain.
> 
> The problem is that I don't think the "Native Asset" vs "Wrapped Asset" distinction is well-defined or useful. There is only one mechanism for issuing ZSA notes: the holder of an issuance authorizing key uses it to sign the sighash of an issuance transaction (and currently unused auxiliary data). The distinction that the "Native Asset" and "Wrapped Asset" definitions are trying to make is entirely invisible to the protocol. Therefore it should not be in ZIP 227.

> **vivek-arte** replied at 2026-01-30T05:45:10Z:
> 
> To tie up the loose end regarding the ZIP definitions - the ZIP definitions have since been updated in https://github.com/zcash/zips/pull/1155, which fixes the ZIPs concern.

---

### str4d on `src/note/asset_base.rs` (line 120)
**Date:** 2025-11-21T18:22:00Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2550616659
```diff
   bool::from(!asset_base.is_identity()),
+            "The Asset Base is the identity point, which is invalid."
+        );
+
+        // AssetBase = ZSAValueBase(AssetDigest)
+        AssetBase(asset_base)
+    }
+
+    /// Note type for the "native" currency (zec), maintains backward compatibility with Orchard untyped notes.
+    pub fn native() -> Self {
+        AssetBase(pallas::Point::hash_to_curve(
+            VALUE_COMMITMENT_PERSONALIZATION,
+        )(&NATIVE_ASSET_BASE_V_BYTES[..]))
```

The slice notation should not be necessary hereh (it isn't present in the existing equivalent call that is deleted in this PR):
```suggestion
        )(&NATIVE_ASSET_BASE_V_BYTES))
```

> **PaulLaux** replied at 2026-02-04T20:06:40Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2765785384
> 
> removed slice notation in https://github.com/QED-it/orchard/pull/216/commits/b5518f1b2688889b7eab8a92a773e1655ba5f95f
> renamed to `ZATOSHI_ASSET_BASE_V_BYTES` in https://github.com/QED-it/orchard/pull/216/commits/d8caa76a5dc3cdbc6fd2c4e97d61a1f0fe54af79.
> 
> 
> The second change was done following our conversation that we agreed to replace Native with Zatoshi. 
> 
> However in this function, we get 
> ```rust
>     /// Note type for zatoshi, maintains backward compatibility with Orchard untyped notes.
>     pub fn zatoshi() -> Self {
>         AssetBase(pallas::Point::hash_to_curve(
>             VALUE_COMMITMENT_PERSONALIZATION,
>         )(&ZATOSHI_ASSET_BASE_V_BYTES))
>     }
> ```
> Is this really what we want? (`ZATOSHI_ASSET_BASE_V_BYTES` sounds a bit strange)

---

### str4d on `src/note/asset_base.rs` (line 177)
**Date:** 2025-11-21T18:38:34Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2550650833
```diff
ndencies")))]
+pub mod testing {
+    use super::AssetBase;
+
+    use proptest::prelude::*;
+
+    use crate::issuance_auth::{
+        testing::arb_issuance_authorizing_key, IssueValidatingKey, ZSASchnorr,
+    };
+
+    prop_compose! {
+        /// Generate a uniformly distributed note type
+        pub fn arb_asset_base()(
+            is_native in prop::bool::ANY,
+            isk in arb_issuance_authorizing_key(),
+            asset_desc_hash in any::<[u8; 32]>(),
+        ) -> AssetBase {
```

Nit: we should only get arbitrary `(isk, asset_desc_hash)` if `is_native`; the generation should be conditional. I think you do this with a second sequence of arguments? We essentially want the equivalent of `(!is_native).then(|| arb_zsa_asset_base())`.

> **PaulLaux** replied at 2026-02-04T20:19:29Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2765826466
> 
> Done in https://github.com/QED-it/orchard/pull/216/commits/058964217044d9c51dac9b0f9708429fb55ef41e
> 
> Now `prop_oneof!` randomly selects one branch per test case:
> ```rust
>         pub fn arb_asset_base()
>             (asset in prop_oneof![
>                 Just(AssetBase::native()),
>                 arb_zsa_asset_base(),
>             ])
>             -> AssetBase
>         {
>             asset
>         }
> ```

---

### str4d on `src/circuit/circuit_vanilla.rs` (line 6)
**Date:** 2025-12-01T21:16:33Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2578704772
```diff
@@ -0,0 +1,883 @@
+//! The Orchard Action circuit implementation for the Vanilla variation of the Orchard protocol.
+//!
+//! Includes the configuration, synthesis, and proof verification logic.
+
+// Review hint: this file is largely derived from src/circuit.rs
+
```

We indeed leveraged this by reviewing:
```
git diff main zsa1 \
  -M \
  --color-moved=dimmed-zebra \
  --color-moved-ws=allow-indentation-change \
  src/circuit*
```

```suggestion
```

> **PaulLaux** replied at 2026-02-04T20:28:07Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2765852858
> 
> Nice
> Removed hint in https://github.com/QED-it/orchard/pull/216/commits/fec254a591e97036a1fe5fedf189f00c4404434c

---

### str4d on `src/bundle.rs` (line 6)
**Date:** 2025-12-03T15:14:34Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2585521988
```diff
@@ -1,5 +1,6 @@
 //! Structs related to bundles of Orchard actions.
 
+pub mod burn_validation;
 use alloc::vec::Vec;
 
 pub mod commitments;
```

Wow the imports in this file are scuffed for some reason. But no need to make them moreso by mixing module definitions with unrelated imports.
```suggestion
use alloc::vec::Vec;

pub mod burn_validation;
pub mod commitments;
```

> **PaulLaux** replied at 2026-02-04T20:34:55Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2765874889
> 
> done in https://github.com/QED-it/orchard/pull/216/commits/f83d6526e09a5480ce83f4e358ee957954eae1e5

---

### str4d on `src/bundle.rs` (line 76)
**Date:** 2025-12-03T15:18:37Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2585536670
```diff
@@ -66,37 +70,65 @@ pub struct Flags {
     /// guaranteed to be dummy notes. If `true`, the created notes may be either real or
     /// dummy notes.
     outputs_enabled: bool,
+    /// Flag denoting whether ZSA transaction is enabled.
+    ///
+    /// If `false`,  all notes within [`Action`]s in the transaction's [`Bundle`] are
+    /// guaranteed to be notes with native asset.
```

```suggestion
    /// Flag denoting whether ZSA functionality is enabled in the transaction.
    ///
    /// If `false`, all notes within [`Action`]s in the transaction's [`Bundle`] are
    /// guaranteed to be notes with native asset. If `true`, `Action`s may use any asset.
```

> **PaulLaux** replied at 2026-02-04T20:36:25Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2765880040
> 
> done in https://github.com/QED-it/orchard/commit/f83d6526e09a5480ce83f4e358ee957954eae1e5

---

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

### str4d on `src/bundle.rs` (line 155)
**Date:** 2025-12-03T15:20:36Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2585544143
```diff
@@ -117,6 +149,14 @@ impl Flags {
         self.outputs_enabled
     }
 
+    /// Flag denoting whether ZSA transaction is enabled.
+    ///
+    /// If `false`,  all notes within [`Action`]s in the transaction's [`Bundle`] are
+    /// guaranteed to be notes with native asset.
```

```suggestion
    /// Flag denoting whether ZSA functionality is enabled in the transaction.
    ///
    /// If `false`, all notes within [`Action`]s in the transaction's [`Bundle`] are
    /// guaranteed to be notes with native asset. If `true`, `Action`s may use any asset.
```

> **PaulLaux** replied at 2026-02-04T20:37:12Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2765882992
> 
> done in https://github.com/QED-it/orchard/pull/216/commits/f83d6526e09a5480ce83f4e358ee957954eae1e5

---

### str4d on `src/bundle.rs` (line 100)
**Date:** 2025-12-03T15:21:16Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2585546655
```diff
lf {
+    pub(crate) const fn from_parts(
+        spends_enabled: bool,
+        outputs_enabled: bool,
+        zsa_enabled: bool,
+    ) -> Self {
         Flags {
             spends_enabled,
             outputs_enabled,
+            zsa_enabled,
         }
     }
 
-    /// The flag set with both spends and outputs enabled.
-    pub const ENABLED: Flags = Flags {
+    /// The flag set with both spends and outputs enabled and ZSA disabled.
+    pub const ENABLED_WITHOUT_ZSA: Flags = Flags {
```

Undo this rename; it is unnecessary churn (and you already chose not to rename `OUTPUTS_DISABLED`).
```suggestion
    pub const ENABLED: Flags = Flags {
```

> **PaulLaux** replied at 2026-02-04T20:38:15Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2765886319
> 
> done in https://github.com/QED-it/orchard/pull/216/commits/f83d6526e09a5480ce83f4e358ee957954eae1e5

---

### str4d on `src/bundle.rs` (line 114)
**Date:** 2025-12-03T15:21:38Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2585548116
```diff
abled and ZSA disabled.
+    pub const ENABLED_WITHOUT_ZSA: Flags = Flags {
+        spends_enabled: true,
+        outputs_enabled: true,
+        zsa_enabled: false,
+    };
+
+    /// The flags set with spends, outputs and ZSA enabled.
+    pub const ENABLED_WITH_ZSA: Flags = Flags {
         spends_enabled: true,
         outputs_enabled: true,
+        zsa_enabled: true,
+    };
+
+    /// The flag set with spends and ZSA disabled.
+    pub const SPENDS_DISABLED_WITHOUT_ZSA: Flags = Flags {
```

Undo this rename; it is unnecessary churn (and you already chose not to rename `OUTPUTS_DISABLED`).
```suggestion
    pub const SPENDS_DISABLED: Flags = Flags {
```

> **PaulLaux** replied at 2026-02-04T20:38:40Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2765887825
> 
> done in https://github.com/QED-it/orchard/pull/216/commits/f83d6526e09a5480ce83f4e358ee957954eae1e5

---

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

### str4d on `src/bundle.rs` (line 223)
**Date:** 2025-12-03T15:38:43Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2585611775
```diff
Orchard spends minus the sum of Orchard outputs.
     value_balance: V,
+    /// Assets intended for burning
+    burn: Vec<(AssetBase, NoteValue)>,
     /// The root of the Orchard commitment tree that this bundle commits to.
     anchor: Anchor,
+    /// Block height after which this Bundle's Actions are invalid by consensus.
+    ///
+    /// For the OrchardZSA protocol, `expiry_height` is set to 0, indicating no expiry.
+    /// This field is reserved for future use.
+    expiry_height: u32,
```

Possible consensus bug: the changes here cannot represent multi-Action Group bundles.

I first noticed that there's a structural problem here: Orchard bundles do not have expiry heights, Orchard Action Groups do. I then realised that you are not introducing Action Groups in this PR, which I think causes a consensus problem: AFAICT there is no rule in ZIP 230 requiring that `nActionGroupsOrchard` must be set to either 0 or 1 in NU7, but the changes in this PR mean that `nActionGroupsOrchard > 1` is unrepresentable.

I note that there *is* a consensus rule in [ZIP 227](https://zips.z.cash/zip-0227#specification-consensus-rule-changes) for this (along with the same consensus rule on `nAGExpiryHeight` as in ZIP 230 that it must be set to 0 in NU7, effectively disabling it until a future NU), but if left purely as a consensus rule then the parser must support parsing `ActionGroup`s (in order to then be visible to the consensus rule engine).

I suspect that what you actually intended was for the `nActionGroupsOrchard` consensus rule to be noted in ZIP 230, so that transaction parsers that observe the NU7 branch ID in the transaction header can enforce it themselves. If that's the case, then the mapping from the ZIP 230 encoding to this `Bundle` struct can be done entirely at parsing time, including checking those two fields are set to their expected hard-coded values. If that is not the case, then this PR needs further reworking to introduce an `ActionGroup` struct.

In either case, there is no need to include this field all at this time due to it being hard-coded in consensus (and in any case it is incorrect to include here; it would go onto the `ActionGroup`):
```suggestion
```

> **PaulLaux** replied at 2026-02-04T20:52:54Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2765933298
> 
> Indeed, removed `expiry_height: u32` from OrchardZSA in https://github.com/QED-it/orchard/pull/216/commits/6c3de5dc63414329d30a7cfa86a555b7e5261142
> 
> and now using the tx parser to enforce the `expiry_height = 0` consensus rule (in librustzcash).

---

### str4d on `src/bundle.rs` (line 265)
**Date:** 2025-12-03T15:39:01Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2585613027
```diff
>,
+        actions: NonEmpty<Action<A::SpendAuth, P>>,
         flags: Flags,
         value_balance: V,
+        burn: Vec<(AssetBase, NoteValue)>,
         anchor: Anchor,
-        authorization: T,
+        authorization: A,
     ) -> Self {
         Bundle {
             actions,
             flags,
             value_balance,
+            burn,
             anchor,
+            // For the OrchardZSA protocol, `expiry_height` is set to 0, indicating no expiry.
+            expiry_height: 0,
```

```suggestion
```

> **PaulLaux** replied at 2026-02-04T20:53:41Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2765935736
> 
> removed in https://github.com/QED-it/orchard/commit/6c3de5dc63414329d30a7cfa86a555b7e5261142

---

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

### str4d on `src/bundle.rs` (line 301)
**Date:** 2025-12-03T15:39:41Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2585615651
```diff
@@ impl<T: Authorization, V> Bundle<T, V> {
         &self.value_balance
     }
 
+    /// Returns assets intended for burning
+    pub fn burn(&self) -> &Vec<(AssetBase, NoteValue)> {
+        &self.burn
+    }
+
     /// Returns the root of the Orchard commitment tree that this bundle commits to.
     pub fn anchor(&self) -> &Anchor {
         &self.anchor
     }
 
+    /// Returns the expiry height for this bundle.
+    pub fn expiry_height(&self) -> u32 {
+        self.expiry_height
+    }
+
```

```suggestion
```

> **PaulLaux** replied at 2026-02-04T20:54:09Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2765937143
> 
> removed in https://github.com/QED-it/orchard/commit/6c3de5dc63414329d30a7cfa86a555b7e5261142

---

### str4d on `src/bundle.rs` (line 321)
**Date:** 2025-12-03T15:40:01Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2585617028
```diff
@@ -246,12 +311,14 @@ impl<T: Authorization, V> Bundle<T, V> {
     pub fn try_map_value_balance<V0, E, F: FnOnce(V) -> Result<V0, E>>(
         self,
         f: F,
-    ) -> Result<Bundle<T, V0>, E> {
+    ) -> Result<Bundle<A, V0, P>, E> {
         Ok(Bundle {
             actions: self.actions,
             flags: self.flags,
             value_balance: f(self.value_balance)?,
+            burn: self.burn,
             anchor: self.anchor,
+            expiry_height: self.expiry_height,
```

```suggestion
```

> **PaulLaux** replied at 2026-02-04T20:54:28Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2765938213
> 
> removed in https://github.com/QED-it/orchard/commit/6c3de5dc63414329d30a7cfa86a555b7e5261142

---

### str4d on `src/bundle.rs` (line 342)
**Date:** 2025-12-03T15:40:17Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2585618253
```diff
:SpendAuth) -> U::SpendAuth,
+        step: impl FnOnce(&mut R, A) -> U,
+    ) -> Bundle<U, V, P> {
         let authorization = self.authorization;
         Bundle {
             actions: self
                 .actions
                 .map(|a| a.map(|a_auth| spend_auth(context, &authorization, a_auth))),
             flags: self.flags,
             value_balance: self.value_balance,
+            burn: self.burn,
             anchor: self.anchor,
+            expiry_height: self.expiry_height,
```

```suggestion
```

> **PaulLaux** replied at 2026-02-04T20:54:43Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2765939007
> 
> removed in https://github.com/QED-it/orchard/commit/6c3de5dc63414329d30a7cfa86a555b7e5261142

---

### str4d on `src/bundle.rs` (line 367)
**Date:** 2025-12-03T15:40:25Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2585618943
```diff
@@ -293,7 +362,9 @@ impl<T: Authorization, V> Bundle<T, V> {
             actions: NonEmpty::from_vec(new_actions).unwrap(),
             flags: self.flags,
             value_balance: self.value_balance,
+            burn: self.burn,
             anchor: self.anchor,
+            expiry_height: self.expiry_height,
```

```suggestion
```

> **PaulLaux** replied at 2026-02-04T20:54:49Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2765939333
> 
> removed in https://github.com/QED-it/orchard/commit/6c3de5dc63414329d30a7cfa86a555b7e5261142

---

### str4d on `src/bundle.rs` (line 478)
**Date:** 2025-12-03T15:43:07Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2585631816
```diff
thorization, V: Copy + Into<i64>> Bundle<T, V> {
+pub(crate) fn derive_bvk<A, V: Clone + Into<i64>, P: OrchardPrimitives>(
+    actions: &NonEmpty<Action<A, P>>,
+    value_balance: V,
+    burn: &[(AssetBase, NoteValue)],
+) -> redpallas::VerificationKey<Binding> {
+    let cv_nets: Vec<_> = actions.into_iter().map(|a| a.cv_net().clone()).collect();
+    derive_bvk_raw(&cv_nets, ValueSum::from_raw(value_balance.into()), burn)
+}
+
+pub(crate) fn derive_bvk_raw(
+    cv_nets: &[ValueCommitment],
```

This should take an `impl Iterator`, which would both avoid the `.collect()`s in the two callsites, and also be easier for when Action Groups are introduced.

> **PaulLaux** replied at 2026-02-04T20:57:38Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2765948059
> 
> moved to `impl Iterator` in https://github.com/QED-it/orchard/pull/216/commits/f83d6526e09a5480ce83f4e358ee957954eae1e5

---

### str4d on `src/bundle.rs` (line 482)
**Date:** 2025-12-03T15:44:06Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2585636883
```diff
>>,
+    value_balance: V,
+    burn: &[(AssetBase, NoteValue)],
+) -> redpallas::VerificationKey<Binding> {
+    let cv_nets: Vec<_> = actions.into_iter().map(|a| a.cv_net().clone()).collect();
+    derive_bvk_raw(&cv_nets, ValueSum::from_raw(value_balance.into()), burn)
+}
+
+pub(crate) fn derive_bvk_raw(
+    cv_nets: &[ValueCommitment],
+    value_balance: ValueSum,
+    burn: &[(AssetBase, NoteValue)],
+) -> redpallas::VerificationKey<Binding> {
+    (cv_nets.iter().sum::<ValueCommitment>()
```

Please do not delete consensus rule references.
```suggestion
    // https://p.z.cash/TCR:bad-txns-orchard-binding-signature-invalid?partial
    (cv_nets.iter().sum::<ValueCommitment>()
```

> **PaulLaux** replied at 2026-02-04T20:58:19Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2765950320
> 
> restored in https://github.com/QED-it/orchard/pull/216/commits/f83d6526e09a5480ce83f4e358ee957954eae1e5

---

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

### str4d on `src/bundle.rs` (line 563)
**Date:** 2025-12-03T15:56:16Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2585689194
```diff
BundleAuthorizingCommitment {
-        BundleAuthorizingCommitment(hash_bundle_auth_data(self))
+    /// The `sighash_version_map` provides the mapping from each
+    /// `OrchardSighashVersion` to the corresponding `SighashInfo`
+    /// encoding.
+    pub fn authorizing_commitment(
+        &self,
+        sighash_version_map: &BTreeMap<OrchardSighashVersion, Vec<u8>>,
+    ) -> BundleAuthorizingCommitment {
+        BundleAuthorizingCommitment(hash_bundle_auth_data(self, sighash_version_map))
```

This feels wrong to me; it implies that the `sighashInfo` comes from outside the transaction, but ZIP 230 is clear that it is encoded as part of `OrchardSignature` and thus should already be present within `self`.

Per my earlier review comment, after refactoring `OrchardSighashVersion` into `OrchardSighashKind ` as I suggested, `sighashInfo` *would* be stored within `self` in some in-memory representation, and then I think instead of passing a map here, we'd want to pass a closure that takes the `OrchardSighashKind` and returns the encoding of its `sighashInfo`.

> **PaulLaux** replied at 2026-02-04T21:03:59Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2765970321
> 
> Following the previous changes (rename to `OrchardSighashKind`), we changed `authorizing_commitment` to take a closure instead of a map in https://github.com/QED-it/orchard/pull/216/commits/57c33af24665829d6c1e756ad157d6fddc6205a0
> 
> ```rust
>     pub fn authorizing_commitment(
>         &self,
>         sighash_info_for_kind: impl Fn(&OrchardSighashKind) -> &'static [u8],
>     ) -> BundleAuthorizingCommitment {..}
> ```

---

### str4d on `src/circuit/orchard_sinsemilla_chip.rs`
**Date:** 2025-12-08T16:33:37Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2599305911
```diff
@@ -0,0 +1,88 @@
+//! Defines the `OrchardSinsemillaChip` trait to abstract over `SinsemillaChip` and `SinsemillaChip` types.
```

Comment looks wrong; probably means to reference `SinsemillaInstructions` somewhere. Fix as appropriate.

> **PaulLaux** replied at 2026-02-04T21:09:40Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2765988428
> 
> fixed comment in https://github.com/QED-it/orchard/pull/216/commits/4f0357336d94b670259a71d4034f9fbb002dac1e

---

### str4d on `src/circuit/gadget.rs`
**Date:** 2025-12-08T16:43:25Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2599340202
```diff
chip_new(&self) -> NoteCommitChip<Lookup> {
         NoteCommitChip::construct(self.new_note_commit_config.clone())
     }
 
-    pub(super) fn note_commit_chip_old(&self) -> NoteCommitChip {
+    pub(super) fn note_commit_chip_old(&self) -> NoteCommitChip<Lookup> {
         NoteCommitChip::construct(self.old_note_commit_config.clone())
     }
+
+    pub(super) fn cond_swap_chip(&self) -> CondSwapChip<pallas::Base> {
+        CondSwapChip::construct(self.merkle_config_1.cond_swap_config.clone())
```

In `halo2_gadgets 0.4.0` (specifically https://github.com/zcash/halo2/commit/a73ad8f80ae9b8a7c0967eac6223e920dd843581) I changed this to be a new method instead of partially-exposed fields. When `orchard 0.12.0` gets merged into the integration branch, this will become:
```suggestion
        CondSwapChip::construct(self.merkle_config_1.cond_swap_config().clone())
```

> **PaulLaux** replied at 2026-02-05T06:54:45Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2767414209
> 
> we upgraded to `halo2_gadgets 0.4.0` and made the mentioned change in https://github.com/QED-it/orchard/commit/4f0357336d94b670259a71d4034f9fbb002dac1e

---

### str4d on `src/circuit/value_commit_orchard.rs`
**Date:** 2025-12-08T16:54:42Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2599374820
```diff
                  &v_net_magnitude_sign.1,
+                )?
+            }
+        };
+
+        // blind = [rcv] ValueCommitR
+        let (blind, _rcv) = {
+            let value_commit_r = OrchardFixedBasesFull::ValueCommitR;
+            let value_commit_r = FixedPoint::from_inner(ecc_chip, value_commit_r);
+
+            // [rcv] ValueCommitR
+            value_commit_r.mul(layouter.namespace(|| "[rcv] ValueCommitR"), rcv)?
+        };
+
+        // [v] ValueCommitV + [rcv] ValueCommitR
```

```suggestion
        // [v_net_magnitude_sign] asset_base + [rcv] ValueCommitR
```

> **PaulLaux** replied at 2026-02-05T07:00:23Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2767430055
> 
> done in https://github.com/QED-it/orchard/pull/216/commits/4f0357336d94b670259a71d4034f9fbb002dac1e

---

### str4d on `src/circuit/value_commit_orchard.rs`
**Date:** 2025-12-08T16:57:32Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2599387594
```diff
gnitude_asset = [magnitude] asset
+                let magnitude_asset = {
+                    let magnitude_scalar = ScalarVar::from_base(
+                        ecc_chip.clone(),
+                        layouter.namespace(|| "magnitude"),
+                        &v_net_magnitude_sign.0,
+                    )?;
+                    let (magnitude_asset, _) = params
+                        .asset
+                        .mul(layouter.namespace(|| "[magnitude] asset"), magnitude_scalar)?;
```

Rename this field to be clearer:
```suggestion
                        .asset_base
                        .mul(layouter.namespace(|| "[magnitude] asset_base"), magnitude_scalar)?;
```

> **PaulLaux** replied at 2026-02-05T07:00:48Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2767431165
> 
> done in https://github.com/QED-it/orchard/pull/216/commits/4f0357336d94b670259a71d4034f9fbb002dac1e

---

### str4d on `src/circuit/value_commit_orchard.rs`
**Date:** 2025-12-08T16:58:01Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2599389930
```diff
                &v_net_magnitude_sign.0,
+                    )?;
+                    let (magnitude_asset, _) = params
+                        .asset
+                        .mul(layouter.namespace(|| "[magnitude] asset"), magnitude_scalar)?;
+                    magnitude_asset
+                };
+
+                // commitment = [sign] magnitude_asset = [v_net_magnitude_sign] asset
+                magnitude_asset.mul_sign(
+                    layouter.namespace(|| "[sign] commitment"),
```

```suggestion
                    layouter.namespace(|| "[sign] magnitude_asset"),
```

> **PaulLaux** replied at 2026-02-05T07:01:08Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2767432019
> 
> done in https://github.com/QED-it/orchard/pull/216/commits/4f0357336d94b670259a71d4034f9fbb002dac1e

---

### str4d on `src/circuit/value_commit_orchard.rs`
**Date:** 2025-12-08T16:59:52Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2599397621
```diff
+                    let (magnitude_asset, _) = params
+                        .asset
+                        .mul(layouter.namespace(|| "[magnitude] asset"), magnitude_scalar)?;
+                    magnitude_asset
+                };
+
+                // commitment = [sign] magnitude_asset = [v_net_magnitude_sign] asset
+                magnitude_asset.mul_sign(
+                    layouter.namespace(|| "[sign] commitment"),
+                    &v_net_magnitude_sign.1,
+                )?
```

I have not reviewed this circuit logic.

---

### str4d on `src/circuit/derive_nullifier.rs`
**Date:** 2025-12-08T17:01:58Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2599406000
```diff
@@ -0,0 +1,112 @@
+//! Derive nullifier logic for the Orchard circuit.
+
+use crate::constants::nullifier_l::nullifier_l;
+use halo2_gadgets::utilities::cond_swap::CondSwapChip;
+use halo2_proofs::circuit::AssignedCell;
+use pasta_curves::pallas;
+
+pub struct ZsaNullifierParams {
+    pub cond_swap_chip: CondSwapChip<pallas::Base>,
+    pub split_flag: AssignedCell<pallas::Base, pallas::Base>,
```

To clarify their actual publicity:
```suggestion
pub(super) struct ZsaNullifierParams {
    pub(super) cond_swap_chip: CondSwapChip<pallas::Base>,
    pub(super) split_flag: AssignedCell<pallas::Base, pallas::Base>,
```

> **PaulLaux** replied at 2026-02-05T07:01:29Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2767432860
> 
> done in https://github.com/QED-it/orchard/pull/216/commits/4f0357336d94b670259a71d4034f9fbb002dac1e

---

### str4d on `src/circuit/derive_nullifier.rs`
**Date:** 2025-12-08T17:20:43Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2599465276
```diff
+            None => Ok(nf.extract_p()),
+            Some(zsa_params) => {
+                // Add NullifierL to nf
+                // split_note_nf = NullifierL + nf
+                let nullifier_l = Point::new_from_constant(
+                    ecc_chip.clone(),
+                    layouter.namespace(|| "witness NullifierL constant"),
+                    nullifier_l(),
+                )?;
+                let split_note_nf = nullifier_l.add(layouter.namespace(|| "split_note_nf"), &nf)?;
```

I have not checked that `.add()` is the correct addition function to use here.

---

### str4d on `src/circuit/value_commit_orchard.rs`
**Date:** 2025-12-08T17:33:54Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2599503258
```diff
 SinsemillaConfig},
+        utilities::lookup_range_check::{
+            LookupRangeCheck4_5BConfig, PallasLookupRangeCheck4_5BConfig,
+        },
+    };
+
+    use group::Curve;
+    use halo2_proofs::{
+        circuit::{Layouter, SimpleFloorPlanner, Value},
+        dev::MockProver,
+        plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance},
+    };
+    use pasta_curves::pallas;
+
+    use rand::{rngs::OsRng, RngCore};
+
+    #[test]
+    fn test_value_commit_orchard() {
```

```suggestion
    fn test_value_commit_orchard_zsa() {
```
because the test hard-codes `Some(ZsaValueCommitParams { .. })` and thus is only testing the OrchardZSA version of `value_commit_orchard()`.

> **PaulLaux** replied at 2026-02-05T07:05:33Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2767443396
> 
> done in https://github.com/QED-it/orchard/commit/4f0357336d94b670259a71d4034f9fbb002dac1e

---

### str4d on `src/test_vectors/zip32.rs`
**Date:** 2025-12-08T17:38:55Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2599516192
```diff
@@ -1,4 +1,4 @@
-//! Test vectors for Orchard ZIP 32 key derivation.
+// From https://github.com/zcash-hackworks/zcash-test-vectors/blob/master/orchard_zip32.py
```

Undo this change: move the comment back where it was, and re-introduce the module comment (which is present to document this module in the context of the `orchard` crate, and obviously not going to be present in the test vector generator).

> **PaulLaux** replied at 2026-02-05T07:08:36Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2767455624
> 
> done in https://github.com/QED-it/orchard/pull/216/commits/f83d6526e09a5480ce83f4e358ee957954eae1e5

---

### str4d on `src/primitives/compact_action.rs`
**Date:** 2025-12-08T17:52:25Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2599562825
```diff
&self) -> EphemeralKeyBytes {
+        EphemeralKeyBytes(self.ephemeral_key.0)
+    }
+
+    fn cmstar(&self) -> &ExtractedNoteCommitment {
+        &self.cmx
+    }
+
+    fn cmstar_bytes(&self) -> [u8; 32] {
+        self.cmx.to_bytes()
+    }
+
+    fn enc_ciphertext(&self) -> Option<&P::NoteCiphertextBytes> {
+        None
+    }
+
+    fn enc_ciphertext_compact(&self) -> P::CompactNoteCiphertextBytes {
+        P::CompactNoteCiphertextBytes::from_slice(self.enc_ciphertext.as_ref()).unwrap()
```

```suggestion
        self.enc_ciphertext.clone()
```
and alter the `OrchardPrimitives::CompactNoteCiphertextBytes` associated type bounds as necessary to be `Clone`.

> **PaulLaux** replied at 2026-02-05T07:17:07Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2767483026
> 
> Done in https://github.com/QED-it/orchard/pull/216/commits/f83d6526e09a5480ce83f4e358ee957954eae1e5
> 
> Used `self.enc_ciphertext` directly - the `NoteBytes` trait already requires Copy, so no additional bounds needed.
> 

---

### str4d on `src/primitives/compact_action.rs`
**Date:** 2025-12-08T17:53:04Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2599565711
```diff
ctedNoteCommitment {
+        self.cmx()
+    }
+
+    fn cmstar_bytes(&self) -> [u8; 32] {
+        self.cmx().to_bytes()
+    }
+
+    fn enc_ciphertext(&self) -> Option<&P::NoteCiphertextBytes> {
+        Some(&self.encrypted_note().enc_ciphertext)
+    }
+
+    fn enc_ciphertext_compact(&self) -> P::CompactNoteCiphertextBytes {
+        P::CompactNoteCiphertextBytes::from_slice(
+            &self.encrypted_note().enc_ciphertext.as_ref()[..P::COMPACT_NOTE_SIZE],
+        )
+        .unwrap()
```

```suggestion
        .expect("P::CompactNoteCiphertextBytes should have size P::COMPACT_NOTE_SIZE")
```

> **PaulLaux** replied at 2026-02-05T07:20:52Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2767493813
> 
> updated to      `.expect("Pr::CompactNoteCiphertextBytes should have size Pr::COMPACT_NOTE_SIZE")` in https://github.com/QED-it/orchard/pull/216/commits/f83d6526e09a5480ce83f4e358ee957954eae1e5
> 
> to take the rename `P` -> `Pr` into account.
> 

---

### str4d on `src/primitives/compact_action.rs`
**Date:** 2025-12-08T17:54:50Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2599572079
```diff
@@ -0,0 +1,181 @@
+//! Defines actions for Orchard shielded outputs and compact action for light clients.
+
+// Review hint: this file is largely derived from src/note_encryption.rs
+
```

```suggestion
```

> **PaulLaux** replied at 2026-02-05T07:21:27Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2767495443
> 
> removed in https://github.com/QED-it/orchard/pull/216/commits/f83d6526e09a5480ce83f4e358ee957954eae1e5

---

### str4d on `src/primitives/orchard_domain.rs`
**Date:** 2025-12-08T17:58:09Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2599584010
```diff
ecific note encryption domain.
+
+// Review hint: this file is largely derived from src/note_encryption.rs
+
+use crate::{
+    action::Action, note::Rho, primitives::compact_action::CompactAction,
+    primitives::orchard_primitives::OrchardPrimitives,
+};
+
+/// Orchard-specific note encryption logic.
+#[derive(Debug, Clone)]
+pub struct OrchardDomain<P: OrchardPrimitives> {
+    /// A parameter needed to generate the nullifier.
+    pub rho: Rho,
+    phantom: core::marker::PhantomData<P>,
+}
```

Bug: Missing `memuse::DynamicUsage` impl that was not moved from `src/note_encryption.rs`:
```suggestion
}

impl<P: OrchardPrimitives> memuse::DynamicUsage for OrchardDomain<P> {
    fn dynamic_usage(&self) -> usize {
        self.rho.dynamic_usage()
    }

    fn dynamic_usage_bounds(&self) -> (usize, Option<usize>) {
        self.rho.dynamic_usage_bounds()
    }
}
```

> **PaulLaux** replied at 2026-02-05T07:22:52Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2767499422
> 
> reintroduced in https://github.com/QED-it/orchard/pull/216/commits/f83d6526e09a5480ce83f4e358ee957954eae1e5

---

### str4d on `src/primitives/orchard_domain.rs`
**Date:** 2025-12-08T17:59:51Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2599589396
```diff
c.
+#[derive(Debug, Clone)]
+pub struct OrchardDomain<P: OrchardPrimitives> {
+    /// A parameter needed to generate the nullifier.
+    pub rho: Rho,
+    phantom: core::marker::PhantomData<P>,
+}
+
+impl<P: OrchardPrimitives> OrchardDomain<P> {
+    /// Constructs a domain that can be used to trial-decrypt this action's output note.
+    pub fn for_action<T>(act: &Action<T, P>) -> Self {
+        Self {
+            rho: act.rho(),
+            phantom: Default::default(),
+        }
+    }
+
```

Bug: missing method that was not moved from `src/note_encryption.rs`:
```suggestion

    /// Constructs a domain that can be used to trial-decrypt a PCZT action's output note.
    pub fn for_pczt_action(act: &crate::pczt::Action) -> Self {
        Self {
            rho: Rho::from_nf_old(act.spend().nullifier),
            phantom: Default::default(),
        }
    }

```

> **PaulLaux** replied at 2026-02-05T07:24:03Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2767503006
> 
> reintroduced in https://github.com/QED-it/orchard/pull/216/commits/f83d6526e09a5480ce83f4e358ee957954eae1e5 

---

### str4d on `src/primitives/orchard_domain.rs`
**Date:** 2025-12-08T18:01:25Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2599594554
```diff
&Action<T, P>) -> Self {
+        Self {
+            rho: act.rho(),
+            phantom: Default::default(),
+        }
+    }
+
+    /// Constructs a domain that can be used to trial-decrypt this compact action's output note.
+    pub fn for_compact_action(act: &CompactAction<P>) -> Self {
+        Self {
+            rho: act.rho(),
+            phantom: Default::default(),
+        }
+    }
+
+    /// Constructs a domain from a rho.
+    #[cfg(test)]
+    pub fn for_rho(rho: Rho) -> Self {
```

```suggestion
    pub(crate) fn for_rho(rho: Rho) -> Self {
```

> **PaulLaux** replied at 2026-02-05T07:24:25Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2767504264
> 
> done in https://github.com/QED-it/orchard/pull/216/commits/f83d6526e09a5480ce83f4e358ee957954eae1e5

---

### str4d on `src/primitives/orchard_domain.rs`
**Date:** 2025-12-08T18:01:36Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2599594936
```diff
@@ -0,0 +1,43 @@
+//! Orchard-specific note encryption domain.
+
+// Review hint: this file is largely derived from src/note_encryption.rs
+
```

```suggestion
```

> **PaulLaux** replied at 2026-02-05T07:24:41Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2767505113
> 
> done in https://github.com/QED-it/orchard/pull/216/commits/f83d6526e09a5480ce83f4e358ee957954eae1e5

---

### str4d on `src/primitives/zcash_note_encryption_domain.rs`
**Date:** 2025-12-08T18:42:18Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2599737628
```diff
     .update(cmx_bytes)
+            .update(ephemeral_key.as_ref())
+            .finalize()
+            .as_bytes()
+            .try_into()
+            .unwrap(),
+    )
+}
+
+/// Retrieves the version of the note plaintext.
+/// Returns `Some(u8)` if the version is recognized, otherwise `None`.
+pub(super) fn parse_note_version(plaintext: &[u8]) -> Option<u8> {
+    plaintext.first().and_then(|version| match *version {
+        NOTE_VERSION_BYTE_V2 | NOTE_VERSION_BYTE_V3 => Some(*version),
```

Where will the constraints on note plaintext version be checked?

> **PaulLaux** replied at 2026-02-05T08:32:09Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2767727973
> 
> Initially, we had thoughts about whether Orchard is the right place for this validation - the note PT version is affected directly by the TX version, a detail that is external to the Orchard crate.
> 
> Eventually added in https://github.com/QED-it/orchard/pull/216/commits/589312c4eae76bc2a936bc7177d2b579545a2058 (full details)
> 
>   Added `is_valid_note_plaintext_lead_byte()` to the `OrchardPrimitives` trait, validating:
>   - `0x02` for OrchardVanilla (TxV5)
>   - `0x03` for OrchardZSA (TxV6)
> 
> Validation is called in `parse_note_plaintext_without_memo()`, returning `None` on mismatch.
> 
> Changed:
>   - `src/primitives/orchard_primitives.rs` - trait definition
>   - `src/primitives/orchard_primitives_vanilla.rs` - validates 0x02
>   - `src/primitives/orchard_primitives_zsa.rs` - validates 0x03
>   - `src/primitives/zcash_note_encryption_domain.rs` - calls validation 

---

### str4d on `src/primitives/zcash_note_encryption_domain.rs`
**Date:** 2025-12-08T18:45:25Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2599745324
```diff
ize = 32; // rseed (or rcm prior to ZIP 212)
+
+const NOTE_VERSION_OFFSET: usize = 0;
+const NOTE_DIVERSIFIER_OFFSET: usize = NOTE_VERSION_OFFSET + NOTE_VERSION_SIZE;
+const NOTE_VALUE_OFFSET: usize = NOTE_DIVERSIFIER_OFFSET + NOTE_DIVERSIFIER_SIZE;
+const NOTE_RSEED_OFFSET: usize = NOTE_VALUE_OFFSET + NOTE_VALUE_SIZE;
+
+/// The size of a Vanilla compact note.
+pub(super) const COMPACT_NOTE_SIZE_VANILLA: usize =
+    NOTE_VERSION_SIZE + NOTE_DIVERSIFIER_SIZE + NOTE_VALUE_SIZE + NOTE_RSEED_SIZE;
```

Since we've already done the addition above:
```suggestion
    NOTE_RSEED_OFFSET + NOTE_RSEED_SIZE;
```

> **PaulLaux** replied at 2026-02-05T08:33:43Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2767733737
> 
> done in https://github.com/QED-it/orchard/pull/216/commits/f83d6526e09a5480ce83f4e358ee957954eae1e5#diff-b09e391fc1e6a31eed5cbfbac587d9762e74acfd6c69ae2603e00056ef49bb3b

---

### str4d on `src/primitives/compact_action.rs`
**Date:** 2025-12-08T20:39:02Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2600054911
```diff
itment {
+        self.cmx()
+    }
+
+    fn cmstar_bytes(&self) -> [u8; 32] {
+        self.cmx().to_bytes()
+    }
+
+    fn enc_ciphertext(&self) -> Option<&P::NoteCiphertextBytes> {
+        Some(&self.encrypted_note().enc_ciphertext)
+    }
+
+    fn enc_ciphertext_compact(&self) -> P::CompactNoteCiphertextBytes {
+        P::CompactNoteCiphertextBytes::from_slice(
+            &self.encrypted_note().enc_ciphertext.as_ref()[..P::COMPACT_NOTE_SIZE],
+        )
+        .unwrap()
+    }
+}
+
```

Bug: missing trait impl that was not moved from `src/note_encryption.rs`:
```suggestion

impl ShieldedOutput<OrchardDomain, ENC_CIPHERTEXT_SIZE> for crate::pczt::Action {
    fn ephemeral_key(&self) -> EphemeralKeyBytes {
        EphemeralKeyBytes(self.output().encrypted_note().epk_bytes)
    }

    fn cmstar_bytes(&self) -> [u8; 32] {
        self.output().cmx().to_bytes()
    }

    fn enc_ciphertext(&self) -> &[u8; ENC_CIPHERTEXT_SIZE] {
        &self.output().encrypted_note().enc_ciphertext
    }
}

```
(fix it as necessary to be correct for the updated `ShieldedOutput` trait).

> **PaulLaux** replied at 2026-02-05T08:38:50Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2767752426
> 
> done in https://github.com/QED-it/orchard/pull/216/commits/bb84ff20cd733fcc70801b51f00217db3cd79ac9:
> Added `ShieldedOutput<OrchardDomain<OrchardVanilla>>` impl for `pczt::Action` 

---

### str4d on `src/bundle/commitments.rs` (line 122)
**Date:** 2025-12-09T11:48:35Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2602307494
```diff
+        ia.update(action.asset_desc_hash());
+
+        let mut ind = hasher(ZCASH_ORCHARD_ZSA_ISSUE_NOTE_PERSONALIZATION);
+        for note in action.notes().iter() {
+            ind.update(&note.recipient().to_raw_address_bytes());
+            ind.update(&note.value().to_bytes());
+            ind.update(&note.rho().to_bytes());
+            ind.update(note.rseed().as_bytes());
+        }
+        ia.update(ind.finalize().as_bytes());
+        ia.update(&[u8::from(action.is_finalized())]);
```

ZIP 230 specifies a `flags_issuance` byte with a specific encoding for the bits. It happens that `u8::from(bool)` happens to produce the same bitflag encoding at present, but this is fragile and forces the parser and serializer to be split across various locations.

Instead, define an `IssuanceFlags` type, similar to the `Flags` type we already have for the Orchard bundle.

> **PaulLaux** replied at 2026-02-05T08:43:39Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2767770474
> 
> done in https://github.com/QED-it/orchard/pull/216/commits/313544d699a6e25f4674b291937924640cb21553

---

### str4d on `src/bundle/commitments.rs` (line 154)
**Date:** 2025-12-09T11:55:03Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2602328317
```diff
//zips.z.cash/zip-0246
+pub(crate) fn hash_issue_bundle_auth_data(
+    bundle: &IssueBundle<Signed>,
+    sighash_version_map: &BTreeMap<IssueSighashVersion, Vec<u8>>,
+) -> Blake2bHash {
+    let mut h = hasher(ZCASH_ORCHARD_ZSA_ISSUE_SIG_PERSONALIZATION);
+    let version_bytes = sighash_version_map
+        .get(bundle.authorization().signature().version())
+        .expect("Unknown issue sighash version.");
+    h.update(&get_compact_size(version_bytes.len()));
+    h.update(version_bytes);
```

Theses should be `sighash_info` bytes, not `version` bytes (because in future there may be more data here than just the `sighashInfo` version). Rename the variable to `sighash_info`, in addition to the refactor I requested in my earlier comment that means we are using a `sighashInfo` serializer function that is passed in (and can ensure all of `sighashInfo` is included).

> **PaulLaux** replied at 2026-02-05T08:47:18Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2767784129
> 
> done in continuation with previous comment in https://github.com/QED-it/orchard/pull/216/commits/57c33af24665829d6c1e756ad157d6fddc6205a0
> 

---

### str4d on `src/bundle/commitments.rs` (line 243)
**Date:** 2025-12-09T11:59:18Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2602342339
```diff
g).unwrap().0
+    }
+
+    /// Verify that the hash for an Orchard Vanilla bundle matches a fixed reference value
+    /// to ensure consistency.
+    #[test]
+    fn test_hash_bundle_txid_data_for_orchard_vanilla() {
+        let bundle = generate_bundle::<OrchardVanilla>(BundleType::DEFAULT_VANILLA);
+        let sighash = hash_bundle_txid_data(&bundle);
+        assert_eq!(
+            sighash.to_hex().as_str(),
+            "f3ea89ea2b1e17b3313a6f2f9e4e47c21eec1574902f5ea6961227e1eaed2327"
```

How was this reference value calculated?

> **PaulLaux** replied at 2026-02-11T20:54:40Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2795484381
> 
> To make sure this implementation produces exactly the same bundles/commitments as the pre-ZSA Orchard implementation, we wrote auxiliary code to compute the bundle commitments: https://github.com/QED-it/orchard/pull/240 (build on top of zcash/orchard)
> Next, we used the commitment values here for Orchard vanilla comparison.
> 
> For the OrchardZSA bundles/commitments and the issue bundle digest, we simply lock in-place to ensure future changes do not modify the commitment values.
> 
> 
> To be backward compatible with pre-ZSA orchard we had to introduce new code in `builder.rs/build_bundle()`. The change pad zatosh-only bundles before per-asset processing, as discussed in one of our calls. This code needes to be reviewed since it was not part of the implementation during this review. Details in https://github.com/QED-it/orchard/pull/239

> **PaulLaux** replied at 2026-02-11T21:10:04Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2795545371
> 
> In addition, removed the ability to create dummy notes with custom assets (non-zatoshi assets) in https://github.com/QED-it/orchard/pull/216/commits/b90d40ff807e5a03880ec40a2da72f0c7e652bdf. It is not needed.

---

### str4d on `src/bundle/commitments.rs` (line 255)
**Date:** 2025-12-09T11:59:38Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2602343402
```diff
6961227e1eaed2327"
+        );
+    }
+
+    /// Verify that the hash for an OrchardZSA bundle matches a fixed reference value
+    /// to ensure consistency.
+    #[test]
+    fn test_hash_bundle_txid_data_for_orchard_zsa() {
+        let bundle = generate_bundle::<OrchardZSA>(BundleType::DEFAULT_ZSA);
+        let sighash = hash_bundle_txid_data(&bundle);
+        assert_eq!(
+            sighash.to_hex().as_str(),
+            "a0d843b7278788e3b47dc9fe1e1da227a94898b7111d76514a87df486d32773c"
```

How was this reference value calculated?

> **PaulLaux** replied at 2026-02-11T20:55:56Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2795489944
> 
> a lock in-place as described in https://github.com/zcash/orchard/pull/471#discussion_r2795484381

---

### str4d on `src/bundle/commitments.rs` (line 279)
**Date:** 2025-12-09T12:01:18Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2602349839
```diff
tment for an Orchard Vanilla bundle matches a fixed
+    /// reference value to ensure consistency.
+    #[test]
+    fn test_hash_bundle_auth_data_for_orchard_vanilla() {
+        let bundle = generate_auth_bundle::<OrchardVanilla>(BundleType::DEFAULT_VANILLA);
+        let orchard_auth_digest = hash_bundle_auth_data(&bundle, &BTreeMap::new());
+        assert_eq!(
+            orchard_auth_digest.to_hex().as_str(),
+            "c99aa5a33fd4e7b78de0ee846397e2eb0da3a5d176e6df57d0401c49f51d7295"
```

How was this reference value calculated?

> **PaulLaux** replied at 2026-02-11T20:57:51Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2795497972
> 
> as computed in https://github.com/QED-it/orchard/pull/240 and discussed in https://github.com/zcash/orchard/pull/471#discussion_r2795484381

---

### str4d on `src/bundle/commitments.rs` (line 294)
**Date:** 2025-12-09T12:01:36Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2602350657
```diff
st_hash_bundle_auth_data_for_orchard_zsa() {
+        let mut sighash_version_map = BTreeMap::new();
+        sighash_version_map.insert(OrchardSighashVersion::V0, vec![0]);
+
+        let bundle = generate_auth_bundle::<OrchardZSA>(BundleType::DEFAULT_ZSA);
+        let orchard_auth_digest = hash_bundle_auth_data(&bundle, &sighash_version_map);
+        assert_eq!(
+            orchard_auth_digest.to_hex().as_str(),
+            "9d47819082f2323b30ceabe0fea993b39541cc0e62a8be6e1bc2a19840b0d9ab"
```

How was this reference value calculated?

> **PaulLaux** replied at 2026-02-11T20:58:11Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2795499417
> 
> a lock in-place as described in https://github.com/zcash/orchard/pull/471#discussion_r2795484381

---

### str4d on `src/bundle/commitments.rs` (line 370)
**Date:** 2025-12-09T12:05:36Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2602362960
```diff
dle.update_rho(&first_nullifier), isk)
+    }
+
+    /// Verify that the `issuance_digest` of an IssueBundle matches a fixed reference value
+    /// to ensure consistency.
+    #[test]
+    fn test_hash_issue_bundle_txid_data() {
+        let (bundle, _) = generate_issue_bundle();
+        let issuance_digest = hash_issue_bundle_txid_data(&bundle);
+        assert_eq!(
+            issuance_digest.to_hex().as_str(),
+            "7d7e9b66cee8896453aa7dffdbe885b880b700a49cfff947ab1503a2407b5e1b"
```

How was this reference value calculated?

> **PaulLaux** replied at 2026-02-11T20:58:20Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2795500177
> 
> a lock in-place as described in https://github.com/zcash/orchard/pull/471#discussion_r2795484381

---

### str4d on `src/bundle/commitments.rs` (line 389)
**Date:** 2025-12-09T12:05:45Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2602363436
```diff
mitment().into();
+        let signed_bundle = bundle.prepare(issuance_digest).sign(&isk).unwrap();
+
+        let mut sighash_version_map = BTreeMap::new();
+        sighash_version_map.insert(IssueSighashVersion::V0, vec![0]);
+
+        let issuance_auth_digest =
+            hash_issue_bundle_auth_data(&signed_bundle, &sighash_version_map);
+        assert_eq!(
+            issuance_auth_digest.to_hex().as_str(),
+            "b0e465381e86b4462403723283e75b5b1928110cf2a45a0602d5a5037f07c9ad"
```

How was this reference value calculated?

> **PaulLaux** replied at 2026-02-11T20:58:28Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2795500703
> 
> a lock in-place as described in https://github.com/zcash/orchard/pull/471#discussion_r2795484381

---

### str4d on `src/builder.rs` (line 66)
**Date:** 2025-12-09T12:09:06Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2602373392
```diff
  /// The default bundle type has all flags enabled, and does not require a bundle to be produced
-    /// if no spends or outputs have been added to the bundle.
-    pub const DEFAULT: BundleType = BundleType::Transactional {
-        flags: Flags::ENABLED,
+    /// The default bundle type has all flags enabled, ZSA disabled, and does not require a bundle
+    /// to be produced.
+    pub const DEFAULT_VANILLA: BundleType = BundleType::Transactional {
+        flags: Flags::ENABLED_WITHOUT_ZSA,
```

Ditto my previous comment about undoing this to reduce churn:
```suggestion
    pub const DEFAULT: BundleType = BundleType::Transactional {
        flags: Flags::ENABLED,
```

> **PaulLaux** replied at 2026-02-05T19:20:13Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2770756625
> 
> done in https://github.com/QED-it/orchard/pull/216/commits/f83d6526e09a5480ce83f4e358ee957954eae1e5#diff-e4f794ca308aa712cbad31feb714df7cada1bbe453a30e232e45891571430263

---

### str4d on `src/builder.rs` (line 64)
**Date:** 2025-12-09T12:10:26Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2602378140
```diff
@@ -53,17 +60,23 @@ pub enum BundleType {
 }
 
 impl BundleType {
-    /// The default bundle type has all flags enabled, and does not require a bundle to be produced
-    /// if no spends or outputs have been added to the bundle.
-    pub const DEFAULT: BundleType = BundleType::Transactional {
-        flags: Flags::ENABLED,
+    /// The default bundle type has all flags enabled, ZSA disabled, and does not require a bundle
+    /// to be produced.
```

Undo this comment deletion:
```suggestion
    /// to be produced if no spends or outputs have been added to the bundle.
```
or if it is no longer accurate, modify it to be so instead of removing it.

> **PaulLaux** replied at 2026-02-05T19:22:17Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2770766294
> 
> Restored in https://github.com/QED-it/orchard/pull/216/commits/f83d6526e09a5480ce83f4e358ee957954eae1e5#diff-e4f794ca308aa712cbad31feb714df7cada1bbe453a30e232e45891571430263

---

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

### str4d on `src/builder.rs` (line 486)
**Date:** 2025-12-09T12:20:34Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2602410770
```diff
@@ -423,19 +483,39 @@ impl ActionInfo {
     }
 
     /// Returns the value sum for this action.
+    /// Split notes do not contribute to the value sum.
```

```suggestion
    ///
    /// Split notes do not contribute to the value sum.
```

> **PaulLaux** replied at 2026-02-05T19:48:07Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2770860665
> 
> done in https://github.com/QED-it/orchard/pull/216/commits/f83d6526e09a5480ce83f4e358ee957954eae1e5#diff-e4f794ca308aa712cbad31feb714df7cada1bbe453a30e232e45891571430263

---

### str4d on `src/builder.rs` (line 516)
**Date:** 2025-12-09T12:22:01Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2602415043
```diff
   ///
+    /// Panics if the asset types of the spent and output notes do not match.
     #[cfg(feature = "circuit")]
-    fn build(self, mut rng: impl RngCore) -> (Action<SigningMetadata>, Circuit) {
+    fn build<FL: OrchardFlavor>(
+        self,
+        mut rng: impl RngCore,
+    ) -> (Action<SigningMetadata, FL>, Witnesses) {
+        assert_eq!(
+            self.spend.note.asset(),
+            self.output.asset,
+            "spend and recipient note types must be equal"
+        );
+
```

Move this check to the `ActionInfo::new` constructor, so we can rely on it as a type invariant.
```suggestion
```

> **PaulLaux** replied at 2026-02-05T19:50:57Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2770873860
> 
> Moved to `ActionInfo::new()` in https://github.com/QED-it/orchard/pull/216/commits/f83d6526e09a5480ce83f4e358ee957954eae1e5

---

### str4d on `src/builder.rs` (line 505)
**Date:** 2025-12-09T12:22:26Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2602416292
```diff
 if self.spend.split_flag {
+            NoteValue::zero()
+        } else {
+            self.spend.note.value()
+        };
+
+        spent_value - self.output.value
     }
 
     /// Builds the action.
     ///
     /// Defined in [Zcash Protocol Spec § 4.7.3: Sending Notes (Orchard)][orchardsend].
     ///
     /// [orchardsend]: https://zips.z.cash/protocol/nu5.pdf#orchardsend
+    ///
+    /// # Panics
+    ///
+    /// Panics if the asset types of the spent and output notes do not match.
```

Move this to the `ActionInfo::new` constructor.
```suggestion
```

> **PaulLaux** replied at 2026-02-05T19:51:49Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2770878169
> 
> Moved to `ActionInfo::new()` in https://github.com/QED-it/orchard/pull/216/commits/f83d6526e09a5480ce83f4e358ee957954eae1e5

---

### str4d on `src/builder.rs` (line 544)
**Date:** 2025-12-09T12:23:09Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2602418341
```diff
Parts { ak, alpha },
                 },
             ),
-            Circuit::from_action_context_unchecked(self.spend, note, alpha, self.rcv),
+            Witnesses::from_action_context_unchecked::<FL>(self.spend, note, alpha, self.rcv),
         )
     }
 
     fn build_for_pczt(self, mut rng: impl RngCore) -> crate::pczt::Action {
+        assert_eq!(
+            self.spend.note.asset(),
+            self.output.asset,
+            "spend and recipient note types must be equal"
+        );
```

```suggestion
```

> **PaulLaux** replied at 2026-02-05T19:52:18Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2770880154
> 
> done in https://github.com/QED-it/orchard/pull/216/commits/f83d6526e09a5480ce83f4e358ee957954eae1e5

---

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

### str4d on `src/builder.rs` (line 608)
**Date:** 2025-12-09T12:24:20Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2602421894
```diff
 spent, and outputs
-/// to receive funds.
+/// A tuple containing an in-progress bundle with no proofs or signatures, and its associated metadata.
+#[cfg(feature = "circuit")]
+pub type UnauthorizedBundleWithMetadata<V, FL> = (UnauthorizedBundle<V, FL>, BundleMetadata);
+
+/// A builder for constructing an Orchard [`Bundle`] by specifying notes to spend, outputs to
+/// receive, and assets to burn.
+/// This builder provides a structured way to incrementally assemble the components of a bundle.
```

```suggestion
///
/// This builder provides a structured way to incrementally assemble the components of a bundle.
```

> **PaulLaux** replied at 2026-02-05T19:53:02Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2770883121
> 
> done in https://github.com/QED-it/orchard/pull/216/commits/f83d6526e09a5480ce83f4e358ee957954eae1e5

---

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

### str4d on `src/builder.rs` (line 699)
**Date:** 2025-12-09T12:25:42Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2602426619
```diff
@@ -598,11 +691,32 @@ impl Builder {
         }
 
         self.outputs
-            .push(OutputInfo::new(ovk, recipient, value, memo));
+            .push(OutputInfo::new(ovk, recipient, value, asset, memo));
 
         Ok(())
     }
 
+    /// Add an instruction to burn a given amount of a specific asset.
```

To follow the Rust style guide, and our existing convention:
```suggestion
    /// Adds an instruction to burn a given amount of a specific asset.
```

> **PaulLaux** replied at 2026-02-05T19:53:38Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2770885409
> 
> done in https://github.com/QED-it/orchard/pull/216/commits/f83d6526e09a5480ce83f4e358ee957954eae1e5

---

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

### str4d on `src/builder.rs` (line 786)
**Date:** 2025-12-09T12:49:47Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2602512993
```diff
@@ -780,45 +969,78 @@ fn build_bundle<B, R: RngCore>(
         return Err(BuildError::OutputsDisabled);
     }
 
-    let num_actions = bundle_type
-        .num_actions(num_requested_spends, num_requested_outputs)
-        .map_err(|_| BuildError::BundleTypeNotSatisfiable)?;
-
```

Bug: the builder is now ignoring some of the `bundle_type` rules, which in particular means that:
- Validation rules on `BundleType::Transactional` are not being enforced.
- `BundleType::Coinbase` now incorrectly includes padding.

Undo this deletion and instead modify `BundleType::num_actions` as necessary to perform the correct calculation for a `BundleType::Transactional` that contains Custom Assets.

> **PaulLaux** replied at 2026-02-05T20:01:26Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2770919225
> 
> Done in https://github.com/QED-it/orchard/pull/216/commits/e48d478b5d6588fda97bab007197adf8a1928a50
> 
> Restored `bundle_type.num_actions()` to enforce validation rules and correct padding. Return type changed to `Option<...>` to handle the case when no bundle is required.

---

### str4d on `src/builder.rs` (line 977)
**Date:** 2025-12-09T12:51:44Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2602520525
```diff
 let mut indexed_spends = spends
-            .into_iter()
-            .chain(iter::repeat_with(|| SpendInfo::dummy(&mut rng)))
-            .enumerate()
-            .take(num_actions)
-            .collect::<Vec<_>>();
+        // Use Vec::with_capacity().extend(...) instead of .collect() to avoid reallocations,
+        // as we can estimate the vector size beforehand.
+        let mut indexed_spends_outputs =
+            Vec::with_capacity(spends.len().max(outputs.len()).max(MIN_ACTIONS));
```

```suggestion
        let mut indexed_spends_outputs = Vec::with_capacity(num_actions);
```

> **PaulLaux** replied at 2026-02-05T20:03:26Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2770926517
> 
> done in https://github.com/QED-it/orchard/pull/216/commits/e48d478b5d6588fda97bab007197adf8a1928a50
> 
> continued from https://github.com/zcash/orchard/pull/471#discussion_r2602512993

---

### str4d on `src/builder.rs` (line 1008)
**Date:** 2025-12-09T12:54:56Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2602532807
```diff
              .collect::<Vec<_>>();
 
-        // Shuffle the spends and outputs, so that learning the position of a
-        // specific spent note or output note doesn't reveal anything on its own about
-        // the meaning of that note in the transaction context.
-        indexed_spends.shuffle(&mut rng);
-        indexed_outputs.shuffle(&mut rng);
+                // Shuffle the spends and outputs, so that the position does not reveal any
+                // information about the content.
```

"information about the content" is not what this shuffle is protecting (that is protected by the encryption). The previous comment was correct; preserve it.
```suggestion
                // Shuffle the spends and outputs, so that learning the position of a
                // specific spent note or output note doesn't reveal anything on its own
                // about the meaning of that note in the transaction context.
```

> **PaulLaux** replied at 2026-02-05T20:04:56Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2770931889
> 
> done in https://github.com/QED-it/orchard/pull/216/commits/f83d6526e09a5480ce83f4e358ee957954eae1e5

---

### str4d on `src/builder.rs` (line 1029)
**Date:** 2025-12-09T12:57:15Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2602541601
```diff
   indexed_spends_outputs.extend(
+            iter::repeat_with(|| {
+                (
+                    (SpendInfo::dummy(AssetBase::native(), &mut rng), None),
+                    (OutputInfo::dummy(&mut rng, AssetBase::native()), None),
+                )
+            })
+            .take(MIN_ACTIONS.saturating_sub(indexed_spends_outputs.len())),
+        );
+
+        // Shuffle the spends and outputs, so that the position does not reveal any information
+        // about the content.
```

```suggestion
        // We shuffled the spends and outputs within each `AssetBase` above; now we
        // shuffle the actions to achieve a similar property across `AssetBase`s.
```

> **PaulLaux** replied at 2026-02-05T20:05:18Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2770933079
> 
> done in https://github.com/QED-it/orchard/pull/216/commits/f83d6526e09a5480ce83f4e358ee957954eae1e5

---

### str4d on `src/builder.rs` (line 915)
**Date:** 2025-12-09T12:58:55Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2602548040
```diff
@@ -726,30 +907,30 @@ pub fn bundle<V: TryFrom<i64>>(
                 .into_bsk();
 
             // Create the actions.
-            let (actions, circuits): (Vec<_>, Vec<_>) =
+            let (actions, witnesses): (Vec<_>, Vec<_>) =
                 pre_actions.into_iter().map(|a| a.build(&mut rng)).unzip();
 
+            // `actions` is never empty. It contains at least MIN_ACTIONS=2 actions.
+            let actions = NonEmpty::from_vec(actions).unwrap();
+
```

After the bug is fixed, this change becomes invalid.
```suggestion
```
(and correspondingly below on the method result).

> **PaulLaux** replied at 2026-02-05T20:06:11Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2770935973
> 
> Indeed.
> Removed in https://github.com/QED-it/orchard/pull/216/commits/e48d478b5d6588fda97bab007197adf8a1928a50

---

### str4d on `src/builder.rs` (line 1073)
**Date:** 2025-12-09T13:01:15Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2602556915
```diff
(OverflowError)?;
 
-    finisher(pre_actions, flags, value_balance, bundle_meta, rng)
+    let burn_vec = burn
+        .into_iter()
+        .map(|(asset, value)| {
+            Ok((
+                asset,
+                NoteValue::from_raw(
+                    u64::try_from(i128::from(value))
+                        .map_err(|_| BuildError::ValueSum(OverflowError))?,
+                ),
+            ))
+        })
+        .collect::<Result<Vec<(AssetBase, NoteValue)>, BuildError>>()?;
+
```

What is going on here? `value` already has type `NoteValue`.

> **PaulLaux** replied at 2026-02-05T20:12:19Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2770957436
> 
> A leftover from a previous iteration. 
> Replaced with simply     `let burn_vec = burn.into_iter().collect();`
> 
> in https://github.com/QED-it/orchard/pull/216/commits/f83d6526e09a5480ce83f4e358ee957954eae1e5#diff-e4f794ca308aa712cbad31feb714df7cada1bbe453a30e232e45891571430263

---

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

### str4d on `src/builder.rs` (line 1225)
**Date:** 2025-12-09T13:04:45Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2602570477
```diff
ature(VerSpendAuthSig),
 }
 
 impl MaybeSigned {
-    fn finalize(self) -> Result<redpallas::Signature<SpendAuth>, BuildError> {
+    fn finalize(self) -> Result<VerSpendAuthSig, BuildError> {
         match self {
             Self::Signature(sig) => Ok(sig),
             _ => Err(BuildError::MissingSignatures),
         }
     }
 }
 
-impl<P: fmt::Debug, V> Bundle<InProgress<P, Unauthorized>, V> {
+impl<Proof: fmt::Debug, V, P: OrchardPrimitives> Bundle<InProgress<Proof, Unauthorized>, V, P> {
```

I would prefer that you do not rename existing generic parameter types. In particular, `Proof` is the name of the concrete proof type of an authorized bundle, so it was intentional that we did not use it here for a type that may or may not be a proof yet, to avoid confusion.
```suggestion
impl<P: fmt::Debug, V, Pr: OrchardPrimitives> Bundle<InProgress<P, Unauthorized>, V, Pr> {
```
(and similarly below)

> **PaulLaux** replied at 2026-02-05T20:20:37Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2770986507
> 
> Renamed in https://github.com/QED-it/orchard/pull/216/commits/f83d6526e09a5480ce83f4e358ee957954eae1e5#diff-e4f794ca308aa712cbad31feb714df7cada1bbe453a30e232e45891571430263

---

### str4d on `src/builder.rs` (line 1284)
**Date:** 2025-12-09T14:34:57Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2602938883
```diff
@@ -1016,50 +1280,50 @@ impl<V> Bundle<InProgress<Proof, Unauthorized>, V> {
     }
 }
 
-impl<P: fmt::Debug, V> Bundle<InProgress<P, PartiallyAuthorized>, V> {
+impl<Proof: fmt::Debug, V, P: OrchardPrimitives>
+    Bundle<InProgress<Proof, PartiallyAuthorized>, V, P>
```

Ditto:
```suggestion
impl<P: fmt::Debug, V, Pr: OrchardPrimitives>
    Bundle<InProgress<P, PartiallyAuthorized>, V, Pr>
```

> **PaulLaux** replied at 2026-02-05T20:21:19Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2770988894
> 
> done in https://github.com/QED-it/orchard/pull/216/commits/f83d6526e09a5480ce83f4e358ee957954eae1e5#diff-e4f794ca308aa712cbad31feb714df7cada1bbe453a30e232e45891571430263

---

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

### str4d on `src/builder.rs` (line 1335)
**Date:** 2025-12-09T14:44:43Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2602977967
```diff
or> {
         let mut signature_valid_for = 0usize;
         let bundle = self.map_authorization(
             &mut signature_valid_for,
             |valid_for, partial, maybe| match maybe {
                 MaybeSigned::SigningMetadata(parts) => {
                     let rk = parts.ak.randomize(&parts.alpha);
-                    if rk.verify(&partial.sigs.sighash[..], signature).is_ok() {
+                    if rk
+                        .verify(&partial.sigs.sighash[..], signature.sig())
```

Bug: This needs to check that the `sighash_info` within `signature` is compatible with `partial.sigs.sighash`. Currently it will either fall through and error with `BuildError::InvalidExternalSignature` (if `signature` was created correctly with a non-v0 sighash), or silently append a `signature` using the v0 sighash but a non-v0 `sighash_info`.

In practice I think this means that we will eventually need a different API for providing signatures over non-v0 sighashes (and maybe this actually only lives in PCZT-land for simplicity), so here we should return an error if the `sighash_info` within `signature` does not select the v0 sighash.

> **PaulLaux** replied at 2026-02-05T20:27:57Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2771011678
> 
> Fixed in https://github.com/QED-it/orchard/pull/216/commits/dc861afa2d8257687f5a3082d107a7afe817b063. 
> Added validation at the start of `append_signature` to check sighash compatibility and  ensure that signatures with non v0 sighash are rejected. Preventing silent acceptance of incompatible signatures.

---

### str4d on `src/builder.rs` (line 767)
**Date:** 2025-12-09T14:48:39Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2602993570
```diff
mpl Builder {
     /// The returned bundle will have no proof or signatures; these can be applied with
     /// [`Bundle::create_proof`] and [`Bundle::apply_signatures`] respectively.
     #[cfg(feature = "circuit")]
-    pub fn build<V: TryFrom<i64>>(
+    pub fn build<V: TryFrom<i64>, FL: OrchardFlavor>(
         self,
         rng: impl RngCore,
-    ) -> Result<Option<(UnauthorizedBundle<V>, BundleMetadata)>, BuildError> {
+    ) -> Result<UnauthorizedBundleWithMetadata<V, FL>, BuildError> {
```

Per my earlier comment, revert this change:
```suggestion
    ) -> Result<Option<UnauthorizedBundleWithMetadata<V, FL>>, BuildError> {
```

> **PaulLaux** replied at 2026-02-05T20:29:35Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2771018274
> 
> done in https://github.com/QED-it/orchard/pull/216/commits/e48d478b5d6588fda97bab007197adf8a1928a50#diff-e4f794ca308aa712cbad31feb714df7cada1bbe453a30e232e45891571430263

---

### str4d on `src/builder.rs` (line 1578)
**Date:** 2025-12-09T14:50:59Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2603002641
```diff
Value,
     };
 
-    #[test]
-    fn shielding_bundle() {
-        let pk = ProvingKey::build();
+    fn shielding_bundle<FL: OrchardFlavor>() {
+        let pk = ProvingKey::build::<FL>();
         let mut rng = OsRng;
 
         let sk = SpendingKey::random(&mut rng);
         let fvk = FullViewingKey::from(&sk);
         let recipient = fvk.address_at(0u32, Scope::External);
 
         let mut builder = Builder::new(
-            BundleType::DEFAULT,
+            BundleType::DEFAULT_VANILLA,
```

Similar to one of my prior comments, this should test with `BundleType::DEFAULT_ZSA` when `FL` is set to `OrchardZSA` in the `shielding_bundle_zsa()` test. Maybe we *also* want to test the current combination; if so, add another test variant.

> **PaulLaux** replied at 2026-02-05T20:48:35Z:
> **Link:** https://github.com/zcash/orchard/pull/471#discussion_r2771087880
> 
> Fixed in https://github.com/QED-it/orchard/pull/216/commits/f0cf7ea231d340809bf6530bd5c900bf8b86a876
> 
> The `shielding_bundle_zsa()` test now uses `BundleType::DEFAULT_ZSA`:
> 
> We also added a test for the cross-combination (OrchardZSA with vanilla flags) in https://github.com/QED-it/orchard/pull/216/commits/44687bc6fe29a3b3dfc5b4e860d0467fb5296a6b

---

### str4d on `Cargo.lock` (line 1)
**Date:** 2025-12-09T14:54:23Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2603016346

I did not review the changes to this file.

---

### str4d on `book/src/design/circuit/zsa-note-commit.md` (line 1)
**Date:** 2025-12-09T14:54:36Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2603017118

I did not review this file.

---

### str4d on `book/src/design/circuit/zsa-note-commit.png` (line 1)
**Date:** 2025-12-09T14:54:47Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2603017726

I did not review this file.

---

### str4d on `book/src/design/commitments.md` (line 1)
**Date:** 2025-12-09T14:54:55Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2603018328

I did not review the changes to this file.

---

### str4d on `book/src/design/nullifiers.md` (line 1)
**Date:** 2025-12-09T14:55:01Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2603018801

I did not review the changes to this file.

---

### str4d on `src/circuit/circuit_description_zsa` (line 1)
**Date:** 2025-12-09T14:55:14Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2603019602

I did not review this file.

---

### str4d on `src/circuit/circuit_proof_test_case_zsa.bin` (line 1)
**Date:** 2025-12-09T14:55:25Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2603020239

I did not review this file.

---

### str4d on `src/circuit/circuit_zsa.rs` (line 1)
**Date:** 2025-12-09T14:55:35Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2603020866

I did not review this file.

---

### str4d on `src/circuit/note_commit.rs` (line 1)
**Date:** 2025-12-09T14:56:12Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2603023173

I did not review the changes to this file. I will try to review it later this week.

---

### str4d on `src/issuance.rs` (line 1)
**Date:** 2025-12-09T14:56:27Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2603024026

I did not review this file.

---

### str4d on `src/issuance/auth.rs` (line 1)
**Date:** 2025-12-09T14:56:39Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2603024764

I did not review this file.

---

### str4d on `src/primitives/orchard_primitives_zsa.rs` (line 1)
**Date:** 2025-12-09T14:56:52Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2603025624

I did not review this file.

---

### str4d on `src/test_vectors/asset_base.rs` (line 1)
**Date:** 2025-12-09T14:57:05Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2603026408

I did not review this file.

---

### str4d on `src/test_vectors/issuance_auth_sig.rs` (line 1)
**Date:** 2025-12-09T14:57:14Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2603026949

I did not review this file.

---

### str4d on `src/test_vectors/keys.rs` (line 1)
**Date:** 2025-12-09T14:57:24Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2603027522

I did not review the changes to this file.

---

### str4d on `src/test_vectors/merkle_path.rs` (line 1)
**Date:** 2025-12-09T14:57:32Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2603028064

I did not review the changes to this file.

---

### str4d on `src/test_vectors/note_encryption.rs` (line 1)
**Date:** 2025-12-09T14:57:54Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2603029387

I did not review the changes to this file (between it and `note_encryption_vanilla.rs`).

---

### str4d on `src/test_vectors/note_encryption_vanilla.rs` (line 1)
**Date:** 2025-12-09T14:58:13Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2603030565

I did not review the changes to this file (between it and `note_encryption.rs`).

---

### str4d on `src/test_vectors/note_encryption_zsa.rs` (line 1)
**Date:** 2025-12-09T14:58:23Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2603031122

I did not review this file.

---

### str4d on `tests/builder.rs` (line 1)
**Date:** 2025-12-09T14:58:43Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2603032452

I did not review the changes to this file.

---

### str4d on `tests/issuance_global_state.rs` (line 1)
**Date:** 2025-12-09T14:58:56Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2603033329

I did not review this file.

---

### str4d on `tests/zsa.rs` (line 1)
**Date:** 2025-12-09T14:59:07Z
**Link:** https://github.com/zcash/orchard/pull/471#discussion_r2603034010

I did not review this file.

---


## Summary
- **Total reviews:** 143 (2 with body text)
- **Total inline review comments:** 335 (193 threads + 142 replies)
- **Total general comments:** 0