# PR #471 - Files Not Reviewed

Extracted from https://github.com/zcash/orchard/pull/471
Comments where the reviewer indicated they did not review a file or its changes.

## Quick Summary

| # | File | Note |
| --- | --- | --- |
| 1 | `src/circuit/value_commit_orchard.rs` | I have not reviewed this circuit logic. |
| 2 | `src/circuit/derive_nullifier.rs` | I have not checked that `.add()` is the correct addition function to use here. |
| 3 | `Cargo.lock` | I did not review the changes to this file. |
| 4 | `book/src/design/circuit/zsa-note-commit.md` | I did not review this file. |
| 5 | `book/src/design/circuit/zsa-note-commit.png` | I did not review this file. |
| 6 | `book/src/design/commitments.md` | I did not review the changes to this file. |
| 7 | `book/src/design/nullifiers.md` | I did not review the changes to this file. |
| 8 | `src/circuit/circuit_description_zsa` | I did not review this file. |
| 9 | `src/circuit/circuit_proof_test_case_zsa.bin` | I did not review this file. |
| 10 | `src/circuit/circuit_zsa.rs` | I did not review this file. |
| 11 | `src/circuit/note_commit.rs` | I did not review the changes to this file. I will try to review it later this week. |
| 12 | `src/issuance.rs` | I did not review this file. |
| 13 | `src/issuance/auth.rs` | I did not review this file. |
| 14 | `src/primitives/orchard_primitives_zsa.rs` | I did not review this file. |
| 15 | `src/test_vectors/asset_base.rs` | I did not review this file. |
| 16 | `src/test_vectors/issuance_auth_sig.rs` | I did not review this file. |
| 17 | `src/test_vectors/keys.rs` | I did not review the changes to this file. |
| 18 | `src/test_vectors/merkle_path.rs` | I did not review the changes to this file. |
| 19 | `src/test_vectors/note_encryption.rs` | I did not review the changes to this file (between it and `note_encryption_vanilla.rs`). |
| 20 | `src/test_vectors/note_encryption_vanilla.rs` | I did not review the changes to this file (between it and `note_encryption.rs`). |
| 21 | `src/test_vectors/note_encryption_zsa.rs` | I did not review this file. |
| 22 | `tests/builder.rs` | I did not review the changes to this file. |
| 23 | `tests/issuance_global_state.rs` | I did not review this file. |
| 24 | `tests/zsa.rs` | I did not review this file. |

## Not Reviewed Files

- src/circuit/value_commit_orchard.rs, https://github.com/zcash/orchard/pull/471#discussion_r2599397621
- src/circuit/derive_nullifier.rs, https://github.com/zcash/orchard/pull/471#discussion_r2599465276
- Cargo.lock, https://github.com/zcash/orchard/pull/471#discussion_r2603016346
- book/src/design/circuit/zsa-note-commit.md, https://github.com/zcash/orchard/pull/471#discussion_r2603017118
- book/src/design/circuit/zsa-note-commit.png, https://github.com/zcash/orchard/pull/471#discussion_r2603017726
- book/src/design/commitments.md, https://github.com/zcash/orchard/pull/471#discussion_r2603018328
- book/src/design/nullifiers.md, https://github.com/zcash/orchard/pull/471#discussion_r2603018801
- src/circuit/circuit_description_zsa, https://github.com/zcash/orchard/pull/471#discussion_r2603019602
- src/circuit/circuit_proof_test_case_zsa.bin, https://github.com/zcash/orchard/pull/471#discussion_r2603020239
- src/circuit/circuit_zsa.rs, https://github.com/zcash/orchard/pull/471#discussion_r2603020866
- src/circuit/note_commit.rs, https://github.com/zcash/orchard/pull/471#discussion_r2603023173
- src/issuance.rs, https://github.com/zcash/orchard/pull/471#discussion_r2603024026
- src/issuance/auth.rs, https://github.com/zcash/orchard/pull/471#discussion_r2603024764
- src/primitives/orchard_primitives_zsa.rs, https://github.com/zcash/orchard/pull/471#discussion_r2603025624
- src/test_vectors/asset_base.rs, https://github.com/zcash/orchard/pull/471#discussion_r2603026408
- src/test_vectors/issuance_auth_sig.rs, https://github.com/zcash/orchard/pull/471#discussion_r2603026949
- src/test_vectors/keys.rs, https://github.com/zcash/orchard/pull/471#discussion_r2603027522
- src/test_vectors/merkle_path.rs, https://github.com/zcash/orchard/pull/471#discussion_r2603028064
- src/test_vectors/note_encryption.rs, https://github.com/zcash/orchard/pull/471#discussion_r2603029387
- src/test_vectors/note_encryption_vanilla.rs, https://github.com/zcash/orchard/pull/471#discussion_r2603030565
- src/test_vectors/note_encryption_zsa.rs, https://github.com/zcash/orchard/pull/471#discussion_r2603031122
- tests/builder.rs, https://github.com/zcash/orchard/pull/471#discussion_r2603032452
- tests/issuance_global_state.rs, https://github.com/zcash/orchard/pull/471#discussion_r2603033329
- tests/zsa.rs, https://github.com/zcash/orchard/pull/471#discussion_r2603034010



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


**Total not-reviewed comments: 24**