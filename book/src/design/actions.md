# Actions

In Sprout, we had a single proof that represented two spent notes and two new notes. This
was necessary in order to facilitate spending multiple notes in a single transaction (to
balance value, an output of one JoinSplit could be spent in the next one), but also
provided a minimal level of arity-hiding: single-JoinSplit transactions all looked like
2-in 2-out transactions, and in multi-JoinSplit transactions each JoinSplit looked like a
1-in 1-out.

In Sapling, we switched to using value commitments to balance the transaction, removing
the min-2 arity requirement. We opted for one proof per spent note and one (much simpler)
proof per output note, which greatly improved the performance of generating outputs, but
removed any arity-hiding from the proofs (instead having the transaction builder pad
transactions to 1-in, 2-out).

For (ZSA) Orchard, we take a combined approach: we define an Orchard transaction as containing a
bundle of actions, where each action is both a spend and an output. This provides the same
inherent arity-hiding as multi-JoinSplit Sprout, but using Sapling value commitments to
balance the transaction without doubling its size.

## Dummy notes for (ZSA) Orchard

For Orchard, a transaction is a bundle of actions, where each action is both a spend and an output.
If we would like to create a transaction with not the same number of spends and ouputs,
we have to add "dummy" spends or outputs in order to have the same number of spends and outpus.
A dummy spend or output is a note with a value equal to zero and a random recipient address.
In the ZK proof, when the spent note value is equal to zero, we are not checking that
the corresponding spent note commitment belongs to the Merkle tree.

## Split notes for ZSA Orchard

For ZSA Orchard, if the number of inputs is larger than the number of ouputs,
we use dummy output notes (as for Orchard) to complete all our actions.
Otherwise, if the number of outputs is larger than the number of inputs,
we use split notes to complete our actions in order to ensure that the AssetBase of each action
was created correctly. Split notes are essentially copies of a real spent note, with a few differences:- The nullifier is randomized so that the proof remains valid (preventing it from being considered double-spending)
- Its value is not included in the transaction's or bundle's value balance.
Inside the ZK proof, we verify that the commitment of each spent note (including each split note)
is part of the Merkle tree. This guarantees that the AssetBase was created properly,
as there exists a note associated with this AssetBase within the Merkle tree.

For more details about split notes, refer to
[ZIP206](https://github.com/zcash/zips/blob/main/zips/zip-0226.rst).

## Memo fields

Each Orchard action has a memo field for its corresponding output, as with Sprout and
Sapling. We did at one point consider having a single Orchard memo field per transaction,
and/or having a mechanism for enabling multiple recipients to decrypt the same memo, but
these were decided against in order to keep the overall design simpler.

