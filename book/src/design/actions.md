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

For Orchard, we take a combined approach: we define an Orchard transaction as containing a
bundle of actions, where each action is both a spend and an output. This provides the same
inherent arity-hiding as multi-JoinSplit Sprout, but using Sapling value commitments to
balance the transaction without doubling its size.

The Zcash Shielded Assets (ZSA) protocol is an extension of the Orchard protocol that enables 
the issuance, transfer and burn of custom Assets on the Zcash chain.
One of the key innovations of ZSA is the introduction of Asset Identifiers, enabling unique 
representation of various assets on the Zcash chain. This mechanism relies on Asset Bases stored 
in ZSA notes, ensuring that transactions preserve asset balance integrity through the unique 
identification of each asset type involved. This balance preservation is critical for maintaining
privacy and security, allowing for transactions that involve multiple asset types without 
disclosing which (or how many distinct) Assets are being transferred.

## Split notes

In typical transactions, not all value from a single input note is sent to a single output. Sometimes, an input note is
split into multiple output notes, each potentially going to different recipients or returning as change to the sender.
In ZSA, it's crucial that the output notes in a transaction match the Asset Base (the type of asset they represent) of 
the input notes. This is to ensure that only legitimate asset transactions occur, preventing someone from creating fake 
asset balances by manipulating the Asset Base values in a transaction.



## Memo fields

Each Orchard action has a memo field for its corresponding output, as with Sprout and
Sapling. We did at one point consider having a single Orchard memo field per transaction,
and/or having a mechanism for enabling multiple recipients to decrypt the same memo, but
these were decided against in order to keep the overall design simpler.
