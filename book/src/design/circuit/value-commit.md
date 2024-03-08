# Value Commitment

In the case of the Orchard-based ZSA protocol, the value of different Asset Identifiers in a given 
transaction will be committed using a different value base point. The use of different value base points for different Assets enables the final balance of the transaction to be securely computed, such that each Asset Identifier is balanced independently, which is required as different Assets are not meant to be mutually fungible.

The value commitment is:
$$\mathsf{cv}^{\mathsf{net}} :=
\mathsf{ValueCommit}^{\mathsf{OrchardZSA}}_{\mathsf{rcv}}(\mathsf{AssetBase}_\mathsf{AssetId},\mathsf{v}^{\mathsf{net}}_\mathsf{AssetId})
= [\mathsf{v}^{\mathsf{net}}_\mathsf{AssetId}] \mathsf{AssetBase}_\mathsf{AssetId} + [\mathsf{rcv}] \mathcal{R}^{\mathsf{Orchard}}
$$
where $\mathsf{v}^{\mathsf{net}}_\mathsf{AssetId} = \mathsf{v}^{\mathsf{old}}_\mathsf{AssetId} - \mathsf{v}^{\mathsf{new}}_\mathsf{AssetId}$
such that $\mathsf{v}^{\mathsf{old}}_\mathsf{AssetId}$ and $\mathsf{v}^{\mathsf{new}}_\mathsf{AssetId}$ are the values of the old and new notes of Asset Identifier 
$\mathsf{AssetId}$ respectively.

## Burn Mechanism

The burn mechanism provides a secure and transparent way to irreversibly destroy a certain amount of a custom asset.
It is achieved by reducing the total supply of the asset in circulation, effectively "burning" the specified amount.
The burning process utilizes an extension of the value balance mechanism already used for Zcash (ZEC) assets. This 
mechanism ensures that the sum of all inputs and outputs in a transaction, including any burned assets, is equal to zero, maintaining the overall balance of the system.

For every Custom Asset that is burnt, we add to the $\mathsf{assetBurn}$ set the tuple $(\mathsf{AssetBase}_{\mathsf{AssetId}}, \mathsf{v}_{\mathsf{AssetId}})$.

## Value Balance Verification 

Suppose that the transaction has:

- $n$ Action descriptions with value commitments $\mathsf{cv}^{\mathsf{net}}_i$, committing to values $\mathsf{v}^{\mathsf{net}}_i$, 
with randomness $\mathsf{rcv}_i$
- Orchard balancing value $\mathsf{v}^{\mathsf{balanceOrchard}}$ 
- Asset Burn value $\mathsf{v}_{\mathsf{AssetId}}$ for $(\mathsf{AssetBase}_{\mathsf{AssetId}}, \mathsf{v}_{\mathsf{AssetId}})\in \mathsf{assetBurn}$.

We denote by $\mathcal{S}_{\mathsf{ZEC}}\subseteq \{1,\dots,n\}$ the set of indices of Actions that are related to ZEC, and by
$\mathcal{S}_{\mathsf{AssetId}}\subseteq \{1,\dots,n\}$ the set of indices of Actions that are related to $\mathsf{AssetId}$.
Due to the Consensus Rules, sets  $\mathcal{S}_{\mathsf{ZEC}}$ and $\mathcal{S}_{\mathsf{AssetId}}$ are disjoint.
In a correctly constructed transaction, the following equations hold.
$$\mathsf{v}^{\mathsf{balanceOrchard}} = \sum_{i\in\mathcal{S}_{\mathsf{ZEC}}}\mathsf{v}^{\mathsf{net}}_i$$
$$\mathsf{v}_{\mathsf{AssetId}} = \sum_{i\in\mathcal{S}_{\mathsf{AssetId}}}\mathsf{v}^{\mathsf{net}}_i$$
$$\mathcal{S}_{\mathsf{ZEC}}\cup_{(\mathsf{AssetId},\cdot)\in\mathsf{assetBurn}}\mathcal{S}_{\mathsf{AssetId}}=  \{1,\dots,n\}$$
However, validators cannot check these equations directly because the values are hidden by the commitments.
Instead, validators calculate the transaction binding validating key as:
\begin{align*}
\mathsf{bvk} = & (\sum_{i=1}^n \mathsf{cv}^{\mathsf{net}}_i) - \mathsf{ValueCommit}^{\mathsf{OrchardZSA}}_{0}(\mathcal{V}^{\mathsf{Orchard}},\mathsf{v}^{\mathsf{balanceOrchard}}) \\
& - \sum_{(\mathsf{AssetBase}_{\mathsf{AssetId}}, \mathsf{v}_{\mathsf{AssetId}})\in \mathsf{assetBurn}}\mathsf{ValueCommit}^{\mathsf{OrchardZSA}}_{0}(\mathsf{AssetBase}_\mathsf{AssetId},\mathsf{v}_\mathsf{AssetId})
\end{align*}

The right hand side of the value balance verification equation can be expanded and calculated to:
\begin{align*}
\mathsf{bvk} = & (\sum_{i\in\mathcal{S}_{\mathsf{ZEC}}} \mathsf{cv}^{\mathsf{net}}_i) - \mathsf{ValueCommit}^{\mathsf{OrchardZSA}}_{0}(\mathcal{V}^{\mathsf{Orchard}},\mathsf{v}^{\mathsf{balanceOrchard}}) \\
& + \sum_{(\mathsf{AssetBase}_{\mathsf{AssetId}}, \mathsf{v}_{\mathsf{AssetId}})\in \mathsf{assetBurn}}\left( (\sum_{i\in\mathcal{S}_{\mathsf{AssetId}}} \mathsf{cv}^{\mathsf{net}}_i) - \mathsf{ValueCommit}^{\mathsf{OrchardZSA}}_{0}(\mathsf{AssetBase}_\mathsf{AssetId},\mathsf{v}_\mathsf{AssetId})\right)\\
= & \sum_{i\in\mathcal{S}_{\mathsf{ZEC}}} [\mathsf{rcv}_i]\mathcal{R}^{\mathsf{Orchard}} + \sum_{(\mathsf{AssetBase}_{\mathsf{AssetId}}, \mathsf{v}_{\mathsf{AssetId}})\in \mathsf{assetBurn}}\left( \sum_{i\in\mathcal{S}_{\mathsf{AssetId}}} [\mathsf{rcv}_i]\mathcal{R}^{\mathsf{Orchard}} \right)\\
= & \sum_{i=1}^{n} [\mathsf{rcv}_i]\mathcal{R}^{\mathsf{Orchard}}
\end{align*}


The signer knows $\mathsf{rcv}_i$, and so can calculate the corresponding signing key as:
$$\mathsf{bsk}=\sum_{i=1}^n \mathsf{rcv}_i$$

An Orchard binding signature proves knowledge of the discrete logarithm $\mathsf{bsk}$ of $\mathsf{bvk}$ with respect to 
$\mathcal{R}^{\mathsf{Orchard}}$. That is, $\mathsf{bvk} = [\mathsf{bsk}]\mathcal{R}^{\mathsf{Orchard}}$.
