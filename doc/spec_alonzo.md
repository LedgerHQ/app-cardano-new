# Alonzo for HW wallets specification

[Cardano documentation for Alonzo](https://github.com/IntersectMBO/cardano-ledger)

The recent pre-Alonzo updates to HW wallets have added support for script elements (full support for all address types, including those script-based; script hash-based stake credentials in certificates).

For Alonzo, there are several new elements optionally included in the transaction body. The main problem is that most of them cannot be verified by HW wallets in a viable way:

* Collateral inputs are opaque, so there is a danger of unlimited loss of funds (if the phase-2 validation fails).
* Data and script hashes are computed from potentially very complex data some parts of which might not be verifiable without access to the blockchain, and are a pain to process on HW wallets anyway. (See the section "Computation of complex hashes" for details.)

Our design therefore aims to keep as much Plutus complexity as possible away from HW wallets, and leaves to the human user all the responsibility for verifying that the transaction elements are correct.

Pre-Alonzo UTXOs (unspent transaction outputs) were governed by keys; that was almost entirely true even for funds held on script addresses, because native scripts are essentially a combination of keys and time locks. In other words, the witnesses required to spend UTXOs were just signatures.

With the introduction of Plutus in Alonzo, UTXOs on script addresses can now be governed by Plutus scripts which might or might not require a signature from a HW wallet. HW wallets are fairly protective of their keys and only allow key derivation along paths with prefixes from a fixed set (which is described in detail when we discuss particular elements of transactions). This inevitably imposes certain limitations on authors of Plutus scripts.

This update will enable HW wallet users to both create eUTXOs (extended UTXOs) that are supposed to be consumed by Plutus scripts, and to create transactions consuming eUTXOs that run Plutus scripts in phase-2 validation.

# New transaction signing mode

Transaction signing modes are used to explicitly declare the intent the client has (e.g. to sign a pool registration, or an ordinary payment transaction). They are a protective measure to counter HW wallets’ inability to see whole transactions at once and remove ambiguity and "intent guessing".

For transactions resulting in running Plutus scripts, we will add a new transaction signing mode PLUTUS_TRANSACTION because such transactions differ in several major aspects from existing types of transactions (e.g. inputs must be shown). Items collateral_inputs and required_signers will only be allowed in this new mode, and it will come with an appropriate warning.

The new transaction signing mode will **allow** **mixing key hash credentials** (with keys given by derivation paths, so belonging to the HW wallet, and also given by key hash) and **script credentials** in certificates because use cases for those depend on the Plutus scripts involved, and we do not want to introduce unnecessary restrictions.

We will **allow key hash credentials given by hash**: a user might manage some of his keys outside of a hw wallet and might want to use those keys together with HW wallet keys. (Since witnesses are hidden for ordinary payment transactions using 1852 keys, it is not safe to allow credentials given by key hash in such transactions; we only allow them in the new mode.)

For withdrawals, we will display the whole reward address instead of just a key hash.

For certificates, the key hash will be displayed in bech32 with prefix "stake_vkh" since that is the only key that is supposed to be used ("stake_shared_vkh" is only used within a native script, which uses a script hash credential in certificates).

Allowing signing Plutus txs with 1852 keys results in a security risk: certificates or withdrawals may contain key hashes and the user might inadvertently sign what he does not want to sign while providing a signature needed for a Plutus script, being tricked by a malicious SW wallet into believing that some of the withdrawals / certificates belong to third parties while they are actually his own. We will therefore always show all witnesses and all transaction body elements and let the human user verify they are as intended.

Plutus-related elements will not be allowed for pool registrations at present. There does not seem to be any use case for that: pool owners are assumed to be governed by ordinary keys and not by scripts, and operators have a specific pool cold key schema.

# New transaction body elements

1. The field **network_id**. Optional, see below.
2. The field **datum_hash** in transaction outputs will be optionally included if the output address contains a script hash in its payment part (it will be forbidden otherwise).
3. The field **script_data_hash** in the transaction body will be optionally included.
4. The field **collateral_inputs**. Optional, see below.
5. The field **required_signers**. Optional, see below.

The [CIP on restrictions for HW wallets](https://github.com/cardano-foundation/CIPs/blob/74bb782218e68f713cba7735c4de5a522ee8216a/CIP-0021/CIP-0021.md) will be modified accordingly.

HW wallets only serialize transaction bodies (in order to sign them) and do not see auxiliary data (except Catalyst registration data that needs to be signed) and similar information which is only included in transaction body indirectly via a hash (utxo datum, native and Plutus scripts etc.). The reason is that the amount of such data, and their potentially complex structure, are too much to display meaningfully on a small screen. Consequently, the above-mentioned list is exhaustive --- after adding these two fields, the changes to transaction serialization introduced in Alonzo will be fully reflected in HW wallets.

## Network id

The new transaction body item

    , ? 15 : network_id             ; New

will be optional, even in cases where network id is not included anywhere in the transaction.

Transactions without outputs, withdrawals and pool certificates (which contain a reward address) are subject to an attack where the attacker claims that it is a testnet transaction, while he actually submits it to a mainnet (it is valid for both networks). Such transactions will therefore get a warning and the human user can decide whether to proceed with signing. (Note that the network id is included implicitly via transaction inputs, but those are only shown to the user for Plutus transactions.) We can’t make network id mandatory even in these cases because with multi-party transactions, the person signing a transaction has no control over whether some other party included the network id or not, and we want to avoid forcing all the tools originating transactions to be aware of hardware wallets.

While the [Alonzo CDDL](https://github.com/input-output-hk/cardano-ledger-specs/blob/master/alonzo/test/cddl-files/alonzo.cddl) mentions that the only valid values are 0 or 1, it is better to allow all values between 0 and 15 and only display a warning for values not in {0, 1} --- if a new network appears in the future, there will be no need to update HW wallets’ code immediately.

## Outputs --- optional datum hash field

    transaction_output =
      [ address
      , amount : value
      , ? datum_hash : $hash32 ; New
      ]

The new optional field within transaction output is a hash computed from data with possibly rather complex structure. It only makes sense to allow it for outputs where the payment part of the address contains a script hash; we forbid it in all other cases (a SW wallet trying to include a redundant datum hash is either faulty or trying to harm the user by increasing his transaction fees).

Since we cannot determine if the datum hash is necessary or not (for native scripts, it is superfluous; for Plutus scripts, it is mandatory), we have to display a screen informing the user that no datum hash is present.

A HW wallet will only receive and display the given hash as an opaque byte string and serialize it after confirmation; if there is a need for calculating it within a HW wallet, it will be done via a separate call in the future.

The hash will be displayed in bech32 with the prefix "datum".
(CIP-5 will be modified accordingly.)

## Script data hash

The new optional transaction body item

    ? 11 : script_data_hash       ; New

comes from a possibly very complex structure (with regard to both size and the level of Cardano-specific knowledge necessary to understand it).

A HW wallet will only receive and display the given hash as an opaque byte string and serialize it after confirmation; if there is a need for calculating it within a HW wallet, it will be done via a separate call in the future.

The hash will be displayed in bech32 with the prefix "script_data".
(CIP-5 will be modified accordingly.)

## Collateral inputs

The new optional transaction body item

    ? 13 : set\<transaction_input\> ; Collateral ; new

can be implemented in a straightforward manner: the inputs will be displayed to the user one by one, one screen for each of the input data items (transaction_id, index), and serialized into the transaction body as the user clicks through them.

There is no easy way for a HW wallet to find out or verify what the input contains. It is technically possible: the whole transaction can be sent to the device, which will then parse it and extract the collateral amount to show to the user. But the parsing logic required would bring several problems:

* for general transactions, it seems too complex to fit on Ledger Nano S
* if we restrict it to a special subset of valid transactions, SW wallets will have a hard time creating/finding suitable collateral inputs
* future changes in transaction formats will require continuous updates
* the additional code could introduce bugs preventing users from using the feature, especially considering that Trezor has a release cycle of 1-2 months

Hence, this approach will not be taken.

In the future, a collateral change output will be added to transactions to make it entirely safe, but such changes in Cardano ledger specifications require a hard fork.

## Required signers

The new transaction body item

    , ? 14 : required_signers       ; New

can be included optionally. In the serialized form, it will be an array of key descriptors (path / key hash); HW wallets will not check whether the keys are unique.

There are two ways to supply a required signer key:

* Key hash; it will be displayed in bech32 with the prefix "req_signer_vkh".
  (CIP-5 will be amended accordingly.)
* Key derivation path, which will be displayed to the user.

We allow 1852 (both payment and staking), 1854, 1855 paths as defined in the respective CIPs and used previously in HW wallets. (1853 is reserved for pool operation and we don’t allow any Plutus stuff for such transactions.)

HW wallets will not check whether required signers given by paths are related to requested witness paths.

## Vkey witnesses

We allow 1852 (both payment and staking), 1854, 1855 paths as defined in the respective CIPs and used previously in HW wallets. (1853 is reserved for pool operation and we don’t allow any Plutus stuff for such transactions.)

## Inputs

Transaction inputs must be shown to the users because they are no longer interchangeable (each eUTXOs carries a specific datum hash).

# Computation of complex hashes

Alonzo comes with several types of hashes that are included in the transaction body and computed from complex and possibly quite large data (datum_hash, script_data_hash). We will not include computation of such hashes within the transaction signing call. Of course, it is possible to put these computations into separate calls, but we will not do it either for now.

Reasons:

1. During the implementation of catalyst voting, we discovered that it is not possible (or is exceedingly hard) to compute two rolling hashes at once within transaction signing flow on Ledger Nano S due to memory limitations. Consequently, auxiliary data hash is computed first for Catalyst registration, and only then is the transaction body hash computed. The same holds for Alonzo hashes, with the added complication that there is not enough memory to remember them all between their computation and the point at which they are included in the transaction body (there can be one hash per output and arbitrarily many outputs).

2. The data might be quite large, so clicking through it all on a small screen might not be worth the effort if the output amount is small. Users interested in verifying the hash will have the leeway to calculate it on a separate offline device more suitable to the task, or use the separate call within HW wallet if it is added in the future.

3. Hash computation starting with richly-structured data requires lots of new code, which might bring bugs. Inclusion of the computation within the transaction signing call could result in users being unable to sign transactions even in case they trust the hashes computed outside of HW wallets. Also, users who trust the hashes will needlessly click through long sequences of HW wallet screens they don’t care about, and might even miss something important in the process. It is therefore much safer from this viewpoint to keep the hash computations completely separate.

4. Typical users do not care about details of Cardano smart contract transactions, or are not capable / do not deem it worthy to understand them (e.g. what a redeemer is). Additionally, collateral inputs can’t be validated by HW wallets at all (see the section on collateral inputs below), so at least a portion of the transaction cannot be trusted in the strict sense anyway.

5. The current Ledger Nano S app already takes about 70% of maximum available space, so we are wary about increasing it. The demand for hash verification calls is not yet clear and their implementation and testing will take considerable time which would hamper the release of the Alonzo features for all users, including those who do not care about hash verification on HW wallets.
