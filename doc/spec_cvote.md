# CVote Voting for HW Wallets: CIP-36 and CIP-15

The starting point is [https://cips.cardano.org/cips/cip36/](https://cips.cardano.org/cips/cip36/).

### **New key derivation schema**

CIP-36 will use keys with derivation path
m / 1694' / 1815' / account' / chain / address_index.

For chain, we only allow value 0.

In case of address keys, HW wallets treat derivation paths with account above 100 and address index above 1,000,000 as unreasonable and display a warning (for most users, such values are only likely to occur due to a bug or a malicious actor in the system, and potentially make searching for blockchain items belonging to the user very difficult). We will apply the same restrictions to CIP-36 voting keys.

It is reasonable to allow SW wallets to derive CIP-36 public keys as they need, so there are two relevant forms of derivation paths for public key export:
    m / 1694' / 1815' / account' / chain / address_index
    m / 1694' / 1815' / account'
These new derivation paths need to be added to existing calls for exporting public keys, and the functions classifying derivation paths and the related security policies need to be revised.

CIP-36 voting account keys will be exported silently in non-expert mode on Ledger (similarly to staking keys). On Trezor, there is a parameter in GetPublicKey that determines whether they should be displayed or not.

Keys derived according to the new schema will only be allowed for registration metadata and for signing CIP-36 voting. They cannot be used in the body of Cardano transactions (e.g. in required signers) or to witness Cardano transactions.

The relevant call in CIP-62 is
**api.getVotingKeys**(): Promise<cbor<PublicKey>[]>

### **New format for registration transaction metadata**

New format for registration data (referred to as CIP-36) which is included in Cardano transaction metadata: displayed on the right-hand side in comparison to the previously used format (referred to as CIP-15) on the left-hand side.

#### CIP-15

    registration_cbor = {
      61284: key_registration,
      61285: registration_signature
    }

    $voting_pub_key /= bytes .size 32
    $reward_address /= bytes
    $nonce /= uint
    $staking_pub_key /= bytes .size 32
    $ed25519_signature /= bytes .size 64

    key_registration = {
      1 : $voting_pub_key,
      2 : $staking_pub_key,
      3 : $reward_address,
      4 : $nonce,
    }

    registration_signature = {
      1 : $ed25519_signature
    }

#### CIP-36

    registration_cbor = {
      61284: key_registration,
      61285: registration_witness
    }

    $voting_pub_key /= bytes .size 32
    $reward_address /= bytes
    $nonce /= uint
    $staking_pub_key /= bytes .size 32
    $ed25519_signature /= bytes .size 64

    legacy_key_registration = $voting_pub_key

    $proportion /= uint .size 4
    $voting_purpose /= uint
    delegation = ($voting_pub_key, $proportion) ; see (*) below

    $stake_credential /= $staking_pub_key
    $stake_witness /= $ed25519_signature

    key_registration = {
      1 : [+delegation] / legacy_key_registration,
      2 : $stake_credential,
      3 : $reward_address,
      4 : $nonce,
      ? 5 : $voting_purpose .default 0
    }

    registration_witness = {
      1 : $stake_witness
    }

(*) There seems to be an error in the schema provided in CIP-36: while the schema file says
delegation = ($voting_pub_key, $proportion)
the examples actually use
delegation = [$voting_pub_key, $proportion]
which is consistent with testnet, so that's what will be implemented.

Voting purpose will be implemented as uint64. It will be only shown in expert mode. If it is not sent by the client, a default 0 will be serialized.

HW wallets will validate that the delegation array is non-empty. They won't validate that at least one weight is non-zero (even though it is required): the weights are shown to the user, and even a single zero weight is suspicious (implementing such non-local validations is tedious and costs precious memory in HW wallets).

For voting public keys in the new CIP-36 format, HW wallets will support both device-owned keys (given by derivation path) and third-party keys (given as bytestrings), arbitrarily mixed in a single registration. (The CIP-15 format will only support third-party keys.)
The keys will be displayed in UI with prefixes according to CIP-5 update https://github.com/cardano-foundation/CIPs/pull/342

Test vectors are available at [https://cips.cardano.org/cips/cip36/test-vector.md.html](https://cips.cardano.org/cips/cip36/test-vector.md.html)

####

#### **Duplicate keys**

HW wallets won't check for duplicate keys, they will display keys and their weights as given.

The only way for Ledger to check for duplicity of keys is to impose some kind of canonical ordering on the keys in the array that can be checked locally (i.e. if every two consecutive keys are in the right order, then all the keys are in the right order). That would enforce that copies of the same key are next to each other in the array. That is likely to lead to interoperability issues (the metadata has to be constructed in this way by any client that initiates the transaction). Another (although in this case minor) disadvantage is the amount of code that needs to be added to the Ledger app size.

#### **Reward address restrictions**

1. Currently, any Shelley address is allowed as a Catalyst reward address, and if it is not reward or base address, a warning is shown. The address is shown as bech32.
2. An attacker might want to trick the user into accepting a catalyst reward address that is not under his control, or has staking outside his control, or makes the rewards unspendable (e.g. when a scripthash is used in the payment part).
3. I see three options here:
(a) leave everything to the user, just show him the bech32 address and let him decide, no warnings
(b) leave the final decision on the user, but anything that is not standard and expected gets a warning \--- you need to precisely specify when to show the warning
(c) restrict address type (e.g. no script hash in the payment part), or even add some more specific restrictions on parts of the address (it is supplied), and potentially add some

#### **Across-transaction account restrictions**

There must be no restrictions tying a CIP-36 voting key account to Cardano spending or staking key accounts. Also, there must be no restriction on the reward address account. Users might want to pool rewards from several accounts into a single reward address, even potentially one managed by a third party, and CIP-36 voting keys are managed entirely separately.
There will be no warnings related to mismatched accounts shown. (But non-standard accounts, i.e. above 100, will still get a warning.)

#### **Auxiliary data format**

The current implementation uses the Mary format for transaction metadata, i.e.
[{...registration metadata...}, []].
We will keep supporting this and only this format.

### **New API call for signing voting transactions**

This new API call has nothing to do with Cardano transactions. Most of the data in CIP-36 vote requests are irrelevant for users, so we display only a very limited subset of them (see "UI for voting transactions").

signCVoteRequest(request: SignCVoteRequest):
    SignCVoteResponse

type SignCVoteRequest = {
    // bytestring to sign in hex
    voteCastDataHex: string;

    // the witness path for which we need a signature
    witnessPath: BIP32Path;
}

type SignCVoteResponse = {
    // Hash of the VOTE-CAST message being signed.
    // Callers should check that they serialize tx the same way
    voteCastHashHex: string;

    witness: Witness;
};

type Witness = {
    path: BIP32Path;
    signatureHex: string;
};

The relevant call in CIP-62 is
**api.submitVotes**(votes: Vote[], spendingCounter: number): Promise<hash32>

### **UI for voting transactions**

The voteCastDataHex mentioned above is a hex-encoded vote cast message (includes inputs, see [https://github.com/input-output-hk/chain-libs/pull/836](https://github.com/input-output-hk/chain-libs/pull/836)). It is longer than what can be sent in a single APDU in Ledger, so it has to be transmitted in chunks. For signing, we need to compute its blake2b256 hash (the rolling hash computation mimics what we do for Cardano transactions), and sign the hash for each of the keys derived according to the paths given in SignCVoteRequest.witnessPaths.

The portion of the bytestring potentially interesting to the users is the beginning of it, which is a concatenation of the following:

1. vote plan id (32 bytes),
2. proposal index (1 byte), to be shown as uint8
3. payload type tag (1 byte), to be shown as uint8

These things can be easily parsed from the first chunk of the bytestring. We will only show them in expert mode. (The expert mode can be toggled on in the Ledger app menu, or chosen on the first screen for Trezor.)

