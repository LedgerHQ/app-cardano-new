# Stakepool owner support for HW wallets

## Tech Specs

# 1 Introduction

Ledger and Trezor hardware wallets already support signing transactions for Cardano. The use cases currently supported are:

1. basic funds transfers
2. staking key registration
3. staking key de-registration
4. stake delegation ("binding" the staking key to a stake pool)
5. rewards withdrawal

The purpose of this document is to specify the expected behavior of HW wallets for an additional use case - stakepool
registration from the perspective of stakepool owner(s) in terms of prompts displayed to the user of the HW wallet when confirming such a transaction. There are two aspects to this feature:

1. Signing transactions by multiple parties
2. Ability to build stakepool registration certificates and include them into transactions on a HW wallet

Note that for stakepool deregistration only the involvement of the stakepool operator is required, therefore we are not including that use case.

# 2 Stakepool registration transaction breakdown

Example of a stakepool registration transaction CBOR:

    83a500818258207abd93f2d672f23e7e11720a83c4de66906402c59cb44b90494522124aea65b700018182583900dc24a9b6cc33cd6f0c8c96e3ef8c86402a5261a5145568bf423496743a7f09d3df4cf66a7399c2b05bfa234d5a29560c311fc5db4c4907111a1da927a8021a00030d40031a004c4b4004828a03581c5631ede662cfb10fd5fd69b4667101dd289568e12bcf5f64d1c406fc5820198890ad6c92e80fbdab554dda02da9fb49d001bbd96181f3e07f7a6ab0d06401a1dcd65001a1443fd00d81e820101581de03a7f09d3df4cf66a7399c2b05bfa234d5a29560c311fc5db4c49071181581c3a7f09d3df4cf66a7399c2b05bfa234d5a29560c311fc5db4c4907118184001904d24408080808f682781968747470733a2f2f746573747374616b65706f6f6c2e636f6d5820914c57c1f12bbf4a82b12d977d4f274674856a11ed4b9b95bd70f5d41c5064a683028200581c3a7f09d3df4cf66a7399c2b05bfa234d5a29560c311fc5db4c490711581c5631ede662cfb10fd5fd69b4667101dd289568e12bcf5f64d1c406fca10083825820d014e5e3b8ee2976994104ec8d0802d35fd9c4246b890ae02c3d3a1066a8affd584063ad4e566685baa0eb1480166b1beb64c04a8f77f954431ff152e8a6e6bbda0ae6ea317508a94a1526f6661366301a540aca4344f5fe35f781347318db2b840b82582078b0a45c5aea1044203c1c290b892ae940ed7bbaa01b4b87de0ef5336fd70adf58407a0656e9627df6593a8b99846d29f998c95ed5057259dbb3acb1c1036211ed2b8adcf08dd062e662592c39814a4f41dc8971b714185403c2667c6b588860bb04825820db2487cf9a05346954df7a5e6b5c1c2c87fc65117c9787ba645377cded58b0185840a1a931571a4f5fea40d0b9a8c6e132e705db408f288f944e91de510125c9e78e29a596a9d4ead3ebd5e8c72ff93392a5a5af3b7f97e728b01b2053f01078720df6

Related cardano-cli command to build the pool registration certificate (just the certificate, not the whole tx):

    cardano-cli shelley stake-pool registration-certificate \
      --cold-verification-key-file cold.vkey \
      --vrf-verification-key-file vrf.vkey \
      --pool-pledge 500000000 \
      --pool-cost 340000000 \
      --pool-margin 0.1 \
      --pool-reward-account-verification-key-file ../address_keys/staking_key.pub \
      --pool-owner-stake-verification-key-file ../address_keys/staking_key.pub \
      --testnet-magic 1097911063 \
      --single-host-pool-relay aaaa.bbbb.com \
      --pool-relay-port 5678 \
      --metadata-url https://teststakepool.com \
      --metadata-hash 914c57c1f12bbf4a82b12d977d4f274674856a11ed4b9b95bd70f5d41c5064a6 \
      --out-file pool-registratiooon.cert

Here is the break down of the same transaction into its components which can be parsed out from the CBOR with [https://cbor.me](https://cbor.me) :

    [
      {
      // inputs
      0: [
        [h'7ABD93F2D672F23E7E11720A83C4DE66906402C59CB44B90494522124AEA65B7', 0]
      ],
      // outputs
      1: [
        [h'00DC24A9B6CC33CD6F0C8C96E3EF8C86402A5261A5145568BF423496743A7F09D3DF4CF66A7399C2B05BFA234D5A29560C311FC5DB4C490711', 497625000]
      ],
      // fee
      2: 200000,
      // ttl
          3: 5000000,
          // certificates
      4: [
    [
      3, // pool registration certificate type enum
      h'5631EDE662CFB10FD5FD69B4667101DD289568E12BCF5F64D1C406FC', // b2b-224 cold key hash (i.e. pool hash)
      h'198890AD6C92E80FBDAB554DDA02DA9FB49D001BBD96181F3E07F7A6AB0D0640', // vrf public key (32 bytes) b2b-256 hash
      500000000, // pool pledge
      340000000, // pool cost
      30([1, 1]), // pool margin as a fraction [numerator, denominator] (denominator must be greater or equal than numerator)
      h'E03A7F09D3DF4CF66A7399C2B05BFA234D5A29560C311FC5DB4C490711', // pool reward address
      [
      h'3A7F09D3DF4CF66A7399C2B05BFA234D5A29560C311FC5DB4C490711' // pool owners reward account public key b2b-224 hashes
      ],
      // relay host definitions, see https://github.com/input-output-hk/cardano-ledger-specs/blob/4edcdab87510b2657c62bcf14035817ce6e23455/shelley/chain-and-ledger/shelley-spec-ledger-test/cddl-files/shelley.cddl#L143
      [
      [
          0, // "single host ip=0, single host name = 1, multi host name = 2"
          1234, // relay port
          h'08080808', // relay ipv4 address as 4 bytes
          null // ipv6 address of the relay as 16 bytes
      ]
      // note both ipv4 and ipv6 address can be in the same "single host ip entry"
      ],
      [
      "https://teststakepool.com", // metadata URL
      h'914C57C1F12BBF4A82B12D977D4F274674856A11ED4B9B95BD70F5D41C5064A6' // metadata b2b-256 hash
      ]
    ],
        [
          2, // 2=stake delegation certificate type enum
          [
            0, //delegation amount
            h'3A7F09D3DF4CF66A7399C2B05BFA234D5A29560C311FC5DB4C490711' // staking key hash
          ],
          // pool id (cold key hash)
          h'5631EDE662CFB10FD5FD69B4667101DD289568E12BCF5F64D1C406FC'
        ]
      ]
      },
      // witnesses
      {
      0: [
        [
          h'D014E5E3B8EE2976994104EC8D0802D35FD9C4246B890AE02C3D3A1066A8AFFD',
          h'63AD4E566685BAA0EB1480166B1BEB64C04A8F77F954431FF152E8A6E6BBDA0AE6EA317508A94A1526F6661366301A540ACA4344F5FE35F781347318DB2B840B'
        ],
        [
          h'78B0A45C5AEA1044203C1C290B892AE940ED7BBAA01B4B87DE0EF5336FD70ADF',
          h'7A0656E9627DF6593A8B99846D29F998C95ED5057259DBB3ACB1C1036211ED2B8ADCF08DD062E662592C39814A4F41DC8971B714185403C2667C6B588860BB04'
        ],
        [
          h'DB2487CF9A05346954DF7A5E6B5C1C2C87FC65117C9787BA645377CDED58B018',
          h'A1A931571A4F5FEA40D0B9A8C6E132E705DB408F288F944E91DE510125C9E78E29A596A9D4EAD3EBD5E8C72FF93392A5A5AF3B7F97E728B01B2053F01078720D'
        ]
      ]
      },
      null // tx metadata

Examples of other relay node definition formats:

    [
      [
        0, // "single host ip=0, single host name = 1, multi host name = 2"
        1234, // relay port
        h'08080808', // relay ipv4 address as 4 bytes
        null // ipv6 address of the relay as 16 bytes
      ]
      // note both ipv4 and ipv6 address can be in the same "single host ip entry"
      [
        0, // "single host ip=0, single host name = 1, multi host name = 2"
        1234, // relay port
        h'08080808', // relay ipv4 address as 4 bytes
        h'B80D01200000A3852E8A000034737003' // ipv6 address of the relay as 16 bytes
      ]
      [
        0, // "single host ip=0, single host name = 1, multi host name = 2"
        1234, // relay port
        h'08080808', // relay ipv4 address as 4 bytes
        h'B80D01200000A3852E8A000034737003' // ipv6 address of the relay as 16 bytes
      ],
      [
        1, // single host pool relay
        5678, // host port
        "aaaa.bbbb.com" // host DNS name - A or AAAA DNS record
      ]
      [
        2, // multi-host relay
        "xxx.yyy.net" // DNS name - SRV DNS record
      ]
    ],


# 3 Multi-party transaction signing

Until now, the assumption was that the transaction was signed by a single party meaning that the **hardware wallet was supposed to manage the private keys needed for all the witnesses** to the transaction. This however changes with the introduction of the stakepool registration use case as multiple owners, i.e. parties are supposed to participate in the transaction, each of them supplying their own witnesses to the transaction.

Let's break down the impact of such change on the APIs of the hardware wallets that should support this new use case:

## 3.1 Security issues:

Multi-party transactions provide a potentially new way of how to confuse users and steal their funds. The main problem that hardware wallets have to tackle is the fact that there are UTxOs from multiple parties and the wallet **is not able** to determine the amount of funds for witnesses it needs to sign. As a consequence, if the wallet displays every output's amount, the user is not able to distinguish who is going to pay for that amount.

Addressing this issue is technically very complicated -- in order to provide correct data, the wallet would need to not only receive the transaction itself but all UTxO transactions, determine their amounts plus if it is the owner and then take this information into the account.

Given that there doesn't seem to be any other obvious multi-owner[^1] transaction use-case for now, this seems like an overkill and we therefore propose to just create a special version of signTx call which allows signing **only** by the staking key. This would allow pool owners to sign transactions proposed by the pool operator, as long as the transaction does not spend any of the owner's money. As a side-effect, note that this **would not** enable pool owner and operator being the same hardware wallet.


## 3.2 HW wallets API

Given that the stakepool owner use case requires having the transaction signed by multiple parties, we will be introducing support for partially signed transactions (though with special restrictions due to the security concern raised in section 3.1. which we will elaborate on in section 4).

### 3.2.1 Ledger

The Ledger API returns just the witnesses of the signed transaction, not the full transaction, which means we don't have to deal with the question of how to serialize a partially signed transaction, leaving that responsibility up to the party that integrates with this API.

However, on the JS API level we will have to introduce transaction inputs without a private key derivation path supplied as those will no longer be controlled by the HW wallet but by the co-signer(s) (i.e. pool operator for our specific use case).

### 3.2.2 Trezor

Trezor returns the full transaction body and the witnesses. We propose retaining the same output format even after the inclusion of the multi-party use case, relaxing the assumption that the serialized transaction being returned is submittable as-is.

Trezor would be serializing into the list of witnesses only the witnesses that the device itself has provided, leaving up to the party that integrates with the API to disassemble the transaction and inject the remaining witnesses provided by other parties into the final transaction to be submitted.

Regarding the input format changes required, it's analogous to the changes outlined for Ledger.

# 4 Stakepool registration

## 4.1 Security considerations

### 4.1.1 Separate flow for stakepool registration

Given the security concern raised in section 3, we won't be including support for stakepool registration certificates within the generic transaction signing flow. HW wallets will have a separate flow for stakepool registration which would allow only for transaction inputs/outputs and a single stakepool registration certificate and only the witness for the owner's staking key will be returned from the wallet.

This means we will introduce a dedicated signStakepoolRegistrationCertificateAsOwner call (or something along those lines, TBD how the outward facing API will be impacted) which would share most of the interface that the standard signTransaction call has, but will have the restrictions outlined above. This means, only inputs and outputs will be allowed (without derivation paths as the pool owner does not control those) and a single stakepoolRegistrationCertificate.

Also, even though we will be extending the supported certificate types to be supplied to HW wallets, the internal validation logic will prevent stakepool registration certificates from being included into standard txs produced by the standard signTransaction call.

## 4.2 UX flow

The user will be confirming a single stakepool registration certificate and the hw wallet won't be signing any of the inputs used to pay the pool deposit, which will be the responsibility of the pool operator. This is to mitigate the security concern raised in section 3\.

This means we can omit information about transaction fees/outputs (even if they are given as raw addresses), since owner's funds can't be affected by it and it falls under operator's responsibility to pay the right fees/deposit.

Also, given that this flow is meant just for owners, we don't want to overwhelm the (likely non-technical) users with the low-level details (relay ips, ...) of the stakepool registration certificate, provided they have basic trust in the stakepool operator which has the ultimate responsibility of registering the stake pool with proper parameters.

Fields to show to the owners/deposit payer:

* pool hash
* pool pledge
* pool cost
* pool margin
* pool reward address
* owners' reward addresses
* metadata URL
* transaction TTL

Fields omitted from the UI:

* vrf public key hash
* relay hosts information
* metadata hash
* output address(es)
* amounts sent
* fees
* no withdrawals (forbidden in the tx by design due to security)
* no other certificates (forbidden in the tx by design due to security)

Note that the use case of registering the pledge by the owners (i.e. stake delegation of the amount to be pledged) is already covered by the existing implementation in the hardware wallets as they already support stake delegation.

## 4.3 HW wallets API

The API of both Ledger and Trezor already supports the "Certificate" entity, namely the staking key registration/deregistration and stake delegation types of that entity.

Supporting the certificate registration use case boils down to adding a new type of Certificate, but given the big and potentially unbounded (due to the list of relay nodes) size of that new kind of entry, the implementation won't be that straightforward, requiring streaming of the fields within the "Certificate" message. Let's break the changes down by device:

### 4.3.1 Separate sign Stakepool Registration call

As outlined in 4.1.1, we will have a separate call for signing stakepool registration which would be a restricted version of the sign transaction call with the added support for a single Stakepool registration certificate.

Function signature:

    signStakepoolRegistrationAsOwner(
      networkId,
      protocolMagic,
      inputs, // tx inputs without any path supplied
      outputs // tx outputs, only as addresses
      fee, // same as in a standard tx
      ttl, // same as in a standard tx
      poolParams // stakepool params, structure outlined in below section
      metadataHashHex // same as in a standard tx
    )

### 4.3.1 High-level format of the stakepool registration certificate message

Currently the "Certificate" type of input to the hw wallets' api, be it Ledger or Trezor has a single structure to represent the Certificate which is fine for the existing use cases. However, the stakepool registration usecase involves a complex structure which contains many fields, some of them of potentially unbounded size.

Given the pool parameters complexity and difference from the already implemented certificate types, and to keep the API and its underlying logic simple to implement and understand, the sensible approach seems to be to decouple the certificate "header" stating the type of the certificate and its "payload" which would be specific to the Certificate type:

**Current Certificate Message format** (see Ledger JS [code](https://github.com/vacuumlabs/ledgerjs-cardano-shelley/blob/fca027c12382ff24f97b844a69c82eab58280fad/src/Ada.js#L68), Trezor is [similar](https://github.com/trezor/connect/blob/afe02cfbfae0fe0d85ccd251edfd73f6f2e7d86b/src/js/types/networks/cardano.js#L73)):

    type Certificate = {
      type: number,
      path: BIP32Path,
      poolKeyHashHex: ?string
    };

**Proposed new Certificate message format** (inspired by [CDDL](https://github.com/input-output-hk/cardano-ledger-specs/blob/4edcdab87510b2657c62bcf14035817ce6e23455/shelley/chain-and-ledger/shelley-spec-ledger-test/cddl-files/shelley.cddl#L112)) :

    type Certificate = {
      type: <certificate type enum, "3" for pool registration>
    }

    type StakingCredential { // expected for stake registration/deregistration/delegation
      stakingKeyHash/path
    }

    type PoolKeyHash { // expected for stake delegation
      poolKeyHash
    }

    type PoolParams = { // expected for stakepool registration
      poolKeyHash, (28 bytes)
      vrfKeyHash, (32 bytes)
      pledge, (<= 9 bytes)
      cost, (<= 9 bytes)
      marginNumerator, (<=9 bytes)
      marginDenominaror, (<= 9 bytes)
      rewardAccountKeyHash (28 bytes),
      poolOwnersCount (4 bytes),
      relaysCount (4 bytes),
    }

    type PoolOwnerParams = {
      stakingKeyHash/path // depending on whether the user owns the staking key or not
    }

    type RelayParams = {
      type, // single host ip=0, single hostname = 1, multi host name = 2
      Union(<ipv4Addr, ipv6Addr, portNumber>, <dnsName, portNumber>, <dnsName>)
    }

    type PoolMetadataParams = {
      url (<= 64 bytes ASCII string) // need to whitelist valid characters
      hash (32 bytes) // metadata hash
    }

# 5 Additional resources

* [Functional breakdown of stakepool registration](https://docs.google.com/document/d/1pJdRKEvCsbLxQA25FVATrUFFiIMZd3NFK-NbPwKL2-8/edit#)
* [Stakepool operations with cardano-cli docs](https://docs.cardano.org/projects/cardano-node/en/latest/stake-pool-operations/getConfigFiles_AND_Connect.html)
* [Cardano binary formats specs](https://github.com/input-output-hk/cardano-ledger-specs/blob/master/shelley/chain-and-ledger/shelley-spec-ledger-test/cddl-files/shelley.cddl)

[^1]:  Note: multi-owner and multi-sig are somewhat different and orthogonal concepts. The solution does not preclude multi-sig transactions assuming all of the utxo entries belong to the same multi-sig address. It however prevents two users to mutually agree on a transaction where each user supplies part of the transaction inputs. TODO: is this reasonable assumption? Won't we need this for some escrow-scheme transactions in the future?



# Ledger app for Cardano Stake Pool Operators

## Tech specs

# 1 Introduction

Stake pool operators perform a specific set of operations, different from most "ordinary" users involved in the Cardano blockchain. Currently, the only way they can assemble their transactions is via the cardano-cli tool which runs in a standard OS environment, making them vulnerable to man-in-the-middle attacks and leaking of their credentials as the private keys are stored directly on the computer's hard drive. This can be solved by adding support for stake pool management operations to hardware wallets which would shield the credentials and give an additional layer of assurance when assembling the transactions needed to run the stake pool.

In order to not bloat the common Ledger Cardano app, given the limited storage of the Ledger device and relatively small target audience (several hundreds of users), we will be introducing a new dedicated Ledger application that will offer the functionality required to safely manage a Cardano stake pool. This document serves as a technical specification of such an application for Ledger Nano hardware wallet.

# 2 Functional requirements

The stake pool operator Ledger app will be able to:

1. Deterministically derive the stake pool cold key from Ledger's seed
2. Manage multiple pools (multiple cold keys)
3. Sign stake pool registration transaction (with operator key)
4. Sign stake pool retirement transaction
5. Sign stake pool operational certificate

The stake pool operation won't be doing the following:

1. Manage the VRF key - it will be derived in the CLI tool given that the VRF private key needs to reside on the server running the pool anyway
2. Manage the KES key - same as the VRF key, the KES private key needs to reside on the server running the pool, so there's no added value in storing/deriving the key in the hw wallet

# 3 Functional samples

Below are samples of the different transactions/structures that the operator app will support with notes that should serve as reference for the implementation of the serialization/signing logic.

## 3.1 Stake pool registration

Note that this operation is already supported by the standard Ledger Cardano app, but only witnessing of the pool owners' keys is supported.

The operator app, when signing the transaction in operator mode will return just spending key witnesses for the transaction inputs and the cold key witness. If the operator participates in the pool as an owner, they need to sign the transaction again in owner mode. The transaction signing modes to be passed to Ledger signTransaction call are further discussed in section 5.3.3

### Related cardano-cli command

    cardano-cli shelley stake-pool registration-certificate \
      --cold-verification-key-file cold.vkey \
      --vrf-verification-key-file vrf.vkey \
      --pool-pledge 500000000 \
      --pool-cost 340000000 \
      --pool-margin 0.1 \
      --pool-reward-account-verification-key-file ../address_keys/staking_key.pub \
      --pool-owner-stake-verification-key-file ../address_keys/staking_key.pub \
      --testnet-magic 1097911063 \
      --single-host-pool-relay aaaa.bbbb.com \
      --pool-relay-port 5678 \
      --metadata-url https://teststakepool.com \
      --metadata-hash 914c57c1f12bbf4a82b12d977d4f274674856a11ed4b9b95bd70f5d41c5064a6 \
      --out-file pool-registratiooon.cert

### Example of a stakepool registration transaction CBOR

    83a500818258207abd93f2d672f23e7e11720a83c4de66906402c59cb44b90494522124aea65b700018182583900dc24a9b6cc33cd6f0c8c96e3ef8c86402a5261a5145568bf423496743a7f09d3df4cf66a7399c2b05bfa234d5a29560c311fc5db4c4907111a1da927a8021a00030d40031a004c4b4004828a03581c5631ede662cfb10fd5fd69b4667101dd289568e12bcf5f64d1c406fc5820198890ad6c92e80fbdab554dda02da9fb49d001bbd96181f3e07f7a6ab0d06401a1dcd65001a1443fd00d81e820101581de03a7f09d3df4cf66a7399c2b05bfa234d5a29560c311fc5db4c49071181581c3a7f09d3df4cf66a7399c2b05bfa234d5a29560c311fc5db4c4907118184001904d24408080808f682781968747470733a2f2f746573747374616b65706f6f6c2e636f6d5820914c57c1f12bbf4a82b12d977d4f274674856a11ed4b9b95bd70f5d41c5064a683028200581c3a7f09d3df4cf66a7399c2b05bfa234d5a29560c311fc5db4c490711581c5631ede662cfb10fd5fd69b4667101dd289568e12bcf5f64d1c406fca10083825820d014e5e3b8ee2976994104ec8d0802d35fd9c4246b890ae02c3d3a1066a8affd584063ad4e566685baa0eb1480166b1beb64c04a8f77f954431ff152e8a6e6bbda0ae6ea317508a94a1526f6661366301a540aca4344f5fe35f781347318db2b840b82582078b0a45c5aea1044203c1c290b892ae940ed7bbaa01b4b87de0ef5336fd70adf58407a0656e9627df6593a8b99846d29f998c95ed5057259dbb3acb1c1036211ed2b8adcf08dd062e662592c39814a4f41dc8971b714185403c2667c6b588860bb04825820db2487cf9a05346954df7a5e6b5c1c2c87fc65117c9787ba645377cded58b0185840a1a931571a4f5fea40d0b9a8c6e132e705db408f288f944e91de510125c9e78e29a596a9d4ead3ebd5e8c72ff93392a5a5af3b7f97e728b01b2053f01078720df6

###  Parsed signed transaction

    [
      {
      // inputs
      0: [
        [h'7ABD93F2D672F23E7E11720A83C4DE66906402C59CB44B90494522124AEA65B7', 0]
      ],
      // outputs
      1: [
        [h'00DC24A9B6CC33CD6F0C8C96E3EF8C86402A5261A5145568BF423496743A7F09D3DF4CF66A7399C2B05BFA234D5A29560C311FC5DB4C490711', 497625000]
      ],
      // fee
      2: 200000,
      // ttl
          3: 5000000,
          // certificates
      4: [
    [
      3, // pool registration certificate type enum
      h'5631EDE662CFB10FD5FD69B4667101DD289568E12BCF5F64D1C406FC', // b2b-224 cold key hash (i.e. pool hash)
      h'198890AD6C92E80FBDAB554DDA02DA9FB49D001BBD96181F3E07F7A6AB0D0640', // vrf public key (32 bytes) b2b-256 hash
      500000000, // pool pledge
      340000000, // pool cost
      30([1, 1]), // pool margin as a fraction [numerator, denominator] (denominator must be greater or equal than numerator)
      h'E03A7F09D3DF4CF66A7399C2B05BFA234D5A29560C311FC5DB4C490711', // pool reward address
      [
      h'3A7F09D3DF4CF66A7399C2B05BFA234D5A29560C311FC5DB4C490711' // pool owners reward account public key b2b-224 hashes
      ],
      // relay host definitions, see https://github.com/input-output-hk/cardano-ledger-specs/blob/4edcdab87510b2657c62bcf14035817ce6e23455/shelley/chain-and-ledger/shelley-spec-ledger-test/cddl-files/shelley.cddl#L143
      [
      [
          0, // "single host ip=0, single host name = 1, multi host name = 2"
          1234, // relay port
          h'08080808', // relay ipv4 address as 4 bytes
          null // ipv6 address of the relay as 16 bytes
      ]
      // note both ipv4 and ipv6 address can be in the same "single host ip entry"
      ],
      [
      "https://teststakepool.com", // metadata URL
      h'914C57C1F12BBF4A82B12D977D4F274674856A11ED4B9B95BD70F5D41C5064A6' // metadata b2b-256 hash
      ]
    ],
        [
          2, // 2=stake delegation certificate type enum
          [
            0, //delegation amount
            h'3A7F09D3DF4CF66A7399C2B05BFA234D5A29560C311FC5DB4C490711' // staking key hash
          ],
          // pool id (cold key hash)
          h'5631EDE662CFB10FD5FD69B4667101DD289568E12BCF5F64D1C406FC'
        ]
      ]
      },
      // witnesses
      {
      0: [
        [
          h'D014E5E3B8EE2976994104EC8D0802D35FD9C4246B890AE02C3D3A1066A8AFFD',
          h'63AD4E566685BAA0EB1480166B1BEB64C04A8F77F954431FF152E8A6E6BBDA0AE6EA317508A94A1526F6661366301A540ACA4344F5FE35F781347318DB2B840B'
        ],
        [
          h'78B0A45C5AEA1044203C1C290B892AE940ED7BBAA01B4B87DE0EF5336FD70ADF',
          h'7A0656E9627DF6593A8B99846D29F998C95ED5057259DBB3ACB1C1036211ED2B8ADCF08DD062E662592C39814A4F41DC8971B714185403C2667C6B588860BB04'
        ],
        [
          h'DB2487CF9A05346954DF7A5E6B5C1C2C87FC65117C9787BA645377CDED58B018',
          h'A1A931571A4F5FEA40D0B9A8C6E132E705DB408F288F944E91DE510125C9E78E29A596A9D4EAD3EBD5E8C72FF93392A5A5AF3B7F97E728B01B2053F01078720D'
        ]
      ]
      },
      null // tx metadata
    ]

Note that the tx example here contains also the witness of owner's staking key (the first witness in the list, i.e. for the key "d014...") but the stake pool operator app would be returning only the other two witnesses (for the input spending key and pool cold key) if signing the transaction in "operator mode".

Examples of other relay node definition formats:

    [
      [
        0, // "single host ip=0, single host name = 1, multi host name = 2"
        1234, // relay port
        h'08080808', // relay ipv4 address as 4 bytes
        null // ipv6 address of the relay as 16 bytes
      ]
      // note both ipv4 and ipv6 address can be in the same "single host ip entry"
      [
        0, // "single host ip=0, single host name = 1, multi host name = 2"
        1234, // relay port
        h'08080808', // relay ipv4 address as 4 bytes
        h'B80D01200000A3852E8A000034737003' // ipv6 address of the relay as 16 bytes
      ]
      [
        0, // "single host ip=0, single host name = 1, multi host name = 2"
        1234, // relay port
        h'08080808', // relay ipv4 address as 4 bytes
        h'B80D01200000A3852E8A000034737003' // ipv6 address of the relay as 16 bytes
      ],
      [
        1, // single host pool relay
        5678, // host port
        "aaaa.bbbb.com" // host DNS name - A or AAAA DNS record
      ]
      [
        2, // multi-host relay
        "xxx.yyy.net" // DNS name - SRV DNS record
      ]
    ]

###    Stake pool metadata structure and hash computation

Sample pool metadata:

    {
      "name": "refi93sPool",
      "description": "The pool that tests all the pools",
      "ticker": "REFI",
      "homepage": "https://teststakepool.com"
    }

The hash of the json is the 256-bit digest of its blake2b hash

    b2sum -l 256 pool_meta.json

The metadata above have the hash 914c57c1f12bbf4a82b12d977d4f274674856a11ed4b9b95bd70f5d41c5064a6 supposing the new line characters are the standard unix ones.

## 3.2 Stake pool retirement

### Related cardano-cli commands

    cardano-cli shelley stake-pool retirement-certificate \
    --cold-verification-key-file cold.vkey \
    --epoch 41 \
    --out-file pool.retirement

    cardano-cli shelley transaction build-raw \
    --tx-in 426bba6021cb96ae659a13360a94a1fefd7f14ca2ee08980a3d515842d83bd25#0 \
    --tx-out addr_test1qrwzf2dkeseu6mcv3jtw8muvseqz55np5529269lgg6fvap60uya8h6v7e488xwzkpdl5g6dtg54vrp3rlzaknzfqugse3ujve+497000 \
    --ttl 860000 \
    --fee 325000 \
    --out-file tx.draft \
    --certificate-file pool.retirement

    cardano-cli shelley transaction sign \
    --tx-body-file tx.draft \
    --signing-key-file ../address_keys/payment_key.prv \
    --signing-key-file cold.skey \
    --testnet-magic 1097911063 \
    --out-file tx-retirement.signed

### Sample signed pool retirement transaction CBOR

    83a50081825820426bba6021cb96ae659a13360a94a1fefd7f14ca2ee08980a3d515842d83bd2500018182583900dc24a9b6cc33cd6f0c8c96e3ef8c86402a5261a5145568bf423496743a7f09d3df4cf66a7399c2b05bfa234d5a29560c311fc5db4c4907111a00079568021a0004f588031a000d1f6004818304581c5631ede662cfb10fd5fd69b4667101dd289568e12bcf5f64d1c406fc1829a1008282582078b0a45c5aea1044203c1c290b892ae940ed7bbaa01b4b87de0ef5336fd70adf5840a3670d91100400cc5ce35b17d198b7152c8b9d71c4cc297ff7ce36483d0378a46a01a07fcf9cf5f2f5803d9bc40d9e9073c3c113743ec07be1e5269ca6583900825820db2487cf9a05346954df7a5e6b5c1c2c87fc65117c9787ba645377cded58b01858402406dad89cc0c22f3b3f1ed3d4a4b25d36ec8a0abd984c3429c80bc2e538b493985b245159bf1d95db7b3e6601dd6f0742e1d86b13acc42d9d84f912b9070505f6

Parsed signed transaction:

    [
      {
        0: [ // tx inputs
        [h'426BBA6021CB96AE659A13360A94A1FEFD7F14CA2EE08980A3D515842D83BD25',0]
        ],
        1: [ // tx outputs      [h'00DC24A9B6CC33CD6F0C8C96E3EF8C86402A5261A5145568BF423496743A7F09D3DF4CF66A7399C2B05BFA234D5A29560C311FC5DB4C490711', 497000]
      ],
      2: 325000,
      3: 860000,
      4: [
          [
              4, // stake pool retirement certificate type
              // pool key hash (28 bytes)
              h'5631EDE662CFB10FD5FD69B4667101DD289568E12BCF5F64D1C406FC',
              41 // epoch at which beginning the pool will be retired
          ]
      ]
      },
      {
      0: [ // witnesses
        [ // cold key witness
          h'78B0A45C5AEA1044203C1C290B892AE940ED7BBAA01B4B87DE0EF5336FD70ADF',
    h'A3670D91100400CC5CE35B17D198B7152C8B9D71C4CC297FF7CE36483D0378A46A01A07FCF9CF5F2F5803D9BC40D9E9073C3C113743EC07BE1E5269CA6583900'
        ],
        [ // payment key witness
          h'DB2487CF9A05346954DF7A5E6B5C1C2C87FC65117C9787BA645377CDED58B018',
    h'2406DAD89CC0C22F3B3F1ED3D4A4B25D36EC8A0ABD984C3429C80BC2E538B493985B245159BF1D95DB7B3E6601DD6F0742E1D86B13ACC42D9D84F912B9070505'
        ]
      ]
      },
      null
    ]

## 3.3 Stake pool operational certificate

A stake pool operational certificate is a standalone file that is supposed to be passed to the cardano node executable in order to launch the stake pool to be operated.

### 3.3.1 Related cardano-cli commands

    cardano-cli shelley node issue-op-cert \
    --kes-verification-key-file kes.vkey \
    --cold-signing-key-file cold.skey \
    --operational-certificate-issue-counter cold.counter \
    --kes-period 65 \
    --out-file node.cert

### 3.3.2 Sample CBOR

    828458203d24bc547388cf2403fd978fc3d3a93d1f39acf68a9c00e40512084dc05f2822011841584027aefb2591a124785958d63459c213df2ce10fc6e3fba4cc843b721a05d09287c45cfb4f3822f033194f70b1e8cf76d493162145c5da197d7ac4794af50a7d0f582078b0a45c5aea1044203c1c290b892ae940ed7bbaa01b4b87de0ef5336fd70adf

### 3.3.3 Parsed operational certificate

    [
      [
        // KES public key
        h'3D24BC547388CF2403FD978FC3D3A93D1F39ACF68A9C00E40512084DC05F2822',
        1, // counter value
        65, // KES period
        // signature h'27AEFB2591A124785958D63459C213DF2CE10FC6E3FBA4CC843B721A05D09287C45CFB4F3822F033194F70B1E8CF76D493162145C5DA197D7AC4794AF50A7D0F'
      ],
      cold public key
      h'78B0A45C5AEA1044203C1C290B892AE940ED7BBAA01B4B87DE0EF5336FD70ADF'
    ]

### 3.3.4 Operational certificate signature

How the signature is verified can be seen in this code snippet using cardano-crypto.js:

    var cardanoCryptoJs = require("cardano-crypto.js")

    cardanoCryptoJs.verify(
        Buffer.from(
          // kes public key
      '3D24BC547388CF2403FD978FC3D3A93D1F39ACF68A9C00E40512084DC05F2822'
      // counter as int64 big endian
          + '0000000000000001'
          // KES period as int64 big endian
      + '0000000000000041',
                'hex'
        ),                       Buffer.from('78B0A45C5AEA1044203C1C290B892AE940ED7BBAA01B4B87DE0EF5336FD70ADF', 'hex'),
    Buffer.from('27AEFB2591A124785958D63459C213DF2CE10FC6E3FBA4CC843B721A05D09287C45CFB4F3822F033194F70B1E8CF76D493162145C5DA197D7AC4794AF50A7D0F', 'hex')
    ) // returns true, can try at https://npm.runkit.com/cardano-crypto.js

i.e. the same ed25519 signature algorithm is used as for ordinary transactions though it's not used to sign the hash of the operational certificate structure, but a concatenation of the certificate attributes as shown in the snippet above.

source: [https://github.com/input-output-hk/cardano-ledger-specs/blob/bc0d9f4e8a5fa1850d406351a4535cc2837206f7/shelley/chain-and-ledger/executable-spec/src/Shelley/Spec/Ledger/OCert.hs\#L151](https://github.com/input-output-hk/cardano-ledger-specs/blob/bc0d9f4e8a5fa1850d406351a4535cc2837206f7/shelley/chain-and-ledger/executable-spec/src/Shelley/Spec/Ledger/OCert.hs#L151)

# 4 Proposals

## 4.1 Deterministic derivation of the cold key

The motivation behind deterministic derivation of the cold key as opposed to its random generation, as it's done in the cardano-cli, is that hardware wallets need a way to recover their state from a single seed.

The standard way to deterministically derive keys is via BIP32 (or its ed25519-variant), but at the same time, the BIP44 standard which specifies the structure of derivation paths is designed specifically for wallets. Here's the standard structure of a BIP44 derivation path:

    m / purpose' / coin_type' / account' / role / address_index

After Cardano made the transition to the Shelley era, in order to not collide with the Byron-era addresses, the purpose changed from BIP44's 44' to 1852', so Cardano Shelley keys are derived based on the following structure:

    m / 1852' / 1815' / account' / role / address_index

For pool cold keys, there is no notion of account nor change though. Given that the level 1 1852' index is already Cardano-specific, the Level 2 key can be interpreted as reserved for cardano wallet keys.

We suggest approaching cold key HD derivation as a successor of CIP-1852, so we'd choose the number 1853 for cold key derivation, defining the following derivation path format:

    m / 1853' /1815'/ usecase / cold_key_index'

The usecase would be fixed to 0 for now, but in the future it can be used to introduce new cold key usecases, such as multisig cold keys or other, not yet foreseen ones.

We are also putting 1815' as the level-2 coin index to maintain consistency with CIP-1852 and should any other Cardano clone/hard-fork in the future leverage Cardano's original CIPs, this should allow for straightforward reusability of the same scheme for its pool cold keys as well.

cold_key_index would be hardened, the rationale being that each stake pool is supposed to be managed separately so there is currently no incentive to connect them via a parent public key. If there was an incentive for that, this should be treated as a separate use case and evaluate the security/privacy implications of that with the concrete use case in mind.

## 4.2 Operational certificate counter management/recovery solution

The operational certificate counter is a number that increases each time a new operational certificate is issued, which usually happens when the operator rotates the KES key. Cardano CLI deals with this by having a "counter file" where it stores the last counter value that was used in an operational certificate.

Given that the counter does not have to increase strictly by one and it is not trivial to recover it in case the file is lost, we considered using a globally available increasing value instead, such as the current UNIX timestamp or slot number, adjusting Ledger's UI to show it to the operator in the appropriate representation for the sake of easier validation.

However, after taking into consideration that managing the operational certificate counter is an operational concern, rather than a security one (the blockchain itself rejects operational certificates with a stale counter), to not mix those concerns, we propose keeping the counter value management external to the hardware wallet, not introducing any not-yet-standardized solution to make it more recoverable/resilient and leaving up to the hw wallet software/operator themselves to have whatever certificate counter management solution they prefer, which may be stateful (a file), stateless (use e.g. the current unix timestamp), or even dynamic (retrieve latest counter value from the blockchain). Ledger would then just display the counter value as-is and is up to the operator to validate that the counter is up-to-date (and if not, the worst case would be that the operational certificate would get rejected when the node is launched and attempts to sign blocks which is easy to fix by the operator once they realize).

## 4.3 Stake pool registration transaction structure

We already implemented support for stake pool registration on Ledger hw wallet, but from the owner's perspective. The security concerns related to a single witness applying to all the public key (direct and indirect, e.g. in transaction inputs) referenced in the tx made us enforce that no other certificates/withdrawals apart from the stake pool registration one can be present in the transaction, to avoid accidental withdrawal from owner's reward account to the transaction output address, which does not have to belong to the owner.

We propose keeping the constraints highlighted above for the stake pool operator use case as well as withdrawals/other kinds of certificates can be done in separate transactions and we want to keep the Ledger UI flow as simple as possible even for the pool operators while keeping interoperability with hardware wallet-backed owners bound by the constraints above.

## 4.4. Stake pool registration transaction funding

Regarding stake pool registration certificate transaction funding, we propose that the operator should always be the one doing it, i.e. the inputs to the transaction will be enforced to be internal and signable by the operator's hardware wallet. We may make this optional, but this would introduce the need to explicitly warn the operator about that (so they cannot lose funds from their utxos without being aware) and it seems a lot more straightforward to just have the operator always store the funds to pay the pool registration fees to an address they control with their hardware wallet before making the stake pool registration transaction.

# 5 Ledger app development

## 5.1 General approach

We propose taking the current Ledger Cardano app as a baseline, adding on top of it pool-operator related instructions and extending the existing instruction for signing transactions with operator-specific logic. These extensions would become available if the app is compiled in such mode (specified by a flag in Makefile). This means that the operators would have an extended "all-in-one" app which they can use both to operate their stake pool(s) and to perform other transactions related to their stake pool(s) (but not necessarily), like staking to the pool, signing the pool registration certificate as an owner or distributing the pool rewards among owners.

On the other hand, the app in "standard mode" would not have stake pool operator extensions even hidden in its compiled form as the C (the native language of Ledger apps) preprocessor would completely remove code between "ifdefs", saving precious space for most Ledger app users that don't need stake pool operator functionality.

## 5.3 Required modifications

### 5.3.1 New cold key derivation call

This call will take as an input the cold key derivation path, as defined in section 4.1 and return the ed25519 cold public key. We propose to have it as a separate call from the already existing getExtendedPublicKey call even though it derives the same kind of keys in a similar way given the following reasons:

1. Different context of usage of the keys (wallet operations vs stake pool operations)
2. The policies would be significantly different (a different BIP prefix to match, different path length to enforce)
3. Different UI - the user needs to be explicitly notified that they are about to export a stake pool cold key and the index of the pool
4. No plans for bulk export support for pool cold keys (something currently being developed for getExtendedPublicKey) as the stake pool registration certificate can be in the tx only once anyway (given the restrictions already imposed on stake pool owners due to security)

### 5.3.2 New operational certificate signing call

This call will take as an input the KES public key, the VRF public key, the operational certificate counter and the path to the stake pool cold key to be used to sign that certificate. Ledger will display all four values to the operator and return the operational certificate signature as explained in 3.3.4.

Note that for the sake of consistency with the signTx call which returns only the witnesses and not the whole signed transaction body, it will be up to the party integrating with Ledger to assemble the operational certificate as Ledger nor ledgerjs would be returning it (which is straightforward from the inputs passed to ledgerjs anyway).

### 5.3.3 Extend stake pool registration certificate-related logic

Given the proposals 4.3 and 4.4 related to stake pool registration, we will be extending the signTx call's stake pool registration logic in the following ways:

1. extend the signStakePoolRegistrationAsOwner flag passed in the first message to the Ledger cardano app to be an enum called stakePoolRegistrationUsecase which would have value "2" for stake pool registration as operator (and previously used value "0" would correspond to no stake pool registration, "1" to stake pool owner use case, keeping backwards compatibility)
2. As opposed to the stake pool owner use case, we will enforce all transaction inputs to be signable by Ledger (at least on the JS layer, as Ledger device decouples transaction inputs and witnesses processing)
3. enforce all owner keys to be passed as hashes
4. enforce cold key to be passed as path instead of the hash of the public key
5. allow to pass the pool reward account as a path instead of just an address, as the operator may control it from their hw wallet
6. Show explicitly stake pool relays and VRF key hash to the operator (for owners, they are hidden)

#### Stake pool metadata UI

Regarding stake pool metadata, we propose to show just the hash and URL where it would be hosted, as we already do for owners. Displaying/handling the metadata JSON explicitly in Ledger requires additional serialization logic which is not trivial to introduce given that Ledger Cardano app supports only CBOR serialization right now and we see no added security value as even if the metadata hash happens to be wrong, the operator can re-register the pool with the right metadata with minimal cost. If this turns out to be an issue, we can always revisit this decision in later iterations of the stake pool registration functionality, but now we don't see an inherent security risk in having the operator verify on Ledger just the metadata hash.

### 5.3.4 Introduce stake pool retirement certificate type

We will be introducing a new certificate type which would be available alongside the other three certificate types already supported by Ledger. As opposed to the stake pool registration certificate, given that only the operator is involved in this transaction, there is no need to put special constraints on the transaction that contains it and it can be handled in the same way as stake delegation or stake key registration certificates already are.

The only specific constraint will be that this kind of certificate will be available only when the app is compiled in the "operator" mode.

The logic to validate which kind of witnesses can be returned from ledger will need to be modified to allow for returning a cold key witness for each stake pool retirement certificate present in the transaction being signed.

## 5.3 Ledger app mode check

If the pool management software makes a call to the ledger app not compiled in "operator" mode, the app will return a specific error code which would be known to have that meaning and will be translated to an appropriate human-readable error message. The exact code is TBD as this level of detail is not relevant at the initial stage of the project and will be handled by the ledgerjs library interacting with the Ledger app, shielding developers integrating with Ledger from that concern.

# 6 API

As outlined in section 5, we will be introducing in ledgerjs two new calls (getStakePoolColdKey, signOperationalCertificate) and modifying the signTx call by introducing a new certificate type and logic to activate the "operator" mode of signing the stake pool registration certificate.

## 6.1 Related call signatures

1. Get stake pool cold key

    getPoolColdPublicKey(
      path: BIP32Path
    )

2. Sign transaction call (used for stake pool registration/retirement), remains unmodified on the high level

    signTransaction(
      networkId: int,
      protocolMagic: int,
      inputs: List<TxInput>,
      outputs: List<TxOutput>,
      feeStr: str,
      ttlStr: str,
      certificates: List<Certificate>
      withdrawals: List<Withdrawal>,
      metadataHashHex: str
    )

3. Sign operational certificate

    signOperationalCertificate(
      kesPublicKeyHex: string,
      kesPeriodStr: string,
      counterStr: string,
      coldKeyPath: BIP32Path
    )

## 6.2 Data structure definitions

Below are JavaScript Flow type definitions of the structures that will be exposed in the ledger js library, showing in what way they would be modified to fit the stake pool operator app.

### 6.2.1 Stake pool registration certificate

#### Current version

    type PoolParams = {|
      poolKeyHashHex: string,
      vrfKeyHashHex: string,
      pledgeStr: string,
      costStr: string,
      margin: Margin,
      rewardAccountHex: string,
      poolOwners: Array<PoolOwnerParams>,
      relays: Array<RelayParams>,
      metadata: PoolMetadataParams
    };

#### New version

We will replace the "poolKeyHashHex" key with "poolKey" which would be an object embedding the pool key hash if it is a certificate to be signed as pool owner, otherwise, if a path is passed, it will be treated as a certificate that would be signed from operator's perspective.

    type PoolRegistrationParams = {
      poolKey: PoolKeyParams, // i.e. cold key
      vrfKeyHashHex: string,
      pledgeStr: string,
      costStr: string,
      margin: Margin,
      rewardAccountHex: string,
      poolOwners: Array<PoolOwnerParams>,
      relays: Array<RelayParams>,
      metadata: PoolMetadataParams,
    };

    type PoolKeyParams = {
      keyHashHex: string,
      path: BIP32Path
    }


### 6.2.2 Stake pool retirement certificate

#### Original certificate type

    type Certificate = {|
    type: number,
    path: ?BIP32Path,
    poolKeyHashHex: ?string,
    poolRegistrationParams: ?PoolParams
    |};

#### Updated certificate type

    type Certificate = {|
    type: number,
    path: ?BIP32Path,
    poolKeyHashHex: ?string,
    poolRegistrationParams: ?PoolRegistration,
    poolRetirementParams: ?PoolRetirementParams
    |};

    type PoolRetirementParams = {|
      poolKeyPath: BIP32Path, // i.e. cold key
      retirementEpochStr: string
    |};

### 6.2.3 Operational certificate

A dedicated structure for an operational certificate should not be needed as its fields would be passed as function parameters to a dedicated function to sign operational certificates.

# 7 UX flow

## 7.1 Stake pool registration

Ledger already has the flow for stake pool registration from owner's perspective, which omits info about transaction outputs, the VRF key and pool relays as they are not relevant to the owner.

However, all these fields should be shown to the operator for them to verify as they are supposed to confirm spending from the inputs (as they belong to their wallet) and the output address (if it isn't a change address of their own)

Also, the app will be showing explicitly in the first prompt related to certificate signing whether the user is signing it as an owner or as an operator.

Regarding pool metadata, the user, even as an operator, will be presented with the metadata URL and hash for them to verify, and we won't be exposing the full JSON on Ledger as discussed in 5.3.

## 7.2 Stake pool retirement

Ledger will display the transaction as usual, and when it arrives at the retirement certificate, it will lead the user through a sequence of screens such as the following:

 "Sign stake pool retirement?" -> "Pool <number> (hash)" -> "Since epoch <number>" -> "Confirm sign stake pool retirement?"

## 7.3 Operational certificate

This will be separate from transaction signature flow as operational certificates are not proper transactions submitted to the blockchain. The user will click through the following flow on Ledger:

"Sign operational certificate?" -> "Pool <number> (hash)" -> "Counter value <number>" -> "KES key period <number>" -> "Confirm signing operational certificate?"

# 8 Open questions

1. Should the hw wallet app serialize and compute the hash of the stake pool metadata JSON internally, or should it just take the hash of the metadata as-is (similarly to how we've done it for the stake pool owner use case)?
   Followup: If the answer is yes, what metadata fields should we support? Can/should the metadata structure be nested?
2. Which number to use for Level 2 of the cold key derivation path? (see section 4.1)
3. Is it theoretically possible to have a multisig stake pool cold key and if so, does it make sense in practice? (i.e. should we account for multisig in the proposed cold key derivation scheme?)

# 9 Resources

1. [Shelley binary format specs](https://github.com/input-output-hk/cardano-ledger-specs/blob/master/shelley/chain-and-ledger/shelley-spec-ledger-test/cddl-files/shelley.cddl)
2. [Stake pool operator manual](https://docs.cardano.org/projects/cardano-node/en/latest/stake-pool-operations/getConfigFiles_AND_Connect.html)
