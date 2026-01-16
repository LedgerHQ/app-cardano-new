# Multi-signature for hardware wallets

Transactions involving multiple parties will be managed by software wallets separately from ordinary transactions signed by a single party. We will therefore distinguish between the two types of transactions (the client can choose whether he wants an ordinary transaction or a multisig transaction).

# Transaction signing modes

The current Ledger API determines allowed transaction elements and related security policies via the so-called *transaction signing mode* (it will soon be introduced for Trezor, too)*.* There are 3 modes supported at present:

    enum TransactionSigningMode {
        ORDINARY_TRANSACTION,
        POOL_REGISTRATION_AS_OWNER,
        POOL_REGISTRATION_AS_OPERATOR,  // implemented, but not released yet
    }

We are going to add one new mode MULTISIG_TRANSACTION.

MULTISIG_TRANSACTION mode will be used for pure multisig transactions, i.e. all the key derivation paths will conform to CIP-1854 and only script hashes will be allowed in the relevant transaction elements (so no hashes of CIP-1852 keys will be computed).

We will show information about the signing mode at the beginning of the transaction UI flow in a way that will be clear but not too disturbing (e.g. showing "Start multisig transaction" instead of "Start transaction").

### Mixed signing mode

Theoretically, one might want to support transactions containing both ordinary (single-user) and multisig elements. However, no use case is known for such transactions, and it is quite easy to circumvent them: the transaction elements are independent of each other (certificates from each other etc.), hence a mixed transaction could be split into an ordinary transaction and a pure multisig transaction which will both be signed independently. An individual willing to participate in multisig transactions can create a multisig account where everything is controlled by his own keys, and fund it from his individual account (in ordinary transactions, output addresses are not restricted). For a rare case where one wants two things to occur concurrently or not at all, upcoming Alonzo smart contracts are much more suitable.

Having a mixed mode would also come with inherent security risks. In particular, key derivation paths in CIP-1852 and CIP-1854 schemas differ only in a single digit which is quite easy to overlook, especially for users with reading disorders.

It is possible that we would want to include some mixed mode in the future, but any such mixed mode would have to be thoroughly analyzed in light of smart contracts (whether based on Plutus or any others), and Alonzo smart contract features are not fully known yet. We also consider it reasonable to first see how users interact with multisig features before introducing more complexity.

# Witness signatures

Due to its memory limitations, Ledger only provides the transaction body hash and raw witness signatures to clients. It is thus the responsibility of the software wallet to assemble and serialize the transaction.

In the past, Trezor provided the full serialized transaction, but it no longer makes sense since multisig transactions are signed by multiple parties. Vacuumlabs is currently redesigning Trezor API to align it with what Ledger does (apart from these multisig-related reasons, it will also save memory and potentially allow for larger transactions). We will implement the required changes as part of this project.

## Allowed witnesses

For ordinary transactions, the user always signs a transaction for one of his accounts, and the relevant accounts can be seen from the transaction body (for instance, certificate stake credentials are given by CIP-1852 key derivation paths). We can thus safely hide the witnesses, improving the user experience during transaction signing \--- the worst that can happen is that an irrelevant signature is provided. (We limit the number of witnesses to avoid leaking too many such signatures.)

With multisig transactions, the situation is different. Script hashes that go into the transaction body are opaque and a single script can be witnessed by many paths, so it might matter to the user which path is being used. Consider, for instance, a user that manages two trust fund accounts, with different multisig keys. A simple payment transaction would look totally the same to him when displayed by a HW wallet, irrespective of which trust fund is making the transaction. (For ordinary transactions, we do not care which utxos are used to pay for the transaction, because they all belong to the same entity.)

To make sure that the user is aware about the entity he is signing the transaction for, we are going to show the witness path for every witness in MULTISIG_TRANSACTION.

Only witness paths conforming to CIP-1854 are allowed and the number of witnesses is not limited (apart from some general upper bound originating from memory limitations).

## Witness API

Ledger limits the number of witnesses it can produce during a single transaction signing request: 1 for each input, 1 for each certificate, 1 for each withdrawal etc. The witness paths are given in the respective elements of the transaction body and they are collected by LedgerJS which counts the total number of witnesses it is going to ask and sends it to Ledger before any transaction elements so that the device can verify it.

Trezor will do something similar after certain refactorings related to saving memory.

The number of witnesses for script elements cannot be determined from the transaction body \--- we might want more than one witness per element (e.g. in a 3 of 5 script, one of the participants might own two keys, thus his decisions have a larger weight). Also, a single key might witness many of the script elements, so it does not make sense to tie it to any particular element.

The solution is to add a new field *scriptWitnesses* (or perhaps scriptWitnessPaths) to the transaction signing interface (e.g. in the Transaction type in LedgerJS). This field is supposed to be empty for ordinary transactions and contain all witness paths for multisig transactions. Since all the witnesses are shown, there is no need to limit the number of witnesses.

# Certificates

Certificates contain the *stake_credential* field which is used to distinguish between single user-governed and script-governed staking rights.

For multisig certificates, stake_credential with *scripthash* is used, so we never use CIP-1854 key derivation paths for the *addr_keyhash* field (as it is in the current version). Thus:

* *TransactionSigningMode.ORDINARY_TRANSACTION* should only allow certificates with staking credentials sent as key derivation paths and the purpose should be 1852'.
* *TransactionSigningMode.MULTISIG_TRANSACTION* should allow the keys to only be sent as script hashes.

## Pool registration

Pool operators have an entirely separate key derivation schema for cold keys (1853') and pool owners can only be represented by 1852' paths or by an arbitrary hash.
Pool reward accounts may contain a script hash; however, since neither the type nor the ownership of a pool reward account is relevant for pool operation, such reward accounts will be treated just the same as any opaque third-party reward accounts.

# Displaying scripts

The philosophy of hardware wallets for Cardano is that everything that affects the transaction witness signature is shown to the user (i.e. all elements going into the transaction body), with very few exceptions. The data are shown in a format verifiable by the human user whenever possible. For security, it would be better to display script addresses not just in their bech32-encoded form, but also show the underlying scripts (this would be consistent with how staking info is displayed now). Of course, this leads to a very unsatisfactory user experience (clicking through the whole script every time). A practical compromise is the following:

* During transaction signing, script addresses and script hashes are displayed and processed in their opaque form.
* During address derivation, the script address parts will only be sent as script hashes. The script hashes will be shown to the user for verification.
* We will introduce a separate call for script verification on both Ledger and Trezor. Within this call, the HW wallet will incrementally receive the whole script, show the components of the script to the user, and calculate its hash on the HW wallet. The user can thus be sure that the script the SW wallets is using is indeed the intended one.

So if a user wants to be completely sure about his transaction, he first needs to verify all the scripts included within, then verify all the addresses including script hashes, and finally the transaction itself. (This assumes that SW wallets provide means to initiate the required calls to HW wallets.)

An important consequence of this is that *there is no way to distinguish change outputs* from third-party outputs (the address is just given as an opaque bytestring in both cases), which means hw wallets will have to display all the outputs to the user (when signing regular transactions, we usually hide change outputs so that the user doesn't get confused).

While the multisig scripts are recursive in nature, we can only display them in a linear fashion (with only two lines of text available on Ledger at a time). It might be tempting to try and display some overview of the structure of the script (most of the scripts are supposed to be very simple), but it could be deceiving to the user. For scripts with depth more than 1, Ledger cannot verify the structure beforehand, and for scripts with depth 1, any abbreviated notation (perhaps based on syntax from programming languages) might come unnatural, ambiguous or misleading to the actual users and would increase the size of the Ledger application, so it is best avoided.
There is no agreed-upon format for displaying scripts on software wallets yet[^1], so we propose the following format described by giving an example.

Given the script

    {
        "type": "all",
        "scripts":
        [
          {
            "type": "atLeast",
      "required": 2,
            "scripts":
            [
              {
                "type": "sig",
                "keyHash": "3a55d9f68255dfbefa1efd711f82d005fae1be2e145d616c90cf0fa9"
              },
              {
                "type": "sig",
                "keyHash": "80f9e2c88e6c817008f3a812ed889b4a4da8e0bd103f86e7335422aa"
              },
              {
                "type": "sig",
                "keyHash": "4a55d9f68255dfbefa1efd711f82d005fae1be2e145d616c90cf0fa9"
              }
            ]
          },
          {
            "type": "sig",
            "keyHash": "667ee84f714720123b92dd159bc306925020c460d464cea40eebc59f"
          }
        ]
    }
Ledger (and also Trezor, perhaps with minor modifications) will display the following sequence of messages (the keys will be bech32-encoded):

*Script \- ALL*
*Confirm K scripts*

*Script 1 \- N of K*
*Confirm 2 of 3*

*Script 1.1 \- key path*
*m/1854'/1815'/1'/0/0*

*Script 1.2 \- key*
*80f9e2c88e6c817008f3a812ed889b4a4da8e0bd103f86e7335422aa*

*Script 1.3 \- key*
*4a55d9f68255dfbefa1efd711f82d005fae1be2e145d616c90cf0fa9*

*Script 1 \- 2 of 3*
*finished*

*Script 2 \- key*
*667ee84f714720123b92dd159bc306925020c460d464cea40eebc59f*

*Script \- ALL*
*finished*

The string "1.2" describes the position of the currently displayed script in the recursive hierarchy. For instance, "1.2" means we are in the first script in depth 1 and are confirming its second element. Similarly, "3.1.4" would mean the 4th element of the 1st script contained in the 3rd script in depth 1\. (The whole script is in depth 0 and thus does not get any number.)

All 6 types of scripts will be supported:

    SCRIPT
      = SIGNATURE KEY-HASH  // "key" or "key path"
      | ALL-OF 1*SCRIPT     // "ALL"
      | ANY-OF 1*SCRIPT     // "ANY"
      | N-OF UINT 1*SCRIPT  // "N of K"
      | AFTER SLOT-NO       // "AFTER SLOT"
      | BEFORE SLOT-NO      // "BEFORE SLOT"

***Screens:***

* For scripts which are not recursive (key path, key, AFTER SLOT, BEFORE SLOT), we just display a single screen.
* For the others (ALL, ANY, N of K), we show an initial screen describing the script (including the number of its elements) and its position, followed by the elements, and a final screen.

***Implementation**:* Ledger will keep a fixed array of integers (length, say, 10\) and an index indicating on what level of the recursive structure we currently are. The integers in the array describe how many of the script elements on that level have already been processed. If the depth of the recursion exceeds the limit, Ledger throws ERR_DATA_TOO_LARGE. A similar mechanism will be implemented for Trezor.

***Limit on recursion depth:*** It will be based on available memory. For practical purposes, 10 levels should be sufficient. We don't see a reason to restrict it to an artificially low value if memory is available.

***Script serialization:*** The number of components of a script must be known upfront (before we receive the components) because the canonical CBOR serialization format requires finite arrays. We can thus display the information to the user (e.g. in case of an "N of K" script).

***Display format:*** Based on subsequent experiments, immaterial elements (like whitespace and dashes) could be modified to improve readability.

***Script hashes:*** will be displayed as bech32-encoded bytestrings with *script* as prefix (in line with [CIP-5](https://cips.cardano.org/cips/cip5/)).

# Token minting/burning

Since minting is governed by a script, it will only be allowed for multisig transactions.

The screens shown to the user for token minting correspond to those shown for transaction output: one initial screen, then a series of pairs of screens (asset fingerprint followed by token amount), and finally a final confirmation.

*Minting tokens*

*Asset fingerprint*
*asset1aqrdypg669jgazruv5ah07nuyqe0wxjhe2el6f*

*Token amount*
*123*

*Confirm token minting*

# Derivation path limitations for CIP-1854 keys

We will apply the same limitations as for CIP-1852 keys, that is,
MAX_REASONABLE_ACCOUNT = 100,
MAX_REASONABLE_ADDRESS = 1000000\.

These are "soft" limitations \--- users are warned if they are being exceeded, but can proceed if they wish to do so. (There is no easy way of determining the key or its derivation path from the key hash, so if one inadvertently forgot which key he used in a multisig script, he can try all the possible combinations to recover the funds governed by the script.)

# Major required changes:

1. **Allowing script credentials in addresses, withdrawals and certificates**
- Modify enums for address type
- Modify functions working with addresses
- Change APDU message serialization if necessary (e.g. address params)
- Update user-facing screens

2. **Adding new key hierarchic derivation schema 1854**
- Modify path classification and validation functions
- Modify security policies for public key export
- Add new bech32 prefixes in user-facing functions for the new keys

3. **Update address derivation call**
- Script-based addresses must be supported, which includes computing script hashes on hw wallets, so we need new API for serializing multisig scripts (all 6 types according to [https://github.com/cardano-foundation/CIPs/pull/69](https://github.com/cardano-foundation/CIPs/pull/69))
- opaque script hashes should be supported (as components of addresses both in outputs and in address derivation call)

4. **Support for minting / burning of tokens**
- new field in tx body for minting
- new API for serializing multiasset<int64> (see CDDL)
- support for int64 (logging, displaying to users)
- no empty maps will be allowed in multiasset (neither in outputs nor in mint)

5. **Reevaluation of security model for tx signing**
- introduce transaction signing mode MULTISIG_TRANSACTION which will govern validation and security policies
- devise security policies on addresses containing multisig elements
- impose additional restrictions on tx elements if necessary

6. **Update related javascript libraries (Trezor Connect, LedgerJS) accordingly**
- extend API
- update validation of input parameters
- change APDU/protobuf serialization

7. **Update cardano-hw-cli tool accordingly**
- add support for CIP-1854 keys
- modify transaction parsing to support scripthash fields (in addresses and certificates) and minting
- add support for MULTISIG_TRANSACTION; update witness manipulation to reflect the new API for multisig witnesses
- add separate call for script hash computation

# Computation of script hashes

Script hash is calculated by hashing the CBOR representation of the script but with a zero byte (0x00) prepended before the CBOR, i.e.

    blake2b.hash(0x00 \+ cbor.encode(script), length=28)

The exact description of what gets hashed and how should be documented by IOHK (see [this Slack thread](https://input-output-rnd.slack.com/archives/G010N9UFDNH/p1620122972054300?thread_ts=1620038329.052900&cid=G010N9UFDNH)). Script will be CBOR encoded according to [the CDDL spec](https://github.com/input-output-hk/cardano-ledger-specs/blob/22f53f75e80a70243bd0fa41f570a9a2715d76cc/shelley-ma/shelley-ma-test/cddl-files/shelley-ma.cddl#L241).

## Script address/hash test vectors

All of these samples were generated via cardano-cli.

The resulting Enterprise Script address is included in each vector. You can use [https://slowli.github.io/bech32-buffer/](https://slowli.github.io/bech32-buffer/) to decode the addresses into hashes (the first decoded byte is the address header though).

Enum defining the "type" field:

    enum CardanoScriptType {
      PUB_KEY = 0;
      ALL = 1;
      ANY = 2;
      N_OF_K = 3;
      INVALID_BEFORE = 4;
      INVALID_HEREAFTER = 5;
    }

### Simple

    {
    "type": 0,
    "key_hash": "3a55d9f68255dfbefa1efd711f82d005fae1be2e145d616c90cf0fa9",
    "address": "addr1wxz4y284ankwe7wg2cvqqlxrctjmma0x6s0034h60yl7p6ct870ec",
    "cbor": "8200581c3a55d9f68255dfbefa1efd711f82d005fae1be2e145d616c90cf0fa9"
    }

### Any

    {
    "type": 2,
    "scripts": [
      {
        "type": 0,
        "key_hash": "3a55d9f68255dfbefa1efd711f82d005fae1be2e145d616c90cf0fa9"
      },
      {
        "type": 0,
        "key_hash": "80f9e2c88e6c817008f3a812ed889b4a4da8e0bd103f86e7335422aa"
      }
    ],
    "address": "addr1wxwdl22u6z8fsajs2s33g6n087hf2j0fpejjsr8mpz46ppqcad0ju",
    "cbor": "8202828200581c3a55d9f68255dfbefa1efd711f82d005fae1be2e145d616c90cf0fa98200581c80f9e2c88e6c817008f3a812ed889b4a4da8e0bd103f86e7335422aa"
    }

### N of K

    {
    "type": 3,
    "required": 2,
    "scripts": [
      {
        "type": 0,
        "key_hash": "3a55d9f68255dfbefa1efd711f82d005fae1be2e145d616c90cf0fa9"
      },
      {
        "type": 0,
        "key_hash": "4a55d9f68255dfbefa1efd711f82d005fae1be2e145d616c90cf0fa9"
      },
      {
        "type": 0,
        "key_hash": "5a55d9f68255dfbefa1efd711f82d005fae1be2e145d616c90cf0fa9"
      }
    ],
    "address": "addr1w9lafjxpmkz5300xcd3xf05hazwz7vmn2fm72sdztg0un8crhnw4t",
    "cbor": "830302838200581c3a55d9f68255dfbefa1efd711f82d005fae1be2e145d616c90cf0fa98200581c4a55d9f68255dfbefa1efd711f82d005fae1be2e145d616c90cf0fa98200581c5a55d9f68255dfbefa1efd711f82d005fae1be2e145d616c90cf0fa9"
    }

### Invalid Before

    {
    "type": 1,
    "scripts": [
      {
        "type": 0,
        "key_hash": "3a55d9f68255dfbefa1efd711f82d005fae1be2e145d616c90cf0fa9"
      },
      {
        "type": 4,
        "invalid_before": 100
      }
    ],
    "address": "addr1w8j9n9mqmvrngrvg209nxfvz86k3nja0kaz5hzutntlqq7qxdfev6",
    "cbor": "8201828200581c3a55d9f68255dfbefa1efd711f82d005fae1be2e145d616c90cf0fa982041864"
    }

### Invalid Hereafter

    {
    "type": 1,
    "scripts": [
      {
        "type": 0,
        "key_hash": "3a55d9f68255dfbefa1efd711f82d005fae1be2e145d616c90cf0fa9"
      },
      {
        "type": 5,
        "invalid_hereafter": 200
      }
    ],
    "address": "addr1w880fd42nd0d05gf27uhurhwhn6vkwe7nxt46u3ey9xc97qxvuar4",
    "cbor": "8201828200581c3a55d9f68255dfbefa1efd711f82d005fae1be2e145d616c90cf0fa9820518c8"
    }

### Nested

    {
    "type": 1,
    "scripts": [
      {
        "type": 0,
        "key_hash": "3a55d9f68255dfbefa1efd711f82d005fae1be2e145d616c90cf0fa9"
      },
      {
        "type": 1,
        "scripts": [
          {
            "type": 0,
            "key_hash": "4a55d9f68255dfbefa1efd711f82d005fae1be2e145d616c90cf0fa9"
          }
        ]
      },
      {
        "type": 4,
        "invalid_before": 100
      },
      {
        "type": 5,
        "invalid_hereafter": 200
      }
    ],
    "address": "addr1wy99zpq4g4sn9vp59dyv4fz7jcvgz0haxaxljqdwgeuscygvp3mse",
    "cbor": "8201848200581c3a55d9f68255dfbefa1efd711f82d005fae1be2e145d616c90cf0fa98201818200581c4a55d9f68255dfbefa1efd711f82d005fae1be2e145d616c90cf0fa982041864820518c8"
    }

## Transaction sample

Transaction containing two witnesses and an ALL script:

    83a30081825820ff60ae95c624a89e2c86528563dbbdcc6d73ef2614023f0c79fe8f5c25be7d9e00018282581d70f5bb6672a26bdd5a956da1f09405181aedf10e640e01f87da06a48091a000f424082581d70c12c8cdd1e41c02e58583fa2fce2bcb9011f5f98fe4212303d2c54961a05e3b890021a0002e630a20082825820870deaa8211af39fe8a2f97856f956ab11a2380cd104c0b228322b384417f64f5840b4d3b7cf8100f461f6d94fef91e3c0c2057ba8dc061f21f04cedfde89736c6e2e2c38e695a537b1a30d387bb55624ff4b5e350481419a59e5cd54c741b4117008258205d010cf16fdeff40955633d6c565f3844a288a24967cf6b76acbeb271b4f13c15840c4d5cc875b8180b1f083291a740c6f0742f8d1719d17131526ae1060b5e55326977539a85e1b52e7b584123a21f996de6cc2600fc5f5af4e6908cc4be5e56d0b01818201828200581c80f9e2c88e6c817008f3a812ed889b4a4da8e0bd103f86e7335422aa8200581c667ee84f714720123b92dd159bc306925020c460d464cea40eebc59ff6
