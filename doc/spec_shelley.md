# Useful links

[Cardano documentation](https://docs.cardano.org/en/latest/) - official documentation.

[Delegation Design Spec](https://hydra.iohk.io/build/2006688/download/1/delegation_design_spec.pdf) - contains information about delegation (addresses, certificates, withdrawals, ...).

[Shelley CDDL spec](https://github.com/input-output-hk/cardano-ledger-specs/blob/master/shelley/chain-and-ledger/executable-spec/cddl-files/shelley.cddl).

[Byron address format](https://github.com/input-output-hk/cardano-wallet/wiki/About-Address-Format---Byron).

[The Shelley 1852' purpose and staking path](https://github.com/input-output-hk/implementation-decisions/blob/e2d1bed5e617f0907bc5e12cf1c3f3302a4a7c42/text/1852-hd-chimeric.md).

[Cardano-node documentation](https://docs.cardano.org/projects/cardano-node/en/latest/)

[Trezor documentation](https://docs.trezor.io/trezor-firmware/)

[Ledger Cardano docs](https://github.com/vacuumlabs/ledger-app-cardano-shelley/tree/shelley/doc)

Trezor Cardano README \- // TODO

# General

## Protocol magic vs. Network id

Protocol magic is used to identify the network on the protocol level. Each network (mainnet, testnet, testnet 2, ...) has its own protocol magic. It's a 4 byte number. Network Id is a more compact version of the protocol magic - it's only 4 bits. It is used in addresses to determine, whether they belong to a testnet or any of the (in the future existing) mainnets. Network Id 0 is reserved for all the testnets that might ever exist and the remaining 15 values are used for mainnets.

*Current mainnet protocol magic:* 764824073
*Current mainnet network id:* 1

## Keys

In Shelley two types of keys are used. Payment key and staking key. Payment keys are derived from *m/1852'/1815'/x/[0,1]/y* paths and are used for holding/transferring funds. Staking keys are derived from *m/1852'/1815'/x/2/0* paths, thus there is only one staking key per account. They are used for staking operations - certificates, withdrawals. Shelley addresses are built from the combination of hashes of these keys.

Payment Key - kp = (skp, vkp)
Staking Key - ks = (sks, vks)
*sk = signing key (private), vk = verifying key (public)*

## Addresses

Since the Shelley era Cardano supports multiple address types. Information about address types added in Shelley can be found [here](https://github.com/input-output-hk/cardano-ledger-specs/blob/master/shelley/chain-and-ledger/executable-spec/cddl-files/shelley.cddl#L68). In short, all Shelley address types contain a header, which is 1 byte long. The header is built as: *((address_type << 4) | networkId)*. Byron address has an address type of *0b1000* but never contains the network id. Instead, protocol magic is included in the address in a different way (more about that [here](https://github.com/input-output-hk/cardano-wallet/wiki/About-Address-Format---Byron)).

### Address encoding (Base58 vs. Bech32)

In Shelley, address encoding has been switched from Base58 to Bech32. However, Byron addresses still need to be encoded as Base58. Other address types use Bech32. Thus both formats need to be supported.

### Byron address

Legacy address used mainly during the Byron era, but still supported in Shelley. Has no staking rights. More about address format can be found [here](https://github.com/input-output-hk/cardano-wallet/wiki/About-Address-Format---Byron).

**Example:**

*Mainnet*: Ae2tdPwUPEZCanmBz5g2GEwFqKTKpNJcGYPKfDxoNeKZ8bRHr8366kseiK2

*Testnet:* 2657WMsDfac7BteXkJq5Jzdog4h47fPbkwUM49isuWbYAr2cFRHa3rURP236h9PBe

#### Testnet Byron address format

**Address in Base58:** 2657WMsDfac6k3gFN496wBx38k5NbHdJKbgph4krzZx6FiFCLQfue3cnaPpPPvJYy

**Hex string (CBOR decoded from Base58) - contains address data (described below) and CRC:** 82d818582583581ca082c0ab19db6fe42c459d51c74170ddf0a2a56bdc36ce0c38c5d127a10242182a001a652f97ca

**Diagnostic CBOR:**

```
[
  # address data  24(h'83581CA082C0AB19DB6FE42C459D51C74170DDF0A2A56BDC36CE0C38C5D127A10242182A00'),
  # CRC
  1697617866
]
```

**Address data - contain address root, address attributes and address type (always 0):**

83581CA082C0AB19DB6FE42C459D51C74170DDF0A2A56BDC36CE0C38C5D127A10242182A00

**Address data diagnostic CBOR:**

```
[
  # address root
  h'A082C0AB19DB6FE42C459D51C74170DDF0A2A56BDC36CE0C38C5D127',
  # address attributes -- {2: cbor.encode(protocol_magic)}
  {
    # protocol magic key: cbor encoded protocol magic
    2: h'182A'
  },
  # address type - constant 0
  0
]
```

Protocol magic is included in the address attributes only on testnets. On mainnet it is an empty map.

**Address root:**

A082C0AB19DB6FE42C459D51C74170DDF0A2A56BDC36CE0C38C5D127

Blake2b 28 byte hash of sha3_256 hash of cbor encoded **Data**.

**Data:**

```
[
  0,
  [
    0,
    ext_pub_key # (remove_ed25519_prefix(node.public_key()) + node.chain_code())
  ],
  # address_attributes
  {2: cbor.encode(protocol_magic)}
]
```

Protocol magic is included in the address attributes only on testnets. On mainnet it is an empty map.

### Base address

Introduced in Shelley:

    [header] + [payment_key_hash] + [staking_key_hash]

Base address can have staking rights (as it contains a staking key hash), but the staking key has to be registered on the blockchain first. Funds can be received even without the staking key being registered though. It is also possible to own the funds (payment key) but to use a different staking key to build the address. This would transfer the staking rights to the owner of the staking key. This can be useful for staking your funds for a charity.

**Example:**

*Mainnet*: addr1q8v42wjda8r6mpfj40d36znlgfdcqp7jtj03ah8skh6u8wnrqua2vw243tmjfjt0h5wsru6appuz8c0pfd75ur7myyeqsx9990

*Testnet:* addr_test1qrv42wjda8r6mpfj40d36znlgfdcqp7jtj03ah8skh6u8wnrqua2vw243tmjfjt0h5wsru6appuz8c0pfd75ur7myyeqnsc9fs

### Pointer address

Introduced in Shelley:

    [header] + [payment_key_hash] + [certificate_pointer]

Certificate pointer is a pointer (block, transaction, certificate) to the staking key registration certificate on the blockchain. It replaces staking_key_hash from the base address, but serves the same purpose. Thus pointer address is pretty much the same as the base address in function, but is much shorter (~35B vs 57B) thanks to the certificate pointer.

**Example:**

*Mainnet*: addr1gxq0nckg3ekgzuqg7w5p9mvgnd9ym28qh5grlph8xd2z92spqgpsl97q83

*Testnet:* addr_test1gzq0nckg3ekgzuqg7w5p9mvgnd9ym28qh5grlph8xd2z925ph3wczvf2ag2x9t

### Enterprise address

Introduced in Shelley:

    [header] + [payment_key_hash]

Entreprise address has no staking rights. This is useful for example for exchanges which contain a lot of funds and thus would control too much stake.

**Example:**

*Mainnet*: addr1vxq0nckg3ekgzuqg7w5p9mvgnd9ym28qh5grlph8xd2z92su77c6m

*Testnet*: addr_test1vzq0nckg3ekgzuqg7w5p9mvgnd9ym28qh5grlph8xd2z92s8k2y47

### Reward address

Introduced in Shelley:

    [header] + [staking_key_hash]

Staking rewards are gathered on this address after stake registration and delegation. They can then be withdrawn by a transaction with withdrawals filled in. All of the rewards have to be taken out at once.

**Example:**

*Mainnet*: stake1uyfz49rtntfa9h0s98f6s28sg69weemgjhc4e8hm66d5yacalmqha

*Testnet*: stake_test1uqfz49rtntfa9h0s98f6s28sg69weemgjhc4e8hm66d5yac643znq

### Script address

Address = H(vs) || B

*vs = validation script*

*B = base address, pointer address or none*

- not supported in Byron and not yet in Shelley (should be added later to Shelley)

## Transactions

Transactions don't have a distinct type. Every transaction may transfer funds, post a certificate, withdraw funds or do all at once (to a point).

*Unfortunately we are aware of the fact that currently at most ~14 inputs are supported per transaction. We suspect this is due to the memory heavy CBOR implementation. We plan on fixing this soon.*

### Witnesses

Transactions need a witness (signature) for each input, withdrawal and some certificates. A witness for each key is included only once in a transaction. The signature is built by ed25519.sign_ext function. There are significant differences between Byron and Shelley witnesses - although we need to support both, because a transaction may have Byron inputs.

*Shelley witnesses*:

They only need to contain the public key (not the extended public key) and the signature. Nothing else is needed to verify the signature, although the signing happens with an extended private key.

*Byron witnesses*:

In order to be able to properly verify them, Byron witnesses need to contain the public key, signature, chain code and address attributes (which are empty on mainnet or contain the protocol magic on testnet).

More on witness structure can be found [here](https://github.com/input-output-hk/cardano-ledger-specs/blob/master/shelley/chain-and-ledger/executable-spec/cddl-files/shelley.cddl#L213).

### Certificates

Certificates are posted to the blockchain via transactions and they mark a certain action, thus there are multiple certificate types:

* stake key registration certificate
* stake key de-registration certificate
* delegation certificate

And these three which are not supported by Trezor at the moment:

* stake pool registration certificate
* stake pool retirement certificate
* operational key certificate

Stake key de-registration and delegation certificates both need to be witnessed by the corresponding staking key.

You can read more on certificates in the [delegation design spec](https://hydra.iohk.io/build/2006688/download/1/delegation_design_spec.pdf#subsection.3.4).

Info about their structure can be found [here](https://github.com/input-output-hk/cardano-ledger-specs/blob/25f504bd95104607be722979eb911f8330d1a921/shelley/chain-and-ledger/executable-spec/cddl-files/shelley.cddl#L102).

### Withdrawals

Withdrawals are posted to the blockchain via transactions and they are used to withdraw rewards from reward accounts. When withdrawing funds, the transaction needs to be witnessed by the corresponding staking key.

You can read more on withdrawals in the [delegation design spec](https://hydra.iohk.io/build/2006688/download/1/delegation_design_spec.pdf) (there is not a dedicated section to withdrawals, simply search for 'withdrawal').

### Metadata

Each transaction may contain metadata. Metadata format can be found [here](https://github.com/input-output-hk/cardano-ledger-specs/blob/25f504bd95104607be722979eb911f8330d1a921/shelley/chain-and-ledger/executable-spec/cddl-files/shelley.cddl#L210). It's basically a CBOR serialized map and can contain numbers, bytes, strings or nested maps/lists.

Due to memory limitations we currently enforce a maximum size of 500B for metadata.

### Transaction Explorer

[Cardano explorer](https://explorer.cardano.org/en.html).

### Submitting a transaction

You can use a combination of [cardano-node](https://github.com/input-output-hk/cardano-node) and cardano-cli (part of the cardano-node repo) to submit a transaction.

## Serialization format

Cardano uses [CBOR](https://www.rfc-editor.org/info/rfc7049) as a serialization format. [Here](https://github.com/input-output-hk/cardano-ledger-specs/blob/0e52031c7240a1c2b7faadfa5f3dfe04c2c5e5e8/shelley/chain-and-ledger/executable-spec/cddl-files/shelley.cddl) is the [CDDL](https://tools.ietf.org/html/rfc8610) specification for Shelley. [Cbor tags](https://www.iana.org/assignments/cbor-tags/cbor-tags.xhtml).

## Sample transactions

Examples from https://github.com/input-output-hk/cardano-ledger-specs/pull/1315/files
(seem fully compatible with [https://github.com/input-output-hk/cardano-ledger-specs/blob/master/shelley/chain-and-ledger/executable-spec/cddl-files/shelley.cddl](https://github.com/input-output-hk/cardano-ledger-specs/blob/master/shelley/chain-and-ledger/executable-spec/cddl-files/shelley.cddl)); they are not real since they use a different hash function.
Txs related to stake pools are left out.

### I'm not sure these are valid anymore

-- | Simple Transaction which consumes one UTxO and creates one UTxO
-- | and has one witness
83a400d90102818244b45c4891000181840044cfb2c4144476394f7a0a02185e030aa10081821a6753449f824489ec679d1a6753449f80

```
[
    {
        0: 258([[h'B45C4891', 0]]),
        1: [[0, h'CFB2C414', h'76394F7A', 10]],      <-------- 0 (address type), hash(vkp), hash(vks), amount ; why are there 9 address types?
        2: 94,
        3: 10
    },
    {
        0: [
                [
                    1733510303,                     <---- $vkey
                    [h'89EC679D', 1733510303]       <---- $signature
                ]
           ]
    },
    []
]
```

-- | Simple Transaction which consumes one UTxO and creates one UTxO
-- | and has one witness and some metadata
83a500d90102818244b45c4891000181840044cfb2c4144476394f7a0a02185e030a07444eece652a10081821a6753449f8244b0436c041a6753449f81a10082056568656c6c6f

```
[
    {
        0: 258([[h'B45C4891', 0]]),
        1: [[0, h'CFB2C414', h'76394F7A', 10]],
        2: 94,
        3: 10,
        7: h'4EECE652'
    },
    {
        0: [[1733510303, [h'B0436C04', 1733510303]]]
    },
    [
        {
            0: [5, "hello"]
        }
    ]
]
```

-- | Transaction which consumes two UTxO and creates five UTxO
-- | and has two witnesses
83a400d90102828244b45c4891008244b45c4891010185840044cfb2c4144476394f7a0a840044cfb2c4144476394f7a14840044cfb2c4144476394f7a181e840044f079394944bcbe39001828840044f079394944bcbe390018320218c7030aa10082821a6753449f8244219dc2b31a6753449f821a3344eb568244219dc2b31a3344eb5680

```
[
    {
        0: 258([[h'B45C4891', 0], [h'B45C4891', 1]]),
        1: [[0, h'CFB2C414', h'76394F7A', 10], [0, h'CFB2C414', h'76394F7A', 20], [0, h'CFB2C414', h'76394F7A', 30], [0, h'F0793949', h'BCBE3900', 40], [0, h'F0793949', h'BCBE3900', 50]],
        2: 199,
        3: 10
    },
    {
        0: [
                [1733510303, [h'219DC2B3', 1733510303]],
                [860154710, [h'219DC2B3', 860154710]]
           ]
    },
    []
]
```

-- | Transaction which registers a stake key
83a500d90102818244b45c4891000181840044cfb2c4144476394f7a0a02185e030a048182004476394f7aa10081821a6753449f8244ddb63dc11a6753449f80

```
[
    {
        0: 258([[h'B45C4891', 0]]),
        1: [[0, h'CFB2C414', h'76394F7A', 10]],
        2: 94,
        3: 10,
        4: [
            [0, h'76394F7A']
        ]
    },
    {
        0: [[1733510303, [h'DDB63DC1', 1733510303]]]
    },
    []
]
```

-- | Transaction which delegates a stake key
83a500d90102818244b45c4891000181840044cfb2c4144476394f7a0a02185e030a0481830444bcbe3900442b7dd894a10082821a687c686f8244a61602491a687c686f821a6753449f8244a61602491a6753449f80

```
[
    {
        0: 258([[h'B45C4891', 0]]),
        1: [[0, h'CFB2C414', h'76394F7A', 10]],
        2: 94,
        3: 10,
        4: [
            [4, h'BCBE3900', h'2B7DD894']
        ]
    },
    {
        0: [
            [1752983663, [h'A6160249', 1752983663]],
            [1733510303, [h'A6160249', 1733510303]]
        ]
    },
    []
]
```

-- | Transaction which de-registers a stake key
83a500d90102818244b45c4891000181840044cfb2c4144476394f7a0a02185e030a048182024476394f7aa10081821a6753449f8244518af51d1a6753449f80

```
[
    {
        0: 258([[h'B45C4891', 0]]),
        1: [[0, h'CFB2C414', h'76394F7A', 10]],
        2: 94,
        3: 10,
        4: [
            [2, h'76394F7A']
        ]
    }, {
        0: [[1733510303, [h'518AF51D', 1733510303]]]
    },
    []
]
```

-- | Spending from a multi-sig address
83a400d90102818244b45c4891000181840044cfb2c4144476394f7a0a02185e030aa20082821a6753449f824489ec679d1a6753449f821a3344eb56824489ec679d1a3344eb56018183030283820044cfb2c414820044f0793949820044cfff284080

```
[
    {
        0: 258([[h'B45C4891', 0]]),
        1: [[0, h'CFB2C414', h'76394F7A', 10]],
        2: 94,
        3: 10
    },
    {
        0: [
                [1733510303, [h'89EC679D', 1733510303]],
                [860154710, [h'89EC679D', 860154710]]
           ],
        1: [
                [3, 2, [
                            [0, h'CFB2C414'], [0, h'F0793949'], [0, h'CFFF2840']    <-------- I don't understand this yet
                       ]
                ]
           ]
    },
    []
]
```

-- | Transaction with a Reward Withdrawal
83a500d90102818244b45c4891000181840044cfb2c4144476394f7a0a02185e030a05a182004476394f7a1864a10082821afdd63a158244bebb7df71afdd63a15821a6753449f8244bebb7df71a6753449f80

```
[
    {
        0: 258([[h'B45C4891', 0]]),
        1: [[0, h'CFB2C414', h'76394F7A', 10]],
        2: 94,
        3: 10,
        5: {
                [0, h'76394F7A']: 100
           }
    },
    {
        0: [
                [4258675221, [h'BEBB7DF7', 4258675221]],
                [1733510303, [h'BEBB7DF7', 1733510303]]
           ]
    },
    []
]
```

### Deregister staking key and withdraw funds (this one is valid)

#### CBOR

    83a600818258200d4a5315236df09f331158cae0f78d3df6cdb952a387bcd160dcb1bd2c708c6b00018182583900667ee84f714720123b92dd159bc306925020c460d464cea40eebc59f6c72a09118a3307789bc6d79e3b2149468f62df586085bcee687ca4d1b00000018fab759cd021a00030d40031a0007a120048182018200581cf228837e81c3baaa1879dbeff94e86fa5eba342aa05cd6d1c3bf23ed05a1581de06c72a09118a3307789bc6d79e3b2149468f62df586085bcee687ca4d1b00000001ad72b9d4a10082825820d198d009e0e482bc940331c3709c7ccdc1decbf0675e7c06380c1da3e129e7265840f62f02511ac77eebdbd87221a3bc9c93cf0971a13107ff41b6ea4ea14d720b361f41ab4994b91022763a10ebe1edf8174ca31ec2c7f56be72759d7e75303b603825820f1cea7b5d7f81e6e7858681634d957117ffe4e78bf9d475dbae9101baddda49858407ac236ad5684d22848a725246e83a043611c8ecebf04864d1b9fae6a33f23684790bc05d44a49b1c0a48df00151acafdcc93c29faf93663c9ed704cefd1a4b0df6

#### Parsed CBOR with structure names and types

**In short - everything is fixed size array and sorted map.**

```
# transaction
# array(3)
[
 # transaction body
 # map(6)
 {
   # inputs [id, index]
   # uint(0), array(1), array(2), bytes(32), uint(0)
   0: [[h'0D4...', 0]],

   # outputs [address, amount]
   # uint(1), array(1), array(2), bytes(57), uint(107285535181)
   1: [[h'006...', 107285535181]],

   # fee
   # uint(2), uint(200000)
   2: 200000,

   # ttl
   # uint(3), uint(500000)
   3: 500000,

   # certificates [[type, [keyhash/scripthash, keyhash]]]
   # uint(4), array(1), array(2), uint(1), array(2), uint(0), bytes(28)
   4: [[1,[0, h'F22...']]],

   # withdrawal [reward_address: amount]
   # uint(5), map(1), bytes(29), uint(7204944340)
   5: {h'E06...': 7204944340}
 },
  # witnesses
  # map(1)
 {
   # verifying key witnesses [[vkey -> signature]]
   # uint(0), array(2)
   0: [
       # array(2), bytes(32), bytes(64)
       [h'D19...', h'F62...'],
       # array(2), bytes(32), bytes(64)
       [h'F1C...', h'7AC...']
   ]
 },

 # metadata
 # primitive(22)
 null
]
```

## Setting up Cardano-CLI/Cardano-node

[Official documentation](https://docs.cardano.org/projects/cardano-node/en/latest/)
I wasn’t able to find a permalink to the binaries, but it should be [here](https://hydra.iohk.io/build/3255058) somewhere (**watch out, the link goes to the 1.14.0 version of cardano-node, at time of writing 1.18.0 is current**). Or perhaps you have to build it yourself.
Cardano-node configs can be found [here](https://hydra.iohk.io/job/Cardano/cardano-node/cardano-deployment/latest-finished/download/1/index.html).
Store everything to config folder (or however you want, but adjust all the commands then).

Running the node from the downloaded binaries:

```
cardano-node run \
  --topology config/topology.json \
  --database-path config/db \
  --socket-path config/db/node.socket \
  --host-addr 192.0.2.0 \
  --port 3001 \
  --config config/config.json
```

Set the CARDANO_NODE_SOCKET_PATH variable:

```
export CARDANO_NODE_SOCKET_PATH="/path/to/config/db/node.socket"
```

And you should be able to run your first command against your node (you might need to change `--testnet-magic 42` for `--mainnet`):

```
cardano-cli shelley query tip --testnet-magic 42
```

Returns the current block (slot?) - although the node takes a while to sync

Then you can try running:

```
cardano-cli shelley
cardano-cli shelley query
```

And it'll show you the available commands.

### Creating a sample (testnet) transaction with cardano-cli + some extra commands

**There's also submit command at the end, which most likely won't work because of wrong inputs**

```bash
# generate payment key pair
cardano-cli shelley address key-gen \
  --verification-key-file payment.vkey \
  --signing-key-file payment.skey

# generate staking key pair
cardano-cli shelley stake-address key-gen \
  --verification-key-file stake.vkey \
  --signing-key-file stake.skey

# create deregistration certificate
cardano-cli shelley stake-address deregistration-certificate \
  --stake-verification-key-file stake.vkey \
  --out-file dereg.cert

# create transaction (not signed)
cardano-cli shelley transaction build-raw \
  --tx-in 0d4a5315236df09f331158cae0f78d3df6cdb952a387bcd160dcb1bd2c708c6b#0 \
  --tx-out addr_test1qq4jpnqqm553ha3ds9l80uymawmmyr0zts3fnqsv3x22x3r04zmlnekqfphkmfqg92gp2q7uwgn4rr4v5xfsl7t7ep9qyafvpf+107285535181 \
  --ttl 500000 \
  --fee 200000 \
  --withdrawal stake_test1ur956pzxh87s078uvx2jhlhsnxsnqe3xzxcwluqlrrtphmqzc4g38+7204944340 \
  --certificate-file dereg.cert \
  --out-file tx

# sign transaction (with both payment key and stake key)
cardano-cli shelley transaction sign \
  --tx-body-file tx \
  --signing-key-file payment.skey \
  --signing-key-file stake.skey \
  --testnet-magic 42 \
  --out-file signed-tx

# submit transaction
cardano-cli shelley transaction submit \
  --tx-file signed-tx \
  --testnet-magic 42

# create base address from the generated keys
cardano-cli shelley address build \
  --payment-verification-key-file payment.vkey \
  --stake-verification-key-file stake.vkey \
  --testnet-magic 42 \
  --out-file base.addr
```

# Trezor Dev

For me VS Code was enough to develop everything related to Trezor.

## [Trezor Firmware](https://github.com/trezor/trezor-firmware)

Most of the code is written in Micropython and then compiled to C. Some of the code (mostly crypto stuff) is written directly in C though (luckily I haven’t really had to touch this when updating to Shelley).

The cool thing is, that there is an emulator which doesn’t have to be restarted when changing (most of) the code so it’s kind of quick to develop.

There are 4 main parts to the Trezor FW repo:

- Core
- Common
- Python
- Tests

### Core

All the Cardano related code (except the tests) is in the *core/src/apps/cardano* folder. This has mostly been written by VacuumLabs with some edits made by the Trezor guys overtime. *core/src/apps/common/cbor.py* has also been written by VacuumLabs.

Protobuf is used to communicate with Trezor HW. Cardano currently supports 3 messages:

- CardanoGetPublicKey
- CardanoGetAddress
- CardanoSignTransaction

In the *\_\_init\_\_.py* of the cardano module, these messages are mapped to the corresponding functions in code. This means that when a message of the given type arrives, Trezor knows to call our method.

So adding a new method is just a matter of adding a new protobuf message, function and mapping the message to the function.

#### Building for emulator

[Official doc](https://docs.trezor.io/trezor-firmware/core/build/index.html)
[Emulator doc](https://docs.trezor.io/trezor-firmware/core/build/emulator.html)
Summary:
Install dependencies:
sudo apt-get install scons libsdl2-dev libsdl2-image-dev
In the *core* folder run:
make build\_unix
Run emulator:
pipenv run emu.py
Run emulator with custom mnemonic:
pipenv run emu.py \--mnemonic "all all all all all all all all all all all all"

#### Building firmware for HW Trezor:

[Trezor doc](https://wiki.trezor.io/Developers_guide:Custom_firmware)
In project root invoke:
PRODUCTION=0 ./build-docker.sh \[BRANCH\_NAME\]
E.g.:
PRODUCTION=0 ./build-docker.sh cardano-shelley-update-pr3
This takes about 5 \- 15 minutes.
Then to upload the firmware (Trezor device needs to be in [bootloader mode](https://wiki.trezor.io/User_manual:Updating_the_Trezor_device_firmware__TT)):
cd core
mkdir build/firmware
cp ../build/core/firmware/firmware.bin ./build/firmware/firmware.bin
make upload

### Common

I was only concerned about the *protob/messages-cardano.proto* file. This is where all the protobuf type definitions and message definitions are. When you modify anything in this file you need to run:
make protobuf
make protobuf\_check
This will regenerate all the necessary files in *core* and *python* modules. When adding a new message (not a type) you also need to add it to the cardano section of *messages.proto*.

### Python

This contains the trezorlib/trezorctl. This is basically a python library/CLI to interact with Trezor HW and I’ve used it extensively for testing. All the commands supported by Trezor HW are implemented here so you can easily send commands to Trezor.

**Example command for get address:**
pipenv run trezorctl cardano get-address \--address "m/1852'/1815'/0'/0/3" \-t base \--staking-address "m/1852'/1815'/0'/2/0"
**Example command for sign transaction ([input file](https://gist.github.com/gabrielKerekes/82b3c79efbdc45df5a193da59dfcec94)):**
pipenv run trezorctl cardano sign-tx \-f tx\_deregisterAndWithdraw.json

Adding a new command requires adding it to *python/src/trezorlib/cardano.py* and to *python/src/trezorlib/cli/cardano.py* \- details can be easily deduced from the existing commands.

### Tests

#### Unit tests

Although unit tests are part of the *core* module, I’ll mention them here. All the cardano unit tests are in *core/tests/test\_apps.cardano.\*.py*. In order to run only cardano tests I’ve modified the *run\_tests.sh* script \-\> [result](https://gist.github.com/gabrielKerekes/f9f15ee8fe87366959122131ac4ab319) (note that the original *run\_tests.sh* file can change and the cardano file then needs to be also updated).

Individual tests can also be run from the *core/tests* directory by running (the project needs to be built first \- not rebuilt every time, just built at some point):
../build/unix/trezor-emu-core test\_apps.common.cbor.py

#### Integration tests

All the cardano tests (I was concerned with) are placed in *tests/device\_tests/test\_msg\_cardano\_\*.py*. These tests use the trezorctl and an emulator to run.
The mnemonic *“all all all all all all all all all all all all”* is used to run the tests. So to generate test outputs, run emulator with:
pipenv run ./emu.py \--mnemonic "all all all all all all all all all all all all"
Before running the tests the emulator will always be reset, so it doesn’t need to be started in any special way.

[Here’s](https://gist.github.com/gabrielKerekes/c94e063d1e3e26a348fe6fb30f1a0946) a script I used to run all the cardano tests. It also takes one optional parameter, which you can set so it runs only that type of device tests. E.g:
./run\_tests\_cardano.sh sign\_transaction
Or
./run\_tests\_cardano.sh get\_address

### Shelley update PRs

[PR 1/3](https://github.com/trezor/trezor-firmware/pull/1096)
[PR 2/3](https://github.com/trezor/trezor-firmware/pull/1112)
[PR 3/3](https://github.com/trezor/trezor-firmware/pull/1145)
There have been some more bug fixing PRs. They had a lot of comments but all in all they were really nice and understanding.

## [Trezor Connect (JS library)](https://github.com/trezor/connect)

Trezor Connect is used by client apps to communicate with Trezor. It basically converts JS Objects to protobuf messages.

It consists of three main parts:

- methods
- types
- tests

### Methods

Located in *src/js/core/methods* these methods contain validation and conversion of passed in parameters to protobuf. There are three Cardano methods: *CardanoGetAddress, CardanoGetPublicKey* and *CardanoSignTransaction.* They are all rather similar. They validate the passed in parameters, convert them to protobuf inputs and then the corresponding device command is called.

Device command is what actually sends the corresponding protobuf message and they are all in one file *src/js/device/DeviceCommands.js* \- just search for Cardano.

### Types

This is the rather confusing part. There’s multiple types of types… Flow, Typescript and Protobuf.

#### Flow types

Flow types are actually used by the app and (I think) they are also exported to be used by clients. They are located in *src/js/types/networks/cardano.js*. These are the types the methods mentioned above take in as parameters. The outside facing types.

#### Typescript types

These are located in *src/ts/types/networks/cardano.d.ts*. They aren’t used by Connect but are exported to be used by clients. They are pretty much a copy of the Flow types, but adjusted for typescript.

#### Protobuf types

Located in *src/js/types/trezor/protobuf.js*. This file contains all the protobuf types to which the method parameters are converted. They are pretty much the same as the types in *messages-cardano.proto*.

I had real trouble figuring out what needs to be changed and how and I am still unsure. Perhaps [my PRs](#shelley-update-prs) might help you figure out what needs to change.

### Tests

There are actual functional tests, old functional tests, flow types tests and typescript type tests.

#### Functional tests

Located in *tests/\_\_fixtures\_\_/cardano\*.js*. Data are taken from Trezor FW. These are the current tests at the time of writing, although Trezor is trying to somehow transform their test suite so it can be reused in Connect and FW.

##### Running the tests ([from here](https://github.com/trezor/connect/issues/611#issuecomment-651069514) or [here](https://github.com/trezor/connect/blob/develop/tests/README.md))

You first need to build a “frozen” FW build. So in root of Trezor FW repo run:
pipenv sync
pipenv shell
cd core
PYOPT=0 pipenv run make build\_unix\_frozen
cd build/unix
mv micropython trezor-emu-core-v2.9.9

Then in Trezor Connect folder you can run:
./tests/run.sh \-b \~/repos/trezor-firmware/core/build/unix/trezor-emu-core-v2.9.9 \-f 2.9.9 \-g \-i getPublicKey
(with the correct path to the previously built firmware)

##### Old functional tests

I’ve been modifying this tests also, although they are probably deprecated and not used anymore. No one has told me that explicitly though. These tests are located in *src/\_\_tests\_\_/core/cardano\*.spec.js*.

##### Flow and typescript types

These are located in *src/js/types/\_\_tests\_\_/cardano.js* and *src/ts/types/\_\_tests\_\_/cardano.ts* respectively. They contain all the messages with filled in parameters and their responses to check that the types actually match. I wasn’t able to run TS validation, but Flow tests have been run/checked automatically by VS Code.

### Shelley update PRs {#shelley-update-prs}

[PR 1/3](https://github.com/trezor/connect/pull/623)
[PR 2/3](https://github.com/vacuumlabs/connect/pull/2)
[PR 3/3](https://github.com/vacuumlabs/connect/pull/3)
In the end all the PRs have been merged to one \-\> [Merged PR](https://github.com/trezor/connect/pull/639).
