# Message signing for Cardano HW wallets

This document describes how the [api.signData](https://cips.cardano.org/cips/cip30/#apisigndataaddraddresspayloadbytespromisedatasignature) call, a specific subset of [CIP-8](https://github.com/cardano-foundation/CIPs/blob/master/CIP-0008/README.md), should be implemented in HW wallets. Details discussed below are based on the implementation of [cardano-signer](https://github.com/gitmachtl/cardano-signer/blob/a6822db066a15d3b829350db1fb51d04b5220ac9/src/cardano-signer.js#L590).

# What to sign

We are indirectly signing a *message*. This message is first transformed into the *payload*: either we use the raw message, or its Blake2b-224 hash.

The payload is then wrapped in an envelope called *Sig_structure* which serves several purposes:

* add various metadata related to the message;
* add technical context (signature algorithm etc.);
* make sure that the signed structure cannot be interpreted as a valid transaction (a transaction body is always a map, while the structure is an array with a fixed first item).

Before signing, the Sig_structure is encoded into CBOR. As a precaution, we will deny signing  Sig_structures that are encoded into 32 bytes (so it won't be a tx body hash even if specs change in the future -- the currently used structures have at least 87 bytes).

The message and the signature are then packed into another structure *COSE_Sign1*. This will not be done on HW wallets because it does not require signing. COSE_Sign1 contains a bool flag indicating whether the payload is hashed or not.

There is no distinction between hashed and non-hashed payload in Sig_structure, so from the security perspective, the hash must be computed by the HW wallet -- otherwise the user can be fooled into thinking that he is signing a hash while it would be a raw message. Hashes are not calculable by hand, so get less scrutiny from humans, and a compromised SW wallet could show the user an incorrect hash (an actual raw message as bytes) in order to trick him. Even if the hash is computed within a HW wallet, it would still be possible to fool the user into thinking that he is signing a raw message while it is actually a hash, but it does not seem to be a threat (the message is shown to the user and we are assuming no one can invert the hash function, i.e. construct a bytestring that would hash into a given malicious message). While it might be safer to implement only one of these options for payload, we need both: some third-parties might only implement one of them. This is a consequence of the (flawed) design of CIP-8.

A large portion of raw messages in use now are plain text, and it is highly preferable to display them as human-readable text. HW wallets will attempt to do so, but with additional restrictions similar to [those applied to DNS names](https://github.com/vacuumlabs/ledger-app-cardano-shelley/blob/16b2e3502695f33d5e8491a941ad430befd01e4d/src/textUtils.c#L274). If those restrictions are not met, it will result in an error.

Altogether, there are 5 inputs:

1. The raw message.
2. A bool flag describing whether the message should be shown as text (ASCII with [certain limitations](https://github.com/vacuumlabs/ledger-app-cardano-shelley/blob/16b2e3502695f33d5e8491a941ad430befd01e4d/src/textUtils.c#L274)) or as hex-encoded bytes.
3. A bool flag describing whether the payload is raw or hashed.
4. A derivation path of the key that will be used to sign Sig_structure.
5. Data for the `address` field in the protected header (see the section "Address field").

```cddl
protectedHeader = {
1 : -8,                         // set algorithm to EdDSA
"address" : address_bytes       // raw address given by the user
}

Sig_structure = [
	context : "Signature1",
body_protected : *CBOR_encode*(protectedHeader),
external_aad : bstr,            // empty buffer here
payload : bstr                  // message or its hash as bytes
]
```

**Example of protectedHeader:** (diagnostic notation taken from [https://cbor.nemo157.com/](https://cbor.nemo157.com/))

a201276761646472657373583900fec5a902e307707b6ab3de38104918c0e33cf4c3408e6fcea4f0a199c13582aec9a44fcc6d984be003c5058c660e1d2ff1370fd8b49ba73f

```
{
    1: -8,
    "address": h'00fec5a902e307707b6ab3de38104918c0e33cf4c3408e6fcea4f0a199c13582aec9a44fcc6d984be003c5058c660e1d2ff1370fd8b49ba73f',
}
```

**Example of Sig_structure:**

846a5369676e6174757265315846a201276761646472657373583900fec5a902e307707b6ab3de38104918c0e33cf4c3408e6fcea4f0a199c13582aec9a44fcc6d984be003c5058c660e1d2ff1370fd8b49ba73f40581cd7d7d443331abb00122496b16b6e33e978f2b65766b5f640ff2090eb

```
[
    "Signature1", h'a201276761646472657373583900fec5a902e307707b6ab3de38104918c0e33cf4c3408e6fcea4f0a199c13582aec9a44fcc6d984be003c5058c660e1d2ff1370fd8b49ba73f',
    h'',
    h'd7d7d443331abb00122496b16b6e33e978f2b65766b5f640ff2090eb',
]
```

**Example of COSE_Sign1** (these structures are assembled outside of HW wallets):

84582aa201276761646472657373581d6052e63f22c5107ed776b70f7b92248b02552fd08f3e747bc745099441a166686173686564f4535468697320697320746865207061796c6f61645840dd058b1df86d8de9169ae7e5fedd26a0f69a63af289e4cb7e07dd7a2f882298a207a6fe7003c2044336574a733a1693189d33957d6f6ff7a3d9f749ac45f750f

## Address field

The field is named "address" in CIP-8, but it can actually be anything. What makes sense for many applications is to use just the hash of the key being used to sign the Sig_structure. Because of legacy applications, we have to keep supporting addresses too. There will be thus two options available:

1. Shelley address given as "address parameters" (this a technical term describing what is already implemented within Ledger and Trezor):
* base address with the payment part given via a key derivation path;
* stake address with the stake part given via a key derivation path;
* enterprise address with the payment part given via a key derivation path.
2. Blake-224 hash of a public key given by its derivation path.

Since the address field might be unrelated to the key used for signing and it seems impossible to completely determine what the existing applications use, we don't want to impose restrictions on the derivation paths used.

## User interface

A human user must not think he is signing a hashed payload when he is possibly signing a non-hashed payload. However, showing the hash even when the raw message is signed is useful (DApps tend to present both to the user). The UI will thus:

* Display the raw message in full if it fits into a single Ledger APDU (about 160 bytes, see below), or display the first \~160 bytes of the raw message and its length. A similar mechanism is already implemented for [inline datums](https://github.com/vacuumlabs/ledger-app-cardano-shelley/blob/16b2e3502695f33d5e8491a941ad430befd01e4d/src/signTxOutput_ui.c#L354) (there is little point in showing the whole raw message if it is very long, it would slow down signing significantly).
  Depending on the flag given within the input, the raw message is shown either as an ASCII text or as a hex-encoded bytestring.
  TODO is it safe to hide the last part of the message? perhaps we should not do it for ascii msg?
* Display the hash of the message (computed by the HW wallet).
* Display a prompt asking whether the user wants to sign the raw message / the hash (what is shown depends on the flag describing whether the payload is hashed). The user can confirm or deny, but he cannot change this.

Note: A bit of trouble here is that the raw message might actually be a hash of something, but it's impossible for a HW wallet to do anything about it, so it's up to the user to check the displayed message.

## Message length limitations

If the payload is hashed, there is no need to restrict message length. On both Ledger and Trezor, it will be split into chunks and streamed to the device, without limitations on message length.

If the payload is not hashed, the length of the serialized Sig_structure is 86 bytes \+ size of CBOR encoding of payload length \+ payload length. A payload of size up to 160 bytes will thus safely fit into Ledger APDUs. We don't want to support signing for very long raw messages because it might exceed hardware limitations on the cryptographic functions.
TODO it must be verified that even 160 bytes work on both Ledger and Trezor

## Security policies

For signing, the following keys will be allowed:

* payment keys
* stake keys
* multisig keys (CIP-1854)
* mint keys (CIP-1855)
* DRep keys
* constitutional committee hot and cold keys
* stake pool operator keys

TODO make sure there is no security problem with the last 2 items, e.g. operating certificate is also an array of length 4, but with a different first item vs. Sig_structure

# Supported tools and devices

This should be implemented on Trezor and on all Ledger devices (including Nano S, if at all possible to fit it on the device).

Support should be added in cardano-hw-cli.

TODO hw-cli needs to have the command line arguments designed for each of the 5 input items mentioned above

