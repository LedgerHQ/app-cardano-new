# HW Wallets single-account model

## Motivation

On HW wallets we want to hide transaction change outputs whenever possible. The reasons for this are mostly UX related -- we don't want to unnecessarily bother/confuse the user with the information that he's moving funds to one of his addresses.

The problem is that we are currently a bit too lenient on what we consider a change output. The only requirement for a change output to be hidden is that it's payment path is not "unusual" (account <= 100, address index <= 1,000,000).

This means that if a transaction contains two change outputs belonging to different accounts of the user (e.g. 1852'/1815'/0'/0/0 and 1852'/1815'/1'/0/0) we will not show either of these outputs to the user. The user might thus be unaware that the funds are going to a different account of his and might get quite scared when he sees the loss of funds in his primary account (as software wallets are mostly single-account).

What's worse is that an attacker could spread the user's funds over all the accounts which are still being hidden (SW wallets usually use blockchain-scanning algorithms that do not proceed if an account number has not been used, thus funds in the account, say, 100, are only discoverable if each of the accounts 1 to 99 has been used) and the user wouldn't even know about it from what the HW wallet would show him.

Another problem is that "usual" witnesses are also hidden from the user by default. This means that the user can be made to sign a transaction with any combination of his accounts which would essentially provide cryptographic proof that these accounts are somehow tied together and would thus partially deanonymize them.

You can check [this rather long discussion in the Trezor transaction streaming PR](https://github.com/trezor/trezor-firmware/pull/1683#discussion_r689517936) for more details.

## Solution

Only allow transactions to contain Byron and Shelley paths from a single account. We don't need to check multi-sig or minting paths because they are always shown to the user.

The paths which need to belong to the same account are:

- change output payment path
- stake registration certificate path
- stake delegation certificate path
- stake deregistration certificate path
- pool registration certificate pool owner paths
- withdrawal staking path
- witness request path

This can be done by storing the first encountered path and then comparing the other paths against this path. If the accounts in paths don't match we reject the transaction immediately (thus we never provide a witness that is not in line with the paths included in the tx body).

[Here's an isolated module](https://github.com/trezor/trezor-firmware/blob/b47a177549e80754dd308486e58544dc1c843d72/core/src/apps/cardano/helpers/account_path_check.py) doing this on Trezor.

Note that we do not need to check for staking paths in outputs given by address parameters (instead of the binary encoding of the address) because outputs with payment and staking paths that are not consistent (differ in account) or are non-standard (not a base address etc.) are never considered change outputs and are shown to the users.

### An exception to the rule

In order to continue supporting Byron to Shelley migrations, we consider the Byron account 44'/1815'/0' to be equivalent to the Shelley account 1852'/1815'/0' (so we don't reject transactions containing a mix of paths belonging to these two accounts). While some software wallets consider these Byron and Shelley accounts to be completely separate, other wallets consider these accounts to be logically the same. This exception is required to avoid breaking the latter approach.

An implication of this decision is that funds can be transferred from a Byron account to the corresponding Shelley account without the user being aware of it (not the other way around since Byron outputs are always shown).

## Multisig (CIP-1854)

This policy does not apply to multisig transactions where all outputs and all witnesses are displayed to the user.