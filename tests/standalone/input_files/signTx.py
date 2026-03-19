# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2024 Ledger SAS
# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0

"""
This module provides Ragger tests for Sign TX check
"""

from enum import IntEnum
from typing import List, Optional, Union
from dataclasses import dataclass, field
import base58

from application_client.app_def import FakeNet, NetworkDesc, Mainnet, Testnet, Testnet_legacy
from application_client.security_warnings import WarningBit
from application_client.status_words import StatusWord
from standalone.input_files.derive_address import (
    DeriveAddressTestCase,
    AddressType,
    pointer_to_str,
)

MAX_SIGN_TX_CHUNK_SIZE = 250

class TransactionSigningMode(IntEnum):
    ORDINARY_TRANSACTION = 0x03
    POOL_REGISTRATION_AS_OWNER = 0x04
    POOL_REGISTRATION_AS_OPERATOR = 0x05
    MULTISIG_TRANSACTION = 0x06
    PLUTUS_TRANSACTION = 0x07

class TxAuxiliaryDataType(IntEnum):
    ARBITRARY_HASH = 0x00
    CIP36_REGISTRATION = 0x01

class CredentialParamsType(IntEnum):
    KEY_HASH = 0x00
    SCRIPT_HASH = 0x01
    KEY_PATH = 0x02

class TxOutputFormat(IntEnum):
    ARRAY_LEGACY = 0x00
    MAP_BABBAGE = 0x01

class TxOutputDestinationType(IntEnum):
    THIRD_PARTY = 0x01
    DEVICE_OWNED = 0x02

class PoolKeyType(IntEnum):
    DEVICE_OWNED = 0x01
    THIRD_PARTY = 0x02

class VoteOption(IntEnum):
    NO = 0x00
    YES = 0x01
    ABSTAIN = 0x02

class VoterType(IntEnum):
    COMMITTEE_KEY_HASH = 0
    COMMITTEE_KEY_PATH = 100
    COMMITTEE_SCRIPT_HASH = 1
    DREP_KEY_HASH = 2
    DREP_KEY_PATH = 102
    DREP_SCRIPT_HASH = 3
    STAKE_POOL_KEY_HASH = 4
    STAKE_POOL_KEY_PATH = 104

class CertificateType(IntEnum):
    STAKE_REGISTRATION = 0
    STAKE_DEREGISTRATION = 1
    STAKE_DELEGATION = 2
    STAKE_POOL_REGISTRATION = 3
    STAKE_POOL_RETIREMENT = 4
    STAKE_REGISTRATION_CONWAY = 7
    STAKE_DEREGISTRATION_CONWAY = 8
    VOTE_DELEGATION = 9
    STAKE_POOL_AND_DREP_DELEGATION = 10
    ACCOUNT_REGISTRATION_DELEGATION_TO_STAKE_POOL = 11
    ACCOUNT_REGISTRATION_DELEGATION_TO_DREP = 12
    ACCOUNT_REGISTRATION_DELEGATION_TO_STAKE_POOL_AND_DREP = 13
    AUTHORIZE_COMMITTEE_HOT = 14
    RESIGN_COMMITTEE_COLD = 15
    DREP_REGISTRATION = 16
    DREP_DEREGISTRATION = 17
    DREP_UPDATE = 18

class CIP36VoteRegistrationFormat(IntEnum):
    CIP_15 = 1
    CIP_36 = 2

class CIP36VoteDelegationType(IntEnum):
    KEY = 1
    PATH = 2

class DRepParamsType(IntEnum):
    KEY_HASH = 0
    SCRIPT_HASH = 1
    ABSTAIN = 2
    NO_CONFIDENCE = 3
    KEY_PATH = 100

class TxRequiredSignerType(IntEnum):
    PATH = 0
    HASH = 1

class DatumType(IntEnum):
    HASH = 0
    INLINE = 1

class RelayType(IntEnum):
    SINGLE_HOST_IP_ADDR = 0
    SINGLE_HOST_HOSTNAME = 1
    MULTI_HOST = 2

@dataclass
class TxInput:
    txHashHex: str
    path: Optional[str] = None
    outputIndex: int = 0

@dataclass
class Token:
    assetNameHex: str
    amount: int

@dataclass
class AssetGroup:
    policyIdHex: str
    tokens: List[Token]

@dataclass
class ThirdPartyAddressParams:
    addressHex: str

@dataclass
class TxOutputDestination:
    type: TxOutputDestinationType
    params: Union[ThirdPartyAddressParams, DeriveAddressTestCase]

@dataclass
class Datum:
    type: DatumType
    datumHex: str

@dataclass
class TxOutputAlonzo:
    destination: TxOutputDestination
    amount: int
    format: TxOutputFormat = TxOutputFormat.ARRAY_LEGACY
    tokenBundle: List[AssetGroup] = field(default_factory=list)
    datum: Optional[Datum] = None

@dataclass
class TxOutputBabbage:
    destination: TxOutputDestination
    amount: int
    format: TxOutputFormat = TxOutputFormat.MAP_BABBAGE
    tokenBundle: List[AssetGroup] = field(default_factory=list)
    datum: Optional[Datum] = None
    referenceScriptHex: Optional[str] = None

TxOutput = Union[TxOutputAlonzo, TxOutputBabbage]

@dataclass
class TxAuxiliaryDataHash:
    hashHex: str

@dataclass
class CIP36VoteDelegation:
    type: CIP36VoteDelegationType
    votingKeyPath: str
    weight: int

@dataclass
class TxAuxiliaryDataCIP36:
    format: CIP36VoteRegistrationFormat
    stakingPath: str
    paymentDestination: TxOutputDestination
    nonce: int
    voteKey: Optional[str] = None
    votingPurpose: Optional[int] = None
    delegations: List[CIP36VoteDelegation] = field(default_factory=list)

@dataclass
class TxAuxiliaryData:
    type: TxAuxiliaryDataType
    params: Union[TxAuxiliaryDataHash, TxAuxiliaryDataCIP36]

@dataclass
class RequiredSigner:
    type: TxRequiredSignerType
    pathOrHashHex: (
        str  # BIP44 path (for PATH type) or 28-byte key hash hex (for HASH type)
    )

@dataclass
class CredentialParams:
    type: CredentialParamsType
    keyValue: Optional[str] = None  # keyPath, keyHash or scriptHash

@dataclass
class Withdrawal:
    stakeCredential: CredentialParams
    amount: int

@dataclass
class DRepParams:
    type: DRepParamsType
    keyValue: Optional[str] = None  # keyPath, keyHash or scriptHash

@dataclass
class GovActionId:
    txHashHex: str
    govActionIndex: int

@dataclass
class AnchorParams:
    url: str
    hashHex: str

@dataclass
class VotingProcedure:
    vote: VoteOption
    anchor: Optional[AnchorParams] = None

@dataclass
class Voter:
    type: VoterType
    keyValue: str  # keyPath, keyHash or scriptHash

@dataclass
class Vote:
    govActionId: GovActionId
    votingProcedure: VotingProcedure

@dataclass
class VoterVotes:
    voter: Voter
    votes: List[Vote]

@dataclass
class StakeRegistrationParams:
    stakeCredential: CredentialParams

@dataclass
class StakeRegistrationConwayParams:
    stakeCredential: CredentialParams
    deposit: int

@dataclass
class StakeDelegationParams:
    stakeCredential: CredentialParams
    poolKeyHash: str

@dataclass
class VoteDelegationParams:
    stakeCredential: CredentialParams
    dRep: DRepParams

@dataclass
class AccountRegistrationDelegationToStakePoolParams:
    stakeCredential: CredentialParams
    poolKeyHash: str
    coin: int

@dataclass
class AccountRegistrationDelegationToDRepParams:
    stakeCredential: CredentialParams
    dRep: DRepParams
    coin: int

@dataclass
class AccountRegistrationDelegationToStakePoolAndDRepParams:
    stakeCredential: CredentialParams
    poolKeyHash: str
    dRep: DRepParams
    coin: int

@dataclass
class StakePoolAndDRepDelegationParams:
    stakeCredential: CredentialParams
    poolKeyHash: str
    dRep: DRepParams

@dataclass
class AuthorizeCommitteeParams:
    coldCredential: CredentialParams
    hotCredential: CredentialParams

@dataclass
class ResignCommitteeParams:
    coldCredential: CredentialParams
    anchor: Optional[AnchorParams] = None

@dataclass
class DRepRegistrationParams:
    dRepCredential: CredentialParams
    deposit: int
    anchor: Optional[AnchorParams] = None

@dataclass
class DRepUpdateParams:
    dRepCredential: CredentialParams
    anchor: Optional[AnchorParams] = None

@dataclass
class PoolRetirementParams:
    poolCredential: CredentialParams
    retirementEpoch: int

@dataclass
class Margin:
    numerator: int
    denominator: int

@dataclass
class PoolMetadataParams:
    metadataUrl: str
    metadataHashHex: str

@dataclass
class PoolKey:  # same for PoolRewardAccount and PoolOwner
    type: PoolKeyType
    key: str  # hex string or path

@dataclass
class SingleHostIpAddrRelayParams:
    portNumber: Optional[int] = None
    ipv4: Optional[str] = None
    ipv6: Optional[str] = None

@dataclass
class SingleHostHostnameRelayParams:
    portNumber: int
    dnsName: Optional[str]

@dataclass
class MultiHostRelayParams:
    dnsName: Optional[str]

@dataclass
class Relay:
    type: RelayType
    params: Union[
        SingleHostIpAddrRelayParams, SingleHostHostnameRelayParams, MultiHostRelayParams
    ]

@dataclass
class PoolRegistrationParams:
    poolKey: PoolKey
    vrfKeyHashHex: str
    pledge: int
    cost: int
    margin: Margin
    rewardAccount: PoolKey
    poolOwners: List[PoolKey]
    relays: List[Relay]
    metadata: Optional[PoolMetadataParams] = None

@dataclass
class Certificate:
    type: CertificateType
    params: Union[
        StakeRegistrationParams,
        StakeRegistrationConwayParams,
        StakeDelegationParams,
        VoteDelegationParams,
        StakePoolAndDRepDelegationParams,
        AccountRegistrationDelegationToStakePoolParams,
        AccountRegistrationDelegationToDRepParams,
        AccountRegistrationDelegationToStakePoolAndDRepParams,
        AuthorizeCommitteeParams,
        ResignCommitteeParams,
        DRepRegistrationParams,
        DRepUpdateParams,
        PoolRegistrationParams,
        PoolRetirementParams,
    ]

@dataclass(kw_only=True)
class Transaction:
    network: NetworkDesc
    inputs: List[TxInput]
    outputs: List[TxOutput]
    fee: int = 42
    ttl: Optional[int] = 10
    certificates: List[Certificate] = field(default_factory=list)
    withdrawals: List[Withdrawal] = field(default_factory=list)
    mint: List[AssetGroup] = field(default_factory=list)
    collateralInputs: List[TxInput] = field(default_factory=list)
    requiredSigners: List[RequiredSigner] = field(default_factory=list)
    referenceInputs: List[TxInput] = field(default_factory=list)
    votingProcedures: List[VoterVotes] = field(default_factory=list)
    auxiliaryData: Optional[TxAuxiliaryData] = None
    validityIntervalStart: Optional[int] = None
    scriptDataHash: Optional[str] = None
    includeNetworkId: Optional[bool] = None
    collateralOutput: Optional[TxOutput] = None
    totalCollateral: Optional[int] = None
    treasury: Optional[int] = None
    donation: Optional[int] = None

@dataclass
class Witness:
    path: str
    witnessSignatureHex: Optional[str] = None

@dataclass(kw_only=True)
class SignTxTestCase:
    name: str
    tx: Optional[Transaction] = None
    signingMode: Optional[TransactionSigningMode] = None
    txBody: Optional[str] = None
    options: bool = False
    additionalWitnessPaths: List[str] = field(default_factory=list)
    expected_sw: Optional[StatusWord] = StatusWord.SWO_SUCCESS
    expected_warnings: List[WarningBit] = field(default_factory=list)
    expected_aux_warnings: List[WarningBit] = field(default_factory=list)  # Warnings in auxiliary data (CVote) review
    # TODO: Debug navigation
    unsuitable_in_ragger_reason: Optional[str] = None  # If set, explains why this vector is unsuitable for direct ragger execution
    deny_before_review: bool = False  # For deny tests that fail before review UI is displayed
    tx_streaming: bool = False  # True when the tx body review uses NBGL streaming (multiple chunks)


# pylint: disable=line-too-long
inputs: dict[str, TxInput] = {
    "utxoByron": TxInput(
        "1af8fa0b754ff99253d983894e63a2b09cbb56c833ba18c3384210163f63dcfc",
        "m/44'/1815'/0'/0/0",
    ),
    "utxoByron2": TxInput(
        "3b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7",
        "m/44'/1815'/1'/0/0",
    ),
    "utxoShelley": TxInput(
        "3b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7",
        "m/1852'/1815'/0'/0/0",
    ),
    "utxoShelley2": TxInput(
        "3b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7",
        "m/1852'/1815'/0'/2/1",
    ),
    "utxoShelley3": TxInput(
        "3b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7",
        "m/1852'/1815'/1'/0/0",
    ),
    "utxoNonReasonable": TxInput(
        "3b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7",
        "m/1852'/1815'/456'/0/0",
    ),
    "utxoMultisig": TxInput(
        "3b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7"
    ),
    "utxoNoPath": TxInput(
        "3b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7"
    ),
    "utxoWithPath0": TxInput(
        "3b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7",
        "m/1852'/1815'/0'/0/0",
    ),
}

destinations: dict[str, TxOutputDestination] = {
    "externalByronMainnet": TxOutputDestination(
        TxOutputDestinationType.THIRD_PARTY,
        ThirdPartyAddressParams(
            base58.b58decode(
                "Ae2tdPwUPEZCanmBz5g2GEwFqKTKpNJcGYPKfDxoNeKZ8bRHr8366kseiK2"
            ).hex()
        ),
    ),
    "externalByronDaedalusMainnet": TxOutputDestination(
        TxOutputDestinationType.THIRD_PARTY,
        ThirdPartyAddressParams(
            base58.b58decode(
                "DdzFFzCqrht7HGoJ87gznLktJGywK1LbAJT2sbd4txmgS7FcYLMQFhawb18ojS9Hx55mrbsHPr7PTraKh14TSQbGBPJHbDZ9QVh6Z6Di"
            ).hex()
        ),
    ),
    "externalByronTestnet": TxOutputDestination(
        TxOutputDestinationType.THIRD_PARTY,
        ThirdPartyAddressParams(
            base58.b58decode(
                "2657WMsDfac6Cmfg4Varph2qyLKGi2K9E8jrtvjHVzfSjmbTMGy5sY3HpxCKsmtDA"
            ).hex()
        ),
    ),
    "internalBaseWithStakingPath": TxOutputDestination(
        TxOutputDestinationType.DEVICE_OWNED,
        DeriveAddressTestCase(
            name="",
            netDesc=Mainnet,
            addrType=AddressType.BASE_PAYMENT_KEY_STAKE_KEY,
            spendingValue="m/1852'/1815'/0'/0/0",
            stakingValue="m/1852'/1815'/0'/2/0",
        ),
    ),
    "internalBaseWithStakingKeyHash": TxOutputDestination(
        TxOutputDestinationType.DEVICE_OWNED,
        DeriveAddressTestCase(
            name="",
            netDesc=Mainnet,
            addrType=AddressType.BASE_PAYMENT_KEY_STAKE_KEY,
            spendingValue="m/1852'/1815'/0'/0/0",
            stakingValue="122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277",
        ),
    ),
    "internalEnterprise": TxOutputDestination(
        TxOutputDestinationType.DEVICE_OWNED,
        DeriveAddressTestCase(
            name="",
            netDesc=Mainnet,
            addrType=AddressType.ENTERPRISE_KEY,
            spendingValue="m/1852'/1815'/0'/0/0"
        ),
    ),
    "internalPointer": TxOutputDestination(
        TxOutputDestinationType.DEVICE_OWNED,
        DeriveAddressTestCase(
            name="",
            netDesc=Mainnet,
            addrType=AddressType.POINTER_KEY,
            spendingValue="m/1852'/1815'/0'/0/0",
            stakingValue=pointer_to_str(1, 2, 3),
        ),
    ),
    "internalBaseWithStakingPathNonReasonable": TxOutputDestination(
        TxOutputDestinationType.DEVICE_OWNED,
        DeriveAddressTestCase(
            name="",
            netDesc=Mainnet,
            addrType=AddressType.BASE_PAYMENT_KEY_STAKE_KEY,
            spendingValue="m/1852'/1815'/456'/0/5000000",
            stakingValue="m/1852'/1815'/456'/2/0",
        ),
    ),
    "internalBaseWithStakingPathMap": TxOutputDestination(
        TxOutputDestinationType.DEVICE_OWNED,
        DeriveAddressTestCase(
            name="",
            netDesc=Mainnet,
            addrType=AddressType.BASE_PAYMENT_KEY_STAKE_KEY,
            spendingValue="m/1852'/1815'/0'/0/0",
            stakingValue="m/1852'/1815'/0'/2/0",
        ),
    ),
    "externalShelleyBaseKeyhashKeyhash": TxOutputDestination(
        TxOutputDestinationType.THIRD_PARTY,
        # bech32 addr1q97tqh7wzy8mnx0sr2a57c4ug40zzl222877jz06nt49g4zr43fuq3k0dfpqjh3uvqcsl2qzwuwsvuhclck3scgn3vys6wkj5d
        ThirdPartyAddressParams(
            "017cb05fce110fb999f01abb4f62bc455e217d4a51fde909fa9aea545443ac53c046cf6a42095e3c60310fa802771d0672f8fe2d1861138b09"
        ),
    ),
    "externalShelleyBaseScripthashKeyhash": TxOutputDestination(
        TxOutputDestinationType.THIRD_PARTY,
        # bech32 addr_test1zp0z7zqwhya6mpk5q929ur897g3pp9kkgalpreny8y304rfw6j2jxnwq6enuzvt0lp89wgcsufj7mvcnxpzgkd4hz70qe8ugl4
        ThirdPartyAddressParams(
            "105e2f080eb93bad86d401545e0ce5f2221096d6477e11e6643922fa8d2ed495234dc0d667c1316ff84e572310e265edb31330448b36b7179e"
        ),
    ),
    "externalShelleyBaseScripthashKeyhashMainnet": TxOutputDestination(
        TxOutputDestinationType.THIRD_PARTY,
        # Same payload as externalShelleyBaseScripthashKeyhash, but with Mainnet network id in header nibble.
        ThirdPartyAddressParams(
            "115e2f080eb93bad86d401545e0ce5f2221096d6477e11e6643922fa8d2ed495234dc0d667c1316ff84e572310e265edb31330448b36b7179e"
        ),
    ),
    "externalShelleyBaseScripthashKeyhashFakenet": TxOutputDestination(
        TxOutputDestinationType.THIRD_PARTY,
        # Same address payload as externalShelleyBaseScripthashKeyhash, but with FakeNet network id in header nibble.
        ThirdPartyAddressParams(
            "135e2f080eb93bad86d401545e0ce5f2221096d6477e11e6643922fa8d2ed495234dc0d667c1316ff84e572310e265edb31330448b36b7179e"
        ),
    ),
    "multiassetThirdParty": TxOutputDestination(
        TxOutputDestinationType.THIRD_PARTY,
        # bech32 addr1q84sh2j72ux0l03fxndjnhctdg7hcppsaejafsa84vh7lwgmcs5wgus8qt4atk45lvt4xfxpjtwfhdmvchdf2m3u3hlsd5tq5r
        ThirdPartyAddressParams(
            "01eb0baa5e570cffbe2934db29df0b6a3d7c0430ee65d4c3a7ab2fefb91bc428e4720702ebd5dab4fb175324c192dc9bb76cc5da956e3c8dff"
        ),
    ),
    "trezorParityDatumHash": TxOutputDestination(
        TxOutputDestinationType.THIRD_PARTY,
        # bech32 addr1w9rhu54nz94k9l5v6d9rzfs47h7dv7xffcwkekuxcx3evnqpvuxu0
        ThirdPartyAddressParams(
            "71477e52b3116b62fe8cd34a312615f5fcd678c94e1d6cdb86c1a3964c"
        ),
    ),
    "externalShelleyBaseKeyhashScripthash": TxOutputDestination(
        TxOutputDestinationType.THIRD_PARTY,
        # bech32 addr1yyfatq352yhh7ctw7c3s33qpwrq3pvhcmqg0yvzq9308g9msqj6hs5cg8q8zmtpf2hfrfds25jmcvpta6k5nnpzrn5eqy6fknd
        ThirdPartyAddressParams(
            "2113d58234512f7f616ef62308c40170c110b2f8d810f230402c5e74177004b5785308380e2dac2955d234b60aa4b786057dd5a93984439d32"
        ),
    ),
    "paymentScriptPath": TxOutputDestination(
        TxOutputDestinationType.DEVICE_OWNED,
        DeriveAddressTestCase(
            name="",
            netDesc=Mainnet,
            addrType=AddressType.REWARD_KEY,
            spendingValue="",
            stakingValue="m/1852'/1815'/0'/2/0",
        ),
    ),
    "paymentScriptHash": TxOutputDestination(
        TxOutputDestinationType.DEVICE_OWNED,
        DeriveAddressTestCase(
            name="",
            netDesc=Mainnet,
            addrType=AddressType.REWARD_SCRIPT,
            spendingValue="",
            stakingValue="122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277",
        ),
    ),
    "paymentKeyPath": TxOutputDestination(
        TxOutputDestinationType.DEVICE_OWNED,
        DeriveAddressTestCase(
            name="",
            netDesc=Mainnet,
            addrType=AddressType.REWARD_KEY,
            spendingValue="",
            stakingValue="m/1852'/1815'/0'/2/0",
        ),
    ),
    "deny1": TxOutputDestination(
        TxOutputDestinationType.DEVICE_OWNED,
        DeriveAddressTestCase(
            name="",
            netDesc=Mainnet,
            addrType=AddressType.BASE_PAYMENT_SCRIPT_STAKE_KEY,
            spendingValue="29fb5fd4aa8cadd6705acc8263cee0fc62edca5ac38db593fec2f9fd",
            stakingValue="122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277",
        ),
    ),
    "deny2": TxOutputDestination(
        TxOutputDestinationType.DEVICE_OWNED,
        DeriveAddressTestCase(
            name="",
            netDesc=Mainnet,
            addrType=AddressType.BASE_PAYMENT_SCRIPT_STAKE_SCRIPT,
            spendingValue="29fb5fd4aa8cadd6705acc8263cee0fc62edca5ac38db593fec2f9fd",
            stakingValue="122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277",
        ),
    ),
    "deny3": TxOutputDestination(
        TxOutputDestinationType.DEVICE_OWNED,
        DeriveAddressTestCase(
            name="",
            netDesc=Mainnet,
            addrType=AddressType.BASE_PAYMENT_SCRIPT_STAKE_KEY,
            spendingValue="29fb5fd4aa8cadd6705acc8263cee0fc62edca5ac38db593fec2f9fd",
            stakingValue="m/1852'/1815'/456'/2/0",
        ),
    ),
    "deny4": TxOutputDestination(
        TxOutputDestinationType.DEVICE_OWNED,
        DeriveAddressTestCase(
            name="",
            netDesc=Mainnet,
            addrType=AddressType.BASE_PAYMENT_KEY_STAKE_KEY,
            spendingValue="m/1852'/1815'/1'/0/0",
            stakingValue="m/1852'/1815'/0'/2/0",
        ),
    ),
    "deny5": TxOutputDestination(
        TxOutputDestinationType.DEVICE_OWNED,
        DeriveAddressTestCase(
            name="",
            netDesc=Mainnet,
            addrType=AddressType.BASE_PAYMENT_KEY_STAKE_KEY,
            spendingValue="m/1852'/1815'/1'/0/0",
            stakingValue="m/1852'/1815'/1'/2/0",
        ),
    ),
}

outputs: dict[str, TxOutput] = {
    "externalByronMainnet": TxOutputAlonzo(
        destinations["externalByronMainnet"], 3003112
    ),
    "externalByronDaedalusMainnet": TxOutputAlonzo(
        destinations["externalByronDaedalusMainnet"], 3003112
    ),
    "externalByronTestnet": TxOutputAlonzo(
        destinations["externalByronTestnet"], 3003112
    ),
    "internalBaseWithStakingPath": TxOutputAlonzo(
        destinations["internalBaseWithStakingPath"], 7120787
    ),
    "internalBaseWithStakingPathBabbage": TxOutputBabbage(
        destinations["internalBaseWithStakingPath"], 7120787
    ),
    "internalBaseWithStakingKeyHash": TxOutputAlonzo(
        destinations["internalBaseWithStakingKeyHash"], 7120787
    ),
    "internalEnterprise": TxOutputAlonzo(destinations["internalEnterprise"], 7120787),
    "internalPointer": TxOutputAlonzo(destinations["internalPointer"], 7120787),
    "internalBaseWithStakingPathNonReasonable": TxOutputAlonzo(
        destinations["internalBaseWithStakingPathNonReasonable"], 7120787
    ),
    "internalBaseWithStakingPathMap": TxOutputBabbage(
        destinations["internalBaseWithStakingPathMap"], 7120787
    ),
    "externalShelleyBaseKeyhashKeyhash": TxOutputAlonzo(
        destinations["externalShelleyBaseKeyhashKeyhash"], 1
    ),
    "externalShelleyBaseScripthashKeyhash": TxOutputAlonzo(
        destinations["externalShelleyBaseScripthashKeyhash"], 1
    ),
    "multiassetOneToken": TxOutputAlonzo(
        destinations["multiassetThirdParty"],
        1234,
        tokenBundle=[
            AssetGroup(
                "95a292ffee938be03e9bae5657982a74e9014eb4960108c9e23a5b39",
                [Token("74652474436f696e", 7878754)],
            )
        ],
    ),
    "multiassetManyTokens": TxOutputAlonzo(
        destinations["multiassetThirdParty"],
        1234,
        # fingerprints taken from CIP 14 draft
        tokenBundle=[
            AssetGroup(
                "7eae28af2208be856f7a119668ae52a49b73725e326dc16579dcc373",
                # fingerprint: asset1rjklcrnsdzqp65wjgrg55sy9723kw09mlgvlc3
                [
                    Token("", 3),
                    # fingerprint: asset17jd78wukhtrnmjh3fngzasxm8rck0l2r4hhyyt
                    Token(
                        "1e349c9bdea19fd6c147626a5260bc44b71635f398b67c59881df209", 1
                    ),
                    # fingerprint: asset1pkpwyknlvul7az0xx8czhl60pyel45rpje4z8w
                    Token(
                        "0000000000000000000000000000000000000000000000000000000000000000",
                        2,
                    ),
                ],
            ),
            AssetGroup(
                "95a292ffee938be03e9bae5657982a74e9014eb4960108c9e23a5b39",
                [Token("456c204e69c3b16f", 1234), Token("74652474436f696e", 7878754)],
            ),
        ],
    ),
    "multiassetManyTokensBabbage": TxOutputBabbage(
        destinations["multiassetThirdParty"],
        1234,
        # fingerprints taken from CIP 14 draft
        tokenBundle=[
            AssetGroup(
                "7eae28af2208be856f7a119668ae52a49b73725e326dc16579dcc373",
                # fingerprint: asset1rjklcrnsdzqp65wjgrg55sy9723kw09mlgvlc3
                [
                    Token("", 3),
                    # fingerprint: asset17jd78wukhtrnmjh3fngzasxm8rck0l2r4hhyyt
                    Token(
                        "1e349c9bdea19fd6c147626a5260bc44b71635f398b67c59881df209", 1
                    ),
                    # fingerprint: asset1pkpwyknlvul7az0xx8czhl60pyel45rpje4z8w
                    Token(
                        "0000000000000000000000000000000000000000000000000000000000000000",
                        2,
                    ),
                ],
            ),
            AssetGroup(
                "95a292ffee938be03e9bae5657982a74e9014eb4960108c9e23a5b39",
                [Token("456c204e69c3b16f", 1234), Token("74652474436f696e", 7878754)],
            ),
        ],
    ),
    "multiassetBigNumber": TxOutputAlonzo(
        destinations["multiassetThirdParty"],
        24103998870869519,
        tokenBundle=[
            AssetGroup(
                "95a292ffee938be03e9bae5657982a74e9014eb4960108c9e23a5b39",
                [Token("74652474436f696e", 24103998870869519)],
            )
        ],
    ),
    "multiassetChange": TxOutputAlonzo(
        destinations["internalBaseWithStakingPath"],
        1234,
        tokenBundle=[
            AssetGroup(
                "95a292ffee938be03e9bae5657982a74e9014eb4960108c9e23a5b39",
                [Token("74652474436f696e", 7878754)],
            )
        ],
    ),
    "multiassetDecimalPlaces": TxOutputAlonzo(
        destinations["multiassetThirdParty"],
        1234,
        # fingerprint: asset155nxgqj5acff7fdhc8ranfwyl7nq4ljrks7l6w
        tokenBundle=[
            AssetGroup(
                "6954264b15bc92d6d592febeac84f14645e1ed46ca5ebb9acdb5c15f",
                [Token("5354524950", 3456789)],
            ),
            AssetGroup(
                "af2e27f580f7f08e93190a81f72462f153026d06450924726645891b",
                # fingerprint: asset14yqf3pclzx88jjahydyfad8pxw5xhuca6j7k2p
                [
                    Token("44524950", 1234),
                    # fingerprint: asset12wejgxu04lpg6h3pm056qd207k2sfh7yjklclf
                    Token("ffffffffffffffffffffffff", 1234),
                ],
            ),
        ],
    ),
    "trezorParity1": TxOutputAlonzo(
        destinations["multiassetThirdParty"],
        2000000,
        tokenBundle=[
            AssetGroup(
                "0d63e8d2c5a00cbcffbdf9112487c443466e1ea7d8c834df5ac5c425",
                [Token("74657374436f696e", 7878754)],
            )
        ],
    ),
    "trezorParity2": TxOutputAlonzo(
        destinations["externalShelleyBaseKeyhashKeyhash"],
        2000000,
        tokenBundle=[
            AssetGroup(
                "0d63e8d2c5a00cbcffbdf9112487c443466e1ea7d8c834df5ac5c425",
                [Token("74657374436f696e", 7878754)],
            )
        ],
    ),
    "trezorParityDatumHash1": TxOutputAlonzo(
        destinations["trezorParityDatumHash"],
        1,
        datum=Datum(
            DatumType.HASH,
            "3b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7",
        ),
    ),
    "trezorParityDatumHash2": TxOutputAlonzo(
        destinations["trezorParityDatumHash"],
        1,
        datum=Datum(
            DatumType.HASH,
            "3b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7",
        ),
    ),
    "trezorParityBabbageOutputs": TxOutputBabbage(
        destinations["trezorParityDatumHash"],
        1,
        datum=Datum(DatumType.INLINE, "5579657420616e6f746865722063686f636f6c617465"),
        referenceScriptHex="0080f9e2c88e6c817008f3a812ed889b4a4da8e0bd103f86e7335422aa122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277",
    ),
    "datumHashExternal": TxOutputAlonzo(
        destinations["externalShelleyBaseScripthashKeyhash"],
        7120787,
        datum=Datum(
            DatumType.HASH,
            "ffd4d009f554ba4fd8ed1f1d703244819861a9d34fd4753bcf3ff32f043ce188",
        ),
    ),
    "datumHashExternalFakenet": TxOutputAlonzo(
        destinations["externalShelleyBaseScripthashKeyhashFakenet"],
        7120787,
        datum=Datum(
            DatumType.HASH,
            "ffd4d009f554ba4fd8ed1f1d703244819861a9d34fd4753bcf3ff32f043ce188",
        ),
    ),
    "datumHashExternalMainnet": TxOutputAlonzo(
        destinations["externalShelleyBaseScripthashKeyhashMainnet"],
        7120787,
        datum=Datum(
            DatumType.HASH,
            "ffd4d009f554ba4fd8ed1f1d703244819861a9d34fd4753bcf3ff32f043ce188",
        ),
    ),
    "datumHashWithTokens": TxOutputAlonzo(
        destinations["externalShelleyBaseScripthashKeyhash"],
        7120787,
        datum=Datum(
            DatumType.HASH,
            "ffd4d009f554ba4fd8ed1f1d703244819861a9d34fd4753bcf3ff32f043ce188",
        ),
        tokenBundle=[
            AssetGroup(
                "75a292ffee938be03e9bae5657982a74e9014eb4960108c9e23a5b39",
                [Token("7564247542686911", 47), Token("7564247542686912", 7878754)],
            )
        ],
    ),
    "datumHashWithTokensMap": TxOutputBabbage(
        destinations["externalShelleyBaseScripthashKeyhash"],
        7120787,
        datum=Datum(
            DatumType.HASH,
            "ffd4d009f554ba4fd8ed1f1d703244819861a9d34fd4753bcf3ff32f043ce188",
        ),
        tokenBundle=[
            AssetGroup(
                "75a292ffee938be03e9bae5657982a74e9014eb4960108c9e23a5b39",
                [Token("7564247542686911", 47), Token("7564247542686912", 7878754)],
            )
        ],
    ),
    "missingDatumHashWithTokens": TxOutputAlonzo(
        destinations["externalShelleyBaseScripthashKeyhash"],
        7120787,
        tokenBundle=[
            AssetGroup(
                "75a292ffee938be03e9bae5657982a74e9014eb4960108c9e23a5b39",
                [Token("7564247542686911", 47), Token("7564247542686912", 7878754)],
            )
        ],
    ),
    "inlineDatumWithTokensMap": TxOutputBabbage(
        destinations["externalShelleyBaseScripthashKeyhash"],
        7120787,
        datum=Datum(DatumType.INLINE, "5579657420616e6f746865722063686f636f6c617465"),
        tokenBundle=[
            AssetGroup(
                "75a292ffee938be03e9bae5657982a74e9014eb4960108c9e23a5b39",
                [Token("7564247542686911", 47), Token("7564247542686912", 7878754)],
            )
        ],
    ),
    "inlineDatum480Map": TxOutputBabbage(
        destinations["externalShelleyBaseScripthashKeyhash"],
        7120787,
        datum=Datum(
            DatumType.INLINE,
            "12b8240c5470b47c159597b6f71d78c7fc99d1d8d911cb19b8f50211938ef361a22d30cd8f6354ec50e99a7d3cf3e06797ed4af3d358e01b2a957caa4010da328720b9fbe7a3a6d10209a13d2eb11933eb1bf2ab02713117e421b6dcc66297c41b95ad32d3457a0e6b44d8482385f311465964c3daff226acfb7bbda47011f1a6531db30e5b5977143c48f8b8eb739487f87dc13896f58529cfb48e415fc6123e708cdc3cb15cc1900ecf88c5fc9ff66d8ad6dae18c79e4a3c392a0df4d16ffa3e370f4dad8d8e9d171c5656bb317c78a2711057e7ae0beb1dc66ba01aa69d0c0db244e6742d7758ce8da00dfed6225d4aed4b01c42a0352688ed5803f3fd64873f11355305d9db309f4a2a6673cc408a06b8827a5edef7b0fd8742627fb8aa102a084b7db72fcb5c3d1bf437e2a936b738902a9c0258b462b9f2e9befd2c6bcfc036143bb34342b9124888a5b29fa5d60909c81319f034c11542b05ca3ff6c64c7642ff1e2b25fb60dc9bb6f5c914dd4149f31896955d4d204d822deddc46f852115a479edf7521cdf4ce596805875011855158fd303c33a2a7916a9cb7acaaf5aeca7e6efb75960e9597cd845bd9a93610bf1ab47ab0de943e8a96e26a24c4996f7b07fad437829fee5bc3496192608d4c04ac642cdec7bdbb8a948ad1d434",
        ),
    ),
    "inlineDatum304WithTokensMap": TxOutputBabbage(
        destinations["externalShelleyBaseScripthashKeyhash"],
        7120787,
        datum=Datum(
            DatumType.INLINE,
            "5579657420616e6f746865722063686f636f6c6174655579657420616e6f746865722063686f636f6c6174655579657420616e6f746865722063686f636f6c6174655579657420616e6f746865722063686f636f6c6174655579657420616e6f746865722063686f636f6c6174655579657420616e6f746865722063686f636f6c6174655579657420616e6f746865722063686f636f6c6174655579657420616e6f746865722063686f636f6c6174655579657420616e6f746865722063686f636f6c6174655579657420616e6f746865722063686f636f6c6174655579657420616e6f746865722063686f636f6c6174655579657420616e6f746865722063686f636f6c6174655579657420616e6f746865722063686f636f6c6174655579657420616e6f74686572206374686572",
        ),
        tokenBundle=[
            AssetGroup(
                "75a292ffee938be03e9bae5657982a74e9014eb4960108c9e23a5b39",
                [Token("7564247542686911", 47), Token("7564247542686912", 7878754)],
            )
        ],
    ),
    "datumHashExternalMap": TxOutputBabbage(
        destinations["externalShelleyBaseScripthashKeyhash"],
        7120787,
        datum=Datum(
            DatumType.HASH,
            "ffd4d009f554ba4fd8ed1f1d703244819861a9d34fd4753bcf3ff32f043ce188",
        ),
    ),
    "refScriptExternalMap": TxOutputBabbage(
        destinations["externalShelleyBaseScripthashKeyhash"],
        7120787,
        referenceScriptHex="deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
    ),
    "datumHashRefScriptExternalMap": TxOutputBabbage(
        destinations["externalShelleyBaseScripthashKeyhash"],
        7120787,
        datum=Datum(
            DatumType.HASH,
            "ffd4d009f554ba4fd8ed1f1d703244819861a9d34fd4753bcf3ff32f043ce188",
        ),
        referenceScriptHex="deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
    ),
    "datumHashRefScript240ExternalMap": TxOutputBabbage(
        destinations["externalShelleyBaseScripthashKeyhash"],
        7120787,
        datum=Datum(
            DatumType.HASH,
            "ffd4d009f554ba4fd8ed1f1d703244819861a9d34fd4753bcf3ff32f043ce188",
        ),
        referenceScriptHex="4784392787cc567ac21d7b5346a4a89ae112b7ff7610e402284042aa4e6efca7956a53c3f5cb3ec6745f5e21150f2a77bd71a2adc3f8b9539e9bab41934b477f60a8b302584d1a619ed9b178b5ce6fcad31adc0d6fc17023ede474c09f29fdbfb290a5b30b5240fae5de71168036201772c0d272ae90220181f9bf8c3198e79fc2ae32b076abf4d0e10d3166923ce56994b25c00909e3faab8ef1358c136cd3b197488efc883a7c6cfa3ac63ca9cebc62121c6e22f594420c2abd54e78282adec20ee7dba0e6de65554adb8ee8314f23f86cf7cf0906d4b6c643966baf6c54240c19f4131374e298f38a626a4ad63e61",
    ),
    "datumHashRefScript304ExternalMap": TxOutputBabbage(
        destinations["externalShelleyBaseScripthashKeyhash"],
        7120787,
        datum=Datum(
            DatumType.HASH,
            "ffd4d009f554ba4fd8ed1f1d703244819861a9d34fd4753bcf3ff32f043ce188",
        ),
        referenceScriptHex="deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeaddeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeaddeadbeef",
    ),
    "internalBaseWithTokensMap": TxOutputBabbage(
        destinations["internalBaseWithStakingPath"],
        7120787,
        tokenBundle=[
            AssetGroup(
                "75a292ffee938be03e9bae5657982a74e9014eb4960108c9e23a5b39",
                [Token("7564247542686911", 47)],
            )
        ],
    ),
    "multiassetInvalidAssetGroupOrdering": TxOutputBabbage(
        destinations["multiassetThirdParty"],
        1234,
        tokenBundle=[
            AssetGroup(
                "75a292ffee938be03e9bae5657982a74e9014eb4960108c9e23a5b39",
                [Token("7564247542686911", 47)],
            ),
            AssetGroup(
                "71a292ffee938be03e9bae5657982a74e9014eb4960108c9e23a5b39",
                [Token("7564247542686911", 47)],
            ),
        ],
    ),
    "multiassetAssetGroupsNotUnique": TxOutputBabbage(
        destinations["multiassetThirdParty"],
        1234,
        tokenBundle=[
            AssetGroup(
                "75a292ffee938be03e9bae5657982a74e9014eb4960108c9e23a5b39",
                [Token("7564247542686911", 47)],
            ),
            AssetGroup(
                "75a292ffee938be03e9bae5657982a74e9014eb4960108c9e23a5b39",
                [Token("7564247542686911", 47)],
            ),
        ],
    ),
    "multiassetInvalidTokenOrderingSameLength": TxOutputBabbage(
        destinations["multiassetThirdParty"],
        1234,
        tokenBundle=[
            AssetGroup(
                "75a292ffee938be03e9bae5657982a74e9014eb4960108c9e23a5b39",
                [Token("7564247542686911", 47), Token("74652474436f696e", 7878754)],
            )
        ],
    ),
    "multiassetInvalidTokenOrderingDifferentLengths": TxOutputBabbage(
        destinations["multiassetThirdParty"],
        1234,
        tokenBundle=[
            AssetGroup(
                "75a292ffee938be03e9bae5657982a74e9014eb4960108c9e23a5b39",
                [Token("7564247542686911", 47), Token("756424754268", 7878754)],
            )
        ],
    ),
    "multiassetTokensNotUnique": TxOutputBabbage(
        destinations["multiassetThirdParty"],
        1234,
        tokenBundle=[
            AssetGroup(
                "75a292ffee938be03e9bae5657982a74e9014eb4960108c9e23a5b39",
                [Token("7564247542686911", 47), Token("7564247542686911", 7878754)],
            )
        ],
    ),
    # Inline outputs that appear frequently - extracted for deduplication
    "inlineByronMainnet3003112": TxOutputAlonzo(
        destination=TxOutputDestination(
            type=TxOutputDestinationType.THIRD_PARTY,
            params=ThirdPartyAddressParams(
                addressHex="82d818582183581c9e1c71de652ec8b85fec296f0685ca3988781c94a2e1a5d89d92f45fa0001a0d0c2561"
            ),
        ),
        amount=3003112,
        format=TxOutputFormat.ARRAY_LEGACY,
        tokenBundle=[],
        datum=None,
    ),
    "inlineShelleyBase1": TxOutputAlonzo(
        destination=TxOutputDestination(
            type=TxOutputDestinationType.THIRD_PARTY,
            params=ThirdPartyAddressParams(
                addressHex="017cb05fce110fb999f01abb4f62bc455e217d4a51fde909fa9aea545443ac53c046cf6a42095e3c60310fa802771d0672f8fe2d1861138b09"
            ),
        ),
        amount=1,
        format=TxOutputFormat.ARRAY_LEGACY,
        tokenBundle=[],
        datum=None,
    ),
    "inlineShelleyBase1v2": TxOutputAlonzo(
        destination=TxOutputDestination(
            type=TxOutputDestinationType.THIRD_PARTY,
            params=ThirdPartyAddressParams(
                addressHex="01eb0baa5e570cffbe2934db29df0b6a3d7c0430ee65d4c3a7ab2fefb91bc428e4720702ebd5dab4fb175324c192dc9bb76cc5da956e3c8dff"
            ),
        ),
        amount=1,
        format=TxOutputFormat.ARRAY_LEGACY,
        tokenBundle=[],
        datum=None,
    ),
    "inlineShelleyBase1234": TxOutputAlonzo(
        destination=TxOutputDestination(
            type=TxOutputDestinationType.THIRD_PARTY,
            params=ThirdPartyAddressParams(
                addressHex="01eb0baa5e570cffbe2934db29df0b6a3d7c0430ee65d4c3a7ab2fefb91bc428e4720702ebd5dab4fb175324c192dc9bb76cc5da956e3c8dff"
            ),
        ),
        amount=1234,
        format=TxOutputFormat.ARRAY_LEGACY,
        tokenBundle=[],
        datum=None,
    ),
}

mints: dict[str, List[AssetGroup]] = {
    "mintWithDecimalPlaces": [
        AssetGroup(
            "6954264b15bc92d6d592febeac84f14645e1ed46ca5ebb9acdb5c15f",
            # fingerprint: asset155nxgqj5acff7fdhc8ranfwyl7nq4ljrks7l6w
            [Token("5354524950", -3456789)],
        ),
        AssetGroup(
            "af2e27f580f7f08e93190a81f72462f153026d06450924726645891b",
            # fingerprint: asset14yqf3pclzx88jjahydyfad8pxw5xhuca6j7k2p
            [
                Token("44524950", 1234),
                # fingerprint: asset12wejgxu04lpg6h3pm056qd207k2sfh7yjklclf
                Token("ffffffffffffffffffffffff", 1234),
            ],
        ),
    ],
    # fingerprints taken from CIP 14 draft
    "mintAmountVariety": [
        AssetGroup(
            "7eae28af2208be856f7a119668ae52a49b73725e326dc16579dcc373",
            [
                # fingerprint: asset17jd78wukhtrnmjh3fngzasxm8rck0l2r4hhyyt
                Token("1e349c9bdea19fd6c147626a5260bc44b71635f398b67c59881df209", -1),
                # fingerprint: asset17jd78wukhtrnmjh3fngzasxm8rck0l2r4hhyyt (and incremented)
                Token(
                    "1e349c9bdea19fd6c147626a5260bc44b71635f398b67c59881df20a",
                    9223372036854775807,
                ),
                # fingerprint: asset17jd78wukhtrnmjh3fngzasxm8rck0l2r4hhyyt (and incremented)
                Token(
                    "1e349c9bdea19fd6c147626a5260bc44b71635f398b67c59881df20b",
                    -9223372036854775808,
                ),
            ],
        )
    ],
    "trezorComparison": [
        AssetGroup(
            "0d63e8d2c5a00cbcffbdf9112487c443466e1ea7d8c834df5ac5c425",
            [Token("74657374436f696e", 7878754), Token("75657374436f696e", -7878754)],
        )
    ],
    "deny": [
        AssetGroup(
            "0d63e8d2c5a00cbcffbdf9112487c443466e1ea7d8c834df5ac5c425",
            [Token("75657374436f696e", -7878754)],
        )
    ],
    # fingerprints taken from CIP 14 draft (and incremented)
    "mintInvalidCanonicalOrderingPolicy": [
        AssetGroup(
            "7eae28af2208be856f7a119668ae52a49b73725e326dc16579dcc374",
            # fingerprint: asset1rjklcrnsdzqp65wjgrg55sy9723kw09mlgvlc3
            [
                Token("", 0),
                # fingerprint: asset17jd78wukhtrnmjh3fngzasxm8rck0l2r4hhyyt
                Token("1e349c9bdea19fd6c147626a5260bc44b71635f398b67c59881df209", -1),
            ],
        ),
        # fingerprints taken from CIP 14 draft
        AssetGroup(
            "7eae28af2208be856f7a119668ae52a49b73725e326dc16579dcc373",
            # fingerprint: asset1rjklcrnsdzqp65wjgrg55sy9723kw09mlgvlc3
            [Token("", 0)],
        ),
    ],
    # fingerprints taken from CIP 14 draft (and incremented)
    "mintInvalidCanonicalOrderingAssetName": [
        AssetGroup(
            "7eae28af2208be856f7a119668ae52a49b73725e326dc16579dcc374",
            # fingerprint: asset1rjklcrnsdzqp65wjgrg55sy9723kw09mlgvlc3
            [
                Token("1e349c9bdea19fd6c147626a5260bc44b71635f398b67c59881df209", -1),
                # fingerprint: asset17jd78wukhtrnmjh3fngzasxm8rck0l2r4hhyyt
                Token("", 0),
            ],
        )
    ],
}

poolKeys: dict[str, PoolKey] = {
    "default": PoolKey(PoolKeyType.DEVICE_OWNED, "m/1852'/1815'/0'/0/0"),
    "default1": PoolKey(
        PoolKeyType.THIRD_PARTY,
        "01234567890123456789012345678901234567890123456789012345",
    ),
    "default3": PoolKey(
        PoolKeyType.THIRD_PARTY,
        "f123456789012345678901234567890123456789012345678901234567",
    ),
    "poolKeyPath": PoolKey(PoolKeyType.DEVICE_OWNED, "m/1853'/1815'/0'/0'"),
    "poolKeyHash": PoolKey(
        PoolKeyType.THIRD_PARTY,
        "13381d918ec0283ceeff60f7f4fc21e1540e053ccf8a77307a7a32ad",
    ),
    "poolRewardAccountPath": PoolKey(PoolKeyType.DEVICE_OWNED, "m/1852'/1815'/3'/2/0"),
    "poolRewardAccountHash": PoolKey(
        PoolKeyType.THIRD_PARTY,
        "e1794d9b3408c9fb67b950a48a0690f070f117e9978f7fc1d120fc58ad",
    ),
    "stakingPathOwner0": PoolKey(PoolKeyType.DEVICE_OWNED, "m/1852'/1815'/0'/2/0"),
    "stakingPathOwner1": PoolKey(PoolKeyType.DEVICE_OWNED, "m/1852'/1815'/0'/2/1"),
    "stakingHashOwner0": PoolKey(
        PoolKeyType.THIRD_PARTY,
        "794d9b3408c9fb67b950a48a0690f070f117e9978f7fc1d120fc58ad",
    ),
    "stakingHashOwner1": PoolKey(
        PoolKeyType.THIRD_PARTY,
        "0bd5d796f5e54866a14300ec2a18d706f7461b8f0502cc2a182bc88d",
    ),
    "twoCombinedOwners": PoolKey(PoolKeyType.DEVICE_OWNED, "m/1852'/1815'/0'/2/0"),
}

relays: dict[str, Relay] = {
    "singleHostIPV4Relay0": Relay(
        RelayType.SINGLE_HOST_IP_ADDR,
        SingleHostIpAddrRelayParams(3000, "54.228.75.154"),
    ),
    "singleHostIPV4Relay1": Relay(
        RelayType.SINGLE_HOST_IP_ADDR,
        SingleHostIpAddrRelayParams(4000, "54.228.75.154"),
    ),
    "singleHostIPV6Relay": Relay(
        RelayType.SINGLE_HOST_IP_ADDR,
        SingleHostIpAddrRelayParams(
            3000, "54.228.75.155", "24ff:7801:33a2:e383:a5c4:340a:07c2:76e5"
        ),
    ),
    "singleHostNameRelay": Relay(
        RelayType.SINGLE_HOST_HOSTNAME,
        SingleHostHostnameRelayParams(3000, "aaaa.bbbb.com"),
    ),
    "multiHostNameRelay": Relay(
        RelayType.MULTI_HOST, MultiHostRelayParams("aaaa.bbbc.com")
    ),
}

certificates: dict[str, Certificate] = {
    "poolRegistrationDefault": Certificate(
        CertificateType.STAKE_POOL_REGISTRATION,
        PoolRegistrationParams(
            poolKeys["poolKeyHash"],
            "07821cd344d7fd7e3ae5f2ed863218cb979ff1d59e50c4276bdc479b0d084450",
            50000000000,
            340000000,
            Margin(3, 100),
            poolKeys["poolRewardAccountHash"],
            [poolKeys["stakingPathOwner0"]],
            [relays["singleHostIPV4Relay0"]],
            PoolMetadataParams(
                "https://www.vacuumlabs.com/sampleUrl.json",
                "cdb714fd722c24aeb10c93dbb0ff03bd4783441cd5ba2a8b6f373390520535bb",
            ),
        ),
    ),
    "poolRegistrationMixedOwners": Certificate(
        CertificateType.STAKE_POOL_REGISTRATION,
        PoolRegistrationParams(
            poolKeys["poolKeyHash"],
            "07821cd344d7fd7e3ae5f2ed863218cb979ff1d59e50c4276bdc479b0d084450",
            50000000000,
            340000000,
            Margin(3, 100),
            poolKeys["poolRewardAccountHash"],
            [poolKeys["stakingPathOwner0"], poolKeys["stakingHashOwner0"]],
            [relays["singleHostIPV4Relay0"]],
            PoolMetadataParams(
                "https://www.vacuumlabs.com/sampleUrl.json",
                "cdb714fd722c24aeb10c93dbb0ff03bd4783441cd5ba2a8b6f373390520535bb",
            ),
        ),
    ),
    "poolRegistrationMixedOwnersAllRelays": Certificate(
        CertificateType.STAKE_POOL_REGISTRATION,
        PoolRegistrationParams(
            poolKeys["poolKeyHash"],
            "07821cd344d7fd7e3ae5f2ed863218cb979ff1d59e50c4276bdc479b0d084450",
            50000000000,
            340000000,
            Margin(3, 100),
            poolKeys["poolRewardAccountHash"],
            [poolKeys["stakingPathOwner0"], poolKeys["stakingHashOwner0"]],
            [
                relays["singleHostIPV4Relay0"],
                relays["singleHostIPV6Relay"],
                relays["singleHostNameRelay"],
                relays["multiHostNameRelay"],
            ],
            PoolMetadataParams(
                "https://www.vacuumlabs.com/sampleUrl.json",
                "cdb714fd722c24aeb10c93dbb0ff03bd4783441cd5ba2a8b6f373390520535bb",
            ),
        ),
    ),
    "poolRegistrationMixedOwnersIpv4SingleHostRelays": Certificate(
        CertificateType.STAKE_POOL_REGISTRATION,
        PoolRegistrationParams(
            poolKeys["poolKeyHash"],
            "07821cd344d7fd7e3ae5f2ed863218cb979ff1d59e50c4276bdc479b0d084450",
            50000000000,
            340000000,
            Margin(3, 100),
            poolKeys["poolRewardAccountHash"],
            [poolKeys["stakingPathOwner0"], poolKeys["stakingHashOwner0"]],
            [relays["singleHostIPV4Relay0"], relays["singleHostNameRelay"]],
            PoolMetadataParams(
                "https://www.vacuumlabs.com/sampleUrl.json",
                "cdb714fd722c24aeb10c93dbb0ff03bd4783441cd5ba2a8b6f373390520535bb",
            ),
        ),
    ),
    "poolRegistrationMixedOwnersIpv4Ipv6Relays": Certificate(
        CertificateType.STAKE_POOL_REGISTRATION,
        PoolRegistrationParams(
            poolKeys["poolKeyHash"],
            "07821cd344d7fd7e3ae5f2ed863218cb979ff1d59e50c4276bdc479b0d084450",
            50000000000,
            340000000,
            Margin(3, 100),
            poolKeys["poolRewardAccountHash"],
            [poolKeys["stakingPathOwner0"], poolKeys["stakingHashOwner0"]],
            [relays["singleHostIPV4Relay1"], relays["singleHostIPV6Relay"]],
            PoolMetadataParams(
                "https://www.vacuumlabs.com/sampleUrl.json",
                "cdb714fd722c24aeb10c93dbb0ff03bd4783441cd5ba2a8b6f373390520535bb",
            ),
        ),
    ),
    "poolRegistrationNoRelays": Certificate(
        CertificateType.STAKE_POOL_REGISTRATION,
        PoolRegistrationParams(
            poolKeys["poolKeyHash"],
            "07821cd344d7fd7e3ae5f2ed863218cb979ff1d59e50c4276bdc479b0d084450",
            50000000000,
            340000000,
            Margin(3, 100),
            poolKeys["poolRewardAccountHash"],
            [poolKeys["stakingPathOwner0"]],
            [],
            PoolMetadataParams(
                "https://www.vacuumlabs.com/sampleUrl.json",
                "cdb714fd722c24aeb10c93dbb0ff03bd4783441cd5ba2a8b6f373390520535bb",
            ),
        ),
    ),
    "poolRegistrationNoMetadata": Certificate(
        CertificateType.STAKE_POOL_REGISTRATION,
        PoolRegistrationParams(
            poolKeys["poolKeyHash"],
            "07821cd344d7fd7e3ae5f2ed863218cb979ff1d59e50c4276bdc479b0d084450",
            50000000000,
            340000000,
            Margin(3, 100),
            poolKeys["poolRewardAccountHash"],
            [poolKeys["stakingPathOwner0"]],
            [relays["singleHostIPV4Relay0"]],
        ),
    ),
    "poolRegistrationOperatorNoOwnersNoRelays": Certificate(
        CertificateType.STAKE_POOL_REGISTRATION,
        PoolRegistrationParams(
            poolKeys["poolKeyPath"],
            "07821cd344d7fd7e3ae5f2ed863218cb979ff1d59e50c4276bdc479b0d084450",
            50000000000,
            340000000,
            Margin(3, 100),
            poolKeys["poolRewardAccountHash"],
            [],
            [],
            PoolMetadataParams(
                "https://www.vacuumlabs.com/sampleUrl.json",
                "cdb714fd722c24aeb10c93dbb0ff03bd4783441cd5ba2a8b6f373390520535bb",
            ),
        ),
    ),
    "poolRegistrationOperatorOneOwnerOperatorNoRelays": Certificate(
        CertificateType.STAKE_POOL_REGISTRATION,
        PoolRegistrationParams(
            poolKeys["poolKeyPath"],
            "07821cd344d7fd7e3ae5f2ed863218cb979ff1d59e50c4276bdc479b0d084450",
            50000000000,
            340000000,
            Margin(3, 100),
            poolKeys["poolRewardAccountPath"],
            [poolKeys["stakingHashOwner0"]],
            [],
            PoolMetadataParams(
                "https://www.vacuumlabs.com/sampleUrl.json",
                "cdb714fd722c24aeb10c93dbb0ff03bd4783441cd5ba2a8b6f373390520535bb",
            ),
        ),
    ),
    "poolRegistrationOperatorMultipleOwnersAllRelays": Certificate(
        CertificateType.STAKE_POOL_REGISTRATION,
        PoolRegistrationParams(
            poolKeys["poolKeyPath"],
            "07821cd344d7fd7e3ae5f2ed863218cb979ff1d59e50c4276bdc479b0d084450",
            50000000000,
            340000000,
            Margin(3, 100),
            poolKeys["poolRewardAccountHash"],
            [poolKeys["stakingHashOwner0"], poolKeys["stakingHashOwner1"]],
            [
                relays["singleHostIPV4Relay0"],
                relays["singleHostIPV6Relay"],
                relays["singleHostNameRelay"],
                relays["multiHostNameRelay"],
            ],
            PoolMetadataParams(
                "https://www.vacuumlabs.com/sampleUrl.json",
                "cdb714fd722c24aeb10c93dbb0ff03bd4783441cd5ba2a8b6f373390520535bb",
            ),
        ),
    ),
    "poolRegParamOperator": Certificate(
        CertificateType.STAKE_POOL_REGISTRATION,
        PoolRegistrationParams(
            poolKeys["default"],
            "0123456789012345678901234567890123456789012345678901234567890123",
            0,
            0,
            Margin(0, 1),
            poolKeys["default3"],
            [],
            [],
        ),
    ),
    "poolRegParamOwner": Certificate(
        CertificateType.STAKE_POOL_REGISTRATION,
        PoolRegistrationParams(
            poolKeys["default1"],
            "0123456789012345678901234567890123456789012345678901234567890123",
            0,
            0,
            Margin(0, 1),
            poolKeys["default3"],
            [poolKeys["stakingPathOwner0"]],
            [],
        ),
    ),
    "poolRetirementParam": Certificate(
        CertificateType.STAKE_POOL_RETIREMENT,
        PoolRetirementParams(
            CredentialParams(CredentialParamsType.KEY_PATH, "m/1853'/1815'/0'/1'"), 42
        ),
    ),
    "stakeRegistrationPathParam": Certificate(
        CertificateType.STAKE_REGISTRATION,
        StakeRegistrationParams(
            CredentialParams(CredentialParamsType.KEY_PATH, "m/1852'/1815'/0'/2/0")
        ),
    ),
    "stakeRegistrationScriptHashParam": Certificate(
        CertificateType.STAKE_REGISTRATION,
        StakeRegistrationParams(
            CredentialParams(
                CredentialParamsType.SCRIPT_HASH,
                "29fb5fd4aa8cadd6705acc8263cee0fc62edca5ac38db593fec2f9fd",
            )
        ),
    ),
    "stakeDeregistrationParam": Certificate(
        CertificateType.STAKE_DEREGISTRATION,
        StakeRegistrationParams(
            CredentialParams(CredentialParamsType.KEY_PATH, "m/1852'/1815'/0'/2/0")
        ),
    ),
    "poolRegistrationWrongMargin": Certificate(
        CertificateType.STAKE_POOL_REGISTRATION,
        PoolRegistrationParams(
            poolKeys["poolKeyHash"],
            "07821cd344d7fd7e3ae5f2ed863218cb979ff1d59e50c4276bdc479b0d084450",
            50000000000,
            340000000,
            Margin(3, 1),
            poolKeys["poolRewardAccountHash"],
            [poolKeys["stakingPathOwner0"]],
            [relays["singleHostIPV4Relay0"]],
            PoolMetadataParams(
                "https://www.vacuumlabs.com/sampleUrl.json",
                "cdb714fd722c24aeb10c93dbb0ff03bd4783441cd5ba2a8b6f373390520535bb",
            ),
        ),
    ),
    "denyNoGivenPath": Certificate(
        CertificateType.STAKE_POOL_REGISTRATION,
        PoolRegistrationParams(
            poolKeys["poolKeyHash"],
            "07821cd344d7fd7e3ae5f2ed863218cb979ff1d59e50c4276bdc479b0d084450",
            50000000000,
            340000000,
            Margin(3, 100),
            poolKeys["poolRewardAccountHash"],
            [poolKeys["stakingHashOwner0"]],
            [
                relays["singleHostIPV4Relay0"],
                relays["singleHostIPV6Relay"],
                relays["singleHostNameRelay"],
                relays["multiHostNameRelay"],
            ],
            PoolMetadataParams(
                "https://www.vacuumlabs.com/sampleUrl.json",
                "cdb714fd722c24aeb10c93dbb0ff03bd4783441cd5ba2a8b6f373390520535bb",
            ),
        ),
    ),
    "denyInvalid1": Certificate(
        CertificateType.STAKE_POOL_REGISTRATION,
        PoolRegistrationParams(
            poolKeys["poolKeyHash"],
            "07821cd344d7fd7e3ae5f2ed863218cb979ff1d59e50c4276bdc479b0d084450",
            50000000000,
            340000000,
            Margin(3, 100),
            poolKeys["poolRewardAccountHash"],
            [poolKeys["stakingPathOwner0"], poolKeys["stakingPathOwner1"]],
            [
                relays["singleHostIPV4Relay0"],
                relays["singleHostIPV6Relay"],
                relays["singleHostNameRelay"],
                relays["multiHostNameRelay"],
            ],
            PoolMetadataParams(
                "https://www.vacuumlabs.com/sampleUrl.json",
                "cdb714fd722c24aeb10c93dbb0ff03bd4783441cd5ba2a8b6f373390520535bb",
            ),
        ),
    ),
    "denyInvalid2": Certificate(
        CertificateType.STAKE_POOL_REGISTRATION,
        PoolRegistrationParams(
            poolKeys["poolKeyHash"],
            "07821cd344d7fd7e3ae5f2ed863218cb979ff1d59e50c4276bdc479b0d084450",
            50000000000,
            340000000,
            Margin(3, 100),
            poolKeys["poolRewardAccountHash"],
            [],
            [
                relays["singleHostIPV4Relay0"],
                relays["singleHostIPV6Relay"],
                relays["singleHostNameRelay"],
                relays["multiHostNameRelay"],
            ],
            PoolMetadataParams(
                "https://www.vacuumlabs.com/sampleUrl.json",
                "cdb714fd722c24aeb10c93dbb0ff03bd4783441cd5ba2a8b6f373390520535bb",
            ),
        ),
    ),
    "denyInvalid3": Certificate(
        CertificateType.STAKE_POOL_REGISTRATION,
        PoolRegistrationParams(
            poolKeys["poolKeyHash"],
            "07821cd344d7fd7e3ae5f2ed863218cb979ff1d59e50c4276bdc479b0d084450",
            50000000000,
            340000000,
            Margin(3, 100),
            poolKeys["poolRewardAccountHash"],
            [poolKeys["stakingPathOwner0"]],
            [relays["singleHostIPV4Relay0"]],
            PoolMetadataParams(
                "a" * 129,
                "cdb714fd722c24aeb10c93dbb0ff03bd4783441cd5ba2a8b6f373390520535bb",
            ),
        ),
    ),
    "denyInvalid4": Certificate(
        CertificateType.STAKE_POOL_REGISTRATION,
        PoolRegistrationParams(
            poolKeys["poolKeyHash"],
            "07821cd344d7fd7e3ae5f2ed863218cb979ff1d59e50c4276bdc479b0d084450",
            50000000000,
            340000000,
            Margin(3, 100),
            poolKeys["poolRewardAccountHash"],
            [poolKeys["stakingPathOwner0"]],
            [relays["singleHostIPV4Relay0"]],
            PoolMetadataParams(
                "\n", "6bf124f217d0e5a0a8adb1dbd8540e1334280d49ab861127868339f43b3948"
            ),
        ),
    ),
    "denyInvalid5": Certificate(
        CertificateType.STAKE_POOL_REGISTRATION,
        PoolRegistrationParams(
            poolKeys["poolKeyHash"],
            "07821cd344d7fd7e3ae5f2ed863218cb979ff1d59e50c4276bdc479b0d084450",
            50000000000,
            340000000,
            Margin(3, 100),
            poolKeys["poolRewardAccountHash"],
            [poolKeys["stakingPathOwner0"]],
            [relays["singleHostIPV4Relay0"]],
            PoolMetadataParams(
                "", "cdb714fd722c24aeb10c93dbb0ff03bd4783441cd5ba2a8b6f373390520535bb"
            ),
        ),
    ),
    "denyInvalid6": Certificate(
        CertificateType.STAKE_POOL_REGISTRATION,
        PoolRegistrationParams(
            poolKeys["poolKeyHash"],
            "07821cd344d7fd7e3ae5f2ed863218cb979ff1d59e50c4276bdc479b0d084450",
            50000000000,
            340000000,
            Margin(3, 100),
            poolKeys["poolRewardAccountHash"],
            [poolKeys["stakingPathOwner0"]],
            [relays["singleHostIPV4Relay0"]],
            PoolMetadataParams(
                "https://www.vacuumlabs.com/sampleUrl.json",
                "6bf124f217d0e5a0a8adb1dbd8540e1334280d49ab861127868339f43b3948",
            ),
        ),
    ),
    "denyInvalid7": Certificate(
        CertificateType.STAKE_POOL_REGISTRATION,
        PoolRegistrationParams(
            poolKeys["poolKeyHash"],
            "07821cd344d7fd7e3ae5f2ed863218cb979ff1d59e50c4276bdc479b0d084450",
            50000000000,
            340000000,
            Margin(3, 100),
            poolKeys["poolRewardAccountHash"],
            [poolKeys["stakingPathOwner0"]],
            [relays["singleHostIPV4Relay0"]],
            PoolMetadataParams("https://www.vacuumlabs.com/sampleUrl.json", ""),
        ),
    ),
    "denyRelay1": Certificate(
        CertificateType.STAKE_POOL_REGISTRATION,
        PoolRegistrationParams(
            poolKeys["poolKeyHash"],
            "07821cd344d7fd7e3ae5f2ed863218cb979ff1d59e50c4276bdc479b0d084450",
            50000000000,
            340000000,
            Margin(3, 100),
            poolKeys["poolRewardAccountHash"],
            [poolKeys["stakingPathOwner0"]],
            [
                Relay(
                    RelayType.SINGLE_HOST_HOSTNAME,
                    SingleHostHostnameRelayParams(3000, None),
                )
            ],
            PoolMetadataParams(
                "https://www.vacuumlabs.com/sampleUrl.json",
                "cdb714fd722c24aeb10c93dbb0ff03bd4783441cd5ba2a8b6f373390520535bb",
            ),
        ),
    ),
    "denyRelay2": Certificate(
        CertificateType.STAKE_POOL_REGISTRATION,
        PoolRegistrationParams(
            poolKeys["poolKeyHash"],
            "07821cd344d7fd7e3ae5f2ed863218cb979ff1d59e50c4276bdc479b0d084450",
            50000000000,
            340000000,
            Margin(3, 100),
            poolKeys["poolRewardAccountHash"],
            [poolKeys["stakingPathOwner0"]],
            [Relay(RelayType.MULTI_HOST, MultiHostRelayParams(None))],
            PoolMetadataParams(
                "https://www.vacuumlabs.com/sampleUrl.json",
                "cdb714fd722c24aeb10c93dbb0ff03bd4783441cd5ba2a8b6f373390520535bb",
            ),
        ),
    ),
    "denyStakePool1": Certificate(
        CertificateType.STAKE_POOL_REGISTRATION,
        PoolRegistrationParams(
            poolKeys["default"],
            "07821cd344d7fd7e3ae5f2ed863218cb979ff1d59e50c4276bdc479b0d084450",
            50000000000,
            340000000,
            Margin(3, 100),
            poolKeys["poolRewardAccountHash"],
            [poolKeys["stakingPathOwner0"]],
            [relays["singleHostIPV4Relay0"]],
            PoolMetadataParams(
                "https://www.vacuumlabs.com/sampleUrl.json",
                "cdb714fd722c24aeb10c93dbb0ff03bd4783441cd5ba2a8b6f373390520535bb",
            ),
        ),
    ),
    "denyStakePool2": Certificate(
        CertificateType.STAKE_POOL_REGISTRATION,
        PoolRegistrationParams(
            poolKeys["default1"],
            "07821cd344d7fd7e3ae5f2ed863218cb979ff1d59e50c4276bdc479b0d084450",
            50000000000,
            340000000,
            Margin(3, 100),
            poolKeys["poolRewardAccountHash"],
            [poolKeys["stakingPathOwner0"]],
            [relays["singleHostIPV4Relay0"]],
            PoolMetadataParams(
                "https://www.vacuumlabs.com/sampleUrl.json",
                "cdb714fd722c24aeb10c93dbb0ff03bd4783441cd5ba2a8b6f373390520535bb",
            ),
        ),
    ),
}

# =================
# signTx
# =================
testsByron: List[SignTxTestCase] = [
    SignTxTestCase(
        name="Sign_tx_with_thirdparty_Byron_mainnet_output",
        tx=Transaction(
            network=Mainnet, inputs=[inputs["utxoByron"]], outputs=[outputs["externalByronMainnet"]], fee=42, ttl=10
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a400818258201af8fa0b754ff99253d983894e63a2b09cbb56c833ba18c3384210163f63dcfc00018182582b82d818582183581c9e1c71de652ec8b85fec296f0685ca3988781c94a2e1a5d89d92f45fa0001a0d0c25611a002dd2e802182a030a",
    ),
    SignTxTestCase(
        name="Sign_tx_with_thirdparty_Byron_Daedalus_mainnet_output",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoByron"]],
            outputs=[outputs["externalByronDaedalusMainnet"]],
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a400818258201af8fa0b754ff99253d983894e63a2b09cbb56c833ba18c3384210163f63dcfc00018182584c82d818584283581cd2348b8ef7b8a6d1c922efa499c669b151eeef99e4ce3521e88223f8a101581e581cf281e648a89015a9861bd9e992414d1145ddaf80690be53235b0e2e5001a199834651a002dd2e802182a030a",
    ),
    SignTxTestCase(
        name="Sign_tx_with_thirdparty_Byron_testnet_output",
        tx=Transaction(
            network=Testnet, inputs=[inputs["utxoByron"]], outputs=[outputs["externalByronTestnet"]], fee=42, ttl=10
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a400818258201af8fa0b754ff99253d983894e63a2b09cbb56c833ba18c3384210163f63dcfc00018182582f82d818582583581c709bfb5d9733cbdd72f520cd2c8b9f8f942da5e6cd0b6994e1803b0aa10242182a001aef14e76d1a002dd2e802182a030a",
        expected_warnings=[WarningBit.WARNING_BIT_NETWORK_UNUSUAL],
    ),
]

testsShelleyNoCertificates: List[SignTxTestCase] = [
    SignTxTestCase(
        name="Sign_tx_without_outputs",
        tx=Transaction(network=Mainnet, inputs=[inputs["utxoShelley"]], outputs=[], fee=42, ttl=10),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a400818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b700018002182a030a",
        expected_warnings=[WarningBit.WARNING_BIT_NETWORK_NOT_VERIFIABLE],
    ),
    SignTxTestCase(
        name="Sign_tx_with_258_tag_on_inputs",
        tx=Transaction(network=Mainnet, inputs=[inputs["utxoShelley"]], outputs=[], fee=42, ttl=10),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a400d90102818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b700018002182a030a",
        expected_warnings=[WarningBit.WARNING_BIT_NETWORK_NOT_VERIFIABLE],
    ),
    SignTxTestCase(
        name="Sign_tx_without_change_address",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["externalShelleyBaseKeyhashKeyhash"]],
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a400818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7000181825839017cb05fce110fb999f01abb4f62bc455e217d4a51fde909fa9aea545443ac53c046cf6a42095e3c60310fa802771d0672f8fe2d1861138b090102182a030a",
    ),
    SignTxTestCase(
        name="Sign_tx_with_change_base_address_with_staking_path",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoByron"]],
            outputs=[outputs["externalByronMainnet"], outputs["internalBaseWithStakingPath"]],
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a400818258201af8fa0b754ff99253d983894e63a2b09cbb56c833ba18c3384210163f63dcfc00018282582b82d818582183581c9e1c71de652ec8b85fec296f0685ca3988781c94a2e1a5d89d92f45fa0001a0d0c25611a002dd2e88258390114c16d7f43243bd81478e68b9db53a8528fd4fb1078d58d54a7f11241d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c1a006ca79302182a030a",
    ),
    SignTxTestCase(
        name="Sign_tx_with_change_base_address_with_staking_key_hash",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[
                outputs["externalByronMainnet"],
                outputs["internalBaseWithStakingKeyHash"],
            ],
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a400818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b700018282582b82d818582183581c9e1c71de652ec8b85fec296f0685ca3988781c94a2e1a5d89d92f45fa0001a0d0c25611a002dd2e88258390114c16d7f43243bd81478e68b9db53a8528fd4fb1078d58d54a7f1124122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b42771a006ca79302182a030a",
    ),
    SignTxTestCase(
        name="Sign_tx_with_enterprise_change_address",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["externalByronMainnet"], outputs["internalEnterprise"]],
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a400818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b700018282582b82d818582183581c9e1c71de652ec8b85fec296f0685ca3988781c94a2e1a5d89d92f45fa0001a0d0c25611a002dd2e882581d6114c16d7f43243bd81478e68b9db53a8528fd4fb1078d58d54a7f11241a006ca79302182a030a",
    ),
    SignTxTestCase(
        name="Sign_tx_with_pointer_change_address",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["externalByronMainnet"], outputs["internalPointer"]],
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a400818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b700018282582b82d818582183581c9e1c71de652ec8b85fec296f0685ca3988781c94a2e1a5d89d92f45fa0001a0d0c25611a002dd2e88258204114c16d7f43243bd81478e68b9db53a8528fd4fb1078d58d54a7f11240102031a006ca79302182a030a",
    ),
    SignTxTestCase(
        name="Sign_tx_with_nonreasonable_account_and_address",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoNonReasonable"]],
            outputs=[outputs["internalBaseWithStakingPathNonReasonable"]],
            auxiliaryData=TxAuxiliaryData(
                TxAuxiliaryDataType.ARBITRARY_HASH,
                TxAuxiliaryDataHash(f"{'deadbeef' * 8}"),
            ),
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a500818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b700018182583901f90b0dfcace47bf03e88f7469a2f4fb3a7918461aa4765bfaf55f0dae260546c20562e598fb761f419dad27edcd49f4ee4f0540b8e40d4d51a006ca79302182a030a075820deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        expected_warnings=[WarningBit.WARNING_BIT_UNUSUAL_KEY_DERIVATION_PATH],
    ),
    SignTxTestCase(
        name="Sign_tx_with_path_based_withdrawal",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["externalByronMainnet"]],
            withdrawals=[
                Withdrawal(
                    CredentialParams(
                        CredentialParamsType.KEY_PATH, "m/1852'/1815'/0'/2/0"
                    ),
                    111,
                )
            ],
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a500818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b700018182582b82d818582183581c9e1c71de652ec8b85fec296f0685ca3988781c94a2e1a5d89d92f45fa0001a0d0c25611a002dd2e802182a030a05a1581de11d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c186f",
    ),
    SignTxTestCase(
        name="Sign_tx_with_unusual_path_based_withdrawal",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoNonReasonable"]],
            outputs=[outputs["externalByronMainnet"]],
            withdrawals=[
                Withdrawal(
                    CredentialParams(
                        CredentialParamsType.KEY_PATH, "m/1852'/1815'/456'/2/0"
                    ),
                    111,
                )
            ],
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a500818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b700018182582b82d818582183581c9e1c71de652ec8b85fec296f0685ca3988781c94a2e1a5d89d92f45fa0001a0d0c25611a002dd2e802182a030a05a1581de1e260546c20562e598fb761f419dad27edcd49f4ee4f0540b8e40d4d5186f",
        expected_warnings=[WarningBit.WARNING_BIT_UNUSUAL_KEY_DERIVATION_PATH],
    ),
    SignTxTestCase(
        name="Sign_tx_with_auxiliary_data_hash",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["externalByronMainnet"]],
            auxiliaryData=TxAuxiliaryData(
                TxAuxiliaryDataType.ARBITRARY_HASH,
                TxAuxiliaryDataHash(f"{'deadbeef' * 8}"),
            ),
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a500818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b700018182582b82d818582183581c9e1c71de652ec8b85fec296f0685ca3988781c94a2e1a5d89d92f45fa0001a0d0c25611a002dd2e802182a030a075820deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
    ),
]

testsShelleyWithCertificates: List[SignTxTestCase] = [
    SignTxTestCase(
        name="Sign_tx_with_a_stake_registration_path_certificate_preConway",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["externalByronMainnet"]],
            certificates=[
                Certificate(
                    CertificateType.STAKE_REGISTRATION,
                    StakeRegistrationParams(
                        CredentialParams(
                            CredentialParamsType.KEY_PATH, "m/1852'/1815'/0'/2/0"
                        )
                    ),
                )
            ],
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a500818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b700018182582b82d818582183581c9e1c71de652ec8b85fec296f0685ca3988781c94a2e1a5d89d92f45fa0001a0d0c25611a002dd2e802182a030a048182008200581c1d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c",
    ),
    SignTxTestCase(
        name="Sign_tx_with_a_stake_deregistration_path_certificate_preConway",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["externalByronMainnet"]],
            certificates=[
                Certificate(
                    CertificateType.STAKE_DEREGISTRATION,
                    StakeRegistrationParams(
                        CredentialParams(
                            CredentialParamsType.KEY_PATH, "m/1852'/1815'/0'/2/0"
                        )
                    ),
                )
            ],
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a500818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b700018182582b82d818582183581c9e1c71de652ec8b85fec296f0685ca3988781c94a2e1a5d89d92f45fa0001a0d0c25611a002dd2e802182a030a048182018200581c1d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c",
    ),
    SignTxTestCase(
        name="Sign_tx_with_a_stake_delegation_path_certificate",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["externalByronMainnet"]],
            certificates=[
                Certificate(
                    CertificateType.STAKE_DELEGATION,
                    StakeDelegationParams(
                        CredentialParams(
                            CredentialParamsType.KEY_PATH, "m/1852'/1815'/0'/2/0"
                        ),
                        "f61c42cbf7c8c53af3f520508212ad3e72f674f957fe23ff0acb4973",
                    ),
                )
            ],
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a500818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b700018182582b82d818582183581c9e1c71de652ec8b85fec296f0685ca3988781c94a2e1a5d89d92f45fa0001a0d0c25611a002dd2e802182a030a048183028200581c1d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c581cf61c42cbf7c8c53af3f520508212ad3e72f674f957fe23ff0acb4973",
    ),
    SignTxTestCase(
        name="Sign_tx_and_filter_out_witnesses_with_duplicate_paths",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["externalByronMainnet"]],
            certificates=[
                Certificate(
                    CertificateType.STAKE_DEREGISTRATION,
                    StakeRegistrationParams(
                        CredentialParams(
                            CredentialParamsType.KEY_PATH, "m/1852'/1815'/0'/2/0"
                        )
                    ),
                ),
                Certificate(
                    CertificateType.STAKE_DEREGISTRATION,
                    StakeRegistrationParams(
                        CredentialParams(
                            CredentialParamsType.KEY_PATH, "m/1852'/1815'/0'/2/0"
                        )
                    ),
                ),
            ],
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a500818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b700018182582b82d818582183581c9e1c71de652ec8b85fec296f0685ca3988781c94a2e1a5d89d92f45fa0001a0d0c25611a002dd2e802182a030a048282018200581c1d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c82018200581c1d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c",
    ),
    SignTxTestCase(
        name="Sign_tx_with_pool_retirement_combined_with_stake_registration",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["externalByronMainnet"]],
            certificates=[
                Certificate(
                    CertificateType.STAKE_POOL_RETIREMENT,
                    PoolRetirementParams(
                        CredentialParams(
                            CredentialParamsType.KEY_PATH, "m/1853'/1815'/0'/0'"
                        ),
                        10,
                    ),
                ),
                Certificate(
                    CertificateType.STAKE_REGISTRATION,
                    StakeRegistrationParams(
                        CredentialParams(
                            CredentialParamsType.KEY_PATH, "m/1852'/1815'/0'/2/0"
                        )
                    ),
                ),
            ],
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a500818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b700018182582b82d818582183581c9e1c71de652ec8b85fec296f0685ca3988781c94a2e1a5d89d92f45fa0001a0d0c25611a002dd2e802182a030a04828304581cdbfee4665e58c8f8e9b9ff02b17f32e08a42c855476a5d867c2737b70a82008200581c1d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c",
    ),
    SignTxTestCase(
        name="Sign_tx_with_pool_retirement_combined_with_stake_deregistration",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["externalByronMainnet"]],
            certificates=[
                Certificate(
                    CertificateType.STAKE_POOL_RETIREMENT,
                    PoolRetirementParams(
                        CredentialParams(
                            CredentialParamsType.KEY_PATH, "m/1853'/1815'/0'/0'"
                        ),
                        10,
                    ),
                ),
                Certificate(
                    CertificateType.STAKE_DEREGISTRATION,
                    StakeRegistrationParams(
                        CredentialParams(
                            CredentialParamsType.KEY_PATH, "m/1852'/1815'/0'/2/0"
                        )
                    ),
                ),
            ],
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a500818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b700018182582b82d818582183581c9e1c71de652ec8b85fec296f0685ca3988781c94a2e1a5d89d92f45fa0001a0d0c25611a002dd2e802182a030a04828304581cdbfee4665e58c8f8e9b9ff02b17f32e08a42c855476a5d867c2737b70a82018200581c1d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c",
    ),
]

testsConwayWithCertificates: List[SignTxTestCase] = [
    SignTxTestCase(
        name="Sign_tx_with_a_stake_registration_path_certificate_Conway",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["externalByronMainnet"]],
            certificates=[
                Certificate(
                    CertificateType.STAKE_REGISTRATION_CONWAY,
                    StakeRegistrationConwayParams(
                        CredentialParams(
                            CredentialParamsType.KEY_PATH, "m/1852'/1815'/0'/2/0"
                        ),
                        17,
                    ),
                )
            ],
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a500818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b700018182582b82d818582183581c9e1c71de652ec8b85fec296f0685ca3988781c94a2e1a5d89d92f45fa0001a0d0c25611a002dd2e802182a030a048183078200581c1d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c11",
    ),
    SignTxTestCase(
        name="Sign_tx_with_a_stake_deregistration_path_certificate_Conway",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["externalByronMainnet"]],
            certificates=[
                Certificate(
                    CertificateType.STAKE_DEREGISTRATION_CONWAY,
                    StakeRegistrationConwayParams(
                        CredentialParams(
                            CredentialParamsType.KEY_PATH, "m/1852'/1815'/0'/2/0"
                        ),
                        17,
                    ),
                )
            ],
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a500818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b700018182582b82d818582183581c9e1c71de652ec8b85fec296f0685ca3988781c94a2e1a5d89d92f45fa0001a0d0c25611a002dd2e802182a030a048183088200581c1d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c11",
    ),
    SignTxTestCase(
        name="Sign_tx_with_vote_delegation_certificates",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["externalByronMainnet"]],
            certificates=[
                Certificate(
                    CertificateType.VOTE_DELEGATION,
                    VoteDelegationParams(
                        CredentialParams(
                            CredentialParamsType.KEY_PATH, "m/1852'/1815'/0'/2/0"
                        ),
                        DRepParams(DRepParamsType.KEY_PATH, "m/1852'/1815'/0'/3/0"),
                    ),
                ),
                Certificate(
                    CertificateType.VOTE_DELEGATION,
                    VoteDelegationParams(
                        CredentialParams(
                            CredentialParamsType.KEY_PATH, "m/1852'/1815'/0'/2/0"
                        ),
                        DRepParams(
                            DRepParamsType.KEY_HASH,
                            "7afd028b504c3668102b129b37a86c09a2872f76741dc7a68e2149c8",
                        ),
                    ),
                ),
                Certificate(
                    CertificateType.VOTE_DELEGATION,
                    VoteDelegationParams(
                        CredentialParams(
                            CredentialParamsType.KEY_PATH, "m/1852'/1815'/0'/2/0"
                        ),
                        DRepParams(
                            DRepParamsType.SCRIPT_HASH,
                            "1afd028b504c3668102b129b37a86c09a2872f76741dc7a68e2149c8",
                        ),
                    ),
                ),
                Certificate(
                    CertificateType.VOTE_DELEGATION,
                    VoteDelegationParams(
                        CredentialParams(
                            CredentialParamsType.KEY_PATH, "m/1852'/1815'/0'/2/0"
                        ),
                        DRepParams(DRepParamsType.ABSTAIN),
                    ),
                ),
                Certificate(
                    CertificateType.VOTE_DELEGATION,
                    VoteDelegationParams(
                        CredentialParams(
                            CredentialParamsType.KEY_PATH, "m/1852'/1815'/0'/2/0"
                        ),
                        DRepParams(DRepParamsType.NO_CONFIDENCE),
                    ),
                ),
            ],
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a500818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b700018182582b82d818582183581c9e1c71de652ec8b85fec296f0685ca3988781c94a2e1a5d89d92f45fa0001a0d0c25611a002dd2e802182a030a048583098200581c1d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c8200581cba41c59ac6e1a0e4ac304af98db801097d0bf8d2a5b28a54752426a183098200581c1d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c8200581c7afd028b504c3668102b129b37a86c09a2872f76741dc7a68e2149c883098200581c1d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c8201581c1afd028b504c3668102b129b37a86c09a2872f76741dc7a68e2149c883098200581c1d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c810283098200581c1d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c8103",
    ),
    SignTxTestCase(
        name="Sign_tx_with_stake_pool_and_drep_delegation_certificates",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["externalByronMainnet"]],
            certificates=[
                Certificate(
                    CertificateType.STAKE_POOL_AND_DREP_DELEGATION,
                    StakePoolAndDRepDelegationParams(
                        CredentialParams(
                            CredentialParamsType.KEY_PATH, "m/1852'/1815'/0'/2/0"
                        ),
                        "f61c42cbf7c8c53af3f520508212ad3e72f674f957fe23ff0acb4973",
                        DRepParams(DRepParamsType.KEY_PATH, "m/1852'/1815'/0'/3/0"),
                    ),
                ),
                Certificate(
                    CertificateType.STAKE_POOL_AND_DREP_DELEGATION,
                    StakePoolAndDRepDelegationParams(
                        CredentialParams(
                            CredentialParamsType.KEY_PATH, "m/1852'/1815'/0'/2/0"
                        ),
                        "f61c42cbf7c8c53af3f520508212ad3e72f674f957fe23ff0acb4973",
                        DRepParams(
                            DRepParamsType.KEY_HASH,
                            "7afd028b504c3668102b129b37a86c09a2872f76741dc7a68e2149c8",
                        ),
                    ),
                ),
                Certificate(
                    CertificateType.STAKE_POOL_AND_DREP_DELEGATION,
                    StakePoolAndDRepDelegationParams(
                        CredentialParams(
                            CredentialParamsType.KEY_PATH, "m/1852'/1815'/0'/2/0"
                        ),
                        "f61c42cbf7c8c53af3f520508212ad3e72f674f957fe23ff0acb4973",
                        DRepParams(
                            DRepParamsType.SCRIPT_HASH,
                            "1afd028b504c3668102b129b37a86c09a2872f76741dc7a68e2149c8",
                        ),
                    ),
                ),
                Certificate(
                    CertificateType.STAKE_POOL_AND_DREP_DELEGATION,
                    StakePoolAndDRepDelegationParams(
                        CredentialParams(
                            CredentialParamsType.KEY_PATH, "m/1852'/1815'/0'/2/0"
                        ),
                        "f61c42cbf7c8c53af3f520508212ad3e72f674f957fe23ff0acb4973",
                        DRepParams(DRepParamsType.ABSTAIN),
                    ),
                ),
                Certificate(
                    CertificateType.STAKE_POOL_AND_DREP_DELEGATION,
                    StakePoolAndDRepDelegationParams(
                        CredentialParams(
                            CredentialParamsType.KEY_PATH, "m/1852'/1815'/0'/2/0"
                        ),
                        "f61c42cbf7c8c53af3f520508212ad3e72f674f957fe23ff0acb4973",
                        DRepParams(DRepParamsType.NO_CONFIDENCE),
                    ),
                ),
            ],
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a500818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b700018182582b82d818582183581c9e1c71de652ec8b85fec296f0685ca3988781c94a2e1a5d89d92f45fa0001a0d0c25611a002dd2e802182a030a0485840a8200581c1d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c581cf61c42cbf7c8c53af3f520508212ad3e72f674f957fe23ff0acb49738200581cba41c59ac6e1a0e4ac304af98db801097d0bf8d2a5b28a54752426a1840a8200581c1d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c581cf61c42cbf7c8c53af3f520508212ad3e72f674f957fe23ff0acb49738200581c7afd028b504c3668102b129b37a86c09a2872f76741dc7a68e2149c8840a8200581c1d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c581cf61c42cbf7c8c53af3f520508212ad3e72f674f957fe23ff0acb49738201581c1afd028b504c3668102b129b37a86c09a2872f76741dc7a68e2149c8840a8200581c1d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c581cf61c42cbf7c8c53af3f520508212ad3e72f674f957fe23ff0acb49738102840a8200581c1d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c581cf61c42cbf7c8c53af3f520508212ad3e72f674f957fe23ff0acb49738103",
    ),
    SignTxTestCase(
        name="Sign_tx_with_account_registration_delegation_to_stake_pool_certificate",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["externalByronMainnet"]],
            certificates=[
                Certificate(
                    CertificateType.ACCOUNT_REGISTRATION_DELEGATION_TO_STAKE_POOL,
                    AccountRegistrationDelegationToStakePoolParams(
                        CredentialParams(
                            CredentialParamsType.KEY_PATH, "m/1852'/1815'/0'/2/0"
                        ),
                        "f61c42cbf7c8c53af3f520508212ad3e72f674f957fe23ff0acb4973",
                        1000000,
                    ),
                ),
            ],
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a500818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b700018182582b82d818582183581c9e1c71de652ec8b85fec296f0685ca3988781c94a2e1a5d89d92f45fa0001a0d0c25611a002dd2e802182a030a0481840b8200581c1d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c581cf61c42cbf7c8c53af3f520508212ad3e72f674f957fe23ff0acb49731a000f4240",
    ),
    SignTxTestCase(
        name="Sign_tx_with_account_registration_delegation_to_drep_certificate",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["externalByronMainnet"]],
            certificates=[
                Certificate(
                    CertificateType.ACCOUNT_REGISTRATION_DELEGATION_TO_DREP,
                    AccountRegistrationDelegationToDRepParams(
                        CredentialParams(
                            CredentialParamsType.KEY_PATH, "m/1852'/1815'/0'/2/0"
                        ),
                        DRepParams(DRepParamsType.KEY_PATH, "m/1852'/1815'/0'/3/0"),
                        1000000,
                    ),
                ),
            ],
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a500818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b700018182582b82d818582183581c9e1c71de652ec8b85fec296f0685ca3988781c94a2e1a5d89d92f45fa0001a0d0c25611a002dd2e802182a030a0481840c8200581c1d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c8200581cba41c59ac6e1a0e4ac304af98db801097d0bf8d2a5b28a54752426a11a000f4240",
    ),
    SignTxTestCase(
        name="Sign_tx_with_account_registration_delegation_to_stake_pool_and_drep_certificate",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["externalByronMainnet"]],
            certificates=[
                Certificate(
                    CertificateType.ACCOUNT_REGISTRATION_DELEGATION_TO_STAKE_POOL_AND_DREP,
                    AccountRegistrationDelegationToStakePoolAndDRepParams(
                        CredentialParams(
                            CredentialParamsType.KEY_PATH, "m/1852'/1815'/0'/2/0"
                        ),
                        "f61c42cbf7c8c53af3f520508212ad3e72f674f957fe23ff0acb4973",
                        DRepParams(DRepParamsType.KEY_PATH, "m/1852'/1815'/0'/3/0"),
                        1000000,
                    ),
                ),
            ],
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a500818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b700018182582b82d818582183581c9e1c71de652ec8b85fec296f0685ca3988781c94a2e1a5d89d92f45fa0001a0d0c25611a002dd2e802182a030a0481850d8200581c1d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c581cf61c42cbf7c8c53af3f520508212ad3e72f674f957fe23ff0acb49738200581cba41c59ac6e1a0e4ac304af98db801097d0bf8d2a5b28a54752426a11a000f4240",
    ),
    SignTxTestCase(
        name="Sign_tx_with_all_certificates_except_pool_registration",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["externalByronMainnet"]],
            certificates=[
                certificates["stakeRegistrationPathParam"],
                certificates["stakeDeregistrationParam"],
                Certificate(
                    CertificateType.STAKE_REGISTRATION_CONWAY,
                    StakeRegistrationConwayParams(
                        CredentialParams(CredentialParamsType.KEY_PATH, "m/1852'/1815'/0'/2/0"),
                        17,
                    ),
                ),
                Certificate(
                    CertificateType.STAKE_DEREGISTRATION_CONWAY,
                    StakeRegistrationConwayParams(
                        CredentialParams(CredentialParamsType.KEY_PATH, "m/1852'/1815'/0'/2/0"),
                        17,
                    ),
                ),
                Certificate(
                    CertificateType.STAKE_DELEGATION,
                    StakeDelegationParams(
                        CredentialParams(
                            CredentialParamsType.KEY_PATH, "m/1852'/1815'/0'/2/0"
                        ),
                        "f61c42cbf7c8c53af3f520508212ad3e72f674f957fe23ff0acb4973",
                    ),
                ),
                certificates["poolRetirementParam"],
                Certificate(
                    CertificateType.VOTE_DELEGATION,
                    VoteDelegationParams(
                        CredentialParams(
                            CredentialParamsType.KEY_PATH, "m/1852'/1815'/0'/2/0"
                        ),
                        DRepParams(DRepParamsType.KEY_PATH, "m/1852'/1815'/0'/3/0"),
                    ),
                ),
                Certificate(
                    CertificateType.AUTHORIZE_COMMITTEE_HOT,
                    AuthorizeCommitteeParams(
                        CredentialParams(
                            CredentialParamsType.KEY_PATH, "m/1852'/1815'/0'/4/0"
                        ),
                        CredentialParams(
                            CredentialParamsType.KEY_PATH, "m/1852'/1815'/0'/5/0"
                        ),
                    ),
                ),
                Certificate(
                    CertificateType.RESIGN_COMMITTEE_COLD,
                    ResignCommitteeParams(
                        CredentialParams(
                            CredentialParamsType.KEY_PATH, "m/1852'/1815'/0'/4/0"
                        ),
                        AnchorParams(
                            "https://www.vacuumlabs.com/sampleAnchor",
                            "1afd028b504c3668102b129b37a86c09a2872f76741dc7a68e2149c8deadbeef",
                        ),
                    ),
                ),
                Certificate(
                    CertificateType.DREP_REGISTRATION,
                    DRepRegistrationParams(
                        CredentialParams(
                            CredentialParamsType.KEY_PATH, "m/1852'/1815'/0'/3/0"
                        ),
                        19,
                        AnchorParams(
                            "https://www.vacuumlabs.com/sampleAnchor",
                            "1afd028b504c3668102b129b37a86c09a2872f76741dc7a68e2149c8deadbeef",
                        ),
                    ),
                ),
                Certificate(
                    CertificateType.DREP_DEREGISTRATION,
                    DRepRegistrationParams(
                        CredentialParams(
                            CredentialParamsType.KEY_PATH, "m/1852'/1815'/0'/3/0"
                        ),
                        19,
                    ),
                ),
                Certificate(
                    CertificateType.DREP_UPDATE,
                    DRepUpdateParams(
                        CredentialParams(
                            CredentialParamsType.KEY_PATH, "m/1852'/1815'/0'/3/0"
                        ),
                        AnchorParams(
                            "https://www.vacuumlabs.com/sampleAnchor",
                            "1afd028b504c3668102b129b37a86c09a2872f76741dc7a68e2149c8deadbeef",
                        ),
                    ),
                ),
                Certificate(
                    CertificateType.STAKE_POOL_AND_DREP_DELEGATION,
                    StakePoolAndDRepDelegationParams(
                        CredentialParams(
                            CredentialParamsType.KEY_PATH, "m/1852'/1815'/0'/2/0"
                        ),
                        "f61c42cbf7c8c53af3f520508212ad3e72f674f957fe23ff0acb4973",
                        DRepParams(DRepParamsType.KEY_PATH, "m/1852'/1815'/0'/3/0"),
                    ),
                ),
                Certificate(
                    CertificateType.ACCOUNT_REGISTRATION_DELEGATION_TO_STAKE_POOL,
                    AccountRegistrationDelegationToStakePoolParams(
                        CredentialParams(
                            CredentialParamsType.KEY_PATH, "m/1852'/1815'/0'/2/0"
                        ),
                        "f61c42cbf7c8c53af3f520508212ad3e72f674f957fe23ff0acb4973",
                        1000000,
                    ),
                ),
                Certificate(
                    CertificateType.ACCOUNT_REGISTRATION_DELEGATION_TO_DREP,
                    AccountRegistrationDelegationToDRepParams(
                        CredentialParams(
                            CredentialParamsType.KEY_PATH, "m/1852'/1815'/0'/2/0"
                        ),
                        DRepParams(DRepParamsType.KEY_PATH, "m/1852'/1815'/0'/3/0"),
                        1000000,
                    ),
                ),
                Certificate(
                    CertificateType.ACCOUNT_REGISTRATION_DELEGATION_TO_STAKE_POOL_AND_DREP,
                    AccountRegistrationDelegationToStakePoolAndDRepParams(
                        CredentialParams(
                            CredentialParamsType.KEY_PATH, "m/1852'/1815'/0'/2/0"
                        ),
                        "f61c42cbf7c8c53af3f520508212ad3e72f674f957fe23ff0acb4973",
                        DRepParams(DRepParamsType.KEY_PATH, "m/1852'/1815'/0'/3/0"),
                        1000000,
                    ),
                ),
            ],
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a500818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b700018182582b82d818582183581c9e1c71de652ec8b85fec296f0685ca3988781c94a2e1a5d89d92f45fa0001a0d0c25611a002dd2e802182a030a049082008200581c1d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c82018200581c1d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c83078200581c1d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c1183088200581c1d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c1183028200581c1d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c581cf61c42cbf7c8c53af3f520508212ad3e72f674f957fe23ff0acb49738304581c8e00cd50efb2c15b548abeced2bce0ec4ee445a6954d762aa301d13f182a83098200581c1d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c8200581cba41c59ac6e1a0e4ac304af98db801097d0bf8d2a5b28a54752426a1830e8200581ccf737588be6e9edeb737eb2e6d06e5cbd292bd8ee32e410c0bba1ba68200581cd098c6a0a621f3343abe55877ee88fd5a83363e3c7887b3c48839092830f8200581ccf737588be6e9edeb737eb2e6d06e5cbd292bd8ee32e410c0bba1ba682782768747470733a2f2f7777772e76616375756d6c6162732e636f6d2f73616d706c65416e63686f7258201afd028b504c3668102b129b37a86c09a2872f76741dc7a68e2149c8deadbeef84108200581cba41c59ac6e1a0e4ac304af98db801097d0bf8d2a5b28a54752426a11382782768747470733a2f2f7777772e76616375756d6c6162732e636f6d2f73616d706c65416e63686f7258201afd028b504c3668102b129b37a86c09a2872f76741dc7a68e2149c8deadbeef83118200581cba41c59ac6e1a0e4ac304af98db801097d0bf8d2a5b28a54752426a11383128200581cba41c59ac6e1a0e4ac304af98db801097d0bf8d2a5b28a54752426a182782768747470733a2f2f7777772e76616375756d6c6162732e636f6d2f73616d706c65416e63686f7258201afd028b504c3668102b129b37a86c09a2872f76741dc7a68e2149c8deadbeef840a8200581c1d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c581cf61c42cbf7c8c53af3f520508212ad3e72f674f957fe23ff0acb49738200581cba41c59ac6e1a0e4ac304af98db801097d0bf8d2a5b28a54752426a1840b8200581c1d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c581cf61c42cbf7c8c53af3f520508212ad3e72f674f957fe23ff0acb49731a000f4240840c8200581c1d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c8200581cba41c59ac6e1a0e4ac304af98db801097d0bf8d2a5b28a54752426a11a000f4240850d8200581c1d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c581cf61c42cbf7c8c53af3f520508212ad3e72f674f957fe23ff0acb49738200581cba41c59ac6e1a0e4ac304af98db801097d0bf8d2a5b28a54752426a11a000f4240",
    ),
    SignTxTestCase(
        name="Sign_tx_with_AUTHORIZE_COMMITTEE_HOT_certificates",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["externalByronMainnet"]],
            certificates=[
                Certificate(
                    CertificateType.AUTHORIZE_COMMITTEE_HOT,
                    AuthorizeCommitteeParams(
                        CredentialParams(
                            CredentialParamsType.KEY_PATH, "m/1852'/1815'/0'/4/0"
                        ),
                        CredentialParams(
                            CredentialParamsType.KEY_PATH, "m/1852'/1815'/0'/5/0"
                        ),
                    ),
                ),
                Certificate(
                    CertificateType.AUTHORIZE_COMMITTEE_HOT,
                    AuthorizeCommitteeParams(
                        CredentialParams(
                            CredentialParamsType.KEY_PATH, "m/1852'/1815'/0'/4/0"
                        ),
                        CredentialParams(
                            CredentialParamsType.KEY_HASH,
                            "1afd028b504c3668102b129b37a86c09a2872f76741dc7a68e2149c8",
                        ),
                    ),
                ),
                Certificate(
                    CertificateType.AUTHORIZE_COMMITTEE_HOT,
                    AuthorizeCommitteeParams(
                        CredentialParams(
                            CredentialParamsType.KEY_PATH, "m/1852'/1815'/0'/4/0"
                        ),
                        CredentialParams(
                            CredentialParamsType.SCRIPT_HASH,
                            "1afd028b504c3668102b129b37a86c09a2872f76741dc7a68e2149c8",
                        ),
                    ),
                ),
            ],
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a500818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b700018182582b82d818582183581c9e1c71de652ec8b85fec296f0685ca3988781c94a2e1a5d89d92f45fa0001a0d0c25611a002dd2e802182a030a0483830e8200581ccf737588be6e9edeb737eb2e6d06e5cbd292bd8ee32e410c0bba1ba68200581cd098c6a0a621f3343abe55877ee88fd5a83363e3c7887b3c48839092830e8200581ccf737588be6e9edeb737eb2e6d06e5cbd292bd8ee32e410c0bba1ba68200581c1afd028b504c3668102b129b37a86c09a2872f76741dc7a68e2149c8830e8200581ccf737588be6e9edeb737eb2e6d06e5cbd292bd8ee32e410c0bba1ba68201581c1afd028b504c3668102b129b37a86c09a2872f76741dc7a68e2149c8",
    ),
    SignTxTestCase(
        name="Sign_tx_with_RESIGN_COMMITTEE_COLD_certificates",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["externalByronMainnet"]],
            certificates=[
                Certificate(
                    CertificateType.RESIGN_COMMITTEE_COLD,
                    ResignCommitteeParams(
                        CredentialParams(
                            CredentialParamsType.KEY_PATH, "m/1852'/1815'/0'/4/0"
                        ),
                        AnchorParams(
                            f"{'x' * 128}",
                            "1afd028b504c3668102b129b37a86c09a2872f76741dc7a68e2149c8deadbeef",
                        ),
                    ),
                ),
                Certificate(
                    CertificateType.RESIGN_COMMITTEE_COLD,
                    ResignCommitteeParams(
                        CredentialParams(
                            CredentialParamsType.KEY_PATH, "m/1852'/1815'/0'/4/0"
                        )
                    ),
                ),
            ],
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a500818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b700018182582b82d818582183581c9e1c71de652ec8b85fec296f0685ca3988781c94a2e1a5d89d92f45fa0001a0d0c25611a002dd2e802182a030a0482830f8200581ccf737588be6e9edeb737eb2e6d06e5cbd292bd8ee32e410c0bba1ba6827880787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787858201afd028b504c3668102b129b37a86c09a2872f76741dc7a68e2149c8deadbeef830f8200581ccf737588be6e9edeb737eb2e6d06e5cbd292bd8ee32e410c0bba1ba6f6",
    ),
    SignTxTestCase(
        name="Sign_tx_with_DREP_REGISTRATION_certificates",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["externalByronMainnet"]],
            certificates=[
                Certificate(
                    CertificateType.DREP_REGISTRATION,
                    DRepRegistrationParams(
                        CredentialParams(
                            CredentialParamsType.KEY_PATH, "m/1852'/1815'/0'/3/0"
                        ),
                        19,
                        AnchorParams(
                            "www.vacuumlabs.com",
                            "1afd028b504c3668102b129b37a86c09a2872f76741dc7a68e2149c8deadbeef",
                        ),
                    ),
                ),
                Certificate(
                    CertificateType.DREP_REGISTRATION,
                    DRepRegistrationParams(
                        CredentialParams(
                            CredentialParamsType.KEY_PATH, "m/1852'/1815'/0'/3/0"
                        ),
                        19,
                    ),
                ),
            ],
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a500818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b700018182582b82d818582183581c9e1c71de652ec8b85fec296f0685ca3988781c94a2e1a5d89d92f45fa0001a0d0c25611a002dd2e802182a030a048284108200581cba41c59ac6e1a0e4ac304af98db801097d0bf8d2a5b28a54752426a11382727777772e76616375756d6c6162732e636f6d58201afd028b504c3668102b129b37a86c09a2872f76741dc7a68e2149c8deadbeef84108200581cba41c59ac6e1a0e4ac304af98db801097d0bf8d2a5b28a54752426a113f6",
    ),
    SignTxTestCase(
        name="Sign_tx_with_DREP_DEREGISTRATION_certificate",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["externalByronMainnet"]],
            certificates=[
                Certificate(
                    CertificateType.DREP_DEREGISTRATION,
                    DRepRegistrationParams(
                        CredentialParams(
                            CredentialParamsType.KEY_PATH, "m/1852'/1815'/0'/3/0"
                        ),
                        19,
                    ),
                )
            ],
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a500818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b700018182582b82d818582183581c9e1c71de652ec8b85fec296f0685ca3988781c94a2e1a5d89d92f45fa0001a0d0c25611a002dd2e802182a030a048183118200581cba41c59ac6e1a0e4ac304af98db801097d0bf8d2a5b28a54752426a113",
    ),
    SignTxTestCase(
        name="Sign_tx_with_DREP_UPDATE_certificates",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["externalByronMainnet"]],
            certificates=[
                Certificate(
                    CertificateType.DREP_UPDATE,
                    DRepUpdateParams(
                        CredentialParams(
                            CredentialParamsType.KEY_PATH, "m/1852'/1815'/0'/3/0"
                        ),
                        AnchorParams(
                            "www.vacuumlabs.com",
                            "1afd028b504c3668102b129b37a86c09a2872f76741dc7a68e2149c8deadbeef",
                        ),
                    ),
                ),
                Certificate(
                    CertificateType.DREP_UPDATE,
                    DRepUpdateParams(
                        CredentialParams(
                            CredentialParamsType.KEY_PATH, "m/1852'/1815'/0'/3/0"
                        )
                    ),
                ),
            ],
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a500818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b700018182582b82d818582183581c9e1c71de652ec8b85fec296f0685ca3988781c94a2e1a5d89d92f45fa0001a0d0c25611a002dd2e802182a030a048283128200581cba41c59ac6e1a0e4ac304af98db801097d0bf8d2a5b28a54752426a182727777772e76616375756d6c6162732e636f6d58201afd028b504c3668102b129b37a86c09a2872f76741dc7a68e2149c8deadbeef83128200581cba41c59ac6e1a0e4ac304af98db801097d0bf8d2a5b28a54752426a1f6",
    ),
    SignTxTestCase(
        name="Sign_tx_with_mixed_script_hash_certificates_in_plutus_mode",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["externalByronMainnet"]],
            certificates=[
                Certificate(
                    CertificateType.VOTE_DELEGATION,
                    VoteDelegationParams(
                        CredentialParams(
                            CredentialParamsType.SCRIPT_HASH,
                            "122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277",
                        ),
                        DRepParams(DRepParamsType.KEY_PATH, "m/1852'/1815'/0'/3/0"),
                    ),
                ),
                Certificate(
                    CertificateType.AUTHORIZE_COMMITTEE_HOT,
                    AuthorizeCommitteeParams(
                        CredentialParams(
                            CredentialParamsType.SCRIPT_HASH,
                            "1afd028b504c3668102b129b37a86c09a2872f76741dc7a68e2149c8",
                        ),
                        CredentialParams(
                            CredentialParamsType.KEY_PATH, "m/1852'/1815'/0'/5/0"
                        ),
                    ),
                ),
                Certificate(
                    CertificateType.DREP_REGISTRATION,
                    DRepRegistrationParams(
                        CredentialParams(
                            CredentialParamsType.SCRIPT_HASH,
                            "1afd028b504c3668102b129b37a86c09a2872f76741dc7a68e2149c8",
                        ),
                        19,
                    ),
                ),
                Certificate(
                    CertificateType.STAKE_REGISTRATION_CONWAY,
                    StakeRegistrationConwayParams(
                        CredentialParams(
                            CredentialParamsType.SCRIPT_HASH,
                            "122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277",
                        ),
                        17,
                    ),
                ),
            ],
        ),
        signingMode=TransactionSigningMode.PLUTUS_TRANSACTION,
        txBody="a500818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b700018182582b82d818582183581c9e1c71de652ec8b85fec296f0685ca3988781c94a2e1a5d89d92f45fa0001a0d0c25611a002dd2e802182a030a048483098201581c122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b42778200581cba41c59ac6e1a0e4ac304af98db801097d0bf8d2a5b28a54752426a1830e8201581c1afd028b504c3668102b129b37a86c09a2872f76741dc7a68e2149c88200581cd098c6a0a621f3343abe55877ee88fd5a83363e3c7887b3c4883909284108201581c1afd028b504c3668102b129b37a86c09a2872f76741dc7a68e2149c813f683078201581c122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b427711",
        expected_warnings=[WarningBit.WARNING_BIT_PLUTUS_MISSING_COLLATERAL, WarningBit.WARNING_BIT_PLUTUS_UNKNOWN_COLLATERAL, WarningBit.WARNING_BIT_PLUTUS_MISSING_SCRIPT_DATA_HASH],
    ),
]

testsMultisig: List[SignTxTestCase] = [
    SignTxTestCase(
        name="Sign_tx_without_change_address_with_Shelley_scripthash_output",
        tx=Transaction(
            network=Testnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["externalShelleyBaseScripthashKeyhash"]],
        ),
        signingMode=TransactionSigningMode.MULTISIG_TRANSACTION,
        txBody="a400818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7000181825839105e2f080eb93bad86d401545e0ce5f2221096d6477e11e6643922fa8d2ed495234dc0d667c1316ff84e572310e265edb31330448b36b7179e0102182a030a",
        additionalWitnessPaths=["m/1854'/1815'/0'/0/0"],
        expected_warnings=[WarningBit.WARNING_BIT_NETWORK_UNUSUAL, WarningBit.WARNING_BIT_OUTPUT_MISSING_DATUM],
    ),
    SignTxTestCase(
        name="Sign_tx_with_script_based_withdrawal",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["externalByronMainnet"]],
            withdrawals=[
                Withdrawal(
                    CredentialParams(
                        CredentialParamsType.SCRIPT_HASH,
                        "122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277",
                    ),
                    111,
                )
            ],
        ),
        signingMode=TransactionSigningMode.MULTISIG_TRANSACTION,
        txBody="a500818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b700018182582b82d818582183581c9e1c71de652ec8b85fec296f0685ca3988781c94a2e1a5d89d92f45fa0001a0d0c25611a002dd2e802182a030a05a1581df1122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277186f",
        additionalWitnessPaths=["m/1854'/1815'/0'/2/0"],
    ),
    SignTxTestCase(
        name="Sign_tx_with_a_stake_registration_script_certificate",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["externalByronMainnet"]],
            certificates=[
                Certificate(
                    CertificateType.STAKE_REGISTRATION,
                    StakeRegistrationParams(
                        CredentialParams(
                            CredentialParamsType.SCRIPT_HASH,
                            "122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277",
                        )
                    ),
                )
            ],
        ),
        signingMode=TransactionSigningMode.MULTISIG_TRANSACTION,
        txBody="a500818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b700018182582b82d818582183581c9e1c71de652ec8b85fec296f0685ca3988781c94a2e1a5d89d92f45fa0001a0d0c25611a002dd2e802182a030a048182008201581c122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277",
        additionalWitnessPaths=["m/1854'/1815'/0'/2/0"],
    ),
    SignTxTestCase(
        name="Sign_tx_with_a_stake_delegation_script_certificate",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["externalByronMainnet"]],
            certificates=[
                Certificate(
                    CertificateType.STAKE_DELEGATION,
                    StakeDelegationParams(
                        CredentialParams(
                            CredentialParamsType.SCRIPT_HASH,
                            "122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277",
                        ),
                        "f61c42cbf7c8c53af3f520508212ad3e72f674f957fe23ff0acb4973",
                    ),
                )
            ],
        ),
        signingMode=TransactionSigningMode.MULTISIG_TRANSACTION,
        txBody="a500818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b700018182582b82d818582183581c9e1c71de652ec8b85fec296f0685ca3988781c94a2e1a5d89d92f45fa0001a0d0c25611a002dd2e802182a030a048183028201581c122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277581cf61c42cbf7c8c53af3f520508212ad3e72f674f957fe23ff0acb4973",
        additionalWitnessPaths=["m/1854'/1815'/0'/2/0"],
    ),
    SignTxTestCase(
        name="Sign_tx_with_a_stake_deregistration_script_certificate",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["externalByronMainnet"]],
            certificates=[
                Certificate(
                    CertificateType.STAKE_DEREGISTRATION,
                    StakeRegistrationParams(
                        CredentialParams(
                            CredentialParamsType.SCRIPT_HASH,
                            "122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277",
                        )
                    ),
                )
            ],
        ),
        signingMode=TransactionSigningMode.MULTISIG_TRANSACTION,
        txBody="a500818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b700018182582b82d818582183581c9e1c71de652ec8b85fec296f0685ca3988781c94a2e1a5d89d92f45fa0001a0d0c25611a002dd2e802182a030a048182018201581c122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277",
        additionalWitnessPaths=["m/1854'/1815'/0'/2/0"],
    ),
]

testsAllegra: List[SignTxTestCase] = [
    SignTxTestCase(
        name="Sign_tx_with_no_ttl_and_no_validity_interval_start",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["externalShelleyBaseKeyhashKeyhash"]],
            ttl=None,
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a300818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7000181825839017cb05fce110fb999f01abb4f62bc455e217d4a51fde909fa9aea545443ac53c046cf6a42095e3c60310fa802771d0672f8fe2d1861138b090102182a",
    ),
    SignTxTestCase(
        name="Sign_tx_with_no_ttl_but_with_validity_interval_start",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["externalShelleyBaseKeyhashKeyhash"]],
            ttl=None,
            validityIntervalStart=47,
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a400818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7000181825839017cb05fce110fb999f01abb4f62bc455e217d4a51fde909fa9aea545443ac53c046cf6a42095e3c60310fa802771d0672f8fe2d1861138b090102182a08182f",
    ),
]

testsMary: List[SignTxTestCase] = [
    SignTxTestCase(
        name="Sign_tx_with_a_multiasset_output",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["multiassetOneToken"], outputs["internalBaseWithStakingPath"]],
            validityIntervalStart=7,
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a500818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b700018282583901eb0baa5e570cffbe2934db29df0b6a3d7c0430ee65d4c3a7ab2fefb91bc428e4720702ebd5dab4fb175324c192dc9bb76cc5da956e3c8dff821904d2a1581c95a292ffee938be03e9bae5657982a74e9014eb4960108c9e23a5b39a14874652474436f696e1a007838628258390114c16d7f43243bd81478e68b9db53a8528fd4fb1078d58d54a7f11241d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c1a006ca79302182a030a0807",
    ),
    SignTxTestCase(
        name="Sign_tx_with_a_complex_multiasset_output",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["multiassetManyTokens"], outputs["internalBaseWithStakingPath"]],
            validityIntervalStart=7,
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a500818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b700018282583901eb0baa5e570cffbe2934db29df0b6a3d7c0430ee65d4c3a7ab2fefb91bc428e4720702ebd5dab4fb175324c192dc9bb76cc5da956e3c8dff821904d2a2581c7eae28af2208be856f7a119668ae52a49b73725e326dc16579dcc373a34003581c1e349c9bdea19fd6c147626a5260bc44b71635f398b67c59881df209015820000000000000000000000000000000000000000000000000000000000000000002581c95a292ffee938be03e9bae5657982a74e9014eb4960108c9e23a5b39a248456c204e69c3b16f1904d24874652474436f696e1a007838628258390114c16d7f43243bd81478e68b9db53a8528fd4fb1078d58d54a7f11241d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c1a006ca79302182a030a0807",
    ),
    SignTxTestCase(
        name="Sign_tx_with_big_numbers",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["multiassetBigNumber"]],
            fee=24103998870869519,
            ttl=24103998870869519,
            validityIntervalStart=24103998870869519,
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a500818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b700018182583901eb0baa5e570cffbe2934db29df0b6a3d7c0430ee65d4c3a7ab2fefb91bc428e4720702ebd5dab4fb175324c192dc9bb76cc5da956e3c8dff821b0055a275925d560fa1581c95a292ffee938be03e9bae5657982a74e9014eb4960108c9e23a5b39a14874652474436f696e1b0055a275925d560f021b0055a275925d560f031b0055a275925d560f081b0055a275925d560f",
        expected_warnings=[WarningBit.WARNING_BIT_HIGH_FEE],
    ),
    SignTxTestCase(
        name="Sign_tx_with_a_multiasset_change_output",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["externalShelleyBaseKeyhashKeyhash"], outputs["multiassetChange"]],
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a400818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7000182825839017cb05fce110fb999f01abb4f62bc455e217d4a51fde909fa9aea545443ac53c046cf6a42095e3c60310fa802771d0672f8fe2d1861138b09018258390114c16d7f43243bd81478e68b9db53a8528fd4fb1078d58d54a7f11241d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c821904d2a1581c95a292ffee938be03e9bae5657982a74e9014eb4960108c9e23a5b39a14874652474436f696e1a0078386202182a030a",
    ),
    SignTxTestCase(
        name="Sign_tx_with_zero_fee_TTL_and_validity_interval_start",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["internalBaseWithStakingPath"]],
            fee=0,
            ttl=0,
            validityIntervalStart=0,
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a500818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b70001818258390114c16d7f43243bd81478e68b9db53a8528fd4fb1078d58d54a7f11241d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c1a006ca793020003000800",
    ),
    SignTxTestCase(
        name="Sign_tx_with_output_with_decimal_places",
        tx=Transaction(
            network=Mainnet, inputs=[inputs["utxoShelley"]], outputs=[outputs["multiassetDecimalPlaces"]], fee=33, ttl=None
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a300818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b700018182583901eb0baa5e570cffbe2934db29df0b6a3d7c0430ee65d4c3a7ab2fefb91bc428e4720702ebd5dab4fb175324c192dc9bb76cc5da956e3c8dff821904d2a2581c6954264b15bc92d6d592febeac84f14645e1ed46ca5ebb9acdb5c15fa14553545249501a0034bf15581caf2e27f580f7f08e93190a81f72462f153026d06450924726645891ba244445249501904d24cffffffffffffffffffffffff1904d2021821",
    ),
    SignTxTestCase(
        name="Sign_tx_with_mint_fields_with_various_amounts",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[],
            mint=mints["mintAmountVariety"],
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a500818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b700018002182a030a09a1581c7eae28af2208be856f7a119668ae52a49b73725e326dc16579dcc373a3581c1e349c9bdea19fd6c147626a5260bc44b71635f398b67c59881df20920581c1e349c9bdea19fd6c147626a5260bc44b71635f398b67c59881df20a1b7fffffffffffffff581c1e349c9bdea19fd6c147626a5260bc44b71635f398b67c59881df20b3b7fffffffffffffff",
        expected_warnings=[WarningBit.WARNING_BIT_NETWORK_NOT_VERIFIABLE],
    ),
    SignTxTestCase(
        name="Sign_tx_with_mint_with_decimal_places",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["externalShelleyBaseKeyhashKeyhash"]],
            fee=33,
            ttl=None,
            mint=mints["mintWithDecimalPlaces"],
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a400818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7000181825839017cb05fce110fb999f01abb4f62bc455e217d4a51fde909fa9aea545443ac53c046cf6a42095e3c60310fa802771d0672f8fe2d1861138b090102182109a2581c6954264b15bc92d6d592febeac84f14645e1ed46ca5ebb9acdb5c15fa14553545249503a0034bf14581caf2e27f580f7f08e93190a81f72462f153026d06450924726645891ba244445249501904d24cffffffffffffffffffffffff1904d2",
    ),
    SignTxTestCase(
        name="Sign_tx_with_mint_fields_among_other_fields",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["multiassetOneToken"], outputs["internalBaseWithStakingPath"]],
            fee=10,
            ttl=1000,
            validityIntervalStart=100,
            mint=mints["mintAmountVariety"],
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a600818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b700018282583901eb0baa5e570cffbe2934db29df0b6a3d7c0430ee65d4c3a7ab2fefb91bc428e4720702ebd5dab4fb175324c192dc9bb76cc5da956e3c8dff821904d2a1581c95a292ffee938be03e9bae5657982a74e9014eb4960108c9e23a5b39a14874652474436f696e1a007838628258390114c16d7f43243bd81478e68b9db53a8528fd4fb1078d58d54a7f11241d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c1a006ca793020a031903e808186409a1581c7eae28af2208be856f7a119668ae52a49b73725e326dc16579dcc373a3581c1e349c9bdea19fd6c147626a5260bc44b71635f398b67c59881df20920581c1e349c9bdea19fd6c147626a5260bc44b71635f398b67c59881df20a1b7fffffffffffffff581c1e349c9bdea19fd6c147626a5260bc44b71635f398b67c59881df20b3b7fffffffffffffff",
    ),
]

testsAlonzoTrezorComparison: List[SignTxTestCase] = [
    SignTxTestCase(
        name="Sign_tx_Full_test_for_trezor_feature_parity",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoMultisig"]],
            outputs=[outputs["trezorParity1"], outputs["trezorParityDatumHash1"]],
            validityIntervalStart=47,
            certificates=[
                Certificate(
                    CertificateType.STAKE_REGISTRATION,
                    StakeRegistrationParams(
                        CredentialParams(
                            CredentialParamsType.SCRIPT_HASH,
                            "29fb5fd4aa8cadd6705acc8263cee0fc62edca5ac38db593fec2f9fd",
                        )
                    ),
                ),
                Certificate(
                    CertificateType.STAKE_DEREGISTRATION,
                    StakeRegistrationParams(
                        CredentialParams(
                            CredentialParamsType.SCRIPT_HASH,
                            "29fb5fd4aa8cadd6705acc8263cee0fc62edca5ac38db593fec2f9fd",
                        )
                    ),
                ),
                Certificate(
                    CertificateType.STAKE_DELEGATION,
                    StakeDelegationParams(
                        CredentialParams(
                            CredentialParamsType.SCRIPT_HASH,
                            "29fb5fd4aa8cadd6705acc8263cee0fc62edca5ac38db593fec2f9fd",
                        ),
                        "f61c42cbf7c8c53af3f520508212ad3e72f674f957fe23ff0acb4973",
                    ),
                ),
            ],
            withdrawals=[
                Withdrawal(
                    CredentialParams(
                        CredentialParamsType.SCRIPT_HASH,
                        "29fb5fd4aa8cadd6705acc8263cee0fc62edca5ac38db593fec2f9fd",
                    ),
                    1000,
                )
            ],
            mint=mints["trezorComparison"],
            includeNetworkId=True,
            auxiliaryData=TxAuxiliaryData(
                TxAuxiliaryDataType.ARBITRARY_HASH,
                TxAuxiliaryDataHash(
                    "58ec01578fcdfdc376f09631a7b2adc608eaf57e3720484c7ff37c13cff90fdf"
                ),
            ),
            scriptDataHash="3b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7",
        ),
        signingMode=TransactionSigningMode.MULTISIG_TRANSACTION,
        txBody="ab00818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b700018282583901eb0baa5e570cffbe2934db29df0b6a3d7c0430ee65d4c3a7ab2fefb91bc428e4720702ebd5dab4fb175324c192dc9bb76cc5da956e3c8dff821a001e8480a1581c0d63e8d2c5a00cbcffbdf9112487c443466e1ea7d8c834df5ac5c425a14874657374436f696e1a0078386283581d71477e52b3116b62fe8cd34a312615f5fcd678c94e1d6cdb86c1a3964c0158203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b702182a030a048382008201581c29fb5fd4aa8cadd6705acc8263cee0fc62edca5ac38db593fec2f9fd82018201581c29fb5fd4aa8cadd6705acc8263cee0fc62edca5ac38db593fec2f9fd83028201581c29fb5fd4aa8cadd6705acc8263cee0fc62edca5ac38db593fec2f9fd581cf61c42cbf7c8c53af3f520508212ad3e72f674f957fe23ff0acb497305a1581df129fb5fd4aa8cadd6705acc8263cee0fc62edca5ac38db593fec2f9fd1903e807582058ec01578fcdfdc376f09631a7b2adc608eaf57e3720484c7ff37c13cff90fdf08182f09a1581c0d63e8d2c5a00cbcffbdf9112487c443466e1ea7d8c834df5ac5c425a24874657374436f696e1a007838624875657374436f696e3a007838610b58203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b70f01",
        additionalWitnessPaths=["m/1854'/1815'/0'/0/0", "m/1854'/1815'/0'/2/0"],
    ),
]

testsBabbageTrezorComparison: List[SignTxTestCase] = [
    SignTxTestCase(
        name="Sign_tx_Full_test_for_trezor_feature_parity_Babbage_elements_Plutus",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["trezorParity2"], outputs["trezorParityDatumHash2"]],
            validityIntervalStart=47,
            includeNetworkId=True,
            scriptDataHash="3b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7",
            collateralInputs=[inputs["utxoShelley"]],
            collateralOutput=outputs["externalShelleyBaseKeyhashKeyhash"],
            totalCollateral=10,
            referenceInputs=[inputs["utxoShelley"]],
        ),
        signingMode=TransactionSigningMode.PLUTUS_TRANSACTION,
        txBody="ab00818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7000182825839017cb05fce110fb999f01abb4f62bc455e217d4a51fde909fa9aea545443ac53c046cf6a42095e3c60310fa802771d0672f8fe2d1861138b09821a001e8480a1581c0d63e8d2c5a00cbcffbdf9112487c443466e1ea7d8c834df5ac5c425a14874657374436f696e1a0078386283581d71477e52b3116b62fe8cd34a312615f5fcd678c94e1d6cdb86c1a3964c0158203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b702182a030a08182f0b58203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b70d818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7000f0110825839017cb05fce110fb999f01abb4f62bc455e217d4a51fde909fa9aea545443ac53c046cf6a42095e3c60310fa802771d0672f8fe2d1861138b0901110a12818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b700",
    ),
    SignTxTestCase(
        name="Sign_tx_Full_test_for_trezor_feature_parity_Babbage_elements_ordinary",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["trezorParityBabbageOutputs"]],
            validityIntervalStart=47,
            includeNetworkId=True,
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a600818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7000181a400581d71477e52b3116b62fe8cd34a312615f5fcd678c94e1d6cdb86c1a3964c0101028201d818565579657420616e6f746865722063686f636f6c61746503d81858390080f9e2c88e6c817008f3a812ed889b4a4da8e0bd103f86e7335422aa122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b427702182a030a08182f0f01",
    ),
]

testsMultidelegation: List[SignTxTestCase] = [
    SignTxTestCase(
        name="Sign_tx_with_multidelegation_keys_in_all_tx_elements",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley2"]],
            outputs=[outputs["trezorParity1"], outputs["trezorParityDatumHash1"]],
            validityIntervalStart=47,
            certificates=[
                Certificate(
                    CertificateType.STAKE_REGISTRATION,
                    StakeRegistrationParams(
                        CredentialParams(
                            CredentialParamsType.KEY_PATH, "m/1852'/1815'/0'/2/2"
                        )
                    ),
                ),
                Certificate(
                    CertificateType.STAKE_DEREGISTRATION,
                    StakeRegistrationParams(
                        CredentialParams(
                            CredentialParamsType.KEY_PATH, "m/1852'/1815'/0'/2/2"
                        )
                    ),
                ),
                Certificate(
                    CertificateType.STAKE_DELEGATION,
                    StakeDelegationParams(
                        CredentialParams(
                            CredentialParamsType.KEY_PATH, "m/1852'/1815'/0'/2/2"
                        ),
                        "f61c42cbf7c8c53af3f520508212ad3e72f674f957fe23ff0acb4973",
                    ),
                ),
            ],
            withdrawals=[
                Withdrawal(
                    CredentialParams(
                        CredentialParamsType.KEY_PATH, "m/1852'/1815'/0'/2/3"
                    ),
                    1000,
                )
            ],
            requiredSigners=[
                RequiredSigner(TxRequiredSignerType.PATH, "m/1852'/1815'/0'/2/4")
            ],
            scriptDataHash="3b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7",
            includeNetworkId=True,
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="aa00818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b700018282583901eb0baa5e570cffbe2934db29df0b6a3d7c0430ee65d4c3a7ab2fefb91bc428e4720702ebd5dab4fb175324c192dc9bb76cc5da956e3c8dff821a001e8480a1581c0d63e8d2c5a00cbcffbdf9112487c443466e1ea7d8c834df5ac5c425a14874657374436f696e1a0078386283581d71477e52b3116b62fe8cd34a312615f5fcd678c94e1d6cdb86c1a3964c0158203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b702182a030a048382008200581cee6d266f2b60add5a249a3754f91cf1f423ac94c6cd964b3814f21a382018200581cee6d266f2b60add5a249a3754f91cf1f423ac94c6cd964b3814f21a383028200581cee6d266f2b60add5a249a3754f91cf1f423ac94c6cd964b3814f21a3581cf61c42cbf7c8c53af3f520508212ad3e72f674f957fe23ff0acb497305a1581de198acedf1c6b691f963d928147f66697c7cda3899e30c613037a4e9901903e808182f0b58203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b70e81581c86df572e0e28bec8ca8066e9d8c3681b4ac86c43c57cd52eb06ae8640f01",
        additionalWitnessPaths=["m/1852'/1815'/0'/0/0", "m/1852'/1815'/0'/2/5"],
    ),
]

testsConwayWithoutCertificates: List[SignTxTestCase] = [
    SignTxTestCase(
        name="Sign_tx_with_treasury",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["externalByronMainnet"]],
            treasury=27,
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a500818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b700018182582b82d818582183581c9e1c71de652ec8b85fec296f0685ca3988781c94a2e1a5d89d92f45fa0001a0d0c25611a002dd2e802182a030a15181b",
    ),
    SignTxTestCase(
        name="Sign_tx_with_donation",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["externalByronMainnet"]],
            donation=28,
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a500818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b700018182582b82d818582183581c9e1c71de652ec8b85fec296f0685ca3988781c94a2e1a5d89d92f45fa0001a0d0c25611a002dd2e802182a030a16181c",
    ),
    SignTxTestCase(
        name="Sign_tx_with_treasury_and_donation",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["externalByronMainnet"]],
            treasury=27,
            donation=28,
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a600818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b700018182582b82d818582183581c9e1c71de652ec8b85fec296f0685ca3988781c94a2e1a5d89d92f45fa0001a0d0c25611a002dd2e802182a030a15181b16181c",
    ),
]

vote1 = Vote(
    GovActionId("3b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7", 3),
    VotingProcedure(
        VoteOption.ABSTAIN,
        AnchorParams(
            "www.vacuumlabs.com",
            "1afd028b504c3668102b129b37a86c09a2872f76741dc7a68e2149c8deadbeef",
        ),
    ),
)
vote2 = Vote(
    GovActionId("3b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7", 3),
    VotingProcedure(VoteOption.NO),
)
vote3 = Vote(
    GovActionId("3b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7", 3),
    VotingProcedure(VoteOption.YES),
)
vote1_unique = Vote(
    GovActionId("3b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7", 3),
    VotingProcedure(
        VoteOption.ABSTAIN,
        AnchorParams(
            "www.vacuumlabs.com",
            "1afd028b504c3668102b129b37a86c09a2872f76741dc7a68e2149c8deadbeef",
        ),
    ),
)
vote2_unique = Vote(
    GovActionId("3b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7", 4),
    VotingProcedure(VoteOption.NO),
)
vote3_unique = Vote(
    GovActionId("3b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7", 5),
    VotingProcedure(VoteOption.YES),
)

testsConwayVotingProcedures: List[SignTxTestCase] = [
    SignTxTestCase(
        name="Sign_tx_with_voting_procedures_COMMITTEE_KEY_PATH_voter",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["externalByronMainnet"]],
            votingProcedures=[
                VoterVotes(
                    Voter(VoterType.COMMITTEE_KEY_PATH, "m/1852'/1815'/0'/5/0"), [vote1]
                )
            ],
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a500818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b700018182582b82d818582183581c9e1c71de652ec8b85fec296f0685ca3988781c94a2e1a5d89d92f45fa0001a0d0c25611a002dd2e802182a030a13a18200581cd098c6a0a621f3343abe55877ee88fd5a83363e3c7887b3c48839092a18258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b703820282727777772e76616375756d6c6162732e636f6d58201afd028b504c3668102b129b37a86c09a2872f76741dc7a68e2149c8deadbeef",
    ),
    SignTxTestCase(
        name="Sign_tx_with_voting_procedures_DREP_KEY_PATH_voter",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["externalByronMainnet"]],
            votingProcedures=[
                VoterVotes(
                    Voter(VoterType.DREP_KEY_PATH, "m/1852'/1815'/0'/3/0"), [vote2]
                )
            ],
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a500818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b700018182582b82d818582183581c9e1c71de652ec8b85fec296f0685ca3988781c94a2e1a5d89d92f45fa0001a0d0c25611a002dd2e802182a030a13a18202581cba41c59ac6e1a0e4ac304af98db801097d0bf8d2a5b28a54752426a1a18258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7038200f6",
    ),
    SignTxTestCase(
        name="Sign_tx_with_voting_procedures_STAKE_POOL_KEY_PATH_voter",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["externalByronMainnet"]],
            votingProcedures=[
                VoterVotes(
                    Voter(VoterType.STAKE_POOL_KEY_PATH, "m/1853'/1815'/0'/0'"), [vote3]
                )
            ],
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a500818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b700018182582b82d818582183581c9e1c71de652ec8b85fec296f0685ca3988781c94a2e1a5d89d92f45fa0001a0d0c25611a002dd2e802182a030a13a18204581cdbfee4665e58c8f8e9b9ff02b17f32e08a42c855476a5d867c2737b7a18258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7038201f6",
    ),
    SignTxTestCase(
        name="Sign_tx_with_voting_procedures_COMMITTEE_KEY_HASH_voter",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["externalByronMainnet"]],
            votingProcedures=[
                VoterVotes(
                    Voter(
                        VoterType.COMMITTEE_KEY_HASH,
                        "7afd028b504c3668102b129b37a86c09a2872f76741dc7a68e2149c8",
                    ),
                    [vote1],
                )
            ],
        ),
        signingMode=TransactionSigningMode.PLUTUS_TRANSACTION,
        txBody="a500818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b700018182582b82d818582183581c9e1c71de652ec8b85fec296f0685ca3988781c94a2e1a5d89d92f45fa0001a0d0c25611a002dd2e802182a030a13a18200581c7afd028b504c3668102b129b37a86c09a2872f76741dc7a68e2149c8a18258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b703820282727777772e76616375756d6c6162732e636f6d58201afd028b504c3668102b129b37a86c09a2872f76741dc7a68e2149c8deadbeef",
        expected_warnings=[WarningBit.WARNING_BIT_PLUTUS_MISSING_COLLATERAL, WarningBit.WARNING_BIT_PLUTUS_UNKNOWN_COLLATERAL, WarningBit.WARNING_BIT_PLUTUS_MISSING_SCRIPT_DATA_HASH],
    ),
    SignTxTestCase(
        name="Sign_tx_with_voting_procedures_COMMITTEE_SCRIPT_HASH_voter",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["externalByronMainnet"]],
            votingProcedures=[
                VoterVotes(
                    Voter(
                        VoterType.COMMITTEE_SCRIPT_HASH,
                        "7afd028b504c3668102b129b37a86c09a2872f76741dc7a68e2149c8",
                    ),
                    [vote2],
                )
            ],
        ),
        signingMode=TransactionSigningMode.PLUTUS_TRANSACTION,
        txBody="a500818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b700018182582b82d818582183581c9e1c71de652ec8b85fec296f0685ca3988781c94a2e1a5d89d92f45fa0001a0d0c25611a002dd2e802182a030a13a18201581c7afd028b504c3668102b129b37a86c09a2872f76741dc7a68e2149c8a18258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7038200f6",
        expected_warnings=[WarningBit.WARNING_BIT_PLUTUS_MISSING_COLLATERAL, WarningBit.WARNING_BIT_PLUTUS_UNKNOWN_COLLATERAL, WarningBit.WARNING_BIT_PLUTUS_MISSING_SCRIPT_DATA_HASH],
    ),
    SignTxTestCase(
        name="Sign_tx_with_voting_procedures_DREP_KEY_HASH_voter",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["externalByronMainnet"]],
            votingProcedures=[
                VoterVotes(
                    Voter(
                        VoterType.DREP_KEY_HASH,
                        "7afd028b504c3668102b129b37a86c09a2872f76741dc7a68e2149c8",
                    ),
                    [vote3],
                )
            ],
        ),
        signingMode=TransactionSigningMode.PLUTUS_TRANSACTION,
        txBody="a500818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b700018182582b82d818582183581c9e1c71de652ec8b85fec296f0685ca3988781c94a2e1a5d89d92f45fa0001a0d0c25611a002dd2e802182a030a13a18202581c7afd028b504c3668102b129b37a86c09a2872f76741dc7a68e2149c8a18258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7038201f6",
        expected_warnings=[WarningBit.WARNING_BIT_PLUTUS_MISSING_COLLATERAL, WarningBit.WARNING_BIT_PLUTUS_UNKNOWN_COLLATERAL, WarningBit.WARNING_BIT_PLUTUS_MISSING_SCRIPT_DATA_HASH],
    ),
    SignTxTestCase(
        name="Sign_tx_with_voting_procedures_DREP_SCRIPT_HASH_voter",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["externalByronMainnet"]],
            votingProcedures=[
                VoterVotes(
                    Voter(
                        VoterType.DREP_SCRIPT_HASH,
                        "7afd028b504c3668102b129b37a86c09a2872f76741dc7a68e2149c8",
                    ),
                    [vote1],
                )
            ],
        ),
        signingMode=TransactionSigningMode.PLUTUS_TRANSACTION,
        txBody="a500818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b700018182582b82d818582183581c9e1c71de652ec8b85fec296f0685ca3988781c94a2e1a5d89d92f45fa0001a0d0c25611a002dd2e802182a030a13a18203581c7afd028b504c3668102b129b37a86c09a2872f76741dc7a68e2149c8a18258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b703820282727777772e76616375756d6c6162732e636f6d58201afd028b504c3668102b129b37a86c09a2872f76741dc7a68e2149c8deadbeef",
        expected_warnings=[WarningBit.WARNING_BIT_PLUTUS_MISSING_COLLATERAL, WarningBit.WARNING_BIT_PLUTUS_UNKNOWN_COLLATERAL, WarningBit.WARNING_BIT_PLUTUS_MISSING_SCRIPT_DATA_HASH],
    ),
    SignTxTestCase(
        name="Sign_tx_with_voting_procedures_STAKE_POOL_KEY_HASH_voter",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["externalByronMainnet"]],
            votingProcedures=[
                VoterVotes(
                    Voter(
                        VoterType.STAKE_POOL_KEY_HASH,
                        "7afd028b504c3668102b129b37a86c09a2872f76741dc7a68e2149c8",
                    ),
                    [vote1],
                )
            ],
        ),
        signingMode=TransactionSigningMode.PLUTUS_TRANSACTION,
        txBody="a500818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b700018182582b82d818582183581c9e1c71de652ec8b85fec296f0685ca3988781c94a2e1a5d89d92f45fa0001a0d0c25611a002dd2e802182a030a13a18204581c7afd028b504c3668102b129b37a86c09a2872f76741dc7a68e2149c8a18258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b703820282727777772e76616375756d6c6162732e636f6d58201afd028b504c3668102b129b37a86c09a2872f76741dc7a68e2149c8deadbeef",
        expected_warnings=[WarningBit.WARNING_BIT_PLUTUS_MISSING_COLLATERAL, WarningBit.WARNING_BIT_PLUTUS_UNKNOWN_COLLATERAL, WarningBit.WARNING_BIT_PLUTUS_MISSING_SCRIPT_DATA_HASH],
    ),
    SignTxTestCase(
        name="Sign_tx_with_voting_procedures_single_voter_multiple_votes",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["externalByronMainnet"]],
            votingProcedures=[
                VoterVotes(
                    Voter(VoterType.DREP_KEY_PATH, "m/1852'/1815'/0'/3/0"),
                    [vote1_unique, vote2_unique, vote3_unique],
                )
            ],
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a500818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b700018182582b82d818582183581c9e1c71de652ec8b85fec296f0685ca3988781c94a2e1a5d89d92f45fa0001a0d0c25611a002dd2e802182a030a13a18202581cba41c59ac6e1a0e4ac304af98db801097d0bf8d2a5b28a54752426a1a38258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b703820282727777772e76616375756d6c6162732e636f6d58201afd028b504c3668102b129b37a86c09a2872f76741dc7a68e2149c8deadbeef8258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7048200f68258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7058201f6",
    ),
    SignTxTestCase(
        name="Sign_tx_with_voting_procedures_multiple_voters_single_vote",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["externalByronMainnet"]],
            votingProcedures=[
                VoterVotes(
                    Voter(VoterType.COMMITTEE_KEY_PATH, "m/1852'/1815'/0'/5/0"),
                    [vote1_unique],
                ),
                VoterVotes(
                    Voter(VoterType.DREP_KEY_PATH, "m/1852'/1815'/0'/3/0"),
                    [vote2_unique],
                ),
                VoterVotes(
                    Voter(VoterType.STAKE_POOL_KEY_PATH, "m/1853'/1815'/0'/0'"),
                    [vote3_unique],
                ),
            ],
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a500818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b700018182582b82d818582183581c9e1c71de652ec8b85fec296f0685ca3988781c94a2e1a5d89d92f45fa0001a0d0c25611a002dd2e802182a030a13a38200581cd098c6a0a621f3343abe55877ee88fd5a83363e3c7887b3c48839092a18258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b703820282727777772e76616375756d6c6162732e636f6d58201afd028b504c3668102b129b37a86c09a2872f76741dc7a68e2149c8deadbeef8202581cba41c59ac6e1a0e4ac304af98db801097d0bf8d2a5b28a54752426a1a18258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7048200f68204581cdbfee4665e58c8f8e9b9ff02b17f32e08a42c855476a5d867c2737b7a18258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7058201f6",
    ),
    SignTxTestCase(
        name="Sign_tx_with_voting_procedures_multiple_voters_multiple_votes",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["externalByronMainnet"]],
            votingProcedures=[
                VoterVotes(
                    Voter(
                        VoterType.COMMITTEE_SCRIPT_HASH,
                        "8afd028b504c3668102b129b37a86c09a2872f76741dc7a68e2149c8",
                    ),
                    [vote2_unique, vote3_unique],
                ),
                VoterVotes(
                    Voter(VoterType.DREP_KEY_PATH, "m/1852'/1815'/0'/3/0"),
                    [vote1_unique, vote2_unique],
                ),
            ],
        ),
        signingMode=TransactionSigningMode.PLUTUS_TRANSACTION,
        txBody="a500818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b700018182582b82d818582183581c9e1c71de652ec8b85fec296f0685ca3988781c94a2e1a5d89d92f45fa0001a0d0c25611a002dd2e802182a030a13a28201581c8afd028b504c3668102b129b37a86c09a2872f76741dc7a68e2149c8a28258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7048200f68258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7058201f68202581cba41c59ac6e1a0e4ac304af98db801097d0bf8d2a5b28a54752426a1a28258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b703820282727777772e76616375756d6c6162732e636f6d58201afd028b504c3668102b129b37a86c09a2872f76741dc7a68e2149c8deadbeef8258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7048200f6",
        expected_warnings=[WarningBit.WARNING_BIT_PLUTUS_MISSING_COLLATERAL, WarningBit.WARNING_BIT_PLUTUS_UNKNOWN_COLLATERAL, WarningBit.WARNING_BIT_PLUTUS_MISSING_SCRIPT_DATA_HASH],
    ),
]

# =================
# signTxCVote
# =================
testsCatalystRegistration: List[SignTxTestCase] = [
    SignTxTestCase(
        name="Sign_tx_with_Catalyst_registration_metadata_with_base_address",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["internalBaseWithStakingPath"]],
            validityIntervalStart=7,
            auxiliaryData=TxAuxiliaryData(
                TxAuxiliaryDataType.CIP36_REGISTRATION,
                TxAuxiliaryDataCIP36(
                    CIP36VoteRegistrationFormat.CIP_15,
                    "m/1852'/1815'/0'/2/0",
                    destinations["internalBaseWithStakingPath"],
                    1454448,
                    "4b19e27ffc006ace16592311c4d2f0cafc255eaa47a6178ff540c0a46d07027c",
                ),
            ),
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a600818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b70001818258390114c16d7f43243bd81478e68b9db53a8528fd4fb1078d58d54a7f11241d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c1a006ca79302182a030a075820e9141b460aea0abb69ce113c7302c7c03690267736d6a382ee62d2a53c2ec9260807",
    ),
    SignTxTestCase(
        name="Sign_tx_with_Catalyst_registration_metadata_with_stake_address",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["internalBaseWithStakingPath"]],
            auxiliaryData=TxAuxiliaryData(
                TxAuxiliaryDataType.CIP36_REGISTRATION,
                TxAuxiliaryDataCIP36(
                    CIP36VoteRegistrationFormat.CIP_15,
                    "m/1852'/1815'/0'/2/0",
                    destinations["paymentKeyPath"],
                    1454448,
                    "4b19e27ffc006ace16592311c4d2f0cafc255eaa47a6178ff540c0a46d07027c",
                ),
            ),
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a500818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b70001818258390114c16d7f43243bd81478e68b9db53a8528fd4fb1078d58d54a7f11241d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c1a006ca79302182a030a075820d19f7cb4d48a6ae8d370c64d2a42fca1f61d6b2cf3d0c0c02801541811338deb",
        expected_aux_warnings=[WarningBit.WARNING_BIT_NETWORK_UNUSUAL],
    ),
]

testsCVoteRegistrationCIP36: List[SignTxTestCase] = [
    SignTxTestCase(
        name="Sign_tx_with_CIP36_registration_with_vote_key_hex",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["internalBaseWithStakingPath"]],
            auxiliaryData=TxAuxiliaryData(
                TxAuxiliaryDataType.CIP36_REGISTRATION,
                TxAuxiliaryDataCIP36(
                    CIP36VoteRegistrationFormat.CIP_36,
                    "m/1852'/1815'/0'/2/0",
                    destinations["paymentKeyPath"],
                    1454448,
                    "4b19e27ffc006ace16592311c4d2f0cafc255eaa47a6178ff540c0a46d07027c",
                ),
            ),
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a500818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b70001818258390114c16d7f43243bd81478e68b9db53a8528fd4fb1078d58d54a7f11241d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c1a006ca79302182a030a0758201999b3bb9102b585c42616e40cf1290518d788f967ab4b3329dcb712ac933da0",
        expected_aux_warnings=[WarningBit.WARNING_BIT_NETWORK_UNUSUAL],
    ),
    SignTxTestCase(
        name="Sign_tx_with_CIP36_registration_with_vote_key_path",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["internalBaseWithStakingPath"]],
            validityIntervalStart=7,
            auxiliaryData=TxAuxiliaryData(
                TxAuxiliaryDataType.CIP36_REGISTRATION,
                TxAuxiliaryDataCIP36(
                    CIP36VoteRegistrationFormat.CIP_36,
                    "m/1852'/1815'/0'/2/0",
                    destinations["internalBaseWithStakingPath"],
                    1454448,
                    "m/1694'/1815'/0'/0/1",
                ),
            ),
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a600818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b70001818258390114c16d7f43243bd81478e68b9db53a8528fd4fb1078d58d54a7f11241d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c1a006ca79302182a030a075820d05698c555a117014a3b360a66931ec43bf18e2aa16560fc99dbd92dd7f6f6540807",
    ),
    SignTxTestCase(
        name="Sign_tx_with_CIP36_registration_with_unusual_vote_key_path",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["internalBaseWithStakingPath"]],
            validityIntervalStart=7,
            auxiliaryData=TxAuxiliaryData(
                TxAuxiliaryDataType.CIP36_REGISTRATION,
                TxAuxiliaryDataCIP36(
                    CIP36VoteRegistrationFormat.CIP_36,
                    "m/1852'/1815'/0'/2/0",
                    destinations["internalBaseWithStakingPath"],
                    1454448,
                    "m/1694'/1815'/101'/0/1",
                ),
            ),
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a600818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b70001818258390114c16d7f43243bd81478e68b9db53a8528fd4fb1078d58d54a7f11241d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c1a006ca79302182a030a07582077be323b8df4c6aa1bf2f180112f85ffe8d7f658bc8febdf7dbd5a07453a31cb0807",
    ),
    SignTxTestCase(
        name="Sign_tx_with_CIP36_registration_with_thirdparty_payment_address",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["internalBaseWithStakingPath"]],
            validityIntervalStart=7,
            auxiliaryData=TxAuxiliaryData(
                TxAuxiliaryDataType.CIP36_REGISTRATION,
                TxAuxiliaryDataCIP36(
                    CIP36VoteRegistrationFormat.CIP_36,
                    "m/1852'/1815'/0'/2/0",
                    destinations["externalShelleyBaseKeyhashScripthash"],
                    1454448,
                    "m/1694'/1815'/0'/0/1",
                ),
            ),
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a600818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b70001818258390114c16d7f43243bd81478e68b9db53a8528fd4fb1078d58d54a7f11241d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c1a006ca79302182a030a07582042e408fb03986a958be9e2cca01623a31e23f86f31172a5a9b84acdfce6f0e750807",
        expected_aux_warnings=[WarningBit.WARNING_BIT_NETWORK_UNUSUAL],
    ),
    SignTxTestCase(
        name="Sign_tx_with_CIP36_registration_with_voting_purpose",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["internalBaseWithStakingPath"]],
            validityIntervalStart=7,
            auxiliaryData=TxAuxiliaryData(
                TxAuxiliaryDataType.CIP36_REGISTRATION,
                TxAuxiliaryDataCIP36(
                    CIP36VoteRegistrationFormat.CIP_36,
                    "m/1852'/1815'/0'/2/0",
                    destinations["internalBaseWithStakingPath"],
                    1454448,
                    "4b19e27ffc006ace16592311c4d2f0cafc255eaa47a6178ff540c0a46d07027c",
                    0,
                ),
            ),
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a600818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b70001818258390114c16d7f43243bd81478e68b9db53a8528fd4fb1078d58d54a7f11241d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c1a006ca79302182a030a075820d706aed1ebc1e8af188aae6d37ffdf4e259a0f04635bef5edce7f43ff632c4450807",
    ),
    SignTxTestCase(
        name="Sign_tx_with_CIP36_registration_with_delegations",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["internalBaseWithStakingPath"]],
            validityIntervalStart=7,
            auxiliaryData=TxAuxiliaryData(
                TxAuxiliaryDataType.CIP36_REGISTRATION,
                TxAuxiliaryDataCIP36(
                    CIP36VoteRegistrationFormat.CIP_36,
                    "m/1852'/1815'/0'/2/0",
                    destinations["internalBaseWithStakingPath"],
                    1454448,
                    votingPurpose=2790,
                    delegations=[
                        CIP36VoteDelegation(
                            CIP36VoteDelegationType.KEY,
                            "4b19e27ffc006ace16592311c4d2f0cafc255eaa47a6178ff540c0a46d07027c",
                            9,
                        ),
                        CIP36VoteDelegation(
                            CIP36VoteDelegationType.PATH, "m/1694'/1815'/0'/0/1", 0
                        ),
                    ],
                ),
            ),
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a600818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b70001818258390114c16d7f43243bd81478e68b9db53a8528fd4fb1078d58d54a7f11241d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c1a006ca79302182a030a075820f0e62a047ef597d9fb1bfefb9cd3f4e77558c33510ca552484ee8b5c77bbdf650807",
    ),
    SignTxTestCase(
        name="Sign_tx_with_CIP36_registration_with_delegation_unusual_path_warning",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["internalBaseWithStakingPath"]],
            validityIntervalStart=7,
            auxiliaryData=TxAuxiliaryData(
                TxAuxiliaryDataType.CIP36_REGISTRATION,
                TxAuxiliaryDataCIP36(
                    CIP36VoteRegistrationFormat.CIP_36,
                    "m/1852'/1815'/0'/2/0",
                    destinations["internalBaseWithStakingPath"],
                    1454448,
                    votingPurpose=2790,
                    delegations=[
                        CIP36VoteDelegation(
                            CIP36VoteDelegationType.KEY,
                            "4b19e27ffc006ace16592311c4d2f0cafc255eaa47a6178ff540c0a46d07027c",
                            9,
                        ),
                        CIP36VoteDelegation(
                            CIP36VoteDelegationType.PATH, "m/1694'/1815'/101'/0/1", 0
                        ),
                    ],
                ),
            ),
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a600818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b70001818258390114c16d7f43243bd81478e68b9db53a8528fd4fb1078d58d54a7f11241d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c1a006ca79302182a030a075820dbd3dcc45a668526741d94ba977b0055229dcc10171d4d622c3d700c1701a4110807",
        # For CIP36 auxiliary-data review, unusual vote-key paths are surfaced as
        # dedicated inline UI pairs, not as a separate warning modal.
        expected_aux_warnings=[],
    ),
    SignTxTestCase(
        name="Sign_tx_with_CIP36_registration_with_many_delegations_streaming",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["internalBaseWithStakingPath"]],
            validityIntervalStart=7,
            auxiliaryData=TxAuxiliaryData(
                TxAuxiliaryDataType.CIP36_REGISTRATION,
                TxAuxiliaryDataCIP36(
                    CIP36VoteRegistrationFormat.CIP_36,
                    "m/1852'/1815'/0'/2/0",
                    destinations["internalBaseWithStakingPath"],
                    1454448,
                    votingPurpose=2790,
                    delegations=[
                        CIP36VoteDelegation(
                            CIP36VoteDelegationType.KEY,
                            "4b19e27ffc006ace16592311c4d2f0cafc255eaa47a6178ff540c0a46d07027c",
                            1,
                        )
                    ]
                    * 90,
                ),
            ),
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a600818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b70001818258390114c16d7f43243bd81478e68b9db53a8528fd4fb1078d58d54a7f11241d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c1a006ca79302182a030a07582092cc23c0ff5952db0243e891ef08d1360ed9a33c6970156dfe945dd4df284d980807",
    ),
]

# =================
# signTxPlutus
# =================
def _make_tx_streaming_many_required_signers(required_signer_count: int) -> Transaction:
    return Transaction(
        network=Mainnet,
        inputs=[inputs["utxoShelley"]],
        outputs=[],
        requiredSigners=[
            RequiredSigner(
                TxRequiredSignerType.HASH,
                f"{i:0>8x}646c67fb467f8a5425e9c752e1e262b0420ba4b638f39514",
            )
            for i in range(required_signer_count)
        ],
        includeNetworkId=True,
    )


_tx_streaming_many_required_signers = _make_tx_streaming_many_required_signers(700)
_tx_streaming_many_required_signers_nano = _make_tx_streaming_many_required_signers(256)

_tx_streaming_many_outputs = Transaction(
    network=Mainnet,
    inputs=[inputs["utxoShelley"]],
    outputs=[
        TxOutputAlonzo(
            destinations["externalShelleyBaseKeyhashKeyhash"],
            1000000 + i,
        )
        for i in range(90)
    ],
    includeNetworkId=True,
)

testsAlonzo: List[SignTxTestCase] = [
    SignTxTestCase(
        name="Sign_tx_with_script_data_hash",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[],
            scriptDataHash="ffd4d009f554ba4fd8ed1f1d703244819861a9d34fd4753bcf3ff32f043ce188",
            includeNetworkId=True,
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a600818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b700018002182a030a0b5820ffd4d009f554ba4fd8ed1f1d703244819861a9d34fd4753bcf3ff32f043ce1880f01",
    ),
    # tx does not contain any Plutus elements, but should be accepted (differs only in UI)
    SignTxTestCase(
        name="Sign_tx_with_change_output_as_array",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["internalBaseWithStakingPath"]],
        ),
        signingMode=TransactionSigningMode.PLUTUS_TRANSACTION,
        txBody="a400818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b70001818258390114c16d7f43243bd81478e68b9db53a8528fd4fb1078d58d54a7f11241d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c1a006ca79302182a030a",
        expected_warnings=[WarningBit.WARNING_BIT_PLUTUS_MISSING_COLLATERAL, WarningBit.WARNING_BIT_PLUTUS_UNKNOWN_COLLATERAL, WarningBit.WARNING_BIT_PLUTUS_MISSING_SCRIPT_DATA_HASH],
    ),
    # Dedicated dense-warning fixture for warning-details snapshot coverage.
    SignTxTestCase(
        name="Sign_tx_with_maximum_warning_count",
        tx=Transaction(
            network=FakeNet,
            inputs=[inputs["utxoShelley"]],
            outputs=[
                TxOutputBabbage(
                    destinations["externalShelleyBaseScripthashKeyhashFakenet"],
                    7120787,
                    tokenBundle=[
                        AssetGroup(
                            "75a292ffee938be03e9bae5657982a74e9014eb4960108c9e23a5b39",
                            [Token("7564247542686911", 47), Token("7564247542686912", 7878754)],
                        )
                    ],
                )
            ],
            fee=6000001,
            certificates=[
                Certificate(
                    CertificateType.DREP_UPDATE,
                    DRepUpdateParams(
                        CredentialParams(
                            CredentialParamsType.KEY_PATH, "m/1852'/1815'/0'/3/0"
                        ),
                        AnchorParams(
                            "",
                            "1afd028b504c3668102b129b37a86c09a2872f76741dc7a68e2149c8deadbeef",
                        ),
                    ),
                )
            ],
            collateralOutput=TxOutputBabbage(
                TxOutputDestination(
                    TxOutputDestinationType.THIRD_PARTY,
                    ThirdPartyAddressParams(
                        "037cb05fce110fb999f01abb4f62bc455e217d4a51fde909fa9aea545443ac53c046cf6a42095e3c60310fa802771d0672f8fe2d1861138b09"
                    ),
                ),
                7120787,
                tokenBundle=[
                    AssetGroup(
                        "75a292ffee938be03e9bae5657982a74e9014eb4960108c9e23a5b39",
                        [Token("7564247542686911", 47)],
                    )
                ],
            ),
        ),
        signingMode=TransactionSigningMode.PLUTUS_TRANSACTION,
        txBody="a600818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7000181a2005839135e2f080eb93bad86d401545e0ce5f2221096d6477e11e6643922fa8d2ed495234dc0d667c1316ff84e572310e265edb31330448b36b7179e01821a006ca793a1581c75a292ffee938be03e9bae5657982a74e9014eb4960108c9e23a5b39a2487564247542686911182f4875642475426869121a00783862021a005b8d81030a048183128200581cba41c59ac6e1a0e4ac304af98db801097d0bf8d2a5b28a54752426a1826058201afd028b504c3668102b129b37a86c09a2872f76741dc7a68e2149c8deadbeef10a2005839037cb05fce110fb999f01abb4f62bc455e217d4a51fde909fa9aea545443ac53c046cf6a42095e3c60310fa802771d0672f8fe2d1861138b0901821a006ca793a1581c75a292ffee938be03e9bae5657982a74e9014eb4960108c9e23a5b39a1487564247542686911182f",
        expected_warnings=[
            WarningBit.WARNING_BIT_NETWORK_UNUSUAL,
            WarningBit.WARNING_BIT_PLUTUS_MISSING_COLLATERAL,
            WarningBit.WARNING_BIT_PLUTUS_UNKNOWN_COLLATERAL,
            WarningBit.WARNING_BIT_COLLATERAL_OUTPUT_WARNING,
            WarningBit.WARNING_BIT_PLUTUS_MISSING_SCRIPT_DATA_HASH,
            WarningBit.WARNING_BIT_OUTPUT_MISSING_DATUM,
            WarningBit.WARNING_BIT_EMPTY_ANCHOR_URL,
            WarningBit.WARNING_BIT_HIGH_FEE,
        ],
    ),
    SignTxTestCase(
        name="Sign_tx_with_datum_hash_in_output_as_array",
        tx=Transaction(
            network=Testnet, inputs=[inputs["utxoShelley"]], outputs=[outputs["datumHashExternal"]], fee=42, ttl=10
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a400818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7000181835839105e2f080eb93bad86d401545e0ce5f2221096d6477e11e6643922fa8d2ed495234dc0d667c1316ff84e572310e265edb31330448b36b7179e1a006ca7935820ffd4d009f554ba4fd8ed1f1d703244819861a9d34fd4753bcf3ff32f043ce18802182a030a",
        expected_warnings=[WarningBit.WARNING_BIT_NETWORK_UNUSUAL],
    ),
    SignTxTestCase(
        name="Sign_tx_with_datum_hash_in_output_as_array_fakenet_big_ttl",
        tx=Transaction(
            network=FakeNet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["datumHashExternalFakenet"]],
            fee=42,
            ttl=24103998870869519,
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a400818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7000181835839135e2f080eb93bad86d401545e0ce5f2221096d6477e11e6643922fa8d2ed495234dc0d667c1316ff84e572310e265edb31330448b36b7179e1a006ca7935820ffd4d009f554ba4fd8ed1f1d703244819861a9d34fd4753bcf3ff32f043ce18802182a031b0055a275925d560f",
        expected_warnings=[WarningBit.WARNING_BIT_NETWORK_UNUSUAL],
    ),
    SignTxTestCase(
        name="Sign_tx_with_datum_hash_in_output_as_array_mainnet_big_ttl_epoch_over_1000000",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["datumHashExternalMainnet"]],
            fee=42,
            ttl=24103998870869519,
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a400818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7000181835839115e2f080eb93bad86d401545e0ce5f2221096d6477e11e6643922fa8d2ed495234dc0d667c1316ff84e572310e265edb31330448b36b7179e1a006ca7935820ffd4d009f554ba4fd8ed1f1d703244819861a9d34fd4753bcf3ff32f043ce18802182a031b0055a275925d560f",
    ),
    SignTxTestCase(
        name="Sign_tx_with_datum_hash_in_output_as_array_with_tokens",
        tx=Transaction(
            network=Testnet, inputs=[inputs["utxoShelley"]], outputs=[outputs["datumHashWithTokens"]], fee=42, ttl=10
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a400818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7000181835839105e2f080eb93bad86d401545e0ce5f2221096d6477e11e6643922fa8d2ed495234dc0d667c1316ff84e572310e265edb31330448b36b7179e821a006ca793a1581c75a292ffee938be03e9bae5657982a74e9014eb4960108c9e23a5b39a2487564247542686911182f4875642475426869121a007838625820ffd4d009f554ba4fd8ed1f1d703244819861a9d34fd4753bcf3ff32f043ce18802182a030a",
        expected_warnings=[WarningBit.WARNING_BIT_NETWORK_UNUSUAL],
    ),
    # tests the path where a warning about missing datum hash is shown on Ledger
    SignTxTestCase(
        name="Sign_tx_with_missing_datum_hash_in_output_with_tokens",
        tx=Transaction(
            network=Testnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["missingDatumHashWithTokens"]],
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a400818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7000181825839105e2f080eb93bad86d401545e0ce5f2221096d6477e11e6643922fa8d2ed495234dc0d667c1316ff84e572310e265edb31330448b36b7179e821a006ca793a1581c75a292ffee938be03e9bae5657982a74e9014eb4960108c9e23a5b39a2487564247542686911182f4875642475426869121a0078386202182a030a",
        expected_warnings=[WarningBit.WARNING_BIT_NETWORK_UNUSUAL, WarningBit.WARNING_BIT_OUTPUT_MISSING_DATUM],
    ),
    SignTxTestCase(
        name="Sign_tx_with_collateral_inputs",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[],
            collateralInputs=[inputs["utxoByron"]],
            includeNetworkId=True,
        ),
        signingMode=TransactionSigningMode.PLUTUS_TRANSACTION,
        txBody="a600818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b700018002182a030a0d818258201af8fa0b754ff99253d983894e63a2b09cbb56c833ba18c3384210163f63dcfc000f01",
        expected_warnings=[WarningBit.WARNING_BIT_PLUTUS_UNKNOWN_COLLATERAL, WarningBit.WARNING_BIT_PLUTUS_MISSING_SCRIPT_DATA_HASH],
    ),
    SignTxTestCase(
        name="Sign_tx_with_collateral_inputs_shelley",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[],
            collateralInputs=[inputs["utxoShelley"]],
            includeNetworkId=True,
        ),
        signingMode=TransactionSigningMode.PLUTUS_TRANSACTION,
        txBody="a600818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b700018002182a030a0d818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7000f01",
        expected_warnings=[WarningBit.WARNING_BIT_PLUTUS_UNKNOWN_COLLATERAL, WarningBit.WARNING_BIT_PLUTUS_MISSING_SCRIPT_DATA_HASH],
    ),
    SignTxTestCase(
        name="Sign_tx_with_required_signers_mixed",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[],
            requiredSigners=[
                RequiredSigner(
                    TxRequiredSignerType.HASH,
                    "fea6646c67fb467f8a5425e9c752e1e262b0420ba4b638f39514049a",
                ),
                RequiredSigner(TxRequiredSignerType.PATH, "m/1852'/1815'/0'/0/0"),
            ],
            includeNetworkId=True,
        ),
        signingMode=TransactionSigningMode.PLUTUS_TRANSACTION,
        txBody="a600818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b700018002182a030a0e82581cfea6646c67fb467f8a5425e9c752e1e262b0420ba4b638f39514049a581c14c16d7f43243bd81478e68b9db53a8528fd4fb1078d58d54a7f11240f01",
        expected_warnings=[WarningBit.WARNING_BIT_PLUTUS_MISSING_COLLATERAL, WarningBit.WARNING_BIT_PLUTUS_UNKNOWN_COLLATERAL, WarningBit.WARNING_BIT_PLUTUS_MISSING_SCRIPT_DATA_HASH],
    ),
    SignTxTestCase(
        name="Sign_tx_with_mint_path_in_a_required_signer",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["externalByronMainnet"]],
            requiredSigners=[
                RequiredSigner(TxRequiredSignerType.PATH, "m/1855'/1815'/0'")
            ],
        ),
        signingMode=TransactionSigningMode.PLUTUS_TRANSACTION,
        txBody="a500818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b700018182582b82d818582183581c9e1c71de652ec8b85fec296f0685ca3988781c94a2e1a5d89d92f45fa0001a0d0c25611a002dd2e802182a030a0e81581c43040068ce85252be6164296d6dca9595644bbf424b56b7424458227",
        additionalWitnessPaths=["m/1855'/1815'/0'"],
        expected_warnings=[WarningBit.WARNING_BIT_PLUTUS_MISSING_COLLATERAL, WarningBit.WARNING_BIT_PLUTUS_UNKNOWN_COLLATERAL, WarningBit.WARNING_BIT_PLUTUS_MISSING_SCRIPT_DATA_HASH],
    ),
    SignTxTestCase(
        name="Sign_tx_with_key_hash_in_stake_credential",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[],
            certificates=[
                Certificate(
                    CertificateType.STAKE_DELEGATION,
                    StakeDelegationParams(
                        CredentialParams(
                            CredentialParamsType.KEY_HASH,
                            "29fb5fd4aa8cadd6705acc8263cee0fc62edca5ac38db593fec2f9fd",
                        ),
                        "f61c42cbf7c8c53af3f520508212ad3e72f674f957fe23ff0acb4973",
                    ),
                )
            ],
            withdrawals=[
                Withdrawal(
                    CredentialParams(
                        CredentialParamsType.KEY_HASH,
                        "29fb5fd4aa8cadd6705acc8263cee0fc62edca5ac38db593fec2f9fd",
                    ),
                    1000,
                )
            ],
            includeNetworkId=True,
        ),
        signingMode=TransactionSigningMode.PLUTUS_TRANSACTION,
        txBody="a700818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b700018002182a030a048183028200581c29fb5fd4aa8cadd6705acc8263cee0fc62edca5ac38db593fec2f9fd581cf61c42cbf7c8c53af3f520508212ad3e72f674f957fe23ff0acb497305a1581de129fb5fd4aa8cadd6705acc8263cee0fc62edca5ac38db593fec2f9fd1903e80f01",
        expected_warnings=[WarningBit.WARNING_BIT_PLUTUS_MISSING_COLLATERAL, WarningBit.WARNING_BIT_PLUTUS_UNKNOWN_COLLATERAL, WarningBit.WARNING_BIT_PLUTUS_MISSING_SCRIPT_DATA_HASH],
    ),
]

testsStreaming: List[SignTxTestCase] = [
    # Streaming test: 700 required signers to exceed MAX_UI_PAIRS (255) and trigger streaming NBGL review.
    # Per hash-type signer: 1 byte (type) + 28 bytes (hash) = 29 bytes raw; 1 UI pair.
    # Fixed overhead: 1 input (36B) + fee (8B) + TTL (8B) = 52 bytes.
    # Total raw: 700*29 + 52 = 20,352 bytes < MAX_TX_BUFFER_SIZE (21,504).
    # Total UI pairs: 700 + input(1) + fee(1) + TTL(1) + network_id(2) + tx_hash(1) = 706 > 255.
    # txBody: map(6){0: tagged-set([utxoShelley:0]), 1: [], 2: fee=42, 3: ttl=10,
    #             14: tagged-set(700 hashes), 15: networkId=1}
    # prefix: map header + key0 (input) + key1 (empty outputs) + key2 (fee) + key3 (ttl) + key14 header
    # each signer: 581c (28-byte bstr) + 8-hex-char counter + fixed suffix
    # suffix: key15 (networkId=1)
    SignTxTestCase(
        name="Sign_tx_streaming_many_required_signers",
        tx=_tx_streaming_many_required_signers,
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody=(
            "a600818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b700018002182a030a0e9902bc"
            + "".join(f"581c{i:0>8x}646c67fb467f8a5425e9c752e1e262b0420ba4b638f39514" for i in range(700))
            + "0f01"
        ),
        tx_streaming=True,
        unsuitable_in_ragger_reason="nano: Wallet-sized 700-signer review is reserved for large-screen devices",
    ),
    # Nano-focused streaming copy: 256 required signers still exceeds both Nano (127) and wallet (255)
    # review slabs while staying well below the tx buffer limit.
    SignTxTestCase(
        name="Sign_tx_streaming_many_required_signers_nano",
        tx=_tx_streaming_many_required_signers_nano,
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody=(
            "a600818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b700018002182a030a0e990100"
            + "".join(f"581c{i:0>8x}646c67fb467f8a5425e9c752e1e262b0420ba4b638f39514" for i in range(256))
            + "0f01"
        ),
        tx_streaming=True,
    ),
    # Streaming test: 90 third-party outputs to exceed MAX_UI_PAIRS (255).
    # Per simple third-party output: 2B (length) + 1B (type) + 2B (addr len) + 57B (addr) + 8B (amount)
    #   + 1B (format) + 1B (datum) + 1B (ref_script) + 2B (tokens) = 75 bytes raw; 3 UI pairs.
    # Total raw: 90*75 + 52 = 6,802 bytes.
    # Total UI pairs: 90*3 + input(1) + fee(1) + TTL(1) + network_id(2) + tx_hash(1) = 276 > 250.
    # txBody: map(5){0: [utxoShelley:0], 1: 90 outputs to externalShelleyBaseKeyhashKeyhash
    #             with amounts 1_000_000..1_000_089, 2: fee=42, 3: ttl=10, 15: networkId=1}
    # prefix: map header + key0 (input) + key1 header (90-element array = 0x985a)
    # each output: addr (57 bytes = 825839...8b09) + amount (4-byte uint = 1a000f42{0x40+i:02x})
    # suffix: key2 (fee) + key3 (ttl) + key15 (networkId)
    SignTxTestCase(
        name="Sign_tx_streaming_many_outputs",
        tx=_tx_streaming_many_outputs,
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody=(
            "a500818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b70001985a"
            + "".join(
                f"825839017cb05fce110fb999f01abb4f62bc455e217d4a51fde909fa9aea545443ac53c046cf6a42095e3c60310fa802771d0672f8fe2d1861138b09"
                f"1a000f42{0x40 + i:02x}"
                for i in range(90)
            )
            + "02182a030a0f01"
        ),
        tx_streaming=True,
    ),
]

testsBabbage: List[SignTxTestCase] = [
    SignTxTestCase(
        name="Sign_tx_with_short_inline_datum_in_output_with_tokens",
        tx=Transaction(
            network=Testnet_legacy,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["inlineDatumWithTokensMap"]],
            scriptDataHash="3b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7",
        ),
        signingMode=TransactionSigningMode.PLUTUS_TRANSACTION,
        txBody="a500818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7000181a3005839105e2f080eb93bad86d401545e0ce5f2221096d6477e11e6643922fa8d2ed495234dc0d667c1316ff84e572310e265edb31330448b36b7179e01821a006ca793a1581c75a292ffee938be03e9bae5657982a74e9014eb4960108c9e23a5b39a2487564247542686911182f4875642475426869121a00783862028201d818565579657420616e6f746865722063686f636f6c61746502182a030a0b58203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7",
        expected_warnings=[WarningBit.WARNING_BIT_PLUTUS_MISSING_COLLATERAL, WarningBit.WARNING_BIT_PLUTUS_UNKNOWN_COLLATERAL],
    ),
    SignTxTestCase(
        name="Sign_tx_with_long_inline_datum_480_B_in_output",
        tx=Transaction(
            network=Testnet_legacy,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["inlineDatum480Map"]],
            scriptDataHash="3b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7",
        ),
        signingMode=TransactionSigningMode.PLUTUS_TRANSACTION,
        txBody="a500818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7000181a3005839105e2f080eb93bad86d401545e0ce5f2221096d6477e11e6643922fa8d2ed495234dc0d667c1316ff84e572310e265edb31330448b36b7179e011a006ca793028201d8185901e012b8240c5470b47c159597b6f71d78c7fc99d1d8d911cb19b8f50211938ef361a22d30cd8f6354ec50e99a7d3cf3e06797ed4af3d358e01b2a957caa4010da328720b9fbe7a3a6d10209a13d2eb11933eb1bf2ab02713117e421b6dcc66297c41b95ad32d3457a0e6b44d8482385f311465964c3daff226acfb7bbda47011f1a6531db30e5b5977143c48f8b8eb739487f87dc13896f58529cfb48e415fc6123e708cdc3cb15cc1900ecf88c5fc9ff66d8ad6dae18c79e4a3c392a0df4d16ffa3e370f4dad8d8e9d171c5656bb317c78a2711057e7ae0beb1dc66ba01aa69d0c0db244e6742d7758ce8da00dfed6225d4aed4b01c42a0352688ed5803f3fd64873f11355305d9db309f4a2a6673cc408a06b8827a5edef7b0fd8742627fb8aa102a084b7db72fcb5c3d1bf437e2a936b738902a9c0258b462b9f2e9befd2c6bcfc036143bb34342b9124888a5b29fa5d60909c81319f034c11542b05ca3ff6c64c7642ff1e2b25fb60dc9bb6f5c914dd4149f31896955d4d204d822deddc46f852115a479edf7521cdf4ce596805875011855158fd303c33a2a7916a9cb7acaaf5aeca7e6efb75960e9597cd845bd9a93610bf1ab47ab0de943e8a96e26a24c4996f7b07fad437829fee5bc3496192608d4c04ac642cdec7bdbb8a948ad1d43402182a030a0b58203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7",
        expected_warnings=[WarningBit.WARNING_BIT_PLUTUS_MISSING_COLLATERAL, WarningBit.WARNING_BIT_PLUTUS_UNKNOWN_COLLATERAL],
    ),
    SignTxTestCase(
        name="Sign_tx_with_long_inline_datum_304_B_in_output_with_tokens",
        tx=Transaction(
            network=Testnet_legacy,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["inlineDatum304WithTokensMap"]],
            scriptDataHash="3b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7",
        ),
        signingMode=TransactionSigningMode.PLUTUS_TRANSACTION,
        txBody="a500818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7000181a3005839105e2f080eb93bad86d401545e0ce5f2221096d6477e11e6643922fa8d2ed495234dc0d667c1316ff84e572310e265edb31330448b36b7179e01821a006ca793a1581c75a292ffee938be03e9bae5657982a74e9014eb4960108c9e23a5b39a2487564247542686911182f4875642475426869121a00783862028201d8185901305579657420616e6f746865722063686f636f6c6174655579657420616e6f746865722063686f636f6c6174655579657420616e6f746865722063686f636f6c6174655579657420616e6f746865722063686f636f6c6174655579657420616e6f746865722063686f636f6c6174655579657420616e6f746865722063686f636f6c6174655579657420616e6f746865722063686f636f6c6174655579657420616e6f746865722063686f636f6c6174655579657420616e6f746865722063686f636f6c6174655579657420616e6f746865722063686f636f6c6174655579657420616e6f746865722063686f636f6c6174655579657420616e6f746865722063686f636f6c6174655579657420616e6f746865722063686f636f6c6174655579657420616e6f7468657220637468657202182a030a0b58203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7",
        expected_warnings=[WarningBit.WARNING_BIT_PLUTUS_MISSING_COLLATERAL, WarningBit.WARNING_BIT_PLUTUS_UNKNOWN_COLLATERAL],
    ),
    # reference script
    SignTxTestCase(
        name="Sign_tx_with_datum_hash_and_short_ref_script_in_output",
        tx=Transaction(
            network=Testnet_legacy,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["datumHashRefScriptExternalMap"]],
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a400818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7000181a4005839105e2f080eb93bad86d401545e0ce5f2221096d6477e11e6643922fa8d2ed495234dc0d667c1316ff84e572310e265edb31330448b36b7179e011a006ca7930282005820ffd4d009f554ba4fd8ed1f1d703244819861a9d34fd4753bcf3ff32f043ce18803d81854deadbeefdeadbeefdeadbeefdeadbeefdeadbeef02182a030a",
    ),
    SignTxTestCase(
        name="Sign_tx_with_datum_hash_and_ref_script_240_B_in_output_in_Babbage_format",
        tx=Transaction(
            network=Testnet_legacy,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["datumHashRefScript240ExternalMap"]],
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a400818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7000181a4005839105e2f080eb93bad86d401545e0ce5f2221096d6477e11e6643922fa8d2ed495234dc0d667c1316ff84e572310e265edb31330448b36b7179e011a006ca7930282005820ffd4d009f554ba4fd8ed1f1d703244819861a9d34fd4753bcf3ff32f043ce18803d81858f04784392787cc567ac21d7b5346a4a89ae112b7ff7610e402284042aa4e6efca7956a53c3f5cb3ec6745f5e21150f2a77bd71a2adc3f8b9539e9bab41934b477f60a8b302584d1a619ed9b178b5ce6fcad31adc0d6fc17023ede474c09f29fdbfb290a5b30b5240fae5de71168036201772c0d272ae90220181f9bf8c3198e79fc2ae32b076abf4d0e10d3166923ce56994b25c00909e3faab8ef1358c136cd3b197488efc883a7c6cfa3ac63ca9cebc62121c6e22f594420c2abd54e78282adec20ee7dba0e6de65554adb8ee8314f23f86cf7cf0906d4b6c643966baf6c54240c19f4131374e298f38a626a4ad63e6102182a030a",
    ),
    SignTxTestCase(
        name="Sign_tx_with_datum_hash_and_script_reference_304_B_in_output_as_map",
        tx=Transaction(
            network=Testnet_legacy,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["datumHashRefScript304ExternalMap"]],
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a400818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7000181a4005839105e2f080eb93bad86d401545e0ce5f2221096d6477e11e6643922fa8d2ed495234dc0d667c1316ff84e572310e265edb31330448b36b7179e011a006ca7930282005820ffd4d009f554ba4fd8ed1f1d703244819861a9d34fd4753bcf3ff32f043ce18803d818590130deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeaddeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeaddeadbeef02182a030a",
    ),
    # various output combinations
    SignTxTestCase(
        name="Sign_tx_with_datum_hash_in_output_with_tokens_in_Babbage_format",
        tx=Transaction(
            network=Testnet_legacy,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["datumHashWithTokensMap"]],
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a400818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7000181a3005839105e2f080eb93bad86d401545e0ce5f2221096d6477e11e6643922fa8d2ed495234dc0d667c1316ff84e572310e265edb31330448b36b7179e01821a006ca793a1581c75a292ffee938be03e9bae5657982a74e9014eb4960108c9e23a5b39a2487564247542686911182f4875642475426869121a007838620282005820ffd4d009f554ba4fd8ed1f1d703244819861a9d34fd4753bcf3ff32f043ce18802182a030a",
    ),
    SignTxTestCase(
        name="Sign_tx_with_a_complex_multiasset_output_Babbage",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[
                outputs["multiassetManyTokensBabbage"],
                outputs["internalBaseWithStakingPathBabbage"],
            ],
            validityIntervalStart=7,
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="a500818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7000182a200583901eb0baa5e570cffbe2934db29df0b6a3d7c0430ee65d4c3a7ab2fefb91bc428e4720702ebd5dab4fb175324c192dc9bb76cc5da956e3c8dff01821904d2a2581c7eae28af2208be856f7a119668ae52a49b73725e326dc16579dcc373a34003581c1e349c9bdea19fd6c147626a5260bc44b71635f398b67c59881df209015820000000000000000000000000000000000000000000000000000000000000000002581c95a292ffee938be03e9bae5657982a74e9014eb4960108c9e23a5b39a248456c204e69c3b16f1904d24874652474436f696e1a00783862a20058390114c16d7f43243bd81478e68b9db53a8528fd4fb1078d58d54a7f11241d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c011a006ca79302182a030a0807",
    ),
    # reference inputs
    SignTxTestCase(
        name="Sign_tx_with_change_output_as_map_and_multiple_reference_inputs",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["internalBaseWithStakingPathMap"]],
            scriptDataHash="3b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7",
            collateralInputs=[inputs["utxoShelley"]],
            referenceInputs=[inputs["utxoShelley"], inputs["utxoShelley"]],
        ),
        signingMode=TransactionSigningMode.PLUTUS_TRANSACTION,
        txBody="a700818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7000181a20058390114c16d7f43243bd81478e68b9db53a8528fd4fb1078d58d54a7f11241d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c011a006ca79302182a030a0b58203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b70d818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b70012828258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7008258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b700",
        expected_warnings=[WarningBit.WARNING_BIT_PLUTUS_UNKNOWN_COLLATERAL],
    ),
    # total collateral and collateral return output
    SignTxTestCase(
        name="Sign_tx_with_change_output_as_map_and_total_collateral",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["internalBaseWithStakingPathMap"]],
            scriptDataHash="3b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7",
            totalCollateral=10,
        ),
        signingMode=TransactionSigningMode.PLUTUS_TRANSACTION,
        txBody="a600818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7000181a20058390114c16d7f43243bd81478e68b9db53a8528fd4fb1078d58d54a7f11241d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c011a006ca79302182a030a0b58203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7110a",
        expected_warnings=[WarningBit.WARNING_BIT_PLUTUS_MISSING_COLLATERAL],
    ),
    SignTxTestCase(
        name="Sign_tx_with_change_output_as_map_and_collateral_output_as_array",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["internalBaseWithStakingPathMap"]],
            scriptDataHash="3b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7",
            collateralOutput=TxOutputBabbage(
                destinations["internalBaseWithStakingPathMap"],
                7120787,
                format=TxOutputFormat.ARRAY_LEGACY,
            ),
        ),
        signingMode=TransactionSigningMode.PLUTUS_TRANSACTION,
        txBody="a600818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7000181a20058390114c16d7f43243bd81478e68b9db53a8528fd4fb1078d58d54a7f11241d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c011a006ca79302182a030a0b58203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7108258390114c16d7f43243bd81478e68b9db53a8528fd4fb1078d58d54a7f11241d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c1a006ca793",
        expected_warnings=[WarningBit.WARNING_BIT_PLUTUS_MISSING_COLLATERAL, WarningBit.WARNING_BIT_PLUTUS_UNKNOWN_COLLATERAL],
    ),
    SignTxTestCase(
        name="Sign_tx_with_change_collateral_output_as_map_without_total_collateral",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["internalBaseWithStakingPathMap"]],
            scriptDataHash="3b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7",
            collateralInputs=[inputs["utxoShelley"]],
            collateralOutput=outputs["internalBaseWithTokensMap"],
        ),
        signingMode=TransactionSigningMode.PLUTUS_TRANSACTION,
        txBody="a700818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7000181a20058390114c16d7f43243bd81478e68b9db53a8528fd4fb1078d58d54a7f11241d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c011a006ca79302182a030a0b58203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b70d818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b70010a20058390114c16d7f43243bd81478e68b9db53a8528fd4fb1078d58d54a7f11241d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c01821a006ca793a1581c75a292ffee938be03e9bae5657982a74e9014eb4960108c9e23a5b39a1487564247542686911182f",
        expected_warnings=[WarningBit.WARNING_BIT_PLUTUS_UNKNOWN_COLLATERAL, WarningBit.WARNING_BIT_COLLATERAL_OUTPUT_WARNING],
    ),
    SignTxTestCase(
        name="Sign_tx_with_change_collateral_output_as_map_with_total_collateral",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["internalBaseWithStakingPathMap"]],
            scriptDataHash="3b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7",
            collateralInputs=[inputs["utxoShelley"]],
            collateralOutput=outputs["internalBaseWithTokensMap"],
            totalCollateral=5,
        ),
        signingMode=TransactionSigningMode.PLUTUS_TRANSACTION,
        txBody="a800818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7000181a20058390114c16d7f43243bd81478e68b9db53a8528fd4fb1078d58d54a7f11241d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c011a006ca79302182a030a0b58203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b70d818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b70010a20058390114c16d7f43243bd81478e68b9db53a8528fd4fb1078d58d54a7f11241d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c01821a006ca793a1581c75a292ffee938be03e9bae5657982a74e9014eb4960108c9e23a5b39a1487564247542686911182f1105",
    ),
    SignTxTestCase(
        name="Sign_tx_with_thirdparty_collateral_output_as_map_without_total_collateral",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["multiassetManyTokensBabbage"]],
            scriptDataHash="3b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7",
            collateralInputs=[inputs["utxoShelley"]],
            collateralOutput=outputs["externalShelleyBaseKeyhashKeyhash"],
        ),
        signingMode=TransactionSigningMode.PLUTUS_TRANSACTION,
        txBody="a700818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7000181a200583901eb0baa5e570cffbe2934db29df0b6a3d7c0430ee65d4c3a7ab2fefb91bc428e4720702ebd5dab4fb175324c192dc9bb76cc5da956e3c8dff01821904d2a2581c7eae28af2208be856f7a119668ae52a49b73725e326dc16579dcc373a34003581c1e349c9bdea19fd6c147626a5260bc44b71635f398b67c59881df209015820000000000000000000000000000000000000000000000000000000000000000002581c95a292ffee938be03e9bae5657982a74e9014eb4960108c9e23a5b39a248456c204e69c3b16f1904d24874652474436f696e1a0078386202182a030a0b58203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b70d818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b70010825839017cb05fce110fb999f01abb4f62bc455e217d4a51fde909fa9aea545443ac53c046cf6a42095e3c60310fa802771d0672f8fe2d1861138b0901",
        expected_warnings=[WarningBit.WARNING_BIT_PLUTUS_UNKNOWN_COLLATERAL],
    ),
    SignTxTestCase(
        name="Sign_tx_with_thirdparty_collateral_output_as_map_with_total_collateral",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["multiassetManyTokensBabbage"]],
            scriptDataHash="3b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7",
            collateralInputs=[inputs["utxoShelley"]],
            collateralOutput=outputs["externalShelleyBaseKeyhashKeyhash"],
            totalCollateral=5,
        ),
        signingMode=TransactionSigningMode.PLUTUS_TRANSACTION,
        txBody="a800818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7000181a200583901eb0baa5e570cffbe2934db29df0b6a3d7c0430ee65d4c3a7ab2fefb91bc428e4720702ebd5dab4fb175324c192dc9bb76cc5da956e3c8dff01821904d2a2581c7eae28af2208be856f7a119668ae52a49b73725e326dc16579dcc373a34003581c1e349c9bdea19fd6c147626a5260bc44b71635f398b67c59881df209015820000000000000000000000000000000000000000000000000000000000000000002581c95a292ffee938be03e9bae5657982a74e9014eb4960108c9e23a5b39a248456c204e69c3b16f1904d24874652474436f696e1a0078386202182a030a0b58203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b70d818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b70010825839017cb05fce110fb999f01abb4f62bc455e217d4a51fde909fa9aea545443ac53c046cf6a42095e3c60310fa802771d0672f8fe2d1861138b09011105",
    ),
]

# =================
# signTxPoolRegistration
# =================
poolRegistrationOwnerTestCases: List[SignTxTestCase] = [
    SignTxTestCase(
        name="Sign_tx_Witness_valid_multiple_mixed_owners_all_relays_pool_registration",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoNoPath"]],
            outputs=[outputs["externalShelleyBaseKeyhashKeyhash"]],
            certificates=[certificates["poolRegistrationMixedOwnersAllRelays"]],
        ),
        signingMode=TransactionSigningMode.POOL_REGISTRATION_AS_OWNER,
        txBody="a500818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7000181825839017cb05fce110fb999f01abb4f62bc455e217d4a51fde909fa9aea545443ac53c046cf6a42095e3c60310fa802771d0672f8fe2d1861138b090102182a030a04818a03581c13381d918ec0283ceeff60f7f4fc21e1540e053ccf8a77307a7a32ad582007821cd344d7fd7e3ae5f2ed863218cb979ff1d59e50c4276bdc479b0d0844501b0000000ba43b74001a1443fd00d81e82031864581de1794d9b3408c9fb67b950a48a0690f070f117e9978f7fc1d120fc58ad82581c1d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c581c794d9b3408c9fb67b950a48a0690f070f117e9978f7fc1d120fc58ad848400190bb84436e44b9af68400190bb84436e44b9b500178ff2483e3a2330a34c4a5e576c2078301190bb86d616161612e626262622e636f6d82026d616161612e626262632e636f6d82782968747470733a2f2f7777772e76616375756d6c6162732e636f6d2f73616d706c6555726c2e6a736f6e5820cdb714fd722c24aeb10c93dbb0ff03bd4783441cd5ba2a8b6f373390520535bb",
    ),
    SignTxTestCase(
        name="Sign_tx_Witness_valid_single_path_owner_ipv4_relay_pool_registration",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoNoPath"]],
            outputs=[outputs["externalShelleyBaseKeyhashKeyhash"]],
            certificates=[certificates["poolRegistrationDefault"]],
        ),
        signingMode=TransactionSigningMode.POOL_REGISTRATION_AS_OWNER,
        txBody="a500818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7000181825839017cb05fce110fb999f01abb4f62bc455e217d4a51fde909fa9aea545443ac53c046cf6a42095e3c60310fa802771d0672f8fe2d1861138b090102182a030a04818a03581c13381d918ec0283ceeff60f7f4fc21e1540e053ccf8a77307a7a32ad582007821cd344d7fd7e3ae5f2ed863218cb979ff1d59e50c4276bdc479b0d0844501b0000000ba43b74001a1443fd00d81e82031864581de1794d9b3408c9fb67b950a48a0690f070f117e9978f7fc1d120fc58ad81581c1d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c818400190bb84436e44b9af682782968747470733a2f2f7777772e76616375756d6c6162732e636f6d2f73616d706c6555726c2e6a736f6e5820cdb714fd722c24aeb10c93dbb0ff03bd4783441cd5ba2a8b6f373390520535bb",
    ),
    SignTxTestCase(
        name="Sign_tx_Witness_valid_multiple_mixed_owners_ipv4_relay_pool_registration",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoNoPath"]],
            outputs=[outputs["externalShelleyBaseKeyhashKeyhash"]],
            certificates=[certificates["poolRegistrationMixedOwners"]],
        ),
        signingMode=TransactionSigningMode.POOL_REGISTRATION_AS_OWNER,
        txBody="a500818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7000181825839017cb05fce110fb999f01abb4f62bc455e217d4a51fde909fa9aea545443ac53c046cf6a42095e3c60310fa802771d0672f8fe2d1861138b090102182a030a04818a03581c13381d918ec0283ceeff60f7f4fc21e1540e053ccf8a77307a7a32ad582007821cd344d7fd7e3ae5f2ed863218cb979ff1d59e50c4276bdc479b0d0844501b0000000ba43b74001a1443fd00d81e82031864581de1794d9b3408c9fb67b950a48a0690f070f117e9978f7fc1d120fc58ad82581c1d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c581c794d9b3408c9fb67b950a48a0690f070f117e9978f7fc1d120fc58ad818400190bb84436e44b9af682782968747470733a2f2f7777772e76616375756d6c6162732e636f6d2f73616d706c6555726c2e6a736f6e5820cdb714fd722c24aeb10c93dbb0ff03bd4783441cd5ba2a8b6f373390520535bb",
    ),
    SignTxTestCase(
        name="Sign_tx_Witness_valid_multiple_mixed_owners_mixed_ipv4_single_host_relays_pool_registration",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoNoPath"]],
            outputs=[outputs["externalShelleyBaseKeyhashKeyhash"]],
            certificates=[
                certificates["poolRegistrationMixedOwnersIpv4SingleHostRelays"]
            ],
        ),
        signingMode=TransactionSigningMode.POOL_REGISTRATION_AS_OWNER,
        txBody="a500818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7000181825839017cb05fce110fb999f01abb4f62bc455e217d4a51fde909fa9aea545443ac53c046cf6a42095e3c60310fa802771d0672f8fe2d1861138b090102182a030a04818a03581c13381d918ec0283ceeff60f7f4fc21e1540e053ccf8a77307a7a32ad582007821cd344d7fd7e3ae5f2ed863218cb979ff1d59e50c4276bdc479b0d0844501b0000000ba43b74001a1443fd00d81e82031864581de1794d9b3408c9fb67b950a48a0690f070f117e9978f7fc1d120fc58ad82581c1d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c581c794d9b3408c9fb67b950a48a0690f070f117e9978f7fc1d120fc58ad828400190bb84436e44b9af68301190bb86d616161612e626262622e636f6d82782968747470733a2f2f7777772e76616375756d6c6162732e636f6d2f73616d706c6555726c2e6a736f6e5820cdb714fd722c24aeb10c93dbb0ff03bd4783441cd5ba2a8b6f373390520535bb",
    ),
    SignTxTestCase(
        name="Sign_tx_Witness_valid_multiple_mixed_owners_mixed_ipv4_ipv6_relays_pool_registration",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoNoPath"]],
            outputs=[outputs["externalShelleyBaseKeyhashKeyhash"]],
            certificates=[certificates["poolRegistrationMixedOwnersIpv4Ipv6Relays"]],
        ),
        signingMode=TransactionSigningMode.POOL_REGISTRATION_AS_OWNER,
        txBody="a500818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7000181825839017cb05fce110fb999f01abb4f62bc455e217d4a51fde909fa9aea545443ac53c046cf6a42095e3c60310fa802771d0672f8fe2d1861138b090102182a030a04818a03581c13381d918ec0283ceeff60f7f4fc21e1540e053ccf8a77307a7a32ad582007821cd344d7fd7e3ae5f2ed863218cb979ff1d59e50c4276bdc479b0d0844501b0000000ba43b74001a1443fd00d81e82031864581de1794d9b3408c9fb67b950a48a0690f070f117e9978f7fc1d120fc58ad82581c1d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c581c794d9b3408c9fb67b950a48a0690f070f117e9978f7fc1d120fc58ad828400190fa04436e44b9af68400190bb84436e44b9b500178ff2483e3a2330a34c4a5e576c20782782968747470733a2f2f7777772e76616375756d6c6162732e636f6d2f73616d706c6555726c2e6a736f6e5820cdb714fd722c24aeb10c93dbb0ff03bd4783441cd5ba2a8b6f373390520535bb",
    ),
    SignTxTestCase(
        name="Sign_tx_Witness_valid_single_path_owner_no_relays_pool_registration",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoNoPath"]],
            outputs=[outputs["externalShelleyBaseKeyhashKeyhash"]],
            certificates=[certificates["poolRegistrationNoRelays"]],
        ),
        signingMode=TransactionSigningMode.POOL_REGISTRATION_AS_OWNER,
        txBody="a500818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7000181825839017cb05fce110fb999f01abb4f62bc455e217d4a51fde909fa9aea545443ac53c046cf6a42095e3c60310fa802771d0672f8fe2d1861138b090102182a030a04818a03581c13381d918ec0283ceeff60f7f4fc21e1540e053ccf8a77307a7a32ad582007821cd344d7fd7e3ae5f2ed863218cb979ff1d59e50c4276bdc479b0d0844501b0000000ba43b74001a1443fd00d81e82031864581de1794d9b3408c9fb67b950a48a0690f070f117e9978f7fc1d120fc58ad81581c1d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c8082782968747470733a2f2f7777772e76616375756d6c6162732e636f6d2f73616d706c6555726c2e6a736f6e5820cdb714fd722c24aeb10c93dbb0ff03bd4783441cd5ba2a8b6f373390520535bb",
        expected_warnings=[WarningBit.WARNING_BIT_POOL_REGISTRATION_NO_RELAYS],
    ),
    SignTxTestCase(
        name="Sign_tx_Witness_pool_registration_with_no_metadata",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoNoPath"]],
            outputs=[outputs["externalShelleyBaseKeyhashKeyhash"]],
            certificates=[certificates["poolRegistrationNoMetadata"]],
        ),
        signingMode=TransactionSigningMode.POOL_REGISTRATION_AS_OWNER,
        txBody="a500818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7000181825839017cb05fce110fb999f01abb4f62bc455e217d4a51fde909fa9aea545443ac53c046cf6a42095e3c60310fa802771d0672f8fe2d1861138b090102182a030a04818a03581c13381d918ec0283ceeff60f7f4fc21e1540e053ccf8a77307a7a32ad582007821cd344d7fd7e3ae5f2ed863218cb979ff1d59e50c4276bdc479b0d0844501b0000000ba43b74001a1443fd00d81e82031864581de1794d9b3408c9fb67b950a48a0690f070f117e9978f7fc1d120fc58ad81581c1d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c818400190bb84436e44b9af6f6",
    ),
    SignTxTestCase(
        name="Sign_tx_Witness_pool_registration_without_outputs",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoNoPath"]],
            outputs=[],
            certificates=[certificates["poolRegistrationMixedOwnersAllRelays"]],
        ),
        signingMode=TransactionSigningMode.POOL_REGISTRATION_AS_OWNER,
        txBody="a500818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b700018002182a030a04818a03581c13381d918ec0283ceeff60f7f4fc21e1540e053ccf8a77307a7a32ad582007821cd344d7fd7e3ae5f2ed863218cb979ff1d59e50c4276bdc479b0d0844501b0000000ba43b74001a1443fd00d81e82031864581de1794d9b3408c9fb67b950a48a0690f070f117e9978f7fc1d120fc58ad82581c1d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c581c794d9b3408c9fb67b950a48a0690f070f117e9978f7fc1d120fc58ad848400190bb84436e44b9af68400190bb84436e44b9b500178ff2483e3a2330a34c4a5e576c2078301190bb86d616161612e626262622e636f6d82026d616161612e626262632e636f6d82782968747470733a2f2f7777772e76616375756d6c6162732e636f6d2f73616d706c6555726c2e6a736f6e5820cdb714fd722c24aeb10c93dbb0ff03bd4783441cd5ba2a8b6f373390520535bb",
    ),
]

poolRegistrationOperatorTestCases: List[SignTxTestCase] = [
    SignTxTestCase(
        name="Sign_tx_Witness_pool_registration_as_operator_with_no_owners_and_no_relays",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoWithPath0"]],
            outputs=[outputs["externalShelleyBaseKeyhashKeyhash"]],
            certificates=[certificates["poolRegistrationOperatorNoOwnersNoRelays"]],
        ),
        signingMode=TransactionSigningMode.POOL_REGISTRATION_AS_OPERATOR,
        txBody="a500818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7000181825839017cb05fce110fb999f01abb4f62bc455e217d4a51fde909fa9aea545443ac53c046cf6a42095e3c60310fa802771d0672f8fe2d1861138b090102182a030a04818a03581cdbfee4665e58c8f8e9b9ff02b17f32e08a42c855476a5d867c2737b7582007821cd344d7fd7e3ae5f2ed863218cb979ff1d59e50c4276bdc479b0d0844501b0000000ba43b74001a1443fd00d81e82031864581de1794d9b3408c9fb67b950a48a0690f070f117e9978f7fc1d120fc58ad808082782968747470733a2f2f7777772e76616375756d6c6162732e636f6d2f73616d706c6555726c2e6a736f6e5820cdb714fd722c24aeb10c93dbb0ff03bd4783441cd5ba2a8b6f373390520535bb",
        expected_warnings=[WarningBit.WARNING_BIT_POOL_REGISTRATION_NO_OWNERS, WarningBit.WARNING_BIT_POOL_REGISTRATION_NO_RELAYS],
    ),
    SignTxTestCase(
        name="Sign_tx_Witness_pool_registration_as_operator_with_one_owner_and_no_relays",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoWithPath0"]],
            outputs=[outputs["externalShelleyBaseKeyhashKeyhash"]],
            certificates=[
                certificates["poolRegistrationOperatorOneOwnerOperatorNoRelays"]
            ],
        ),
        signingMode=TransactionSigningMode.POOL_REGISTRATION_AS_OPERATOR,
        txBody="a500818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7000181825839017cb05fce110fb999f01abb4f62bc455e217d4a51fde909fa9aea545443ac53c046cf6a42095e3c60310fa802771d0672f8fe2d1861138b090102182a030a04818a03581cdbfee4665e58c8f8e9b9ff02b17f32e08a42c855476a5d867c2737b7582007821cd344d7fd7e3ae5f2ed863218cb979ff1d59e50c4276bdc479b0d0844501b0000000ba43b74001a1443fd00d81e82031864581de1eef1689a3970b7880dcf3cb4ca9f22453b3833824fea34105117c84081581c794d9b3408c9fb67b950a48a0690f070f117e9978f7fc1d120fc58ad8082782968747470733a2f2f7777772e76616375756d6c6162732e636f6d2f73616d706c6555726c2e6a736f6e5820cdb714fd722c24aeb10c93dbb0ff03bd4783441cd5ba2a8b6f373390520535bb",
        expected_warnings=[WarningBit.WARNING_BIT_POOL_REGISTRATION_NO_RELAYS],
    ),
    SignTxTestCase(
        name="Sign_tx_Witness_pool_registration_as_operator_with_multiple_owners_and_all_relays",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoWithPath0"]],
            outputs=[outputs["externalShelleyBaseKeyhashKeyhash"]],
            certificates=[
                certificates["poolRegistrationOperatorMultipleOwnersAllRelays"]
            ],
        ),
        signingMode=TransactionSigningMode.POOL_REGISTRATION_AS_OPERATOR,
        txBody="a500818258203b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7000181825839017cb05fce110fb999f01abb4f62bc455e217d4a51fde909fa9aea545443ac53c046cf6a42095e3c60310fa802771d0672f8fe2d1861138b090102182a030a04818a03581cdbfee4665e58c8f8e9b9ff02b17f32e08a42c855476a5d867c2737b7582007821cd344d7fd7e3ae5f2ed863218cb979ff1d59e50c4276bdc479b0d0844501b0000000ba43b74001a1443fd00d81e82031864581de1794d9b3408c9fb67b950a48a0690f070f117e9978f7fc1d120fc58ad82581c794d9b3408c9fb67b950a48a0690f070f117e9978f7fc1d120fc58ad581c0bd5d796f5e54866a14300ec2a18d706f7461b8f0502cc2a182bc88d848400190bb84436e44b9af68400190bb84436e44b9b500178ff2483e3a2330a34c4a5e576c2078301190bb86d616161612e626262622e636f6d82026d616161612e626262632e636f6d82782968747470733a2f2f7777772e76616375756d6c6162732e636f6d2f73616d706c6555726c2e6a736f6e5820cdb714fd722c24aeb10c93dbb0ff03bd4783441cd5ba2a8b6f373390520535bb",
    ),
]

# =================
# Denies signTx
# =================
transactionInitDenyTestCases: List[SignTxTestCase] = [
    SignTxTestCase(
        name="Non_mainnet_protocol_magic",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824072),
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="",
        expected_sw=StatusWord.SWO_INVALID_PROTOCOL_MAGIC,
    ),
    SignTxTestCase(
        name="Invalid_network_id",
        tx=Transaction(
            network=NetworkDesc(networkId=16, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="",
        expected_sw=StatusWord.SWO_INVALID_NETWORK_ID,
    ),
    SignTxTestCase(
        name="Zero_inputs",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[],
            outputs=[outputs["inlineByronMainnet3003112"]],
            ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="",
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="Pool_registration_operator_too_few_certificates",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            ),
        signingMode=TransactionSigningMode.POOL_REGISTRATION_AS_OPERATOR,
        txBody="",
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
        expected_warnings=[WarningBit.WARNING_BIT_NETWORK_UNUSUAL],
    ),
    SignTxTestCase(
        name="Pool_registration_owner_too_few_certificates",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoMultisig"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            ),
        signingMode=TransactionSigningMode.POOL_REGISTRATION_AS_OWNER,
        txBody="",
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
        expected_warnings=[WarningBit.WARNING_BIT_NETWORK_UNUSUAL],
    ),
    SignTxTestCase(
        name="Pool_registration_operator_too_many_certificates",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            certificates=[
                Certificate(
                    type=CertificateType.STAKE_POOL_REGISTRATION,
                    params=PoolRegistrationParams(
                        poolKey=PoolKey(
                            type=PoolKeyType.DEVICE_OWNED, key="m/1852'/1815'/0'/0/0"
                        ),
                        vrfKeyHashHex="0123456789012345678901234567890123456789012345678901234567890123",
                        pledge=0,
                        cost=0,
                        margin=Margin(numerator=0, denominator=1),
                        rewardAccount=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="f123456789012345678901234567890123456789012345678901234567",
                        ),
                        poolOwners=[],
                        relays=[],
                        metadata=None,
                    ),
                ),
                Certificate(
                    type=CertificateType.STAKE_POOL_REGISTRATION,
                    params=PoolRegistrationParams(
                        poolKey=PoolKey(
                            type=PoolKeyType.DEVICE_OWNED, key="m/1852'/1815'/0'/0/0"
                        ),
                        vrfKeyHashHex="0123456789012345678901234567890123456789012345678901234567890123",
                        pledge=0,
                        cost=0,
                        margin=Margin(numerator=0, denominator=1),
                        rewardAccount=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="f123456789012345678901234567890123456789012345678901234567",
                        ),
                        poolOwners=[],
                        relays=[],
                        metadata=None,
                    ),
                ),
            ],
            ),
        signingMode=TransactionSigningMode.POOL_REGISTRATION_AS_OPERATOR,
        txBody="",
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="Pool_registration_owner_too_many_certificates",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoMultisig"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            certificates=[
                Certificate(
                    type=CertificateType.STAKE_POOL_REGISTRATION,
                    params=PoolRegistrationParams(
                        poolKey=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="01234567890123456789012345678901234567890123456789012345",
                        ),
                        vrfKeyHashHex="0123456789012345678901234567890123456789012345678901234567890123",
                        pledge=0,
                        cost=0,
                        margin=Margin(numerator=0, denominator=1),
                        rewardAccount=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="f123456789012345678901234567890123456789012345678901234567",
                        ),
                        poolOwners=[
                            PoolKey(
                                type=PoolKeyType.DEVICE_OWNED,
                                key="m/1852'/1815'/0'/2/0",
                            )
                        ],
                        relays=[],
                        metadata=None,
                    ),
                ),
                Certificate(
                    type=CertificateType.STAKE_POOL_REGISTRATION,
                    params=PoolRegistrationParams(
                        poolKey=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="01234567890123456789012345678901234567890123456789012345",
                        ),
                        vrfKeyHashHex="0123456789012345678901234567890123456789012345678901234567890123",
                        pledge=0,
                        cost=0,
                        margin=Margin(numerator=0, denominator=1),
                        rewardAccount=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="f123456789012345678901234567890123456789012345678901234567",
                        ),
                        poolOwners=[
                            PoolKey(
                                type=PoolKeyType.DEVICE_OWNED,
                                key="m/1852'/1815'/0'/2/0",
                            )
                        ],
                        relays=[],
                        metadata=None,
                    ),
                ),
            ],
            ),
        signingMode=TransactionSigningMode.POOL_REGISTRATION_AS_OWNER,
        txBody="",
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="Pool_registration_operator_too_many_withdrawals",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            certificates=[
                Certificate(
                    type=CertificateType.STAKE_POOL_REGISTRATION,
                    params=PoolRegistrationParams(
                        poolKey=PoolKey(
                            type=PoolKeyType.DEVICE_OWNED, key="m/1852'/1815'/0'/0/0"
                        ),
                        vrfKeyHashHex="0123456789012345678901234567890123456789012345678901234567890123",
                        pledge=0,
                        cost=0,
                        margin=Margin(numerator=0, denominator=1),
                        rewardAccount=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="f123456789012345678901234567890123456789012345678901234567",
                        ),
                        poolOwners=[],
                        relays=[],
                        metadata=None,
                    ),
                )
            ],
            withdrawals=[
                Withdrawal(
                    stakeCredential=CredentialParams(
                        type=CredentialParamsType.SCRIPT_HASH,
                        keyValue="29fb5fd4aa8cadd6705acc8263cee0fc62edca5ac38db593fec2f9fd",
                    ),
                    amount=1000,
                )
            ],
            ),
        signingMode=TransactionSigningMode.POOL_REGISTRATION_AS_OPERATOR,
        txBody="",
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="Pool_registration_owner_too_many_withdrawals",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoMultisig"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            certificates=[
                Certificate(
                    type=CertificateType.STAKE_POOL_REGISTRATION,
                    params=PoolRegistrationParams(
                        poolKey=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="01234567890123456789012345678901234567890123456789012345",
                        ),
                        vrfKeyHashHex="0123456789012345678901234567890123456789012345678901234567890123",
                        pledge=0,
                        cost=0,
                        margin=Margin(numerator=0, denominator=1),
                        rewardAccount=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="f123456789012345678901234567890123456789012345678901234567",
                        ),
                        poolOwners=[
                            PoolKey(
                                type=PoolKeyType.DEVICE_OWNED,
                                key="m/1852'/1815'/0'/2/0",
                            )
                        ],
                        relays=[],
                        metadata=None,
                    ),
                )
            ],
            withdrawals=[
                Withdrawal(
                    stakeCredential=CredentialParams(
                        type=CredentialParamsType.SCRIPT_HASH,
                        keyValue="29fb5fd4aa8cadd6705acc8263cee0fc62edca5ac38db593fec2f9fd",
                    ),
                    amount=1000,
                )
            ],
            ),
        signingMode=TransactionSigningMode.POOL_REGISTRATION_AS_OWNER,
        txBody="",
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="Pool_registration_operator_mint_included",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            certificates=[
                Certificate(
                    type=CertificateType.STAKE_POOL_REGISTRATION,
                    params=PoolRegistrationParams(
                        poolKey=PoolKey(
                            type=PoolKeyType.DEVICE_OWNED, key="m/1852'/1815'/0'/0/0"
                        ),
                        vrfKeyHashHex="0123456789012345678901234567890123456789012345678901234567890123",
                        pledge=0,
                        cost=0,
                        margin=Margin(numerator=0, denominator=1),
                        rewardAccount=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="f123456789012345678901234567890123456789012345678901234567",
                        ),
                        poolOwners=[],
                        relays=[],
                        metadata=None,
                    ),
                )
            ],
            mint=[
                AssetGroup(
                    policyIdHex="0d63e8d2c5a00cbcffbdf9112487c443466e1ea7d8c834df5ac5c425",
                    tokens=[Token(assetNameHex="75657374436f696e", amount=-7878754)],
                )
            ],
            ),
        signingMode=TransactionSigningMode.POOL_REGISTRATION_AS_OPERATOR,
        txBody="",
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="Pool_registration_owner_mint_included",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoMultisig"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            certificates=[
                Certificate(
                    type=CertificateType.STAKE_POOL_REGISTRATION,
                    params=PoolRegistrationParams(
                        poolKey=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="01234567890123456789012345678901234567890123456789012345",
                        ),
                        vrfKeyHashHex="0123456789012345678901234567890123456789012345678901234567890123",
                        pledge=0,
                        cost=0,
                        margin=Margin(numerator=0, denominator=1),
                        rewardAccount=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="f123456789012345678901234567890123456789012345678901234567",
                        ),
                        poolOwners=[
                            PoolKey(
                                type=PoolKeyType.DEVICE_OWNED,
                                key="m/1852'/1815'/0'/2/0",
                            )
                        ],
                        relays=[],
                        metadata=None,
                    ),
                )
            ],
            mint=[
                AssetGroup(
                    policyIdHex="0d63e8d2c5a00cbcffbdf9112487c443466e1ea7d8c834df5ac5c425",
                    tokens=[Token(assetNameHex="75657374436f696e", amount=-7878754)],
                )
            ],
            ),
        signingMode=TransactionSigningMode.POOL_REGISTRATION_AS_OWNER,
        txBody="",
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="Ordinary_tx_collateral_inputs_included",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            collateralInputs=[inputs["utxoShelley"]],
            ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="",
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
        expected_warnings=[WarningBit.WARNING_BIT_NETWORK_UNUSUAL],
    ),
    SignTxTestCase(
        name="Multisig_tx_collateral_inputs_included",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            collateralInputs=[inputs["utxoShelley"]],
            ),
        signingMode=TransactionSigningMode.MULTISIG_TRANSACTION,
        txBody="",
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="Pool_registration_operator_collateral_inputs_included",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            certificates=[
                Certificate(
                    type=CertificateType.STAKE_POOL_REGISTRATION,
                    params=PoolRegistrationParams(
                        poolKey=PoolKey(
                            type=PoolKeyType.DEVICE_OWNED, key="m/1852'/1815'/0'/0/0"
                        ),
                        vrfKeyHashHex="0123456789012345678901234567890123456789012345678901234567890123",
                        pledge=0,
                        cost=0,
                        margin=Margin(numerator=0, denominator=1),
                        rewardAccount=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="f123456789012345678901234567890123456789012345678901234567",
                        ),
                        poolOwners=[],
                        relays=[],
                        metadata=None,
                    ),
                )
            ],
            collateralInputs=[inputs["utxoShelley"]],
            ),
        signingMode=TransactionSigningMode.POOL_REGISTRATION_AS_OPERATOR,
        txBody="",
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="Pool_registration_owner_collateral_inputs_included",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoMultisig"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            certificates=[
                Certificate(
                    type=CertificateType.STAKE_POOL_REGISTRATION,
                    params=PoolRegistrationParams(
                        poolKey=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="01234567890123456789012345678901234567890123456789012345",
                        ),
                        vrfKeyHashHex="0123456789012345678901234567890123456789012345678901234567890123",
                        pledge=0,
                        cost=0,
                        margin=Margin(numerator=0, denominator=1),
                        rewardAccount=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="f123456789012345678901234567890123456789012345678901234567",
                        ),
                        poolOwners=[
                            PoolKey(
                                type=PoolKeyType.DEVICE_OWNED,
                                key="m/1852'/1815'/0'/2/0",
                            )
                        ],
                        relays=[],
                        metadata=None,
                    ),
                )
            ],
            collateralInputs=[inputs["utxoShelley"]],
            ),
        signingMode=TransactionSigningMode.POOL_REGISTRATION_AS_OWNER,
        txBody="",
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="Pool_registration_operator_required_signers_included",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            certificates=[
                Certificate(
                    type=CertificateType.STAKE_POOL_REGISTRATION,
                    params=PoolRegistrationParams(
                        poolKey=PoolKey(
                            type=PoolKeyType.DEVICE_OWNED, key="m/1852'/1815'/0'/0/0"
                        ),
                        vrfKeyHashHex="0123456789012345678901234567890123456789012345678901234567890123",
                        pledge=0,
                        cost=0,
                        margin=Margin(numerator=0, denominator=1),
                        rewardAccount=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="f123456789012345678901234567890123456789012345678901234567",
                        ),
                        poolOwners=[],
                        relays=[],
                        metadata=None,
                    ),
                )
            ],
            requiredSigners=[
                RequiredSigner(
                    type=TxRequiredSignerType.PATH, pathOrHashHex="m/1852'/1815'/0'/0/0"
                )
            ],
            ),
        signingMode=TransactionSigningMode.POOL_REGISTRATION_AS_OPERATOR,
        txBody="",
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="Pool_registration_owner_required_signers_included",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoMultisig"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            certificates=[
                Certificate(
                    type=CertificateType.STAKE_POOL_REGISTRATION,
                    params=PoolRegistrationParams(
                        poolKey=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="01234567890123456789012345678901234567890123456789012345",
                        ),
                        vrfKeyHashHex="0123456789012345678901234567890123456789012345678901234567890123",
                        pledge=0,
                        cost=0,
                        margin=Margin(numerator=0, denominator=1),
                        rewardAccount=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="f123456789012345678901234567890123456789012345678901234567",
                        ),
                        poolOwners=[
                            PoolKey(
                                type=PoolKeyType.DEVICE_OWNED,
                                key="m/1852'/1815'/0'/2/0",
                            )
                        ],
                        relays=[],
                        metadata=None,
                    ),
                )
            ],
            requiredSigners=[
                RequiredSigner(
                    type=TxRequiredSignerType.PATH, pathOrHashHex="m/1852'/1815'/0'/0/0"
                )
            ],
            ),
        signingMode=TransactionSigningMode.POOL_REGISTRATION_AS_OWNER,
        txBody="",
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="Ordinary_tx_collateral_output_included",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            collateralOutput=TxOutputAlonzo(
                destination=TxOutputDestination(
                    type=TxOutputDestinationType.THIRD_PARTY,
                    params=ThirdPartyAddressParams(
                        addressHex="017cb05fce110fb999f01abb4f62bc455e217d4a51fde909fa9aea545443ac53c046cf6a42095e3c60310fa802771d0672f8fe2d1861138b09"
                    ),
                ),
                amount=1,
                format=TxOutputFormat.ARRAY_LEGACY,
                tokenBundle=[],
                datum=None,
            ),
            ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="",
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="Multisig_tx_collateral_output_included",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            collateralOutput=TxOutputAlonzo(
                destination=TxOutputDestination(
                    type=TxOutputDestinationType.THIRD_PARTY,
                    params=ThirdPartyAddressParams(
                        addressHex="017cb05fce110fb999f01abb4f62bc455e217d4a51fde909fa9aea545443ac53c046cf6a42095e3c60310fa802771d0672f8fe2d1861138b09"
                    ),
                ),
                amount=1,
                format=TxOutputFormat.ARRAY_LEGACY,
                tokenBundle=[],
                datum=None,
            ),
            ),
        signingMode=TransactionSigningMode.MULTISIG_TRANSACTION,
        txBody="",
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="Pool_registration_operator_collateral_output_included",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            certificates=[
                Certificate(
                    type=CertificateType.STAKE_POOL_REGISTRATION,
                    params=PoolRegistrationParams(
                        poolKey=PoolKey(
                            type=PoolKeyType.DEVICE_OWNED, key="m/1852'/1815'/0'/0/0"
                        ),
                        vrfKeyHashHex="0123456789012345678901234567890123456789012345678901234567890123",
                        pledge=0,
                        cost=0,
                        margin=Margin(numerator=0, denominator=1),
                        rewardAccount=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="f123456789012345678901234567890123456789012345678901234567",
                        ),
                        poolOwners=[],
                        relays=[],
                        metadata=None,
                    ),
                )
            ],
            collateralOutput=TxOutputAlonzo(
                destination=TxOutputDestination(
                    type=TxOutputDestinationType.THIRD_PARTY,
                    params=ThirdPartyAddressParams(
                        addressHex="017cb05fce110fb999f01abb4f62bc455e217d4a51fde909fa9aea545443ac53c046cf6a42095e3c60310fa802771d0672f8fe2d1861138b09"
                    ),
                ),
                amount=1,
                format=TxOutputFormat.ARRAY_LEGACY,
                tokenBundle=[],
                datum=None,
            ),
            ),
        signingMode=TransactionSigningMode.POOL_REGISTRATION_AS_OPERATOR,
        txBody="",
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="Pool_registration_owner_collateral_output_included",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoMultisig"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            certificates=[
                Certificate(
                    type=CertificateType.STAKE_POOL_REGISTRATION,
                    params=PoolRegistrationParams(
                        poolKey=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="01234567890123456789012345678901234567890123456789012345",
                        ),
                        vrfKeyHashHex="0123456789012345678901234567890123456789012345678901234567890123",
                        pledge=0,
                        cost=0,
                        margin=Margin(numerator=0, denominator=1),
                        rewardAccount=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="f123456789012345678901234567890123456789012345678901234567",
                        ),
                        poolOwners=[
                            PoolKey(
                                type=PoolKeyType.DEVICE_OWNED,
                                key="m/1852'/1815'/0'/2/0",
                            )
                        ],
                        relays=[],
                        metadata=None,
                    ),
                )
            ],
            collateralOutput=TxOutputAlonzo(
                destination=TxOutputDestination(
                    type=TxOutputDestinationType.THIRD_PARTY,
                    params=ThirdPartyAddressParams(
                        addressHex="017cb05fce110fb999f01abb4f62bc455e217d4a51fde909fa9aea545443ac53c046cf6a42095e3c60310fa802771d0672f8fe2d1861138b09"
                    ),
                ),
                amount=1,
                format=TxOutputFormat.ARRAY_LEGACY,
                tokenBundle=[],
                datum=None,
            ),
            ),
        signingMode=TransactionSigningMode.POOL_REGISTRATION_AS_OWNER,
        txBody="",
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="Ordinary_tx_total_collateral_included",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            totalCollateral=8,
            ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="",
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="Multisig_tx_total_collateral_included",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            totalCollateral=8,
            ),
        signingMode=TransactionSigningMode.MULTISIG_TRANSACTION,
        txBody="",
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="Pool_registration_operator_total_collateral_included",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            certificates=[
                Certificate(
                    type=CertificateType.STAKE_POOL_REGISTRATION,
                    params=PoolRegistrationParams(
                        poolKey=PoolKey(
                            type=PoolKeyType.DEVICE_OWNED, key="m/1852'/1815'/0'/0/0"
                        ),
                        vrfKeyHashHex="0123456789012345678901234567890123456789012345678901234567890123",
                        pledge=0,
                        cost=0,
                        margin=Margin(numerator=0, denominator=1),
                        rewardAccount=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="f123456789012345678901234567890123456789012345678901234567",
                        ),
                        poolOwners=[],
                        relays=[],
                        metadata=None,
                    ),
                )
            ],
            totalCollateral=8,
            ),
        signingMode=TransactionSigningMode.POOL_REGISTRATION_AS_OPERATOR,
        txBody="",
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="Pool_registration_owner_total_collateral_included",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoMultisig"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            certificates=[
                Certificate(
                    type=CertificateType.STAKE_POOL_REGISTRATION,
                    params=PoolRegistrationParams(
                        poolKey=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="01234567890123456789012345678901234567890123456789012345",
                        ),
                        vrfKeyHashHex="0123456789012345678901234567890123456789012345678901234567890123",
                        pledge=0,
                        cost=0,
                        margin=Margin(numerator=0, denominator=1),
                        rewardAccount=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="f123456789012345678901234567890123456789012345678901234567",
                        ),
                        poolOwners=[
                            PoolKey(
                                type=PoolKeyType.DEVICE_OWNED,
                                key="m/1852'/1815'/0'/2/0",
                            )
                        ],
                        relays=[],
                        metadata=None,
                    ),
                )
            ],
            totalCollateral=8,
            ),
        signingMode=TransactionSigningMode.POOL_REGISTRATION_AS_OWNER,
        txBody="",
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="Ordinary_tx_reference_inputs_included",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            referenceInputs=[
                TxInput(
                    txHashHex="3b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7",
                    path="m/1852'/1815'/0'/0/0",
                    outputIndex=0,
                )
            ],
            ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="",
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="Multisig_tx_reference_inputs_included",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            referenceInputs=[
                TxInput(
                    txHashHex="3b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7",
                    path="m/1852'/1815'/0'/0/0",
                    outputIndex=0,
                )
            ],
            ),
        signingMode=TransactionSigningMode.MULTISIG_TRANSACTION,
        txBody="",
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="Pool_registration_operator_reference_inputs_included",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            certificates=[
                Certificate(
                    type=CertificateType.STAKE_POOL_REGISTRATION,
                    params=PoolRegistrationParams(
                        poolKey=PoolKey(
                            type=PoolKeyType.DEVICE_OWNED, key="m/1852'/1815'/0'/0/0"
                        ),
                        vrfKeyHashHex="0123456789012345678901234567890123456789012345678901234567890123",
                        pledge=0,
                        cost=0,
                        margin=Margin(numerator=0, denominator=1),
                        rewardAccount=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="f123456789012345678901234567890123456789012345678901234567",
                        ),
                        poolOwners=[],
                        relays=[],
                        metadata=None,
                    ),
                )
            ],
            referenceInputs=[
                TxInput(
                    txHashHex="3b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7",
                    path="m/1852'/1815'/0'/0/0",
                    outputIndex=0,
                )
            ],
            ),
        signingMode=TransactionSigningMode.POOL_REGISTRATION_AS_OPERATOR,
        txBody="",
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="Pool_registration_owner_reference_inputs_included",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoMultisig"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            certificates=[
                Certificate(
                    type=CertificateType.STAKE_POOL_REGISTRATION,
                    params=PoolRegistrationParams(
                        poolKey=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="01234567890123456789012345678901234567890123456789012345",
                        ),
                        vrfKeyHashHex="0123456789012345678901234567890123456789012345678901234567890123",
                        pledge=0,
                        cost=0,
                        margin=Margin(numerator=0, denominator=1),
                        rewardAccount=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="f123456789012345678901234567890123456789012345678901234567",
                        ),
                        poolOwners=[
                            PoolKey(
                                type=PoolKeyType.DEVICE_OWNED,
                                key="m/1852'/1815'/0'/2/0",
                            )
                        ],
                        relays=[],
                        metadata=None,
                    ),
                )
            ],
            referenceInputs=[
                TxInput(
                    txHashHex="3b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7",
                    path="m/1852'/1815'/0'/0/0",
                    outputIndex=0,
                )
            ],
            ),
        signingMode=TransactionSigningMode.POOL_REGISTRATION_AS_OWNER,
        txBody="",
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
]

addressParamsDenyTestCases: List[SignTxTestCase] = [
    SignTxTestCase(
        name="Reward_address_key",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[
                TxOutputAlonzo(
                    destination=TxOutputDestination(
                        type=TxOutputDestinationType.DEVICE_OWNED,
                        params=DeriveAddressTestCase(
                            name="",
                            netDesc=NetworkDesc(networkId=1, protocol=764824073),
                            addrType=AddressType.REWARD_KEY,
                            spendingValue="",
                            stakingValue="m/1852'/1815'/0'/2/0",
                            result="",
                            result_hex=None,
                            nano_nav_confirm=None,
                            nano_nav_show=None,
                        ),
                    ),
                    amount=10,
                    format=TxOutputFormat.ARRAY_LEGACY,
                    tokenBundle=[],
                    datum=None,
                )
            ],
            ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="",
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="Reward_address_script",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[
                TxOutputAlonzo(
                    destination=TxOutputDestination(
                        type=TxOutputDestinationType.DEVICE_OWNED,
                        params=DeriveAddressTestCase(
                            name="",
                            netDesc=NetworkDesc(networkId=1, protocol=764824073),
                            addrType=AddressType.REWARD_SCRIPT,
                            spendingValue="",
                            stakingValue="122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277",
                            result="",
                            result_hex=None,
                            nano_nav_confirm=None,
                            nano_nav_show=None,
                        ),
                    ),
                    amount=10,
                    format=TxOutputFormat.ARRAY_LEGACY,
                    tokenBundle=[],
                    datum=None,
                )
            ],
            ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="",
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="No_spending_path_Ordinary_Tx_1",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[
                TxOutputAlonzo(
                    destination=TxOutputDestination(
                        type=TxOutputDestinationType.DEVICE_OWNED,
                        params=DeriveAddressTestCase(
                            name="",
                            netDesc=NetworkDesc(networkId=1, protocol=764824073),
                            addrType=AddressType.BASE_PAYMENT_SCRIPT_STAKE_KEY,
                            spendingValue="29fb5fd4aa8cadd6705acc8263cee0fc62edca5ac38db593fec2f9fd",
                            stakingValue="122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277",
                            result="",
                            result_hex=None,
                            nano_nav_confirm=None,
                            nano_nav_show=None,
                        ),
                    ),
                    amount=3003112,
                    format=TxOutputFormat.ARRAY_LEGACY,
                    tokenBundle=[],
                    datum=None,
                )
            ],
            ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="",
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="No_spending_path_Ordinary_Tx_2",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[
                TxOutputAlonzo(
                    destination=TxOutputDestination(
                        type=TxOutputDestinationType.DEVICE_OWNED,
                        params=DeriveAddressTestCase(
                            name="",
                            netDesc=NetworkDesc(networkId=1, protocol=764824073),
                            addrType=AddressType.BASE_PAYMENT_SCRIPT_STAKE_SCRIPT,
                            spendingValue="29fb5fd4aa8cadd6705acc8263cee0fc62edca5ac38db593fec2f9fd",
                            stakingValue="122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277",
                            result="",
                            result_hex=None,
                            nano_nav_confirm=None,
                            nano_nav_show=None,
                        ),
                    ),
                    amount=3003112,
                    format=TxOutputFormat.ARRAY_LEGACY,
                    tokenBundle=[],
                    datum=None,
                )
            ],
            ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="",
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="Pool_operator_spending_choice_not_path",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[
                TxOutputAlonzo(
                    destination=TxOutputDestination(
                        type=TxOutputDestinationType.DEVICE_OWNED,
                        params=DeriveAddressTestCase(
                            name="",
                            netDesc=NetworkDesc(networkId=1, protocol=764824073),
                            addrType=AddressType.BASE_PAYMENT_SCRIPT_STAKE_KEY,
                            spendingValue="122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277",
                            stakingValue="m/1852'/1815'/456'/2/0",
                            result="",
                            result_hex=None,
                            nano_nav_confirm=None,
                            nano_nav_show=None,
                        ),
                    ),
                    amount=10,
                    format=TxOutputFormat.ARRAY_LEGACY,
                    tokenBundle=[],
                    datum=None,
                )
            ],
            ),
        signingMode=TransactionSigningMode.POOL_REGISTRATION_AS_OPERATOR,
        txBody="",
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="Multisig_unconditionally",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[
                TxOutputAlonzo(
                    destination=TxOutputDestination(
                        type=TxOutputDestinationType.DEVICE_OWNED,
                        params=DeriveAddressTestCase(
                            name="",
                            netDesc=NetworkDesc(networkId=1, protocol=764824073),
                            addrType=AddressType.BASE_PAYMENT_KEY_STAKE_KEY,
                            spendingValue="m/1852'/1815'/0'/0/0",
                            stakingValue="m/1852'/1815'/0'/2/0",
                            result="",
                            result_hex=None,
                            nano_nav_confirm=None,
                            nano_nav_show=None,
                        ),
                    ),
                    amount=7120787,
                    format=TxOutputFormat.ARRAY_LEGACY,
                    tokenBundle=[],
                    datum=None,
                )
            ],
            ),
        signingMode=TransactionSigningMode.MULTISIG_TRANSACTION,
        txBody="",
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="Pool_owner_unconditionally",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoMultisig"]],
            outputs=[
                TxOutputAlonzo(
                    destination=TxOutputDestination(
                        type=TxOutputDestinationType.DEVICE_OWNED,
                        params=DeriveAddressTestCase(
                            name="",
                            netDesc=NetworkDesc(networkId=1, protocol=764824073),
                            addrType=AddressType.BASE_PAYMENT_KEY_STAKE_KEY,
                            spendingValue="m/1852'/1815'/0'/0/0",
                            stakingValue="m/1852'/1815'/0'/2/0",
                            result="",
                            result_hex=None,
                            nano_nav_confirm=None,
                            nano_nav_show=None,
                        ),
                    ),
                    amount=7120787,
                    format=TxOutputFormat.ARRAY_LEGACY,
                    tokenBundle=[],
                    datum=None,
                )
            ],
            ),
        signingMode=TransactionSigningMode.POOL_REGISTRATION_AS_OWNER,
        txBody="",
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
]

certificateDenyTestCases: List[SignTxTestCase] = [
    SignTxTestCase(
        name="Pool_registration_in_Ordinary_Tx",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            certificates=[
                Certificate(
                    type=CertificateType.STAKE_POOL_REGISTRATION,
                    params=PoolRegistrationParams(
                        poolKey=PoolKey(
                            type=PoolKeyType.DEVICE_OWNED, key="m/1852'/1815'/0'/0/0"
                        ),
                        vrfKeyHashHex="0123456789012345678901234567890123456789012345678901234567890123",
                        pledge=0,
                        cost=0,
                        margin=Margin(numerator=0, denominator=1),
                        rewardAccount=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="f123456789012345678901234567890123456789012345678901234567",
                        ),
                        poolOwners=[],
                        relays=[],
                        metadata=None,
                    ),
                )
            ],
            ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="",
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="Pool_registration_in_Multisig_Tx",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            certificates=[
                Certificate(
                    type=CertificateType.STAKE_POOL_REGISTRATION,
                    params=PoolRegistrationParams(
                        poolKey=PoolKey(
                            type=PoolKeyType.DEVICE_OWNED, key="m/1852'/1815'/0'/0/0"
                        ),
                        vrfKeyHashHex="0123456789012345678901234567890123456789012345678901234567890123",
                        pledge=0,
                        cost=0,
                        margin=Margin(numerator=0, denominator=1),
                        rewardAccount=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="f123456789012345678901234567890123456789012345678901234567",
                        ),
                        poolOwners=[],
                        relays=[],
                        metadata=None,
                    ),
                )
            ],
            ),
        signingMode=TransactionSigningMode.MULTISIG_TRANSACTION,
        txBody="",
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="Pool_registration_in_Plutus_Tx",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            certificates=[
                Certificate(
                    type=CertificateType.STAKE_POOL_REGISTRATION,
                    params=PoolRegistrationParams(
                        poolKey=PoolKey(
                            type=PoolKeyType.DEVICE_OWNED, key="m/1852'/1815'/0'/0/0"
                        ),
                        vrfKeyHashHex="0123456789012345678901234567890123456789012345678901234567890123",
                        pledge=0,
                        cost=0,
                        margin=Margin(numerator=0, denominator=1),
                        rewardAccount=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="f123456789012345678901234567890123456789012345678901234567",
                        ),
                        poolOwners=[],
                        relays=[],
                        metadata=None,
                    ),
                )
            ],
            ),
        signingMode=TransactionSigningMode.PLUTUS_TRANSACTION,
        txBody="",
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="Pool_retirement_in_Multisig_Tx",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            certificates=[
                Certificate(
                    type=CertificateType.STAKE_POOL_RETIREMENT,
                    params=PoolRetirementParams(
                        poolCredential=CredentialParams(
                            type=CredentialParamsType.KEY_PATH,
                            keyValue="m/1853'/1815'/0'/1'",
                        ),
                        retirementEpoch=42,
                    ),
                )
            ],
            ),
        signingMode=TransactionSigningMode.MULTISIG_TRANSACTION,
        txBody="",
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="Stake_registration_in_Pool_Registration_Operator",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            certificates=[
                Certificate(
                    type=CertificateType.STAKE_REGISTRATION,
                    params=StakeRegistrationParams(
                        stakeCredential=CredentialParams(
                            type=CredentialParamsType.KEY_PATH,
                            keyValue="m/1852'/1815'/0'/2/0",
                        )
                    ),
                )
            ],
            ),
        signingMode=TransactionSigningMode.POOL_REGISTRATION_AS_OPERATOR,
        txBody="",
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="Stake_registration_in_Pool_Registration_Owner",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoMultisig"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            certificates=[
                Certificate(
                    type=CertificateType.STAKE_REGISTRATION,
                    params=StakeRegistrationParams(
                        stakeCredential=CredentialParams(
                            type=CredentialParamsType.KEY_PATH,
                            keyValue="m/1852'/1815'/0'/2/0",
                        )
                    ),
                )
            ],
            ),
        signingMode=TransactionSigningMode.POOL_REGISTRATION_AS_OWNER,
        txBody="",
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="Stake_deregistration_in_Pool_Registration_Operator",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            certificates=[
                Certificate(
                    type=CertificateType.STAKE_DEREGISTRATION,
                    params=StakeRegistrationParams(
                        stakeCredential=CredentialParams(
                            type=CredentialParamsType.KEY_PATH,
                            keyValue="m/1852'/1815'/0'/2/0",
                        )
                    ),
                )
            ],
            ),
        signingMode=TransactionSigningMode.POOL_REGISTRATION_AS_OPERATOR,
        txBody="",
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="Stake_deregistration_in_Pool_Registration_Owner",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoMultisig"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            certificates=[
                Certificate(
                    type=CertificateType.STAKE_DEREGISTRATION,
                    params=StakeRegistrationParams(
                        stakeCredential=CredentialParams(
                            type=CredentialParamsType.KEY_PATH,
                            keyValue="m/1852'/1815'/0'/2/0",
                        )
                    ),
                )
            ],
            ),
        signingMode=TransactionSigningMode.POOL_REGISTRATION_AS_OWNER,
        txBody="",
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="Stake_delegation_in_Pool_Registration_Operator",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            certificates=[
                Certificate(
                    type=CertificateType.STAKE_DELEGATION,
                    params=StakeDelegationParams(
                        stakeCredential=CredentialParams(
                            type=CredentialParamsType.KEY_PATH,
                            keyValue="m/1852'/1815'/0'/2/0",
                        ),
                        poolKeyHash="",
                    ),
                )
            ],
            ),
        signingMode=TransactionSigningMode.POOL_REGISTRATION_AS_OPERATOR,
        txBody="",
        expected_sw=StatusWord.SWO_TX_PARSING_FAIL_CERTIFICATES,
        deny_before_review=True,
    ),
    SignTxTestCase(
        name="Stake_delegation_in_Pool_Registration_Owner",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoMultisig"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            certificates=[
                Certificate(
                    type=CertificateType.STAKE_DELEGATION,
                    params=StakeDelegationParams(
                        stakeCredential=CredentialParams(
                            type=CredentialParamsType.KEY_PATH,
                            keyValue="m/1852'/1815'/0'/2/0",
                        ),
                        poolKeyHash="",
                    ),
                )
            ],
            ),
        signingMode=TransactionSigningMode.POOL_REGISTRATION_AS_OWNER,
        txBody="",
        expected_sw=StatusWord.SWO_TX_PARSING_FAIL_CERTIFICATES,
        deny_before_review=True,
    ),
    SignTxTestCase(
        name="Pool_retirement_in_Pool_Registration_Operator",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            certificates=[
                Certificate(
                    type=CertificateType.STAKE_POOL_RETIREMENT,
                    params=PoolRetirementParams(
                        poolCredential=CredentialParams(
                            type=CredentialParamsType.KEY_PATH,
                            keyValue="m/1853'/1815'/0'/1'",
                        ),
                        retirementEpoch=42,
                    ),
                )
            ],
            ),
        signingMode=TransactionSigningMode.POOL_REGISTRATION_AS_OPERATOR,
        txBody="",
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="Pool_retirement_in_Pool_Registration_Owner",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoMultisig"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            certificates=[
                Certificate(
                    type=CertificateType.STAKE_POOL_RETIREMENT,
                    params=PoolRetirementParams(
                        poolCredential=CredentialParams(
                            type=CredentialParamsType.KEY_PATH,
                            keyValue="m/1853'/1815'/0'/1'",
                        ),
                        retirementEpoch=42,
                    ),
                )
            ],
            ),
        signingMode=TransactionSigningMode.POOL_REGISTRATION_AS_OWNER,
        txBody="",
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
]

certificateStakingDenyTestCases: List[SignTxTestCase] = [
    SignTxTestCase(
        name="Script_hash_in_Ordinary_Tx",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            certificates=[
                Certificate(
                    type=CertificateType.STAKE_REGISTRATION,
                    params=StakeRegistrationParams(
                        stakeCredential=CredentialParams(
                            type=CredentialParamsType.SCRIPT_HASH,
                            keyValue="29fb5fd4aa8cadd6705acc8263cee0fc62edca5ac38db593fec2f9fd",
                        )
                    ),
                )
            ],
            ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="",
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="Non_staking_path_in_Ordinary_Tx",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            certificates=[
                Certificate(
                    type=CertificateType.STAKE_REGISTRATION,
                    params=StakeRegistrationParams(
                        stakeCredential=CredentialParams(
                            type=CredentialParamsType.KEY_PATH,
                            keyValue="m/1852'/1815'/0'/0/0",
                        )
                    ),
                )
            ],
            ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="",
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="Path_in_Multisig_Tx",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            certificates=[
                Certificate(
                    type=CertificateType.STAKE_REGISTRATION,
                    params=StakeRegistrationParams(
                        stakeCredential=CredentialParams(
                            type=CredentialParamsType.KEY_PATH,
                            keyValue="m/1852'/1815'/0'/2/0",
                        )
                    ),
                )
            ],
            ),
        signingMode=TransactionSigningMode.MULTISIG_TRANSACTION,
        txBody="",
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
]

certificateStakePoolRetirementDenyTestCases: List[SignTxTestCase] = [
    SignTxTestCase(
        name="Non_pool_cold_key_in_Ordinary_Tx",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            certificates=[
                Certificate(
                    type=CertificateType.STAKE_POOL_RETIREMENT,
                    params=PoolRetirementParams(
                        poolCredential=CredentialParams(
                            type=CredentialParamsType.KEY_PATH,
                            keyValue="m/1853'/1815'/0'/0",
                        ),
                        retirementEpoch=42,
                    ),
                )
            ],
            ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="",
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
        expected_warnings=[WarningBit.WARNING_BIT_NETWORK_UNUSUAL],
    ),
]

withdrawalDenyTestCases: List[SignTxTestCase] = [
    SignTxTestCase(
        name="Deny_tx_with_invalid_canonical_ordering_of_withdrawals",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[],
            withdrawals=[
                Withdrawal(
                    stakeCredential=CredentialParams(
                        type=CredentialParamsType.KEY_PATH,
                        keyValue="m/1852'/1815'/0'/2/1",
                    ),
                    amount=33333,
                ),
                Withdrawal(
                    stakeCredential=CredentialParams(
                        type=CredentialParamsType.KEY_PATH,
                        keyValue="m/1852'/1815'/0'/2/0",
                    ),
                    amount=33333,
                ),
            ],
            ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="",
        expected_sw=StatusWord.SWO_TX_PARSING_FAIL_WITHDRAWALS,
        unsuitable_in_ragger_reason="Seed-dependent: canonical ordering depends on derived reward addresses",
    ),
    SignTxTestCase(
        name="Script_hash_as_stake_credential_in_Ordinary_Tx",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            withdrawals=[
                Withdrawal(
                    stakeCredential=CredentialParams(
                        type=CredentialParamsType.SCRIPT_HASH,
                        keyValue="29fb5fd4aa8cadd6705acc8263cee0fc62edca5ac38db593fec2f9fd",
                    ),
                    amount=1000,
                )
            ],
            ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="",
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="Non_staking_path_as_stake_credential_in_Ordinary_Tx",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            withdrawals=[
                Withdrawal(
                    stakeCredential=CredentialParams(
                        type=CredentialParamsType.KEY_PATH,
                        keyValue="m/1852'/1815'/0'/0/0",
                    ),
                    amount=1000,
                )
            ],
            ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="",
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="Staking_path_as_stake_credential_in_Multisig_Tx",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            withdrawals=[
                Withdrawal(
                    stakeCredential=CredentialParams(
                        type=CredentialParamsType.KEY_PATH,
                        keyValue="m/1852'/1815'/0'/2/0",
                    ),
                    amount=1000,
                )
            ],
            ),
        signingMode=TransactionSigningMode.MULTISIG_TRANSACTION,
        txBody="",
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="Non_staking_path_as_stake_credential_in_Plutus_Tx",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            withdrawals=[
                Withdrawal(
                    stakeCredential=CredentialParams(
                        type=CredentialParamsType.KEY_PATH,
                        keyValue="m/1852'/1815'/0'/0/0",
                    ),
                    amount=1000,
                )
            ],
            ),
        signingMode=TransactionSigningMode.PLUTUS_TRANSACTION,
        txBody="",
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
]

witnessDenyTestCases: List[SignTxTestCase] = [
    SignTxTestCase(
        name="Ordinary_account_path_in_Ordinary_Tx",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="",
        additionalWitnessPaths=["m/1852'/1815'/0'"],
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="Multisig_account_path_in_Ordinary_Tx",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="",
        additionalWitnessPaths=["m/1854'/1815'/0'"],
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="Multisig_spending_path_in_Ordinary_Tx",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="",
        additionalWitnessPaths=["m/1854'/1815'/0'/0/0"],
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="Multisig_staking_path_in_Ordinary_Tx",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="",
        additionalWitnessPaths=["m/1854'/1815'/0'/2/0"],
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="Mint_path_in_Ordinary_Tx",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="",
        additionalWitnessPaths=["m/1855'/1815'/0'"],
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="Ordinary_account_path_in_Multisig_Tx",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            ),
        signingMode=TransactionSigningMode.MULTISIG_TRANSACTION,
        txBody="",
        additionalWitnessPaths=["m/1852'/1815'/0'"],
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="Multisig_account_path_in_Multisig_Tx",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            ),
        signingMode=TransactionSigningMode.MULTISIG_TRANSACTION,
        txBody="",
        additionalWitnessPaths=["m/1854'/1815'/0'"],
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="Ordinary_spending_path_in_Multisig_Tx",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            ),
        signingMode=TransactionSigningMode.MULTISIG_TRANSACTION,
        txBody="",
        additionalWitnessPaths=["m/1852'/1815'/0'/0/0"],
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="Ordinary_staking_path_in_Multisig_Tx",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            ),
        signingMode=TransactionSigningMode.MULTISIG_TRANSACTION,
        txBody="",
        additionalWitnessPaths=["m/1852'/1815'/0'/2/0"],
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="Mint_path_in_Multisig_Tx",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            ),
        signingMode=TransactionSigningMode.MULTISIG_TRANSACTION,
        txBody="",
        additionalWitnessPaths=["m/1855'/1815'/0'"],
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="Pool_cold_path_in_Multisig_Tx",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            ),
        signingMode=TransactionSigningMode.MULTISIG_TRANSACTION,
        txBody="",
        additionalWitnessPaths=["m/1853'/1815'/0'/0'"],
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="Ordinary_account_path_in_Plutus_Tx",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            ),
        signingMode=TransactionSigningMode.PLUTUS_TRANSACTION,
        txBody="",
        additionalWitnessPaths=["m/1852'/1815'/0'"],
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="Multisig_account_path_in_Plutus_Tx",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            ),
        signingMode=TransactionSigningMode.PLUTUS_TRANSACTION,
        txBody="",
        additionalWitnessPaths=["m/1854'/1815'/0'"],
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="Multisig_account_path_in_Pool_Registration_Owner_Tx",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoMultisig"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            certificates=[
                Certificate(
                    type=CertificateType.STAKE_POOL_REGISTRATION,
                    params=PoolRegistrationParams(
                        poolKey=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="01234567890123456789012345678901234567890123456789012345",
                        ),
                        vrfKeyHashHex="0123456789012345678901234567890123456789012345678901234567890123",
                        pledge=0,
                        cost=0,
                        margin=Margin(numerator=0, denominator=1),
                        rewardAccount=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="f123456789012345678901234567890123456789012345678901234567",
                        ),
                        poolOwners=[
                            PoolKey(
                                type=PoolKeyType.DEVICE_OWNED,
                                key="m/1852'/1815'/0'/2/0",
                            )
                        ],
                        relays=[],
                        metadata=None,
                    ),
                )
            ],
            ),
        signingMode=TransactionSigningMode.POOL_REGISTRATION_AS_OWNER,
        txBody="",
        additionalWitnessPaths=["m/1854'/1815'/0'"],
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="Ordinary_spending_path_in_Pool_Registration_Owner_Tx",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoMultisig"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            certificates=[
                Certificate(
                    type=CertificateType.STAKE_POOL_REGISTRATION,
                    params=PoolRegistrationParams(
                        poolKey=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="01234567890123456789012345678901234567890123456789012345",
                        ),
                        vrfKeyHashHex="0123456789012345678901234567890123456789012345678901234567890123",
                        pledge=0,
                        cost=0,
                        margin=Margin(numerator=0, denominator=1),
                        rewardAccount=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="f123456789012345678901234567890123456789012345678901234567",
                        ),
                        poolOwners=[
                            PoolKey(
                                type=PoolKeyType.DEVICE_OWNED,
                                key="m/1852'/1815'/0'/2/0",
                            )
                        ],
                        relays=[],
                        metadata=None,
                    ),
                )
            ],
            ),
        signingMode=TransactionSigningMode.POOL_REGISTRATION_AS_OWNER,
        txBody="",
        additionalWitnessPaths=["m/1852'/1815'/0'/0/0"],
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="Multisig_spending_path_in_Pool_Registration_Owner_Tx",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoMultisig"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            certificates=[
                Certificate(
                    type=CertificateType.STAKE_POOL_REGISTRATION,
                    params=PoolRegistrationParams(
                        poolKey=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="01234567890123456789012345678901234567890123456789012345",
                        ),
                        vrfKeyHashHex="0123456789012345678901234567890123456789012345678901234567890123",
                        pledge=0,
                        cost=0,
                        margin=Margin(numerator=0, denominator=1),
                        rewardAccount=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="f123456789012345678901234567890123456789012345678901234567",
                        ),
                        poolOwners=[
                            PoolKey(
                                type=PoolKeyType.DEVICE_OWNED,
                                key="m/1852'/1815'/0'/2/0",
                            )
                        ],
                        relays=[],
                        metadata=None,
                    ),
                )
            ],
            ),
        signingMode=TransactionSigningMode.POOL_REGISTRATION_AS_OWNER,
        txBody="",
        additionalWitnessPaths=["m/1854'/1815'/0'/0/0"],
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="Multisig_staking_path_in_Pool_Registration_Owner_Tx",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoMultisig"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            certificates=[
                Certificate(
                    type=CertificateType.STAKE_POOL_REGISTRATION,
                    params=PoolRegistrationParams(
                        poolKey=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="01234567890123456789012345678901234567890123456789012345",
                        ),
                        vrfKeyHashHex="0123456789012345678901234567890123456789012345678901234567890123",
                        pledge=0,
                        cost=0,
                        margin=Margin(numerator=0, denominator=1),
                        rewardAccount=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="f123456789012345678901234567890123456789012345678901234567",
                        ),
                        poolOwners=[
                            PoolKey(
                                type=PoolKeyType.DEVICE_OWNED,
                                key="m/1852'/1815'/0'/2/0",
                            )
                        ],
                        relays=[],
                        metadata=None,
                    ),
                )
            ],
            ),
        signingMode=TransactionSigningMode.POOL_REGISTRATION_AS_OWNER,
        txBody="",
        additionalWitnessPaths=["m/1854'/1815'/0'/2/0"],
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="Mint_path_in_Pool_Registration_Owner_Tx",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoMultisig"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            certificates=[
                Certificate(
                    type=CertificateType.STAKE_POOL_REGISTRATION,
                    params=PoolRegistrationParams(
                        poolKey=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="01234567890123456789012345678901234567890123456789012345",
                        ),
                        vrfKeyHashHex="0123456789012345678901234567890123456789012345678901234567890123",
                        pledge=0,
                        cost=0,
                        margin=Margin(numerator=0, denominator=1),
                        rewardAccount=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="f123456789012345678901234567890123456789012345678901234567",
                        ),
                        poolOwners=[
                            PoolKey(
                                type=PoolKeyType.DEVICE_OWNED,
                                key="m/1852'/1815'/0'/2/0",
                            )
                        ],
                        relays=[],
                        metadata=None,
                    ),
                )
            ],
            ),
        signingMode=TransactionSigningMode.POOL_REGISTRATION_AS_OWNER,
        txBody="",
        additionalWitnessPaths=["m/1855'/1815'/0'"],
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="Pool_cold_path_in_Pool_Registration_Owner_Tx",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoMultisig"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            certificates=[
                Certificate(
                    type=CertificateType.STAKE_POOL_REGISTRATION,
                    params=PoolRegistrationParams(
                        poolKey=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="01234567890123456789012345678901234567890123456789012345",
                        ),
                        vrfKeyHashHex="0123456789012345678901234567890123456789012345678901234567890123",
                        pledge=0,
                        cost=0,
                        margin=Margin(numerator=0, denominator=1),
                        rewardAccount=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="f123456789012345678901234567890123456789012345678901234567",
                        ),
                        poolOwners=[
                            PoolKey(
                                type=PoolKeyType.DEVICE_OWNED,
                                key="m/1852'/1815'/0'/2/0",
                            )
                        ],
                        relays=[],
                        metadata=None,
                    ),
                )
            ],
            ),
        signingMode=TransactionSigningMode.POOL_REGISTRATION_AS_OWNER,
        txBody="",
        additionalWitnessPaths=["m/1853'/1815'/0'/0'"],
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="Multisig_account_path_in_Pool_Registration_Operator_Tx",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            certificates=[
                Certificate(
                    type=CertificateType.STAKE_POOL_REGISTRATION,
                    params=PoolRegistrationParams(
                        poolKey=PoolKey(
                            type=PoolKeyType.DEVICE_OWNED, key="m/1852'/1815'/0'/0/0"
                        ),
                        vrfKeyHashHex="0123456789012345678901234567890123456789012345678901234567890123",
                        pledge=0,
                        cost=0,
                        margin=Margin(numerator=0, denominator=1),
                        rewardAccount=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="f123456789012345678901234567890123456789012345678901234567",
                        ),
                        poolOwners=[],
                        relays=[],
                        metadata=None,
                    ),
                )
            ],
            ),
        signingMode=TransactionSigningMode.POOL_REGISTRATION_AS_OPERATOR,
        txBody="",
        additionalWitnessPaths=["m/1854'/1815'/0'"],
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="Multisig_spending_path_in_Pool_Registration_Operator_Tx",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            certificates=[
                Certificate(
                    type=CertificateType.STAKE_POOL_REGISTRATION,
                    params=PoolRegistrationParams(
                        poolKey=PoolKey(
                            type=PoolKeyType.DEVICE_OWNED, key="m/1852'/1815'/0'/0/0"
                        ),
                        vrfKeyHashHex="0123456789012345678901234567890123456789012345678901234567890123",
                        pledge=0,
                        cost=0,
                        margin=Margin(numerator=0, denominator=1),
                        rewardAccount=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="f123456789012345678901234567890123456789012345678901234567",
                        ),
                        poolOwners=[],
                        relays=[],
                        metadata=None,
                    ),
                )
            ],
            ),
        signingMode=TransactionSigningMode.POOL_REGISTRATION_AS_OPERATOR,
        txBody="",
        additionalWitnessPaths=["m/1854'/1815'/0'/0/0"],
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="Ordinary_staking_path_in_Pool_Registration_Operator_Tx",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            certificates=[
                Certificate(
                    type=CertificateType.STAKE_POOL_REGISTRATION,
                    params=PoolRegistrationParams(
                        poolKey=PoolKey(
                            type=PoolKeyType.DEVICE_OWNED, key="m/1852'/1815'/0'/0/0"
                        ),
                        vrfKeyHashHex="0123456789012345678901234567890123456789012345678901234567890123",
                        pledge=0,
                        cost=0,
                        margin=Margin(numerator=0, denominator=1),
                        rewardAccount=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="f123456789012345678901234567890123456789012345678901234567",
                        ),
                        poolOwners=[],
                        relays=[],
                        metadata=None,
                    ),
                )
            ],
            ),
        signingMode=TransactionSigningMode.POOL_REGISTRATION_AS_OPERATOR,
        txBody="",
        additionalWitnessPaths=["m/1852'/1815'/0'/2/0"],
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="Multisig_staking_path_in_Pool_Registration_Operator_Tx",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            certificates=[
                Certificate(
                    type=CertificateType.STAKE_POOL_REGISTRATION,
                    params=PoolRegistrationParams(
                        poolKey=PoolKey(
                            type=PoolKeyType.DEVICE_OWNED, key="m/1852'/1815'/0'/0/0"
                        ),
                        vrfKeyHashHex="0123456789012345678901234567890123456789012345678901234567890123",
                        pledge=0,
                        cost=0,
                        margin=Margin(numerator=0, denominator=1),
                        rewardAccount=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="f123456789012345678901234567890123456789012345678901234567",
                        ),
                        poolOwners=[],
                        relays=[],
                        metadata=None,
                    ),
                )
            ],
            ),
        signingMode=TransactionSigningMode.POOL_REGISTRATION_AS_OPERATOR,
        txBody="",
        additionalWitnessPaths=["m/1854'/1815'/0'/2/0"],
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="Mint_path_in_Pool_Registration_Operator_Tx",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            certificates=[
                Certificate(
                    type=CertificateType.STAKE_POOL_REGISTRATION,
                    params=PoolRegistrationParams(
                        poolKey=PoolKey(
                            type=PoolKeyType.DEVICE_OWNED, key="m/1852'/1815'/0'/0/0"
                        ),
                        vrfKeyHashHex="0123456789012345678901234567890123456789012345678901234567890123",
                        pledge=0,
                        cost=0,
                        margin=Margin(numerator=0, denominator=1),
                        rewardAccount=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="f123456789012345678901234567890123456789012345678901234567",
                        ),
                        poolOwners=[],
                        relays=[],
                        metadata=None,
                    ),
                )
            ],
            ),
        signingMode=TransactionSigningMode.POOL_REGISTRATION_AS_OPERATOR,
        txBody="",
        additionalWitnessPaths=["m/1855'/1815'/0'"],
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
]

singleAccountDenyTestCases: List[SignTxTestCase] = [
    SignTxTestCase(
        name="Input_and_change_output_account_mismatch",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[
                TxOutputAlonzo(
                    destination=TxOutputDestination(
                        type=TxOutputDestinationType.THIRD_PARTY,
                        params=ThirdPartyAddressParams(
                            addressHex="01eb0baa5e570cffbe2934db29df0b6a3d7c0430ee65d4c3a7ab2fefb91bc428e4720702ebd5dab4fb175324c192dc9bb76cc5da956e3c8dff"
                        ),
                    ),
                    amount=1,
                    format=TxOutputFormat.ARRAY_LEGACY,
                    tokenBundle=[],
                    datum=None,
                ),
                TxOutputAlonzo(
                    destination=TxOutputDestination(
                        type=TxOutputDestinationType.DEVICE_OWNED,
                        params=DeriveAddressTestCase(
                            name="",
                            netDesc=NetworkDesc(networkId=1, protocol=764824073),
                            addrType=AddressType.BASE_PAYMENT_KEY_STAKE_KEY,
                            spendingValue="m/1852'/1815'/1'/0/0",
                            stakingValue="m/1852'/1815'/0'/2/0",
                            result="",
                            result_hex=None,
                            nano_nav_confirm=None,
                            nano_nav_show=None,
                        ),
                    ),
                    amount=7120787,
                    format=TxOutputFormat.ARRAY_LEGACY,
                    tokenBundle=[],
                    datum=None,
                ),
            ],
            ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="",
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="Input_and_stake_deregistration_certificate_account_mismatch",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["inlineShelleyBase1v2"]],
            certificates=[
                Certificate(
                    type=CertificateType.STAKE_DEREGISTRATION,
                    params=StakeRegistrationParams(
                        stakeCredential=CredentialParams(
                            type=CredentialParamsType.KEY_PATH,
                            keyValue="m/1852'/1815'/1'/2/0",
                        )
                    ),
                )
            ],
            ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="",
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="Input_and_withdrawal_account_mismatch",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["inlineShelleyBase1v2"]],
            withdrawals=[
                Withdrawal(
                    stakeCredential=CredentialParams(
                        type=CredentialParamsType.KEY_PATH,
                        keyValue="m/1852'/1815'/1'/2/0",
                    ),
                    amount=1000,
                )
            ],
            ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="",
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="Change_output_and_stake_deregistration_account_mismatch",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[
                TxOutputAlonzo(
                    destination=TxOutputDestination(
                        type=TxOutputDestinationType.THIRD_PARTY,
                        params=ThirdPartyAddressParams(
                            addressHex="01eb0baa5e570cffbe2934db29df0b6a3d7c0430ee65d4c3a7ab2fefb91bc428e4720702ebd5dab4fb175324c192dc9bb76cc5da956e3c8dff"
                        ),
                    ),
                    amount=1,
                    format=TxOutputFormat.ARRAY_LEGACY,
                    tokenBundle=[],
                    datum=None,
                ),
                TxOutputAlonzo(
                    destination=TxOutputDestination(
                        type=TxOutputDestinationType.DEVICE_OWNED,
                        params=DeriveAddressTestCase(
                            name="",
                            netDesc=NetworkDesc(networkId=1, protocol=764824073),
                            addrType=AddressType.BASE_PAYMENT_KEY_STAKE_KEY,
                            spendingValue="m/1852'/1815'/0'/0/0",
                            stakingValue="m/1852'/1815'/0'/2/0",
                            result="",
                            result_hex=None,
                            nano_nav_confirm=None,
                            nano_nav_show=None,
                        ),
                    ),
                    amount=7120787,
                    format=TxOutputFormat.ARRAY_LEGACY,
                    tokenBundle=[],
                    datum=None,
                ),
            ],
            certificates=[
                Certificate(
                    type=CertificateType.STAKE_DEREGISTRATION,
                    params=StakeRegistrationParams(
                        stakeCredential=CredentialParams(
                            type=CredentialParamsType.KEY_PATH,
                            keyValue="m/1852'/1815'/1'/2/0",
                        )
                    ),
                )
            ],
            ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="",
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
        deny_before_review=True,
    ),
    SignTxTestCase(
        name="Change_output_and_withdrawal_account_mismatch",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[
                TxOutputAlonzo(
                    destination=TxOutputDestination(
                        type=TxOutputDestinationType.THIRD_PARTY,
                        params=ThirdPartyAddressParams(
                            addressHex="01eb0baa5e570cffbe2934db29df0b6a3d7c0430ee65d4c3a7ab2fefb91bc428e4720702ebd5dab4fb175324c192dc9bb76cc5da956e3c8dff"
                        ),
                    ),
                    amount=1,
                    format=TxOutputFormat.ARRAY_LEGACY,
                    tokenBundle=[],
                    datum=None,
                ),
                TxOutputAlonzo(
                    destination=TxOutputDestination(
                        type=TxOutputDestinationType.DEVICE_OWNED,
                        params=DeriveAddressTestCase(
                            name="",
                            netDesc=NetworkDesc(networkId=1, protocol=764824073),
                            addrType=AddressType.BASE_PAYMENT_KEY_STAKE_KEY,
                            spendingValue="m/1852'/1815'/0'/0/0",
                            stakingValue="m/1852'/1815'/0'/2/0",
                            result="",
                            result_hex=None,
                            nano_nav_confirm=None,
                            nano_nav_show=None,
                        ),
                    ),
                    amount=7120787,
                    format=TxOutputFormat.ARRAY_LEGACY,
                    tokenBundle=[],
                    datum=None,
                ),
            ],
            withdrawals=[
                Withdrawal(
                    stakeCredential=CredentialParams(
                        type=CredentialParamsType.KEY_PATH,
                        keyValue="m/1852'/1815'/1'/2/0",
                    ),
                    amount=1000,
                )
            ],
            ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="",
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
        deny_before_review=True,
    ),
    SignTxTestCase(
        name="Stake_deregistration_certificate_and_withdrawal_account_mismatch",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["inlineShelleyBase1v2"]],
            certificates=[
                Certificate(
                    type=CertificateType.STAKE_DEREGISTRATION,
                    params=StakeRegistrationParams(
                        stakeCredential=CredentialParams(
                            type=CredentialParamsType.KEY_PATH,
                            keyValue="m/1852'/1815'/0'/2/0",
                        )
                    ),
                )
            ],
            withdrawals=[
                Withdrawal(
                    stakeCredential=CredentialParams(
                        type=CredentialParamsType.KEY_PATH,
                        keyValue="m/1852'/1815'/1'/2/0",
                    ),
                    amount=1000,
                )
            ],
            ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="",
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
        deny_before_review=True,
    ),
    SignTxTestCase(
        name="Byron_to_Shelley_transfer_input_account_mismatch",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[
                TxInput(
                    txHashHex="3b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7",
                    path="m/44'/1815'/1'/0/0",
                    outputIndex=0,
                ),
                TxInput(
                    txHashHex="3b40265111d8bb3c3c608d95b3a0bf83461ace32d79336579a1939b3aad1c0b7",
                    path="m/1852'/1815'/1'/0/0",
                    outputIndex=0,
                ),
            ],
            outputs=[
                TxOutputAlonzo(
                    destination=TxOutputDestination(
                        type=TxOutputDestinationType.THIRD_PARTY,
                        params=ThirdPartyAddressParams(
                            addressHex="115e2f080eb93bad86d401545e0ce5f2221096d6477e11e6643922fa8d4dc0d667c1316ff84e572310e265edb31330448b36b7179e28dd419e"
                        ),
                    ),
                    amount=1,
                    format=TxOutputFormat.ARRAY_LEGACY,
                    tokenBundle=[],
                    datum=None,
                )
            ],
            ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="",
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
        expected_warnings=[WarningBit.WARNING_BIT_NETWORK_UNUSUAL],
    ),
    SignTxTestCase(
        name="Byron_to_Shelley_transfer_output_account_mismatch",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoByron2"]],
            outputs=[
                TxOutputAlonzo(
                    destination=TxOutputDestination(
                        type=TxOutputDestinationType.DEVICE_OWNED,
                        params=DeriveAddressTestCase(
                            name="",
                            netDesc=NetworkDesc(networkId=1, protocol=764824073),
                            addrType=AddressType.BASE_PAYMENT_KEY_STAKE_KEY,
                            spendingValue="m/1852'/1815'/1'/0/0",
                            stakingValue="m/1852'/1815'/1'/2/0",
                            result="",
                            result_hex=None,
                            nano_nav_confirm=None,
                            nano_nav_show=None,
                        ),
                    ),
                    amount=7120787,
                    format=TxOutputFormat.ARRAY_LEGACY,
                    tokenBundle=[],
                    datum=None,
                )
            ],
            ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="",
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
]

collateralOutputDenyTestCases: List[SignTxTestCase] = [
    SignTxTestCase(
        name="Collateral_output_with_datum_hash",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            collateralOutput=TxOutputAlonzo(
                destination=TxOutputDestination(
                    type=TxOutputDestinationType.THIRD_PARTY,
                    params=ThirdPartyAddressParams(
                        addressHex="105e2f080eb93bad86d401545e0ce5f2221096d6477e11e6643922fa8d2ed495234dc0d667c1316ff84e572310e265edb31330448b36b7179e"
                    ),
                ),
                amount=7120787,
                format=TxOutputFormat.ARRAY_LEGACY,
                tokenBundle=[],
                datum=Datum(
                    type=DatumType.HASH,
                    datumHex="ffd4d009f554ba4fd8ed1f1d703244819861a9d34fd4753bcf3ff32f043ce188",
                ),
            ),
            ),
        signingMode=TransactionSigningMode.PLUTUS_TRANSACTION,
        txBody="",
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="Collateral_output_with_inline_datum",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            collateralOutput=TxOutputBabbage(
                destination=TxOutputDestination(
                    type=TxOutputDestinationType.THIRD_PARTY,
                    params=ThirdPartyAddressParams(
                        addressHex="105e2f080eb93bad86d401545e0ce5f2221096d6477e11e6643922fa8d2ed495234dc0d667c1316ff84e572310e265edb31330448b36b7179e"
                    ),
                ),
                amount=7120787,
                format=TxOutputFormat.MAP_BABBAGE,
                tokenBundle=[],
                datum=Datum(
                    type=DatumType.INLINE,
                    datumHex="12b8240c5470b47c159597b6f71d78c7fc99d1d8d911cb19b8f50211938ef361a22d30cd8f6354ec50e99a7d3cf3e06797ed4af3d358e01b2a957caa4010da328720b9fbe7a3a6d10209a13d2eb11933eb1bf2ab02713117e421b6dcc66297c41b95ad32d3457a0e6b44d8482385f311465964c3daff226acfb7bbda47011f1a6531db30e5b5977143c48f8b8eb739487f87dc13896f58529cfb48e415fc6123e708cdc3cb15cc1900ecf88c5fc9ff66d8ad6dae18c79e4a3c392a0df4d16ffa3e370f4dad8d8e9d171c5656bb317c78a2711057e7ae0beb1dc66ba01aa69d0c0db244e6742d7758ce8da00dfed6225d4aed4b01c42a0352688ed5803f3fd64873f11355305d9db309f4a2a6673cc408a06b8827a5edef7b0fd8742627fb8aa102a084b7db72fcb5c3d1bf437e2a936b738902a9c0258b462b9f2e9befd2c6bcfc036143bb34342b9124888a5b29fa5d60909c81319f034c11542b05ca3ff6c64c7642ff1e2b25fb60dc9bb6f5c914dd4149f31896955d4d204d822deddc46f852115a479edf7521cdf4ce596805875011855158fd303c33a2a7916a9cb7acaaf5aeca7e6efb75960e9597cd845bd9a93610bf1ab47ab0de943e8a96e26a24c4996f7b07fad437829fee5bc3496192608d4c04ac642cdec7bdbb8a948ad1d434",
                ),
                referenceScriptHex=None,
            ),
            ),
        signingMode=TransactionSigningMode.PLUTUS_TRANSACTION,
        txBody="",
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="Collateral_output_with_reference_script",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["inlineByronMainnet3003112"]],
            collateralOutput=TxOutputBabbage(
                destination=TxOutputDestination(
                    type=TxOutputDestinationType.THIRD_PARTY,
                    params=ThirdPartyAddressParams(
                        addressHex="105e2f080eb93bad86d401545e0ce5f2221096d6477e11e6643922fa8d2ed495234dc0d667c1316ff84e572310e265edb31330448b36b7179e"
                    ),
                ),
                amount=7120787,
                format=TxOutputFormat.MAP_BABBAGE,
                tokenBundle=[],
                datum=None,
                referenceScriptHex="deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            ),
            ),
        signingMode=TransactionSigningMode.PLUTUS_TRANSACTION,
        txBody="",
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
]

testsInvalidTokenBundleOrdering: List[SignTxTestCase] = [
    SignTxTestCase(
        name="Deny_tx_where_asset_groups_are_not_ordered",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[
                TxOutputAlonzo(
                    destination=TxOutputDestination(
                        type=TxOutputDestinationType.THIRD_PARTY,
                        params=ThirdPartyAddressParams(
                            addressHex="01eb0baa5e570cffbe2934db29df0b6a3d7c0430ee65d4c3a7ab2fefb91bc428e4720702ebd5dab4fb175324c192dc9bb76cc5da956e3c8dff"
                        ),
                    ),
                    amount=1234,
                    format=TxOutputFormat.ARRAY_LEGACY,
                    tokenBundle=[
                        AssetGroup(
                            policyIdHex="75a292ffee938be03e9bae5657982a74e9014eb4960108c9e23a5b39",
                            tokens=[Token(assetNameHex="7564247542686911", amount=47)],
                        ),
                        AssetGroup(
                            policyIdHex="71a292ffee938be03e9bae5657982a74e9014eb4960108c9e23a5b39",
                            tokens=[Token(assetNameHex="7564247542686911", amount=47)],
                        ),
                    ],
                    datum=None,
                )
            ],
            ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="",
        expected_sw=StatusWord.SWO_TX_PARSING_FAIL_CANONICAL_ORDER,
    ),
    SignTxTestCase(
        name="Deny_tx_where_asset_groups_are_not_unique",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[
                TxOutputAlonzo(
                    destination=TxOutputDestination(
                        type=TxOutputDestinationType.THIRD_PARTY,
                        params=ThirdPartyAddressParams(
                            addressHex="01eb0baa5e570cffbe2934db29df0b6a3d7c0430ee65d4c3a7ab2fefb91bc428e4720702ebd5dab4fb175324c192dc9bb76cc5da956e3c8dff"
                        ),
                    ),
                    amount=1234,
                    format=TxOutputFormat.ARRAY_LEGACY,
                    tokenBundle=[
                        AssetGroup(
                            policyIdHex="75a292ffee938be03e9bae5657982a74e9014eb4960108c9e23a5b39",
                            tokens=[Token(assetNameHex="7564247542686911", amount=47)],
                        ),
                        AssetGroup(
                            policyIdHex="75a292ffee938be03e9bae5657982a74e9014eb4960108c9e23a5b39",
                            tokens=[Token(assetNameHex="7564247542686911", amount=47)],
                        ),
                    ],
                    datum=None,
                )
            ],
            ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="",
        expected_sw=StatusWord.SWO_TX_PARSING_FAIL_CANONICAL_ORDER,
    ),
    SignTxTestCase(
        name="Deny_tx_where_tokens_within_an_asset_group_are_not_ordered_alphabetical",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[
                TxOutputAlonzo(
                    destination=TxOutputDestination(
                        type=TxOutputDestinationType.THIRD_PARTY,
                        params=ThirdPartyAddressParams(
                            addressHex="01eb0baa5e570cffbe2934db29df0b6a3d7c0430ee65d4c3a7ab2fefb91bc428e4720702ebd5dab4fb175324c192dc9bb76cc5da956e3c8dff"
                        ),
                    ),
                    amount=1234,
                    format=TxOutputFormat.ARRAY_LEGACY,
                    tokenBundle=[
                        AssetGroup(
                            policyIdHex="75a292ffee938be03e9bae5657982a74e9014eb4960108c9e23a5b39",
                            tokens=[
                                Token(assetNameHex="7564247542686911", amount=47),
                                Token(assetNameHex="74652474436f696e", amount=7878754),
                            ],
                        )
                    ],
                    datum=None,
                )
            ],
            ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="",
        expected_sw=StatusWord.SWO_TX_PARSING_FAIL_CANONICAL_ORDER,
    ),
    SignTxTestCase(
        name="Deny_tx_where_tokens_within_an_asset_group_are_not_ordered_length",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[
                TxOutputAlonzo(
                    destination=TxOutputDestination(
                        type=TxOutputDestinationType.THIRD_PARTY,
                        params=ThirdPartyAddressParams(
                            addressHex="01eb0baa5e570cffbe2934db29df0b6a3d7c0430ee65d4c3a7ab2fefb91bc428e4720702ebd5dab4fb175324c192dc9bb76cc5da956e3c8dff"
                        ),
                    ),
                    amount=1234,
                    format=TxOutputFormat.ARRAY_LEGACY,
                    tokenBundle=[
                        AssetGroup(
                            policyIdHex="75a292ffee938be03e9bae5657982a74e9014eb4960108c9e23a5b39",
                            tokens=[
                                Token(assetNameHex="7564247542686911", amount=47),
                                Token(assetNameHex="756424754268", amount=7878754),
                            ],
                        )
                    ],
                    datum=None,
                )
            ],
            ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="",
        expected_sw=StatusWord.SWO_TX_PARSING_FAIL_CANONICAL_ORDER,
    ),
    SignTxTestCase(
        name="Deny_tx_where_tokens_within_an_asset_group_are_not_unique",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[
                TxOutputAlonzo(
                    destination=TxOutputDestination(
                        type=TxOutputDestinationType.THIRD_PARTY,
                        params=ThirdPartyAddressParams(
                            addressHex="01eb0baa5e570cffbe2934db29df0b6a3d7c0430ee65d4c3a7ab2fefb91bc428e4720702ebd5dab4fb175324c192dc9bb76cc5da956e3c8dff"
                        ),
                    ),
                    amount=1234,
                    format=TxOutputFormat.ARRAY_LEGACY,
                    tokenBundle=[
                        AssetGroup(
                            policyIdHex="75a292ffee938be03e9bae5657982a74e9014eb4960108c9e23a5b39",
                            tokens=[
                                Token(assetNameHex="7564247542686911", amount=47),
                                Token(assetNameHex="7564247542686911", amount=7878754),
                            ],
                        )
                    ],
                    datum=None,
                )
            ],
            ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="",
        expected_sw=StatusWord.SWO_TX_PARSING_FAIL_CANONICAL_ORDER,
    ),
    SignTxTestCase(
        name="Deny_tx_with_mint_fields_with_invalid_canonical_ordering_of_policies",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[],
            mint=[
                AssetGroup(
                    policyIdHex="7eae28af2208be856f7a119668ae52a49b73725e326dc16579dcc374",
                    tokens=[
                        Token(assetNameHex="", amount=1),
                        Token(
                            assetNameHex="1e349c9bdea19fd6c147626a5260bc44b71635f398b67c59881df209",
                            amount=-1,
                        ),
                    ],
                ),
                AssetGroup(
                    policyIdHex="7eae28af2208be856f7a119668ae52a49b73725e326dc16579dcc373",
                    tokens=[Token(assetNameHex="", amount=1)],
                ),
            ],
            ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="",
        expected_sw=StatusWord.SWO_TX_PARSING_FAIL_CANONICAL_ORDER,
    ),
    SignTxTestCase(
        name="Deny_tx_with_mint_fields_with_invalid_canonical_ordering_of_asset_names",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[],
            mint=[
                AssetGroup(
                    policyIdHex="7eae28af2208be856f7a119668ae52a49b73725e326dc16579dcc374",
                    tokens=[
                        Token(
                            assetNameHex="1e349c9bdea19fd6c147626a5260bc44b71635f398b67c59881df209",
                            amount=-1,
                        ),
                        Token(assetNameHex="", amount=1),
                    ],
                )
            ],
            ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="",
        expected_sw=StatusWord.SWO_TX_PARSING_FAIL_CANONICAL_ORDER,
    ),
    SignTxTestCase(
        name="Deny_tx_with_voter_with_zero_votes",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["externalByronMainnet"]],
            votingProcedures=[
                VoterVotes(
                    Voter(VoterType.DREP_KEY_PATH, "m/1852'/1815'/0'/3/0"), []
                )
            ],
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="",
        expected_sw=StatusWord.SWO_TX_PARSING_FAIL_VOTING_PROCEDURES,
    ),
    SignTxTestCase(
        name="Deny_tx_with_mint_token_group_with_zero_tokens",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[],
            mint=[
                AssetGroup(
                    policyIdHex="7eae28af2208be856f7a119668ae52a49b73725e326dc16579dcc374",
                    tokens=[],
                )
            ],
            ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="",
        expected_sw=StatusWord.SWO_TX_PARSING_FAIL_MINT,
    ),
    SignTxTestCase(
        name="Deny_tx_with_output_token_group_with_zero_tokens",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[
                TxOutputAlonzo(
                    destination=TxOutputDestination(
                        type=TxOutputDestinationType.THIRD_PARTY,
                        params=ThirdPartyAddressParams(
                            addressHex="01eb0baa5e570cffbe2934db29df0b6a3d7c0430ee65d4c3a7ab2fefb91bc428e4720702ebd5dab4fb175324c192dc9bb76cc5da956e3c8dff"
                        ),
                    ),
                    amount=1234,
                    format=TxOutputFormat.ARRAY_LEGACY,
                    tokenBundle=[
                        AssetGroup(
                            policyIdHex="75a292ffee938be03e9bae5657982a74e9014eb4960108c9e23a5b39",
                            tokens=[],
                        ),
                    ],
                    datum=None,
                )
            ],
            ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="",
        expected_sw=StatusWord.SWO_TX_PARSING_FAIL_OUTPUTS,
    ),
]

poolRegistrationOwnerDenyTestCases: List[SignTxTestCase] = [
    SignTxTestCase(
        name="Different_index",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoMultisig"]],
            outputs=[outputs["inlineShelleyBase1"]],
            certificates=[
                Certificate(
                    type=CertificateType.STAKE_POOL_REGISTRATION,
                    params=PoolRegistrationParams(
                        poolKey=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="13381d918ec0283ceeff60f7f4fc21e1540e053ccf8a77307a7a32ad",
                        ),
                        vrfKeyHashHex="07821cd344d7fd7e3ae5f2ed863218cb979ff1d59e50c4276bdc479b0d084450",
                        pledge=50000000000,
                        cost=340000000,
                        margin=Margin(numerator=3, denominator=100),
                        rewardAccount=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="e1794d9b3408c9fb67b950a48a0690f070f117e9978f7fc1d120fc58ad",
                        ),
                        poolOwners=[
                            PoolKey(
                                type=PoolKeyType.DEVICE_OWNED,
                                key="m/1852'/1815'/0'/2/0",
                            ),
                            PoolKey(
                                type=PoolKeyType.THIRD_PARTY,
                                key="794d9b3408c9fb67b950a48a0690f070f117e9978f7fc1d120fc58ad",
                            ),
                        ],
                        relays=[
                            Relay(
                                type=RelayType.SINGLE_HOST_IP_ADDR,
                                params=SingleHostIpAddrRelayParams(
                                    portNumber=3000, ipv4="54.228.75.154", ipv6=None
                                ),
                            ),
                            Relay(
                                type=RelayType.SINGLE_HOST_IP_ADDR,
                                params=SingleHostIpAddrRelayParams(
                                    portNumber=3000,
                                    ipv4="54.228.75.155",
                                    ipv6="24ff:7801:33a2:e383:a5c4:340a:07c2:76e5",
                                ),
                            ),
                            Relay(
                                type=RelayType.SINGLE_HOST_HOSTNAME,
                                params=SingleHostHostnameRelayParams(
                                    portNumber=3000, dnsName="aaaa.bbbb.com"
                                ),
                            ),
                            Relay(
                                type=RelayType.MULTI_HOST,
                                params=MultiHostRelayParams(dnsName="aaaa.bbbc.com"),
                            ),
                        ],
                        metadata=PoolMetadataParams(
                            metadataUrl="https://www.vacuumlabs.com/sampleUrl.json",
                            metadataHashHex="cdb714fd722c24aeb10c93dbb0ff03bd4783441cd5ba2a8b6f373390520535bb",
                        ),
                    ),
                )
            ],
            ),
        signingMode=TransactionSigningMode.POOL_REGISTRATION_AS_OWNER,
        txBody="",
        additionalWitnessPaths=["m/1852'/1815'/0'/2/0", "m/1852'/1815'/0'/2/1"],
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="Different_prefix",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoMultisig"]],
            outputs=[outputs["inlineShelleyBase1"]],
            certificates=[
                Certificate(
                    type=CertificateType.STAKE_POOL_REGISTRATION,
                    params=PoolRegistrationParams(
                        poolKey=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="13381d918ec0283ceeff60f7f4fc21e1540e053ccf8a77307a7a32ad",
                        ),
                        vrfKeyHashHex="07821cd344d7fd7e3ae5f2ed863218cb979ff1d59e50c4276bdc479b0d084450",
                        pledge=50000000000,
                        cost=340000000,
                        margin=Margin(numerator=3, denominator=100),
                        rewardAccount=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="e1794d9b3408c9fb67b950a48a0690f070f117e9978f7fc1d120fc58ad",
                        ),
                        poolOwners=[
                            PoolKey(
                                type=PoolKeyType.DEVICE_OWNED,
                                key="m/1852'/1815'/0'/2/0",
                            ),
                            PoolKey(
                                type=PoolKeyType.THIRD_PARTY,
                                key="794d9b3408c9fb67b950a48a0690f070f117e9978f7fc1d120fc58ad",
                            ),
                        ],
                        relays=[
                            Relay(
                                type=RelayType.SINGLE_HOST_IP_ADDR,
                                params=SingleHostIpAddrRelayParams(
                                    portNumber=3000, ipv4="54.228.75.154", ipv6=None
                                ),
                            ),
                            Relay(
                                type=RelayType.SINGLE_HOST_IP_ADDR,
                                params=SingleHostIpAddrRelayParams(
                                    portNumber=3000,
                                    ipv4="54.228.75.155",
                                    ipv6="24ff:7801:33a2:e383:a5c4:340a:07c2:76e5",
                                ),
                            ),
                            Relay(
                                type=RelayType.SINGLE_HOST_HOSTNAME,
                                params=SingleHostHostnameRelayParams(
                                    portNumber=3000, dnsName="aaaa.bbbb.com"
                                ),
                            ),
                            Relay(
                                type=RelayType.MULTI_HOST,
                                params=MultiHostRelayParams(dnsName="aaaa.bbbc.com"),
                            ),
                        ],
                        metadata=PoolMetadataParams(
                            metadataUrl="https://www.vacuumlabs.com/sampleUrl.json",
                            metadataHashHex="cdb714fd722c24aeb10c93dbb0ff03bd4783441cd5ba2a8b6f373390520535bb",
                        ),
                    ),
                )
            ],
            ),
        signingMode=TransactionSigningMode.POOL_REGISTRATION_AS_OWNER,
        txBody="",
        additionalWitnessPaths=["m/1852'/1815'/0'/2/0", "m/1854'/1815'/0'/2/0"],
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="No_path_given",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoMultisig"]],
            outputs=[outputs["inlineShelleyBase1"]],
            certificates=[
                Certificate(
                    type=CertificateType.STAKE_POOL_REGISTRATION,
                    params=PoolRegistrationParams(
                        poolKey=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="13381d918ec0283ceeff60f7f4fc21e1540e053ccf8a77307a7a32ad",
                        ),
                        vrfKeyHashHex="07821cd344d7fd7e3ae5f2ed863218cb979ff1d59e50c4276bdc479b0d084450",
                        pledge=50000000000,
                        cost=340000000,
                        margin=Margin(numerator=3, denominator=100),
                        rewardAccount=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="e1794d9b3408c9fb67b950a48a0690f070f117e9978f7fc1d120fc58ad",
                        ),
                        poolOwners=[
                            PoolKey(
                                type=PoolKeyType.THIRD_PARTY,
                                key="794d9b3408c9fb67b950a48a0690f070f117e9978f7fc1d120fc58ad",
                            )
                        ],
                        relays=[
                            Relay(
                                type=RelayType.SINGLE_HOST_IP_ADDR,
                                params=SingleHostIpAddrRelayParams(
                                    portNumber=3000, ipv4="54.228.75.154", ipv6=None
                                ),
                            ),
                            Relay(
                                type=RelayType.SINGLE_HOST_IP_ADDR,
                                params=SingleHostIpAddrRelayParams(
                                    portNumber=3000,
                                    ipv4="54.228.75.155",
                                    ipv6="24ff:7801:33a2:e383:a5c4:340a:07c2:76e5",
                                ),
                            ),
                            Relay(
                                type=RelayType.SINGLE_HOST_HOSTNAME,
                                params=SingleHostHostnameRelayParams(
                                    portNumber=3000, dnsName="aaaa.bbbb.com"
                                ),
                            ),
                            Relay(
                                type=RelayType.MULTI_HOST,
                                params=MultiHostRelayParams(dnsName="aaaa.bbbc.com"),
                            ),
                        ],
                        metadata=PoolMetadataParams(
                            metadataUrl="https://www.vacuumlabs.com/sampleUrl.json",
                            metadataHashHex="cdb714fd722c24aeb10c93dbb0ff03bd4783441cd5ba2a8b6f373390520535bb",
                        ),
                    ),
                )
            ],
            ),
        signingMode=TransactionSigningMode.POOL_REGISTRATION_AS_OWNER,
        txBody="",
        additionalWitnessPaths=["m/1852'/1815'/0'/2/0", "m/1854'/1815'/0'/2/0"],
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="Invalid_numerator_denominator_relationship",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoMultisig"]],
            outputs=[outputs["inlineShelleyBase1"]],
            certificates=[
                Certificate(
                    type=CertificateType.STAKE_POOL_REGISTRATION,
                    params=PoolRegistrationParams(
                        poolKey=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="13381d918ec0283ceeff60f7f4fc21e1540e053ccf8a77307a7a32ad",
                        ),
                        vrfKeyHashHex="07821cd344d7fd7e3ae5f2ed863218cb979ff1d59e50c4276bdc479b0d084450",
                        pledge=50000000000,
                        cost=340000000,
                        margin=Margin(numerator=3, denominator=1),
                        rewardAccount=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="e1794d9b3408c9fb67b950a48a0690f070f117e9978f7fc1d120fc58ad",
                        ),
                        poolOwners=[
                            PoolKey(
                                type=PoolKeyType.DEVICE_OWNED,
                                key="m/1852'/1815'/0'/2/0",
                            )
                        ],
                        relays=[
                            Relay(
                                type=RelayType.SINGLE_HOST_IP_ADDR,
                                params=SingleHostIpAddrRelayParams(
                                    portNumber=3000, ipv4="54.228.75.154", ipv6=None
                                ),
                            )
                        ],
                        metadata=PoolMetadataParams(
                            metadataUrl="https://www.vacuumlabs.com/sampleUrl.json",
                            metadataHashHex="cdb714fd722c24aeb10c93dbb0ff03bd4783441cd5ba2a8b6f373390520535bb",
                        ),
                    ),
                )
            ],
            ),
        signingMode=TransactionSigningMode.POOL_REGISTRATION_AS_OWNER,
        txBody="",
        additionalWitnessPaths=["m/1852'/1815'/0'/2/0", "m/1854'/1815'/0'/2/0"],
        expected_sw=StatusWord.SWO_TX_PARSING_FAIL_CERTIFICATES,
        deny_before_review=True,
    ),
]

stakePoolRegistrationPoolIdDenyTestCases: List[SignTxTestCase] = [
    SignTxTestCase(
        name="Path_sent_in_for_Pool_Registration_Owner_Tx",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoMultisig"]],
            outputs=[outputs["inlineShelleyBase1"]],
            certificates=[
                Certificate(
                    type=CertificateType.STAKE_POOL_REGISTRATION,
                    params=PoolRegistrationParams(
                        poolKey=PoolKey(
                            type=PoolKeyType.DEVICE_OWNED, key="m/1852'/1815'/0'/0/0"
                        ),
                        vrfKeyHashHex="07821cd344d7fd7e3ae5f2ed863218cb979ff1d59e50c4276bdc479b0d084450",
                        pledge=50000000000,
                        cost=340000000,
                        margin=Margin(numerator=3, denominator=100),
                        rewardAccount=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="e1794d9b3408c9fb67b950a48a0690f070f117e9978f7fc1d120fc58ad",
                        ),
                        poolOwners=[
                            PoolKey(
                                type=PoolKeyType.DEVICE_OWNED,
                                key="m/1852'/1815'/0'/2/0",
                            )
                        ],
                        relays=[
                            Relay(
                                type=RelayType.SINGLE_HOST_IP_ADDR,
                                params=SingleHostIpAddrRelayParams(
                                    portNumber=3000, ipv4="54.228.75.154", ipv6=None
                                ),
                            )
                        ],
                        metadata=PoolMetadataParams(
                            metadataUrl="https://www.vacuumlabs.com/sampleUrl.json",
                            metadataHashHex="cdb714fd722c24aeb10c93dbb0ff03bd4783441cd5ba2a8b6f373390520535bb",
                        ),
                    ),
                )
            ],
            ),
        signingMode=TransactionSigningMode.POOL_REGISTRATION_AS_OWNER,
        txBody="",
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
        deny_before_review=True,
    ),
    SignTxTestCase(
        name="Hash_sent_in_for_Pool_Registration_Operator_Tx",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoMultisig"]],
            outputs=[outputs["inlineShelleyBase1"]],
            certificates=[
                Certificate(
                    type=CertificateType.STAKE_POOL_REGISTRATION,
                    params=PoolRegistrationParams(
                        poolKey=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="01234567890123456789012345678901234567890123456789012345",
                        ),
                        vrfKeyHashHex="07821cd344d7fd7e3ae5f2ed863218cb979ff1d59e50c4276bdc479b0d084450",
                        pledge=50000000000,
                        cost=340000000,
                        margin=Margin(numerator=3, denominator=100),
                        rewardAccount=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="e1794d9b3408c9fb67b950a48a0690f070f117e9978f7fc1d120fc58ad",
                        ),
                        poolOwners=[
                            PoolKey(
                                type=PoolKeyType.DEVICE_OWNED,
                                key="m/1852'/1815'/0'/2/0",
                            )
                        ],
                        relays=[
                            Relay(
                                type=RelayType.SINGLE_HOST_IP_ADDR,
                                params=SingleHostIpAddrRelayParams(
                                    portNumber=3000, ipv4="54.228.75.154", ipv6=None
                                ),
                            )
                        ],
                        metadata=PoolMetadataParams(
                            metadataUrl="https://www.vacuumlabs.com/sampleUrl.json",
                            metadataHashHex="cdb714fd722c24aeb10c93dbb0ff03bd4783441cd5ba2a8b6f373390520535bb",
                        ),
                    ),
                )
            ],
            ),
        signingMode=TransactionSigningMode.POOL_REGISTRATION_AS_OPERATOR,
        txBody="",
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
        deny_before_review=True,
    ),
]

stakePoolRegistrationOwnerDenyTestCases: List[SignTxTestCase] = [
    SignTxTestCase(
        name="Non_staking_path_for_Pool_Registration_Owner_Tx",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoMultisig"]],
            outputs=[outputs["inlineShelleyBase1"]],
            certificates=[
                Certificate(
                    type=CertificateType.STAKE_POOL_REGISTRATION,
                    params=PoolRegistrationParams(
                        poolKey=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="13381d918ec0283ceeff60f7f4fc21e1540e053ccf8a77307a7a32ad",
                        ),
                        vrfKeyHashHex="07821cd344d7fd7e3ae5f2ed863218cb979ff1d59e50c4276bdc479b0d084450",
                        pledge=50000000000,
                        cost=340000000,
                        margin=Margin(numerator=3, denominator=100),
                        rewardAccount=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="e1794d9b3408c9fb67b950a48a0690f070f117e9978f7fc1d120fc58ad",
                        ),
                        poolOwners=[
                            PoolKey(
                                type=PoolKeyType.DEVICE_OWNED,
                                key="m/1852'/1815'/0'/0/0",
                            )
                        ],
                        relays=[
                            Relay(
                                type=RelayType.SINGLE_HOST_IP_ADDR,
                                params=SingleHostIpAddrRelayParams(
                                    portNumber=3000, ipv4="54.228.75.154", ipv6=None
                                ),
                            )
                        ],
                        metadata=PoolMetadataParams(
                            metadataUrl="https://www.vacuumlabs.com/sampleUrl.json",
                            metadataHashHex="cdb714fd722c24aeb10c93dbb0ff03bd4783441cd5ba2a8b6f373390520535bb",
                        ),
                    ),
                )
            ],
            ),
        signingMode=TransactionSigningMode.POOL_REGISTRATION_AS_OWNER,
        txBody="",
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
]

outputDenyTestCases: List[SignTxTestCase] = [
    SignTxTestCase(
        name="Legacy_output_with_inline_datum",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoShelley"]],
            outputs=[
                TxOutputAlonzo(
                    destination=TxOutputDestination(
                        type=TxOutputDestinationType.THIRD_PARTY,
                        params=ThirdPartyAddressParams(
                            addressHex="01eb0baa5e570cffbe2934db29df0b6a3d7c0430ee65d4c3a7ab2fefb91bc428e4720702ebd5dab4fb175324c192dc9bb76cc5da956e3c8dff"
                        ),
                    ),
                    amount=1234,
                    format=TxOutputFormat.ARRAY_LEGACY,
                    tokenBundle=[],
                    datum=Datum(
                        type=DatumType.INLINE,
                        datumHex="deadbeef",
                    ),
                )
            ],
            fee=170000,
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="",
        expected_sw=StatusWord.SWO_TX_PARSING_FAIL_OUTPUTS,
        deny_before_review=True,
    ),
]

testsCVoteRegistrationDenies: List[SignTxTestCase] = [
    SignTxTestCase(
        name="CIP15_registration_with_delegations_rejected",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["internalBaseWithStakingPath"]],
            auxiliaryData=TxAuxiliaryData(
                TxAuxiliaryDataType.CIP36_REGISTRATION,
                TxAuxiliaryDataCIP36(
                    CIP36VoteRegistrationFormat.CIP_15,
                    "m/1852'/1815'/0'/2/0",
                    destinations["internalBaseWithStakingPath"],
                    1454448,
                    "4b19e27ffc006ace16592311c4d2f0cafc255eaa47a6178ff540c0a46d07027c",
                    delegations=[
                        CIP36VoteDelegation(
                            type=CIP36VoteDelegationType.KEY,
                            votingKeyPath="4b19e27ffc006ace16592311c4d2f0cafc255eaa47a6178ff540c0a46d07027c",
                            weight=1,
                        ),
                    ],
                ),
            ),
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="",
        expected_sw=StatusWord.SWO_CVOTE_AUX_DATA_PARSING_FAIL,
        deny_before_review=True,
        unsuitable_in_ragger_reason=None,
    ),
    SignTxTestCase(
        name="CIP36_registration_with_staking_key_as_raw_pubkey",
        tx=Transaction(
            network=Mainnet,
            inputs=[inputs["utxoShelley"]],
            outputs=[outputs["internalBaseWithStakingPath"]],
            auxiliaryData=TxAuxiliaryData(
                TxAuxiliaryDataType.CIP36_REGISTRATION,
                TxAuxiliaryDataCIP36(
                    CIP36VoteRegistrationFormat.CIP_36,
                    "4b19e27ffc006ace16592311c4d2f0cafc255eaa47a6178ff540c0a46d07027c",
                    destinations["internalBaseWithStakingPath"],
                    1454448,
                    "4b19e27ffc006ace16592311c4d2f0cafc255eaa47a6178ff540c0a46d07027c",
                    votingPurpose=0,
                ),
            ),
        ),
        signingMode=TransactionSigningMode.ORDINARY_TRANSACTION,
        txBody="",
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
        deny_before_review=True,
        unsuitable_in_ragger_reason=None,
    ),
]

invalidCertificates: List[SignTxTestCase] = [
    SignTxTestCase(
        name="pool_registration_with_multiple_path_owners",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoMultisig"]],
            outputs=[outputs["inlineShelleyBase1"]],
            certificates=[
                Certificate(
                    type=CertificateType.STAKE_POOL_REGISTRATION,
                    params=PoolRegistrationParams(
                        poolKey=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="13381d918ec0283ceeff60f7f4fc21e1540e053ccf8a77307a7a32ad",
                        ),
                        vrfKeyHashHex="07821cd344d7fd7e3ae5f2ed863218cb979ff1d59e50c4276bdc479b0d084450",
                        pledge=50000000000,
                        cost=340000000,
                        margin=Margin(numerator=3, denominator=100),
                        rewardAccount=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="e1794d9b3408c9fb67b950a48a0690f070f117e9978f7fc1d120fc58ad",
                        ),
                        poolOwners=[
                            PoolKey(
                                type=PoolKeyType.DEVICE_OWNED,
                                key="m/1852'/1815'/0'/2/0",
                            ),
                            PoolKey(
                                type=PoolKeyType.DEVICE_OWNED,
                                key="m/1852'/1815'/0'/2/1",
                            ),
                        ],
                        relays=[
                            Relay(
                                type=RelayType.SINGLE_HOST_IP_ADDR,
                                params=SingleHostIpAddrRelayParams(
                                    portNumber=3000, ipv4="54.228.75.154", ipv6=None
                                ),
                            )
                        ],
                        metadata=PoolMetadataParams(
                            metadataUrl="https://www.vacuumlabs.com/sampleUrl.json",
                            metadataHashHex="cdb714fd722c24aeb10c93dbb0ff03bd4783441cd5ba2a8b6f373390520535bb",
                        ),
                    ),
                )
            ],
            ),
        signingMode=TransactionSigningMode.POOL_REGISTRATION_AS_OWNER,
        txBody="",
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
    SignTxTestCase(
        name="pool_registration_with_no_owners",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoMultisig"]],
            outputs=[outputs["inlineShelleyBase1"]],
            certificates=[
                Certificate(
                    type=CertificateType.STAKE_POOL_REGISTRATION,
                    params=PoolRegistrationParams(
                        poolKey=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="13381d918ec0283ceeff60f7f4fc21e1540e053ccf8a77307a7a32ad",
                        ),
                        vrfKeyHashHex="07821cd344d7fd7e3ae5f2ed863218cb979ff1d59e50c4276bdc479b0d084450",
                        pledge=50000000000,
                        cost=340000000,
                        margin=Margin(numerator=3, denominator=100),
                        rewardAccount=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="e1794d9b3408c9fb67b950a48a0690f070f117e9978f7fc1d120fc58ad",
                        ),
                        poolOwners=[],
                        relays=[
                            Relay(
                                type=RelayType.SINGLE_HOST_IP_ADDR,
                                params=SingleHostIpAddrRelayParams(
                                    portNumber=3000, ipv4="54.228.75.154", ipv6=None
                                ),
                            )
                        ],
                        metadata=PoolMetadataParams(
                            metadataUrl="https://www.vacuumlabs.com/sampleUrl.json",
                            metadataHashHex="cdb714fd722c24aeb10c93dbb0ff03bd4783441cd5ba2a8b6f373390520535bb",
                        ),
                    ),
                )
            ],
            ),
        signingMode=TransactionSigningMode.POOL_REGISTRATION_AS_OWNER,
        txBody="",
        expected_sw=StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED,
    ),
]

invalidPoolMetadataTestCases: List[SignTxTestCase] = [
    SignTxTestCase(
        name="pool_metadata_url_too_long",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoMultisig"]],
            outputs=[outputs["inlineShelleyBase1"]],
            certificates=[
                Certificate(
                    type=CertificateType.STAKE_POOL_REGISTRATION,
                    params=PoolRegistrationParams(
                        poolKey=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="13381d918ec0283ceeff60f7f4fc21e1540e053ccf8a77307a7a32ad",
                        ),
                        vrfKeyHashHex="07821cd344d7fd7e3ae5f2ed863218cb979ff1d59e50c4276bdc479b0d084450",
                        pledge=50000000000,
                        cost=340000000,
                        margin=Margin(numerator=3, denominator=100),
                        rewardAccount=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="e1794d9b3408c9fb67b950a48a0690f070f117e9978f7fc1d120fc58ad",
                        ),
                        poolOwners=[
                            PoolKey(
                                type=PoolKeyType.DEVICE_OWNED,
                                key="m/1852'/1815'/0'/2/0",
                            )
                        ],
                        relays=[
                            Relay(
                                type=RelayType.SINGLE_HOST_IP_ADDR,
                                params=SingleHostIpAddrRelayParams(
                                    portNumber=3000, ipv4="54.228.75.154", ipv6=None
                                ),
                            )
                        ],
                        metadata=PoolMetadataParams(
                            metadataUrl="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                            metadataHashHex="cdb714fd722c24aeb10c93dbb0ff03bd4783441cd5ba2a8b6f373390520535bb",
                        ),
                    ),
                )
            ],
            ),
        signingMode=TransactionSigningMode.POOL_REGISTRATION_AS_OWNER,
        txBody="",
        expected_sw=StatusWord.SWO_TX_PARSING_FAIL_CERTIFICATES,
        deny_before_review=True,
    ),
    SignTxTestCase(
        name="pool_metadata_invalid_url",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoMultisig"]],
            outputs=[outputs["inlineShelleyBase1"]],
            certificates=[
                Certificate(
                    type=CertificateType.STAKE_POOL_REGISTRATION,
                    params=PoolRegistrationParams(
                        poolKey=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="13381d918ec0283ceeff60f7f4fc21e1540e053ccf8a77307a7a32ad",
                        ),
                        vrfKeyHashHex="07821cd344d7fd7e3ae5f2ed863218cb979ff1d59e50c4276bdc479b0d084450",
                        pledge=50000000000,
                        cost=340000000,
                        margin=Margin(numerator=3, denominator=100),
                        rewardAccount=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="e1794d9b3408c9fb67b950a48a0690f070f117e9978f7fc1d120fc58ad",
                        ),
                        poolOwners=[
                            PoolKey(
                                type=PoolKeyType.DEVICE_OWNED,
                                key="m/1852'/1815'/0'/2/0",
                            )
                        ],
                        relays=[
                            Relay(
                                type=RelayType.SINGLE_HOST_IP_ADDR,
                                params=SingleHostIpAddrRelayParams(
                                    portNumber=3000, ipv4="54.228.75.154", ipv6=None
                                ),
                            )
                        ],
                        metadata=PoolMetadataParams(
                            metadataUrl="\n",
                            metadataHashHex="6bf124f217d0e5a0a8adb1dbd8540e1334280d49ab861127868339f43b3948",
                        ),
                    ),
                )
            ],
            ),
        signingMode=TransactionSigningMode.POOL_REGISTRATION_AS_OWNER,
        txBody="",
        expected_sw=StatusWord.SWO_TX_PARSING_FAIL_CERTIFICATES,
        deny_before_review=True,
    ),
    SignTxTestCase(
        name="pool_metadata_invalid_hash_length",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoMultisig"]],
            outputs=[outputs["inlineShelleyBase1"]],
            certificates=[
                Certificate(
                    type=CertificateType.STAKE_POOL_REGISTRATION,
                    params=PoolRegistrationParams(
                        poolKey=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="13381d918ec0283ceeff60f7f4fc21e1540e053ccf8a77307a7a32ad",
                        ),
                        vrfKeyHashHex="07821cd344d7fd7e3ae5f2ed863218cb979ff1d59e50c4276bdc479b0d084450",
                        pledge=50000000000,
                        cost=340000000,
                        margin=Margin(numerator=3, denominator=100),
                        rewardAccount=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="e1794d9b3408c9fb67b950a48a0690f070f117e9978f7fc1d120fc58ad",
                        ),
                        poolOwners=[
                            PoolKey(
                                type=PoolKeyType.DEVICE_OWNED,
                                key="m/1852'/1815'/0'/2/0",
                            )
                        ],
                        relays=[
                            Relay(
                                type=RelayType.SINGLE_HOST_IP_ADDR,
                                params=SingleHostIpAddrRelayParams(
                                    portNumber=3000, ipv4="54.228.75.154", ipv6=None
                                ),
                            )
                        ],
                        metadata=PoolMetadataParams(
                            metadataUrl="https://www.vacuumlabs.com/sampleUrl.json",
                            metadataHashHex="6bf124f217d0e5a0a8adb1dbd8540e1334280d49ab861127868339f43b3948",
                        ),
                    ),
                )
            ],
            ),
        signingMode=TransactionSigningMode.POOL_REGISTRATION_AS_OWNER,
        txBody="",
        expected_sw=StatusWord.SWO_TX_PARSING_FAIL_CERTIFICATES,
        deny_before_review=True,
    ),
    SignTxTestCase(
        name="pool_metadata_missing_hash",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoMultisig"]],
            outputs=[outputs["inlineShelleyBase1"]],
            certificates=[
                Certificate(
                    type=CertificateType.STAKE_POOL_REGISTRATION,
                    params=PoolRegistrationParams(
                        poolKey=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="13381d918ec0283ceeff60f7f4fc21e1540e053ccf8a77307a7a32ad",
                        ),
                        vrfKeyHashHex="07821cd344d7fd7e3ae5f2ed863218cb979ff1d59e50c4276bdc479b0d084450",
                        pledge=50000000000,
                        cost=340000000,
                        margin=Margin(numerator=3, denominator=100),
                        rewardAccount=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="e1794d9b3408c9fb67b950a48a0690f070f117e9978f7fc1d120fc58ad",
                        ),
                        poolOwners=[
                            PoolKey(
                                type=PoolKeyType.DEVICE_OWNED,
                                key="m/1852'/1815'/0'/2/0",
                            )
                        ],
                        relays=[
                            Relay(
                                type=RelayType.SINGLE_HOST_IP_ADDR,
                                params=SingleHostIpAddrRelayParams(
                                    portNumber=3000, ipv4="54.228.75.154", ipv6=None
                                ),
                            )
                        ],
                        metadata=PoolMetadataParams(
                            metadataUrl="https://www.vacuumlabs.com/sampleUrl.json",
                            metadataHashHex="",
                        ),
                    ),
                )
            ],
            ),
        signingMode=TransactionSigningMode.POOL_REGISTRATION_AS_OWNER,
        txBody="",
        expected_sw=StatusWord.SWO_TX_PARSING_FAIL_CERTIFICATES,
        deny_before_review=True,
    ),
]

invalidRelayTestCases: List[SignTxTestCase] = [
    SignTxTestCase(
        name="SingleHostHostname_missing_dns",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoMultisig"]],
            outputs=[outputs["inlineShelleyBase1"]],
            certificates=[
                Certificate(
                    type=CertificateType.STAKE_POOL_REGISTRATION,
                    params=PoolRegistrationParams(
                        poolKey=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="13381d918ec0283ceeff60f7f4fc21e1540e053ccf8a77307a7a32ad",
                        ),
                        vrfKeyHashHex="07821cd344d7fd7e3ae5f2ed863218cb979ff1d59e50c4276bdc479b0d084450",
                        pledge=50000000000,
                        cost=340000000,
                        margin=Margin(numerator=3, denominator=100),
                        rewardAccount=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="e1794d9b3408c9fb67b950a48a0690f070f117e9978f7fc1d120fc58ad",
                        ),
                        poolOwners=[
                            PoolKey(
                                type=PoolKeyType.DEVICE_OWNED,
                                key="m/1852'/1815'/0'/2/0",
                            )
                        ],
                        relays=[
                            Relay(
                                type=RelayType.SINGLE_HOST_HOSTNAME,
                                params=SingleHostHostnameRelayParams(
                                    portNumber=3000, dnsName=None
                                ),
                            )
                        ],
                        metadata=PoolMetadataParams(
                            metadataUrl="https://www.vacuumlabs.com/sampleUrl.json",
                            metadataHashHex="cdb714fd722c24aeb10c93dbb0ff03bd4783441cd5ba2a8b6f373390520535bb",
                        ),
                    ),
                )
            ],
            ),
        signingMode=TransactionSigningMode.POOL_REGISTRATION_AS_OWNER,
        txBody="",
        expected_sw=StatusWord.SWO_TX_PARSING_FAIL_CERTIFICATES,
        deny_before_review=True,
    ),
    SignTxTestCase(
        name="MultiHost_missing_dns",
        tx=Transaction(
            network=NetworkDesc(networkId=1, protocol=764824073),
            inputs=[inputs["utxoMultisig"]],
            outputs=[outputs["inlineShelleyBase1"]],
            certificates=[
                Certificate(
                    type=CertificateType.STAKE_POOL_REGISTRATION,
                    params=PoolRegistrationParams(
                        poolKey=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="13381d918ec0283ceeff60f7f4fc21e1540e053ccf8a77307a7a32ad",
                        ),
                        vrfKeyHashHex="07821cd344d7fd7e3ae5f2ed863218cb979ff1d59e50c4276bdc479b0d084450",
                        pledge=50000000000,
                        cost=340000000,
                        margin=Margin(numerator=3, denominator=100),
                        rewardAccount=PoolKey(
                            type=PoolKeyType.THIRD_PARTY,
                            key="e1794d9b3408c9fb67b950a48a0690f070f117e9978f7fc1d120fc58ad",
                        ),
                        poolOwners=[
                            PoolKey(
                                type=PoolKeyType.DEVICE_OWNED,
                                key="m/1852'/1815'/0'/2/0",
                            )
                        ],
                        relays=[
                            Relay(
                                type=RelayType.MULTI_HOST,
                                params=MultiHostRelayParams(dnsName=None),
                            )
                        ],
                        metadata=PoolMetadataParams(
                            metadataUrl="https://www.vacuumlabs.com/sampleUrl.json",
                            metadataHashHex="cdb714fd722c24aeb10c93dbb0ff03bd4783441cd5ba2a8b6f373390520535bb",
                        ),
                    ),
                )
            ],
            ),
        signingMode=TransactionSigningMode.POOL_REGISTRATION_AS_OWNER,
        txBody="",
        expected_sw=StatusWord.SWO_TX_PARSING_FAIL_CERTIFICATES,
        deny_before_review=True,
    ),
]
