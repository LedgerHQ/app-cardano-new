# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2024 Ledger SAS
# SPDX-License-Identifier: LicenseRef-LEDGER
"""
Minimal command builder used by the modernized test flows.

Provides chunks for the new handler_sign_tx protocol, the operational certificate
flow, and utility helpers shared by the standalone tests that still rely on this
module.
"""

import ipaddress

from dataclasses import dataclass
from enum import IntEnum
from typing import List, Optional

from ragger.bip import pack_derivation_path

from application_client.app_def import AddressType, StakingDataSourceType
from standalone.input_files.signOpCert import OpCertTestCase
from standalone.input_files.cvote import CVoteTestCase, MAX_CIP36_PAYLOAD_SIZE
from standalone.input_files.derive_address import DeriveAddressTestCase
from standalone.input_files.native_script import NativeScript, NativeScriptType, NativeScriptHashDisplayFormat
from standalone.input_files.native_script import NativeScriptParamsPubkey, NativeScriptParamsInvalid
from standalone.input_files.native_script import NativeScriptParamsScripts, NativeScriptParamsNofK
from standalone.input_files.signTx import (
    AnchorParams,
    AuthorizeCommitteeParams,
    Certificate,
    CertificateType,
    CredentialParams,
    CredentialParamsType,
    CIP36VoteDelegation,
    CIP36VoteRegistrationFormat,
    DRepParams,
    DRepRegistrationParams,
    DRepUpdateParams,
    DatumType,
    MultiHostRelayParams,
    PoolKey,
    PoolKeyType,
    PoolMetadataParams,
    PoolRegistrationParams,
    PoolRetirementParams,
    Relay,
    RelayType,
    ResignCommitteeParams,
    SingleHostHostnameRelayParams,
    SingleHostIpAddrRelayParams,
    StakeDelegationParams,
    StakePoolAndDRepDelegationParams,
    AccountRegistrationDelegationToStakePoolParams,
    AccountRegistrationDelegationToDRepParams,
    AccountRegistrationDelegationToStakePoolAndDRepParams,
    StakeRegistrationConwayParams,
    StakeRegistrationParams,
    Transaction,
    TxAuxiliaryDataCIP36,
    TxAuxiliaryDataHash,
    TxAuxiliaryDataType,
    TxOutput,
    TxOutputBabbage,
    TxOutputDestination,
    TxOutputDestinationType,
    TxRequiredSignerType,
    TransactionSigningMode,
    VoteDelegationParams,
    VoterType,
    MAX_SIGN_TX_CHUNK_SIZE,
    Withdrawal,
)

CLA: int = 0xd7

FLAG_INCLUDED_NO: int = 0x01
FLAG_INCLUDED_YES: int = 0x02
SETTINGS_DISABLED: int = 0x00
SETTINGS_ENABLED: int = 0x01
MAX_UINT8: int = 0xFF
MAX_UINT16: int = 0xFFFF
MAX_CIP8_MSG_CHUNK_SIZE = 250
# Mirrors `src/apdu/dispatcher.h::command_e`
class InsType(IntEnum):
    INS_GET_VERSION = 0x03
    INS_GET_APP_NAME = 0x04
    INS_GET_SERIAL = 0x01
    INS_GET_PUBLIC_KEY = 0x10
    INS_DERIVE_ADDRESS = 0x11
    INS_DERIVE_NATIVE_SCRIPT_HASH = 0x12
    INS_SIGN_TX = 0x21
    INS_SIGN_OPCERT = 0x22
    INS_SIGN_CVOTE = 0x23
    INS_SIGN_MSG = 0x24
    INS_DEBUG_SET_SETTINGS = 0xF0  # Debug-only command

# Matches `src/apdu/dispatcher.h::p1_e`
class P1Type(IntEnum):
    P1_UNUSED = 0x00
    # Transaction-related P1 values (0x1x range)
    P1_TX_INIT = 0x10
    P1_TX_CHUNK = 0x11
    P1_TX_CONFIRM = 0x12
    P1_TX_AUX_DATA = 0x13
    P1_TX_SIGN_WITNESS = 0x1F
    # Address derivation P1 values (0x2x range)
    P1_ADDRESS_RETURN = 0x20
    P1_ADDRESS_DISPLAY = 0x21
    # Native script hash derivation P1 values (0x4x range)
    P1_NATIVE_SCRIPT_START_COMPLEX = 0x40
    P1_NATIVE_SCRIPT_ADD_SIMPLE = 0x41
    P1_NATIVE_SCRIPT_FINISH = 0x42
    # Cvote P1 values (0x5x range)
    P1_CVOTE_INIT = 0x50
    P1_CVOTE_CHUNK = 0x51
    P1_CVOTE_CONFIRM = 0x52
    # Message signing P1 values (0x6x range, CIP-8)
    P1_SIGN_MSG_INIT = 0x60
    P1_SIGN_MSG_CHUNK = 0x61
    P1_SIGN_MSG_CONFIRM = 0x62
# Matches `src/apdu/dispatcher.h::p2_e`
class P2Type(IntEnum):
    P2_UNUSED = 0x00
    # Transaction-related P2 values (0x1x range)
    P2_TX_MORE = 0x10
    P2_TX_LAST = 0x11
    # CVote auxiliary data P2 values (0x3x range)
    P2_AUX_DATA_INIT = 0x36
    P2_AUX_DATA_DELEGATION = 0x37


def _credential_path_from_credential(credential: CredentialParams) -> Optional[str]:
    if credential.type.name == "KEY_PATH":
        return credential.keyValue
    return None


def _pool_key_path(pool_key: PoolKey) -> Optional[str]:
    if pool_key.type == PoolKeyType.DEVICE_OWNED:
        return pool_key.key
    return None


def _credential_paths_from_certificate(certificate: Certificate) -> List[str]:
    """Extract witness paths from a certificate (ledgerjs-compatible)."""
    paths: List[str] = []
    params = certificate.params

    if certificate.type == CertificateType.STAKE_REGISTRATION:
        return paths

    if certificate.type in (
        CertificateType.STAKE_REGISTRATION_CONWAY,
        CertificateType.STAKE_DEREGISTRATION,
        CertificateType.STAKE_DEREGISTRATION_CONWAY,
        CertificateType.STAKE_DELEGATION,
        CertificateType.VOTE_DELEGATION,
        CertificateType.STAKE_POOL_AND_DREP_DELEGATION,
        CertificateType.ACCOUNT_REGISTRATION_DELEGATION_TO_STAKE_POOL,
        CertificateType.ACCOUNT_REGISTRATION_DELEGATION_TO_DREP,
        CertificateType.ACCOUNT_REGISTRATION_DELEGATION_TO_STAKE_POOL_AND_DREP,
    ):
        path = _credential_path_from_credential(params.stakeCredential)
        if path:
            paths.append(path)
        return paths

    if certificate.type in (
        CertificateType.AUTHORIZE_COMMITTEE_HOT,
        CertificateType.RESIGN_COMMITTEE_COLD,
    ):
        path = _credential_path_from_credential(params.coldCredential)
        if path:
            paths.append(path)
        return paths

    if certificate.type in (
        CertificateType.DREP_REGISTRATION,
        CertificateType.DREP_DEREGISTRATION,
        CertificateType.DREP_UPDATE,
    ):
        path = _credential_path_from_credential(params.dRepCredential)
        if path:
            paths.append(path)
        return paths

    if certificate.type == CertificateType.STAKE_POOL_REGISTRATION:
        pool_key_path = _pool_key_path(params.poolKey)
        if pool_key_path:
            paths.append(pool_key_path)
        for owner in params.poolOwners:
            owner_path = _pool_key_path(owner)
            if owner_path:
                paths.append(owner_path)
        return paths

    if certificate.type == CertificateType.STAKE_POOL_RETIREMENT:
        path = _credential_path_from_credential(params.poolCredential)
        if path:
            paths.append(path)
        return paths

    return paths


def gather_witness_paths(tx: Transaction,
                         signing_mode: int,
                         additional_witness_paths: List[str]) -> List[str]:
    """Return unique witness paths present in a transaction."""

    witness_paths: List[str] = []

    if signing_mode == TransactionSigningMode.MULTISIG_TRANSACTION:
        for additional_path in additional_witness_paths:
            if additional_path not in witness_paths:
                witness_paths.append(additional_path)
        return witness_paths

    for tx_input in tx.inputs:
        if tx_input.path and tx_input.path not in witness_paths:
            witness_paths.append(tx_input.path)

    for certificate in tx.certificates:
        cert_paths = _credential_paths_from_certificate(certificate)
        for cert_path in cert_paths:
            if cert_path not in witness_paths:
                witness_paths.append(cert_path)

    for withdrawal in tx.withdrawals:
        path = _credential_path_from_credential(withdrawal.stakeCredential)
        if path and path not in witness_paths:
            witness_paths.append(path)

    for required_signer in getattr(tx, "requiredSigners", []):
        if required_signer.type == TxRequiredSignerType.PATH:
            if required_signer.pathOrHashHex not in witness_paths:
                witness_paths.append(required_signer.pathOrHashHex)

    for collateral_input in getattr(tx, "collateralInputs", []):
        if collateral_input.path and collateral_input.path not in witness_paths:
            witness_paths.append(collateral_input.path)

    for voter_votes in getattr(tx, "votingProcedures", []):
        if voter_votes.voter.type in (
            VoterType.COMMITTEE_KEY_PATH,
            VoterType.DREP_KEY_PATH,
            VoterType.STAKE_POOL_KEY_PATH,
        ):
            if voter_votes.voter.keyValue not in witness_paths:
                witness_paths.append(voter_votes.voter.keyValue)

    for additional_path in additional_witness_paths:
        if additional_path not in witness_paths:
            witness_paths.append(additional_path)

    return witness_paths


@dataclass(frozen=True)
class TxInitParams:
    options: int
    network_id: int
    protocol_magic: int
    signing_mode: int
    num_inputs: int
    num_outputs: int
    include_ttl: bool
    num_certificates: int
    num_withdrawals: int
    include_aux_data_hash: bool
    aux_data_type: Optional[int]
    aux_data_hash_hex: Optional[str]
    include_validity_interval_start: bool
    num_mint_asset_groups: int
    include_script_data_hash: bool
    num_collateral_inputs: int
    num_required_signers: int
    include_network_id: bool
    include_collateral_output: bool
    include_total_collateral: bool
    num_reference_inputs: int
    num_voters: int
    include_treasury: bool
    include_donation: bool
    num_witnesses: int


class CommandBuilder:
    def _serialize(self,
                   ins: InsType,
                   p1: int = P1Type.P1_UNUSED,
                   p2: int = P2Type.P2_UNUSED,
                   cdata: bytes = bytes()) -> bytes:
        header = bytearray()
        header.append(CLA)
        header.append(ins)
        header.append(p1)
        header.append(p2)
        if len(cdata) < 256:
            header.append(len(cdata))
        else:
            header.append(0)
            header.append((len(cdata) >> 8) & 0xFF)
            header.append(len(cdata) & 0xFF)
        return header + cdata

    def get_version(self) -> bytes:
        return self._serialize(InsType.INS_GET_VERSION)

    def get_app_name(self) -> bytes:
        return self._serialize(InsType.INS_GET_APP_NAME)

    def get_serial(self) -> bytes:
        return self._serialize(InsType.INS_GET_SERIAL)

    def _serialize_voter(self, voter: object) -> bytes:
        voter_type = VoterType(voter.type)
        voter_data = bytearray()
        voter_data.append(int(voter_type))

        if voter_type in (
            VoterType.COMMITTEE_KEY_PATH,
            VoterType.DREP_KEY_PATH,
            VoterType.STAKE_POOL_KEY_PATH,
        ):
            voter_data.extend(pack_derivation_path(voter.keyValue))
        else:
            voter_data.extend(bytes.fromhex(voter.keyValue))

        return bytes(voter_data)

    def _serialize_address_params(self, test_case: DeriveAddressTestCase) -> bytes:
        """Serialize address parameters (shared by derive_address and sign_msg_init)"""
        data = bytes()
        data += test_case.addrType.to_bytes(1, "big")
        if test_case.addrType == AddressType.BYRON:
            data += test_case.netDesc.protocol.to_bytes(4, "big")
        else:
            data += test_case.netDesc.networkId.to_bytes(1, "big")

        if not test_case.spendingValue.startswith("m/"):
            data += bytes.fromhex(test_case.spendingValue)
        elif test_case.spendingValue:
            data += pack_derivation_path(test_case.spendingValue)

        if test_case.addrType in (AddressType.BYRON, AddressType.ENTERPRISE_KEY,
                        AddressType.ENTERPRISE_SCRIPT):
            staking = StakingDataSourceType.NONE
        elif test_case.addrType in (AddressType.BASE_PAYMENT_KEY_STAKE_SCRIPT,
                          AddressType.BASE_PAYMENT_SCRIPT_STAKE_SCRIPT,
                          AddressType.REWARD_SCRIPT):
            staking = StakingDataSourceType.SCRIPT_HASH
        elif test_case.addrType in (AddressType.POINTER_KEY, AddressType.POINTER_SCRIPT):
            staking = StakingDataSourceType.BLOCKCHAIN_POINTER
        elif not test_case.stakingValue.startswith("m/"):
            staking = StakingDataSourceType.KEY_HASH
        else:
            staking = StakingDataSourceType.KEY_PATH
        data += staking.to_bytes(1, "big")

        if staking == StakingDataSourceType.KEY_PATH:
            data += pack_derivation_path(test_case.stakingValue)
        elif staking in (StakingDataSourceType.KEY_HASH,
                         StakingDataSourceType.SCRIPT_HASH,
                         StakingDataSourceType.BLOCKCHAIN_POINTER):
            data += bytes.fromhex(test_case.stakingValue)
        elif staking != StakingDataSourceType.NONE:
            raise NotImplementedError("Not implemented yet")
        return data

    def derive_address(self, p1: P1Type, test_case: DeriveAddressTestCase) -> bytes:
        data = self._serialize_address_params(test_case)
        return self._serialize(InsType.INS_DERIVE_ADDRESS, p1, P2Type.P2_UNUSED, data)

    def get_pubkey_path(self, path: str) -> bytes:
        data = pack_derivation_path(path)
        return self._serialize(InsType.INS_GET_PUBLIC_KEY, P1Type.P1_UNUSED, P2Type.P2_UNUSED, data)

    def sign_opcert(self, test_case: OpCertTestCase) -> bytes:
        data = bytearray()
        data.extend(bytes.fromhex(test_case.opCert.kesPublicKeyHex))
        data.extend(test_case.opCert.kesPeriod.to_bytes(8, "big"))
        data.extend(test_case.opCert.issueCounter.to_bytes(8, "big"))
        data.extend(pack_derivation_path(test_case.opCert.path))
        return self._serialize(InsType.INS_SIGN_OPCERT, P1Type.P1_UNUSED, P2Type.P2_UNUSED, bytes(data))

    def sign_opCert(self, test_case: OpCertTestCase) -> bytes:
        return self.sign_opcert(test_case)

    def sign_cvote_init(self, testCase: CVoteTestCase) -> bytes:
        """APDU Builder for CIP36 Vote - INIT step

        Args:
            testCase (CVoteTestCase): Test parameters

        Returns:
            Serial data APDU
        """

        # Serialization format:
        #    Full length of voteCastDataHex (4B)
        #    voteCastDataHex (first chunk, up to 250 B)
        data = bytes()
        # 2 hex chars per byte
        data_size = int(len(testCase.cVote.voteCastDataHex) / 2)
        chunk_size = min(MAX_CIP36_PAYLOAD_SIZE * 2, len(testCase.cVote.voteCastDataHex))
        data += data_size.to_bytes(4, "big")
        data += bytes.fromhex(testCase.cVote.voteCastDataHex[:chunk_size])
        # Remove the data sent in this step
        testCase.cVote.voteCastDataHex = testCase.cVote.voteCastDataHex[chunk_size:]
        return self._serialize(InsType.INS_SIGN_CVOTE, P1Type.P1_CVOTE_INIT, 0x00, data)


    def sign_cvote_chunk(self, testCase: CVoteTestCase) -> List[bytes]:
        """APDU Builder for CIP36 Vote - CHUNK step

        Args:
            testCase (CVoteTestCase): Test parameters

        Returns:
            Response APDU
        """

        # Serialization format:
        #    voteCastDataHex (following data, up to MAX_CIP36_PAYLOAD_SIZE B each)
        chunks = []
        payload = testCase.cVote.voteCastDataHex
        max_payload_size = MAX_CIP36_PAYLOAD_SIZE * 2 # 2 hex chars per byte
        while len(payload) > 0:
            chunks.append(self._serialize(InsType.INS_SIGN_CVOTE,
                                          P1Type.P1_CVOTE_CHUNK,
                                          0x00,
                                          bytes.fromhex(payload[:max_payload_size])))
            payload = payload[max_payload_size:]

        return chunks


    def sign_cvote_confirm(self, testCase: CVoteTestCase) -> bytes:
        """APDU Builder for CIP36 Vote - CONFIRM step

        Args:
            testCase (CVoteTestCase): Test parameters

        Returns:
            Serial data APDU
        """

        # Serialization format:
        #    Witness path (1B for length + [0-5] x 4B)
        data = pack_derivation_path(testCase.cVote.witnessPath)
        return self._serialize(InsType.INS_SIGN_CVOTE, P1Type.P1_CVOTE_CONFIRM, 0x00, data)


    def sign_tx_init(self, params: TxInitParams) -> bytes:
        data = bytearray()
        data.extend(params.options.to_bytes(8, "big"))
        data.append(params.network_id)
        data.extend(params.protocol_magic.to_bytes(4, "big"))
        data.append(params.signing_mode)
        data.extend(params.num_inputs.to_bytes(2, "big"))
        data.extend(params.num_outputs.to_bytes(2, "big"))
        data.append(FLAG_INCLUDED_YES if params.include_ttl else FLAG_INCLUDED_NO)
        data.extend(params.num_certificates.to_bytes(2, "big"))
        data.extend(params.num_withdrawals.to_bytes(2, "big"))
        data.append(FLAG_INCLUDED_YES if params.include_aux_data_hash else FLAG_INCLUDED_NO)
        if params.include_aux_data_hash:
            if params.aux_data_type is None:
                raise ValueError("Auxiliary data type is required when include_aux_data_hash is set")
            data.append(params.aux_data_type)
            if params.aux_data_hash_hex is None:
                if params.aux_data_type == TxAuxiliaryDataType.ARBITRARY_HASH:
                    raise ValueError("Auxiliary data hash is required for arbitrary-hash aux data")
            else:
                data.extend(bytes.fromhex(params.aux_data_hash_hex))
        data.append(FLAG_INCLUDED_YES if params.include_validity_interval_start else FLAG_INCLUDED_NO)
        data.extend(params.num_mint_asset_groups.to_bytes(2, "big"))
        data.append(FLAG_INCLUDED_YES if params.include_script_data_hash else FLAG_INCLUDED_NO)
        data.extend(params.num_collateral_inputs.to_bytes(2, "big"))
        data.extend(params.num_required_signers.to_bytes(2, "big"))
        data.append(FLAG_INCLUDED_YES if params.include_network_id else FLAG_INCLUDED_NO)
        data.append(FLAG_INCLUDED_YES if params.include_collateral_output else FLAG_INCLUDED_NO)
        data.append(FLAG_INCLUDED_YES if params.include_total_collateral else FLAG_INCLUDED_NO)
        data.extend(params.num_reference_inputs.to_bytes(2, "big"))
        data.extend(params.num_voters.to_bytes(2, "big"))
        data.append(FLAG_INCLUDED_YES if params.include_treasury else FLAG_INCLUDED_NO)
        data.append(FLAG_INCLUDED_YES if params.include_donation else FLAG_INCLUDED_NO)
        data.extend(params.num_witnesses.to_bytes(2, "big"))
        return self._serialize(InsType.INS_SIGN_TX, P1Type.P1_TX_INIT, P2Type.P2_UNUSED, bytes(data))

    def derive_script_add_simple(self, script: NativeScript) -> bytes:
        data = bytes()
        script_type = 0 if script.type == NativeScriptType.PUBKEY_THIRD_PARTY else script.type
        data += script_type.to_bytes(1, "big")
        if script.type in (NativeScriptType.PUBKEY_DEVICE_OWNED, NativeScriptType.PUBKEY_THIRD_PARTY):
            assert isinstance(script.params, NativeScriptParamsPubkey)
            # Serialize extended credential format
            if script.params.key.startswith("m/"):
                # KEY_PATH credential
                data += CredentialParamsType.KEY_PATH.to_bytes(1, "big")
                data += pack_derivation_path(script.params.key)
            else:
                # KEY_HASH credential
                data += CredentialParamsType.KEY_HASH.to_bytes(1, "big")
                data += bytes.fromhex(script.params.key)
        elif script.type in (NativeScriptType.INVALID_BEFORE, NativeScriptType.INVALID_HEREAFTER):
            assert isinstance(script.params, NativeScriptParamsInvalid)
            data += script.params.slot.to_bytes(8, "big")
        return self._serialize(InsType.INS_DERIVE_NATIVE_SCRIPT_HASH, P1Type.P1_NATIVE_SCRIPT_ADD_SIMPLE, 0x00, data)


    def derive_script_add_complex(self, script: NativeScript) -> bytes:
        data = bytes()
        data += script.type.to_bytes(1, "big")
        if script.type in (NativeScriptType.ALL, NativeScriptType.ANY):
            assert isinstance(script.params, NativeScriptParamsScripts)
            data += len(script.params.scripts).to_bytes(4, "big")
        elif script.type == NativeScriptType.N_OF_K:
            assert isinstance(script.params, NativeScriptParamsNofK)
            data += len(script.params.scripts).to_bytes(4, "big")
            data += script.params.requiredCount.to_bytes(4, "big")
        return self._serialize(InsType.INS_DERIVE_NATIVE_SCRIPT_HASH, P1Type.P1_NATIVE_SCRIPT_START_COMPLEX, 0x00, data)


    def derive_script_finish(self, disp: NativeScriptHashDisplayFormat) -> bytes:
        data = disp.to_bytes(1, "big")
        return self._serialize(InsType.INS_DERIVE_NATIVE_SCRIPT_HASH, P1Type.P1_NATIVE_SCRIPT_FINISH, 0x00, data)

    def build_tx_init_params(self,
                             tx: Transaction,
                             signing_mode: int,
                             witness_paths: List[str],
                             options: int = 0) -> TxInitParams:
        include_aux_data_hash = tx.auxiliaryData is not None
        aux_data_type = None
        aux_data_hash_hex = None
        if include_aux_data_hash:
            if tx.auxiliaryData.type == TxAuxiliaryDataType.ARBITRARY_HASH:
                aux_data_type = TxAuxiliaryDataType.ARBITRARY_HASH
                aux_params = tx.auxiliaryData.params
                if isinstance(aux_params, TxAuxiliaryDataHash):
                    aux_data_hash_hex = aux_params.hashHex
            elif tx.auxiliaryData.type == TxAuxiliaryDataType.CIP36_REGISTRATION:
                aux_data_type = TxAuxiliaryDataType.CIP36_REGISTRATION

        return TxInitParams(
            options=options,
            network_id=tx.network.networkId,
            protocol_magic=tx.network.protocol,
            signing_mode=signing_mode,
            num_inputs=len(tx.inputs),
            num_outputs=len(tx.outputs),
            include_ttl=tx.ttl is not None,
            num_certificates=len(tx.certificates),
            num_withdrawals=len(tx.withdrawals),
            include_aux_data_hash=include_aux_data_hash,
            aux_data_type=aux_data_type,
            aux_data_hash_hex=aux_data_hash_hex,
            include_validity_interval_start=tx.validityIntervalStart is not None,
            num_mint_asset_groups=len(tx.mint),
            include_script_data_hash=tx.scriptDataHash is not None,
            num_collateral_inputs=len(tx.collateralInputs) if getattr(tx, "collateralInputs", None) else 0,
            num_required_signers=len(tx.requiredSigners) if getattr(tx, "requiredSigners", None) else 0,
            include_network_id=bool(getattr(tx, "includeNetworkId", False)),
            include_collateral_output=getattr(tx, "collateralOutput", None) is not None,
            include_total_collateral=getattr(tx, "totalCollateral", None) is not None,
            num_reference_inputs=len(tx.referenceInputs) if getattr(tx, "referenceInputs", None) else 0,
            num_voters=len(tx.votingProcedures) if getattr(tx, "votingProcedures", None) else 0,
            include_treasury=getattr(tx, "treasury", None) is not None,
            include_donation=getattr(tx, "donation", None) is not None,
            num_witnesses=len(witness_paths),
        )

    def sign_tx_aux_data_init(self, tx: Transaction, aux_params: TxAuxiliaryDataCIP36) -> bytes:
        data = bytearray()
        data.append(aux_params.format)
        data.extend(len(aux_params.delegations).to_bytes(2, "big"))
        data.extend(self._serialize_cvote_key_or_path(aux_params.stakingPath))
        data.extend(self._serialize_output_destination(aux_params.paymentDestination, tx))
        data.extend(aux_params.nonce.to_bytes(8, "big"))

        if aux_params.format == CIP36VoteRegistrationFormat.CIP_36:
            voting_purpose = aux_params.votingPurpose if aux_params.votingPurpose is not None else 0
            data.extend(voting_purpose.to_bytes(8, "big"))
            if len(aux_params.delegations) == 0:
                if aux_params.voteKey is None:
                    raise ValueError("CIP-36 vote key is required when delegations are empty")
                data.extend(self._serialize_cvote_key_or_path(aux_params.voteKey))
        else:
            if aux_params.voteKey is None:
                raise ValueError("CIP-15 vote key is required")
            data.extend(self._serialize_cvote_key_or_path(aux_params.voteKey))

        return self._serialize(InsType.INS_SIGN_TX,
                               P1Type.P1_TX_AUX_DATA,
                               P2Type.P2_AUX_DATA_INIT,
                               bytes(data))

    def sign_tx_aux_data_delegation(self, delegation: CIP36VoteDelegation) -> bytes:
        data = bytearray()
        data.extend(self._serialize_cvote_key_or_path(delegation.votingKeyPath))
        data.extend(delegation.weight.to_bytes(4, "big"))
        return self._serialize(InsType.INS_SIGN_TX,
                               P1Type.P1_TX_AUX_DATA,
                               P2Type.P2_AUX_DATA_DELEGATION,
                               bytes(data))

    def sign_tx_witness(self, path: str) -> bytes:
        data = pack_derivation_path(path)
        return self._serialize(InsType.INS_SIGN_TX, P1Type.P1_TX_SIGN_WITNESS, P2Type.P2_UNUSED, data)

    def debug_set_settings(self, expert_mode: bool, silent_export: bool) -> bytes:
        """Build debug settings APDU (only works with DEBUG builds).

        Args:
            expert_mode: True to enable expert mode, False to disable
            silent_export: True to enable silent pubkey export, False to disable

        Returns:
            Serialized APDU command
        """
        data = bytearray()
        data.append(SETTINGS_ENABLED if expert_mode else SETTINGS_DISABLED)
        data.append(SETTINGS_ENABLED if silent_export else SETTINGS_DISABLED)
        return self._serialize(InsType.INS_DEBUG_SET_SETTINGS, P1Type.P1_UNUSED, P2Type.P2_UNUSED, bytes(data))

    def serialize_transaction_chunks(self, tx: Transaction) -> list[bytes]:
        if MAX_SIGN_TX_CHUNK_SIZE <= 0:
            raise ValueError("MAX_SIGN_TX_CHUNK_SIZE must be positive")
        tx_data = self._serialize_transaction_unpacked_raw(tx)
        if not tx_data:
            raise ValueError("Serialized transaction must not be empty")
        chunks: List[bytes] = []
        offset = 0
        while offset < len(tx_data):
            chunk_size = min(MAX_SIGN_TX_CHUNK_SIZE, len(tx_data) - offset)
            chunk_data = tx_data[offset:offset + chunk_size]
            offset += chunk_size
            more = offset < len(tx_data)
            p1 = P1Type.P1_TX_CHUNK if more else P1Type.P1_TX_CONFIRM
            chunk_apdu = self._serialize(InsType.INS_SIGN_TX, p1, P2Type.P2_UNUSED, chunk_data)
            chunks.append(chunk_apdu)
        return chunks

    def _serialize_transaction_unpacked_raw(self, tx: Transaction) -> bytes:
        data = bytearray()
        for tx_input in tx.inputs:
            data.extend(bytes.fromhex(tx_input.txHashHex))
            data.extend(tx_input.outputIndex.to_bytes(4, "big"))

        for tx_output in tx.outputs:
            output_data = self._serialize_output(tx_output, tx)
            data.extend(len(output_data).to_bytes(2, "big"))
            data.extend(output_data)

        data.extend(tx.fee.to_bytes(8, "big"))

        if tx.ttl is not None:
            data.extend(tx.ttl.to_bytes(8, "big"))

        for certificate in tx.certificates:
            data.extend(self._serialize_certificate(certificate))

        for withdrawal in tx.withdrawals:
            data.extend(withdrawal.amount.to_bytes(8, "big"))
            data.extend(self._serialize_credential_inline(withdrawal.stakeCredential))

        if tx.validityIntervalStart is not None:
            data.extend(tx.validityIntervalStart.to_bytes(8, "big"))

        for mint_asset_group in tx.mint:
            data.extend(bytes.fromhex(mint_asset_group.policyIdHex))
            data.extend(len(mint_asset_group.tokens).to_bytes(2, "big"))
            for token in mint_asset_group.tokens:
                asset_name_bytes = bytes.fromhex(token.assetNameHex)
                data.append(len(asset_name_bytes))
                data.extend(asset_name_bytes)
                data.extend(token.amount.to_bytes(8, "big", signed=True))

        script_data_hash = getattr(tx, "scriptDataHash", None)
        if script_data_hash is not None:
            data.extend(bytes.fromhex(script_data_hash))

        collateral_inputs = getattr(tx, "collateralInputs", None)
        if collateral_inputs:
            for collateral_input in collateral_inputs:
                data.extend(bytes.fromhex(collateral_input.txHashHex))
                data.extend(collateral_input.outputIndex.to_bytes(4, "big"))

        required_signers = getattr(tx, "requiredSigners", None)
        if required_signers:
            for required_signer in required_signers:
                data.append(int(required_signer.type))
                if required_signer.type == TxRequiredSignerType.PATH:
                    data.extend(pack_derivation_path(required_signer.pathOrHashHex))
                else:
                    data.extend(bytes.fromhex(required_signer.pathOrHashHex))

        collateral_output = getattr(tx, "collateralOutput", None)
        if collateral_output is not None:
            collateral_data = self._serialize_output(collateral_output, tx)
            data.extend(len(collateral_data).to_bytes(2, "big"))
            data.extend(collateral_data)

        if getattr(tx, "totalCollateral", None) is not None:
            data.extend(tx.totalCollateral.to_bytes(8, "big"))

        reference_inputs = getattr(tx, "referenceInputs", None)
        if reference_inputs:
            for reference_input in reference_inputs:
                data.extend(bytes.fromhex(reference_input.txHashHex))
                data.extend(reference_input.outputIndex.to_bytes(4, "big"))

        voting_procedures = getattr(tx, "votingProcedures", None)
        if voting_procedures:
            for voter_votes in voting_procedures:
                data.extend(self._serialize_voter(voter_votes.voter))

                # Serialize number of votes for this voter
                data.extend(len(voter_votes.votes).to_bytes(2, "big"))

                # Serialize each vote
                for vote in voter_votes.votes:
                    # gov_action_id: tx_hash + index
                    data.extend(bytes.fromhex(vote.govActionId.txHashHex))
                    data.extend(vote.govActionId.govActionIndex.to_bytes(4, "big"))

                    # voting_procedure: vote option
                    data.append(vote.votingProcedure.vote)

                    # anchor inclusion flag
                    data.extend(self._serialize_anchor(vote.votingProcedure.anchor))

        if getattr(tx, "treasury", None) is not None:
            data.extend(tx.treasury.to_bytes(8, "big"))

        if getattr(tx, "donation", None) is not None:
            data.extend(tx.donation.to_bytes(8, "big"))

        return bytes(data)

    def _serialize_output(self, tx_output: TxOutput, tx: Transaction) -> bytearray:
        output_data = bytearray()
        output_data.extend(self._serialize_output_destination(tx_output.destination, tx))

        output_data.extend(tx_output.amount.to_bytes(8, "big"))
        output_data.append(tx_output.format if hasattr(tx_output, "format") else 0)
        num_asset_groups = len(tx_output.tokenBundle) if hasattr(tx_output, "tokenBundle") else 0
        output_data.extend(num_asset_groups.to_bytes(2, "big"))

        if num_asset_groups > 0:
            for asset_group in tx_output.tokenBundle:
                output_data.extend(bytes.fromhex(asset_group.policyIdHex))
                output_data.extend(len(asset_group.tokens).to_bytes(2, "big"))
                for token in asset_group.tokens:
                    asset_name_bytes = bytes.fromhex(token.assetNameHex)
                    output_data.append(len(asset_name_bytes))
                    output_data.extend(asset_name_bytes)
                    output_data.extend(token.amount.to_bytes(8, "big"))

        if hasattr(tx_output, "datum") and tx_output.datum is not None:
            output_data.append(FLAG_INCLUDED_YES)
            datum_type = tx_output.datum.type
            if datum_type == DatumType.HASH:
                output_data.append(int(DatumType.HASH))
                output_data.extend(bytes.fromhex(tx_output.datum.datumHex))
            elif datum_type == DatumType.INLINE:
                output_data.append(int(DatumType.INLINE))
                datum_bytes = bytes.fromhex(tx_output.datum.datumHex)
                output_data.extend(len(datum_bytes).to_bytes(2, "big"))
                output_data.extend(datum_bytes)
        else:
            output_data.append(FLAG_INCLUDED_NO)

        if isinstance(tx_output, TxOutputBabbage) and tx_output.referenceScriptHex is not None:
            output_data.append(FLAG_INCLUDED_YES)
            script_bytes = bytes.fromhex(tx_output.referenceScriptHex)
            output_data.extend(len(script_bytes).to_bytes(2, "big"))
            output_data.extend(script_bytes)
        else:
            output_data.append(FLAG_INCLUDED_NO)

        return output_data

    def _serialize_output_destination(self, tx_output_destination: TxOutputDestination, tx: Transaction) -> bytes:
        destination_data = bytearray()
        destination_data.append(tx_output_destination.type)

        if tx_output_destination.type == TxOutputDestinationType.THIRD_PARTY:
            address_bytes = bytes.fromhex(tx_output_destination.params.addressHex)
            destination_data.extend(len(address_bytes).to_bytes(2, "big"))
            destination_data.extend(address_bytes)
            return bytes(destination_data)

        address_params = tx_output_destination.params
        destination_data.extend(self._serialize_address_params(address_params))
        return bytes(destination_data)

    def _serialize_cvote_key_or_path(self, key_or_path: str) -> bytes:
        data = bytearray()
        if key_or_path.startswith("m/"):
            data.append(CredentialParamsType.KEY_PATH)
            data.extend(pack_derivation_path(key_or_path))
        else:
            data.append(CredentialParamsType.KEY_HASH)
            data.extend(bytes.fromhex(key_or_path))
        return bytes(data)

    def _serialize_credential_inline(self, credential: CredentialParams) -> bytes:
        data = bytearray()
        if credential.keyValue is None:
            raise ValueError("Credential keyValue must be set")
        if credential.type == CredentialParamsType.KEY_PATH:
            data.append(CredentialParamsType.KEY_PATH)
            data.extend(pack_derivation_path(credential.keyValue))
        elif credential.type == CredentialParamsType.KEY_HASH:
            data.append(CredentialParamsType.KEY_HASH)
            data.extend(bytes.fromhex(credential.keyValue))
        elif credential.type == CredentialParamsType.SCRIPT_HASH:
            data.append(CredentialParamsType.SCRIPT_HASH)
            data.extend(bytes.fromhex(credential.keyValue))
        else:
            raise ValueError(f"Unsupported credential type: {credential.type}")
        return bytes(data)

    def _serialize_drep(self, drep: DRepParams) -> bytes:
        result = bytearray()
        result.append(int(drep.type))
        if drep.keyValue is not None:
            if drep.keyValue.startswith("m/"):
                result.extend(pack_derivation_path(drep.keyValue))
            else:
                result.extend(bytes.fromhex(drep.keyValue))
        return bytes(result)

    def _serialize_anchor(self, anchor: Optional[AnchorParams]) -> bytes:
        result = bytearray()
        if anchor is None:
            result.append(FLAG_INCLUDED_NO)
            return bytes(result)

        result.append(FLAG_INCLUDED_YES)
        url_bytes = anchor.url.encode("utf-8")
        if len(url_bytes) > MAX_UINT16:
            raise ValueError("Anchor URL exceeds maximum encodable length")
        result.extend(len(url_bytes).to_bytes(2, "big"))
        result.extend(url_bytes)
        hash_bytes = bytes.fromhex(anchor.hashHex)
        result.extend(hash_bytes)
        return bytes(result)

    def _pool_key_to_credential(self, pool_key: PoolKey) -> CredentialParams:
        if pool_key.type == PoolKeyType.DEVICE_OWNED:
            return CredentialParams(type=CredentialParamsType.KEY_PATH, keyValue=pool_key.key)
        if pool_key.type == PoolKeyType.THIRD_PARTY:
            return CredentialParams(type=CredentialParamsType.KEY_HASH, keyValue=pool_key.key.lower())
        raise ValueError(f"Unsupported pool key type: {pool_key.type}")

    def _serialize_pool_key_reference(self, pool_key: PoolKey) -> bytes:
        data = bytearray()
        if pool_key.type == PoolKeyType.DEVICE_OWNED:
            data.append(CredentialParamsType.KEY_PATH)
            data.extend(pack_derivation_path(pool_key.key))
        elif pool_key.type == PoolKeyType.THIRD_PARTY:
            data.append(CredentialParamsType.KEY_HASH)
            data.extend(bytes.fromhex(pool_key.key.lower()))
        else:
            raise ValueError(f"Unsupported pool key type: {pool_key.type}")
        return bytes(data)

    def _serialize_relay(self, relay: Relay) -> bytes:
        data = bytearray()
        data.append(int(relay.type))
        if relay.type == RelayType.SINGLE_HOST_IP_ADDR:
            params = relay.params
            assert isinstance(params, SingleHostIpAddrRelayParams)
            if params.portNumber is None:
                data.append(FLAG_INCLUDED_NO)
            else:
                data.append(FLAG_INCLUDED_YES)
                data.extend(params.portNumber.to_bytes(2, "big"))
            if not params.ipv4:
                data.append(FLAG_INCLUDED_NO)
            else:
                data.append(FLAG_INCLUDED_YES)
                data.extend(ipaddress.IPv4Address(params.ipv4).packed)
            if not params.ipv6:
                data.append(FLAG_INCLUDED_NO)
            else:
                data.append(FLAG_INCLUDED_YES)
                data.extend(ipaddress.IPv6Address(params.ipv6).packed)
        elif relay.type == RelayType.SINGLE_HOST_HOSTNAME:
            params = relay.params
            assert isinstance(params, SingleHostHostnameRelayParams)
            if params.portNumber is None:
                data.append(FLAG_INCLUDED_NO)
            else:
                data.append(FLAG_INCLUDED_YES)
                data.extend(params.portNumber.to_bytes(2, "big"))
            if params.dnsName is None:
                data.append(FLAG_INCLUDED_NO)
                return bytes(data)
            data.append(FLAG_INCLUDED_YES)
            dns_bytes = params.dnsName.encode("utf-8")
            if len(dns_bytes) > MAX_UINT8:
                raise ValueError("Relay DNS name exceeds maximum length")
            data.append(len(dns_bytes))
            data.extend(dns_bytes)
        elif relay.type == RelayType.MULTI_HOST:
            params = relay.params
            assert isinstance(params, MultiHostRelayParams)
            if params.dnsName is None:
                data.append(FLAG_INCLUDED_NO)
                return bytes(data)
            data.append(FLAG_INCLUDED_YES)
            dns_bytes = params.dnsName.encode("utf-8")
            if len(dns_bytes) > MAX_UINT8:
                raise ValueError("Relay DNS name exceeds maximum length")
            data.append(len(dns_bytes))
            data.extend(dns_bytes)
        else:
            raise ValueError(f"Unsupported relay type: {relay.type}")
        return bytes(data)

    def _serialize_pool_metadata(self, metadata: Optional[PoolMetadataParams]) -> bytes:
        data = bytearray()
        if metadata is None:
            data.append(FLAG_INCLUDED_NO)
            return bytes(data)
        data.append(FLAG_INCLUDED_YES)
        url_bytes = metadata.metadataUrl.encode("utf-8")
        if len(url_bytes) > MAX_UINT16:
            raise ValueError("Pool metadata URL exceeds maximum encodable length")
        data.extend(len(url_bytes).to_bytes(2, "big"))
        data.extend(url_bytes)
        hash_bytes = bytes.fromhex(metadata.metadataHashHex.lower())
        data.extend(hash_bytes)
        return bytes(data)

    def _serialize_pool_registration(self, params: PoolRegistrationParams) -> bytes:
        data = bytearray()
        data.extend(self._serialize_pool_key_reference(params.poolKey))
        vrf_bytes = bytes.fromhex(params.vrfKeyHashHex.lower())
        if len(vrf_bytes) != 32:
            raise ValueError("VRF key hash must be 32 bytes")
        data.extend(vrf_bytes)
        data.extend(params.pledge.to_bytes(8, "big"))
        data.extend(params.cost.to_bytes(8, "big"))
        data.extend(params.margin.numerator.to_bytes(8, "big"))
        data.extend(params.margin.denominator.to_bytes(8, "big"))
        data.extend(self._serialize_pool_key_reference(params.rewardAccount))
        data.append(len(params.poolOwners))
        for owner in params.poolOwners:
            credential = self._pool_key_to_credential(owner)
            data.extend(self._serialize_credential_inline(credential))
        data.append(len(params.relays))
        for relay in params.relays:
            data.extend(self._serialize_relay(relay))
        data.extend(self._serialize_pool_metadata(params.metadata))
        return bytes(data)

    def _serialize_certificate(self, certificate: Certificate) -> bytes:
        result = bytearray()
        result.append(int(certificate.type))

        cert_type = certificate.type
        params = certificate.params

        if cert_type in (CertificateType.STAKE_REGISTRATION, CertificateType.STAKE_DEREGISTRATION):
            assert isinstance(params, StakeRegistrationParams)
            result.extend(self._serialize_credential_inline(params.stakeCredential))
        elif cert_type in (CertificateType.STAKE_REGISTRATION_CONWAY, CertificateType.STAKE_DEREGISTRATION_CONWAY):
            assert isinstance(params, StakeRegistrationConwayParams)
            result.extend(self._serialize_credential_inline(params.stakeCredential))
            result.extend(params.deposit.to_bytes(8, "big"))
        elif cert_type == CertificateType.STAKE_DELEGATION:
            assert isinstance(params, StakeDelegationParams)
            result.extend(self._serialize_credential_inline(params.stakeCredential))
            result.extend(bytes.fromhex(params.poolKeyHash))
        elif cert_type == CertificateType.VOTE_DELEGATION:
            assert isinstance(params, VoteDelegationParams)
            result.extend(self._serialize_credential_inline(params.stakeCredential))
            result.extend(self._serialize_drep(params.dRep))
        elif cert_type == CertificateType.ACCOUNT_REGISTRATION_DELEGATION_TO_STAKE_POOL:
            assert isinstance(params, AccountRegistrationDelegationToStakePoolParams)
            result.extend(self._serialize_credential_inline(params.stakeCredential))
            result.extend(bytes.fromhex(params.poolKeyHash))
            result.extend(params.coin.to_bytes(8, "big"))
        elif cert_type == CertificateType.ACCOUNT_REGISTRATION_DELEGATION_TO_DREP:
            assert isinstance(params, AccountRegistrationDelegationToDRepParams)
            result.extend(self._serialize_credential_inline(params.stakeCredential))
            result.extend(self._serialize_drep(params.dRep))
            result.extend(params.coin.to_bytes(8, "big"))
        elif cert_type == CertificateType.ACCOUNT_REGISTRATION_DELEGATION_TO_STAKE_POOL_AND_DREP:
            assert isinstance(params, AccountRegistrationDelegationToStakePoolAndDRepParams)
            result.extend(self._serialize_credential_inline(params.stakeCredential))
            result.extend(bytes.fromhex(params.poolKeyHash))
            result.extend(self._serialize_drep(params.dRep))
            result.extend(params.coin.to_bytes(8, "big"))
        elif cert_type == CertificateType.STAKE_POOL_AND_DREP_DELEGATION:
            assert isinstance(params, StakePoolAndDRepDelegationParams)
            result.extend(self._serialize_credential_inline(params.stakeCredential))
            result.extend(bytes.fromhex(params.poolKeyHash))
            result.extend(self._serialize_drep(params.dRep))
        elif cert_type == CertificateType.AUTHORIZE_COMMITTEE_HOT:
            assert isinstance(params, AuthorizeCommitteeParams)
            result.extend(self._serialize_credential_inline(params.coldCredential))
            result.extend(self._serialize_credential_inline(params.hotCredential))
        elif cert_type == CertificateType.RESIGN_COMMITTEE_COLD:
            assert isinstance(params, ResignCommitteeParams)
            result.extend(self._serialize_credential_inline(params.coldCredential))
            result.extend(self._serialize_anchor(params.anchor))
        elif cert_type == CertificateType.DREP_REGISTRATION:
            assert isinstance(params, DRepRegistrationParams)
            result.extend(self._serialize_credential_inline(params.dRepCredential))
            result.extend(params.deposit.to_bytes(8, "big"))
            result.extend(self._serialize_anchor(params.anchor))
        elif cert_type == CertificateType.DREP_DEREGISTRATION:
            assert isinstance(params, DRepRegistrationParams)
            result.extend(self._serialize_credential_inline(params.dRepCredential))
            result.extend(params.deposit.to_bytes(8, "big"))
        elif cert_type == CertificateType.DREP_UPDATE:
            assert isinstance(params, DRepUpdateParams)
            result.extend(self._serialize_credential_inline(params.dRepCredential))
            result.extend(self._serialize_anchor(params.anchor))
        elif cert_type == CertificateType.STAKE_POOL_REGISTRATION:
            assert isinstance(params, PoolRegistrationParams)
            result.extend(self._serialize_pool_registration(params))
        elif cert_type == CertificateType.STAKE_POOL_RETIREMENT:
            assert isinstance(params, PoolRetirementParams)
            result.extend(self._serialize_credential_inline(params.poolCredential))
            result.extend(params.retirementEpoch.to_bytes(8, "big"))
        else:
            raise ValueError(f"Unsupported certificate type: {cert_type}")

        return bytes(result)

    def sign_msg_init(self, testCase) -> bytes:
        """APDU Builder for CIP-8 Message Signing - INIT step

        Args:
            testCase: SignMsgTestCase with message data

        Returns:
            Serial data APDU
        """
        from standalone.input_files.signMsg import MessageAddressFieldType

        data = bytearray()

        # Message length (4 bytes BE)
        messageBytes = bytes.fromhex(testCase.msgData.messageHex)
        data.extend(len(messageBytes).to_bytes(4, "big"))

        # Signing path
        data.extend(pack_derivation_path(testCase.msgData.signingPath))

        # Hash payload flag (1 byte)
        data.append(1 if testCase.msgData.hashPayload else 0)

        # Is ASCII flag (1 byte)
        data.append(1 if testCase.msgData.isAscii else 0)

        # Address field type (1 byte)
        data.append(int(testCase.msgData.addressFieldType))

        # Address params (if type is ADDRESS)
        if testCase.msgData.addressFieldType == MessageAddressFieldType.ADDRESS:
            data.extend(self._serialize_address_params(testCase.msgData.addressDesc))

        return self._serialize(InsType.INS_SIGN_MSG, P1Type.P1_SIGN_MSG_INIT, 0x00, bytes(data))

    def build_sign_msg_chunk_payloads(self, testCase) -> list[bytes]:
        messageBytes = bytes.fromhex(testCase.msgData.messageHex)
        chunk_sizes: list[int] = []
        remaining_bytes = len(messageBytes)

        # Both hashed and non-hashed messages use the same chunking:
        # each chunk is min(remaining, MAX_CIP8_MSG_CHUNK_SIZE)
        while remaining_bytes > 0:
            next_chunk = min(remaining_bytes, MAX_CIP8_MSG_CHUNK_SIZE)
            chunk_sizes.append(next_chunk)
            remaining_bytes -= next_chunk

        offset = 0
        payloads: list[bytes] = []
        for size in chunk_sizes:
            chunk_data = messageBytes[offset:offset + size]
            payloads.append(len(chunk_data).to_bytes(4, "big") + chunk_data)
            offset += size

        return payloads

    def sign_msg_chunks(self, testCase) -> list[bytes]:
        """APDU Builder for CIP-8 Message Signing - all CHUNK APDUs"""
        payloads = self.build_sign_msg_chunk_payloads(testCase)
        apdus: list[bytes] = []
        for payload in payloads:
            apdus.append(
                self._serialize(InsType.INS_SIGN_MSG, P1Type.P1_SIGN_MSG_CHUNK, 0x00, payload)
            )
        return apdus

    def sign_msg_confirm(self) -> bytes:
        """APDU Builder for CIP-8 Message Signing - CONFIRM step

        Returns:
            Serial data APDU (empty payload)
        """
        return self._serialize(InsType.INS_SIGN_MSG, P1Type.P1_SIGN_MSG_CONFIRM, 0x00, bytes())
