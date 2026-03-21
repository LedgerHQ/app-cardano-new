# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2024 Ledger SAS
# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0

"""
This module provides Ragger tests for Public Key check
"""

from dataclasses import dataclass
from typing import Optional


@dataclass(kw_only=True)
class PubKeyTestCase:
    name: str
    path: Optional[str] = None
    nav: Optional[bool] = True


# pylint: disable=line-too-long
testsByron = [
    PubKeyTestCase(name="Export_pubkey_byronpath_1", path="m/44'/1815'/1'"),
    PubKeyTestCase(name="Export_pubkey_byronpath_2", path="m/44'/1815'/1'/0/55'"),
    PubKeyTestCase(name="Export_pubkey_byronpath_3", path="m/44'/1815'/1'/0/12'"),
]

testsShelleyUsual = [
    PubKeyTestCase(name="Export_pubkey_shelley_usual_path_0", path="m/1852'/1815'/4'"),
    PubKeyTestCase(
        name="Export_pubkey_shelley_usual_path_1", path="m/1852'/1815'/0'/0/1"
    ),
    PubKeyTestCase(
        name="Export_pubkey_shelley_usual_path_2", path="m/1852'/1815'/0'/2/0"
    ),
    PubKeyTestCase(
        name="Export_pubkey_shelley_usual_path_3", path="m/1852'/1815'/0'/2/1001"
    ),
    PubKeyTestCase(
        name="Export_pubkey_shelley_usual_path_4", path="m/1852'/1815'/0'/3/0"
    ),
    PubKeyTestCase(
        name="Export_pubkey_shelley_usual_path_5", path="m/1852'/1815'/0'/4/0"
    ),
    PubKeyTestCase(
        name="Export_pubkey_shelley_usual_path_6", path="m/1852'/1815'/1'/5/0"
    ),
]

testsShelleyUnusual = [
    PubKeyTestCase(
        name="Export_pubkey_shelley_unusual_path_1", path="m/1852'/1815'/101'"
    ),
    PubKeyTestCase(
        name="Export_pubkey_shelley_unusual_path_2",
        path="m/1852'/1815'/100'/0/1000001'",
    ),
    PubKeyTestCase(
        name="Export_pubkey_shelley_unusual_path_3", path="m/1852'/1815'/0'/2/1000001"
    ),
    PubKeyTestCase(
        name="Export_pubkey_shelley_unusual_path_4", path="m/1852'/1815'/101'/3/0"
    ),
    PubKeyTestCase(
        name="Export_pubkey_shelley_unusual_path_5", path="m/1852'/1815'/101'/4/0"
    ),
    PubKeyTestCase(
        name="Export_pubkey_shelley_unusual_path_6", path="m/1852'/1815'/101'/5/0"
    ),
]

testsMultisig = [
    PubKeyTestCase(
        name="Export_pubkey_multisig_account_path_0", path="m/1854'/1815'/0'"
    ),
    PubKeyTestCase(
        name="Export_pubkey_multisig_payment_path_0", path="m/1854'/1815'/0'/0/0"
    ),
    PubKeyTestCase(
        name="Export_pubkey_multisig_staking_path_0", path="m/1854'/1815'/0'/2/0"
    ),
]

testsColdKeys = [
    PubKeyTestCase(name="Export_pubkey_cold_case", path="m/1853'/1815'/0'/0'"),
    PubKeyTestCase(
        name="Export_pubkey_cold_unusual_case", path="m/1853'/1815'/0'/101'"
    ),
]

testsCVoteKeysUsual = [
    PubKeyTestCase(name="Export_pubkey_CVote_keys_path_2", path="m/1694'/1815'/100'"),
]

testsCVoteKeysUnusual = [
    PubKeyTestCase(name="Export_pubkey_CVote_keys_path_1", path="m/1694'/1815'/0'/0/1"),
    PubKeyTestCase(name="Export_pubkey_CVote_keys_path_3", path="m/1694'/1815'/101'"),
]

testsDRepKeys = [
    PubKeyTestCase(name="Export_pubkey_drep_key_path_0", path="m/1852'/1815'/0'/3/0"),
]

testsCommitteeColdKeys = [
    PubKeyTestCase(
        name="Export_pubkey_committee_cold_key_path_0", path="m/1852'/1815'/0'/4/0"
    ),
]

testsCommitteeHotKeys = [
    PubKeyTestCase(
        name="Export_pubkey_committee_hot_key_path_0", path="m/1852'/1815'/0'/5/0"
    ),
]

testsMintKeys = [
    PubKeyTestCase(name="Export_pubkey_mint_key_path_0", path="m/1855'/1815'/0'"),
]

testsSilentExportRareKeys = [
    PubKeyTestCase(
        name="Export_pubkey_drep_key_path_0_silent", path="m/1852'/1815'/0'/3/0"
    ),
    PubKeyTestCase(
        name="Export_pubkey_committee_cold_key_path_0_silent",
        path="m/1852'/1815'/0'/4/0",
    ),
    PubKeyTestCase(
        name="Export_pubkey_committee_hot_key_path_0_silent",
        path="m/1852'/1815'/0'/5/0",
    ),
    PubKeyTestCase(
        name="Export_pubkey_mint_key_path_0_silent", path="m/1855'/1815'/0'"
    ),
    PubKeyTestCase(name="Export_pubkey_cold_case_silent", path="m/1853'/1815'/0'/0'"),
]


def _parse_bip44_path(path: str) -> list[tuple[int, bool]]:
    parts = path.split("/")[1:]
    parsed: list[tuple[int, bool]] = []
    for part in parts:
        hardened = part.endswith("'")
        value_str = part[:-1] if hardened else part
        parsed.append((int(value_str), hardened))
    return parsed


def _is_silent_export_path(path: str) -> bool:
    parsed = _parse_bip44_path(path)
    if len(parsed) < 3:
        return False
    purpose, purpose_hardened = parsed[0]
    coin_type, coin_type_hardened = parsed[1]
    account, account_hardened = parsed[2]
    if not (purpose_hardened and coin_type_hardened and account_hardened):
        return False
    if purpose not in {1694, 1852, 1854} or coin_type != 1815:
        return False
    if account > 100:
        return False
    if len(parsed) == 3:
        return True
    if len(parsed) != 5:
        return False
    chain, chain_hardened = parsed[3]
    address, address_hardened = parsed[4]
    if chain_hardened or address_hardened:
        return False
    if purpose == 1694:
        if chain != 0:
            return False
    elif chain not in {0, 1, 2}:
        return False
    return address <= 1000000


testsSilentExport = [
    test_case
    for test_case in (
        testsByron
        + testsShelleyUsual
        + testsShelleyUnusual
        + testsMultisig
        + testsColdKeys
        + testsCVoteKeysUsual
        + testsCVoteKeysUnusual
        + testsDRepKeys
        + testsCommitteeColdKeys
        + testsCommitteeHotKeys
        + testsMintKeys
    )
    if _is_silent_export_path(test_case.path)
] + testsSilentExportRareKeys

denyTestCases = [
    PubKeyTestCase(
        name="Export_pubkey_path_shorter_than_3_indexes", path="m/44'/1815'"
    ),
    PubKeyTestCase(
        name="Export_pubkey_path_not_matching_cold_key_structure",
        path="m/1853'/1900'/0'/0/0",
    ),
    PubKeyTestCase(
        name="Export_pubkey_invalid_vote_key_path_1", path="m/1694'/1815'/0'/1/0"
    ),
    PubKeyTestCase(
        name="Export_pubkey_invalid_vote_key_path_2", path="m/1694'/1815'/17"
    ),
    PubKeyTestCase(
        name="Export_pubkey_invalid_vote_key_path_3", path="m/1694'/1815'/0'/1"
    ),
    PubKeyTestCase(
        name="Export_pubkey_invalid_multisig_account_not_hardened",
        path="m/1854'/1815'/0",
    ),
    PubKeyTestCase(
        name="Export_pubkey_invalid_multisig_chain", path="m/1854'/1815'/0'/3/0"
    ),
    PubKeyTestCase(
        name="Export_pubkey_invalid_multisig_address_hardened",
        path="m/1854'/1815'/0'/0/0'",
    ),
    PubKeyTestCase(
        name="Export_pubkey_invalid_mint_policy_not_hardened", path="m/1855'/1815'/0"
    ),
    PubKeyTestCase(
        name="Export_pubkey_invalid_drep_chain", path="m/1852'/1815'/0'/6/0"
    ),
    PubKeyTestCase(
        name="Export_pubkey_invalid_committee_cold_address_hardened",
        path="m/1852'/1815'/0'/4/0'",
    ),
    PubKeyTestCase(
        name="Export_pubkey_invalid_committee_hot_account_not_hardened",
        path="m/1852'/1815'/0/5/0",
    ),
    PubKeyTestCase(
        name="Export_pubkey_invalid_pool_cold_usecase", path="m/1853'/1815'/1'/0'"
    ),
]
