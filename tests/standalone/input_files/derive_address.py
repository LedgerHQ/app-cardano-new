# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2024 Ledger SAS
# SPDX-License-Identifier: LicenseRef-LEDGER
"""
This module provides Ragger tests for Address check
"""

from typing import List, Optional
from dataclasses import dataclass

from ragger.navigator import NavInsID

from application_client.app_def import (
    NetworkDesc,
    AddressType,
    Mainnet,
    Testnet,
    FakeNet,
)


@dataclass(kw_only=True)
class DeriveAddressTestCase:
    name: str
    ledgerjs_name: Optional[str] = None
    netDesc: NetworkDesc = None
    addrType: AddressType = None
    spendingValue: str = ""  # spending path or keyHash
    stakingValue: str = ""  # staking path or keyHash
    result: Optional[str] = ""
    result_hex: Optional[str] = None
    nano_nav_confirm: Optional[List[NavInsID]] = (
        None  # list of specific navigation instructions for Nano
    )
    nano_nav_show: Optional[List[NavInsID]] = (
        None  # list of specific navigation instructions for Nano
    )


def pointer_to_str(blockIndex: int, txIndex: int, certificateIndex: int) -> str:
    data: str = ""
    data += f"{blockIndex.to_bytes(4, 'big').hex()}"
    data += f"{txIndex.to_bytes(4, 'big').hex()}"
    data += f"{certificateIndex.to_bytes(4, 'big').hex()}"
    return data


# pylint: disable=line-too-long
byronTestCases = [
    DeriveAddressTestCase(
        name="Derive_address_byron_mainnet_1",
        ledgerjs_name="mainnet 1",
        netDesc=Mainnet,
        addrType=AddressType.BYRON,
        spendingValue="m/44'/1815'/1'/0/55'",
    ),
    DeriveAddressTestCase(
        name="Derive_address_byron_mainnet_2",
        ledgerjs_name="mainnet 2",
        netDesc=Mainnet,
        addrType=AddressType.BYRON,
        spendingValue="m/44'/1815'/1'/0/12'",
    ),
    DeriveAddressTestCase(
        name="Derive_address_byron_mainnet_3",
        ledgerjs_name="mainnet 3",
        netDesc=Mainnet,
        addrType=AddressType.BYRON,
        spendingValue="m/44'/1815'/101'/0/12'",
    ),
    DeriveAddressTestCase(
        name="Derive_address_byron_mainnet_4",
        ledgerjs_name="mainnet 4",
        netDesc=Mainnet,
        addrType=AddressType.BYRON,
        spendingValue="m/44'/1815'/0'/0/1000001'",
    ),
    DeriveAddressTestCase(
        name="Derive_address_byron_testnet_1",
        ledgerjs_name="testnet 1",
        netDesc=Testnet,
        addrType=AddressType.BYRON,
        spendingValue="m/44'/1815'/1'/0/12'",
        result="2657WMsDfac5679tC5DgShwENgGLwAuGNanDjDaCzuEEqXDsP6i2345FcVkwRYVqX",
    ),
]

rejectTestCases = [
    DeriveAddressTestCase(
        name="Derive_address_path_too_short",
        ledgerjs_name="path too short",
        netDesc=Mainnet,
        addrType=AddressType.BYRON,
        spendingValue="m/44'/1815'/1'"
    ),
    DeriveAddressTestCase(
        name="Derive_address_invalid_path",
        ledgerjs_name="invalid path",
        netDesc=Mainnet,
        addrType=AddressType.BYRON,
        spendingValue="m/44'/1815'/1'/5/10'"
    ),
    DeriveAddressTestCase(
        name="Derive_address_Byron_with_Shelley_path",
        ledgerjs_name="Byron with Shelley path",
        netDesc=Mainnet,
        addrType=AddressType.BYRON,
        spendingValue="m/1852'/1815'/1'/0/10"
    ),
    DeriveAddressTestCase(
        name="Derive_address_base_key_key_with_Byron_spending_path",
        ledgerjs_name="base key/key with Byron spending path",
        netDesc=Mainnet,
        addrType=AddressType.BASE_PAYMENT_KEY_STAKE_KEY,
        spendingValue="m/44'/1815'/1'/0/1",
        stakingValue="m/1852'/1815'/1'/2/0",
    ),
    DeriveAddressTestCase(
        name="Derive_address_base_key_key_with_wrong_spending_path",
        ledgerjs_name="base key/key with wrong spending path",
        netDesc=Mainnet,
        addrType=AddressType.BASE_PAYMENT_KEY_STAKE_KEY,
        spendingValue="m/1852'/1815'/1'/2/0",
        stakingValue="m/1852'/1815'/1'/2/0",
    ),
    DeriveAddressTestCase(
        name="Derive_address_base_key_key_with_wrong_staking_path_1",
        ledgerjs_name="base key/key with wrong staking path 1",
        netDesc=Mainnet,
        addrType=AddressType.BASE_PAYMENT_KEY_STAKE_KEY,
        spendingValue="m/1852'/1815'/1'/0/0",
        stakingValue="m/1852'/1815'/1'/0/1",
    ),
    DeriveAddressTestCase(
        name="Derive_address_base_key_script_with_Byron_spending_path",
        ledgerjs_name="base key/script with Byron spending path",
        netDesc=Mainnet,
        addrType=AddressType.BASE_PAYMENT_KEY_STAKE_SCRIPT,
        spendingValue="m/44'/1815'/1'/0/1",
        stakingValue="222a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277",
    ),
    DeriveAddressTestCase(
        name="Derive_address_base_address_scripthash_keyhash_not_allowed",
        ledgerjs_name="base address scripthash/keyhash not allowed",
        netDesc=Mainnet,
        addrType=AddressType.BASE_PAYMENT_SCRIPT_STAKE_KEY,
        spendingValue="122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277",
        stakingValue="222a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277",
    ),
    DeriveAddressTestCase(
        name="Derive_address_pointer_with_Byron_spending_path",
        ledgerjs_name="pointer with Byron spending path",
        netDesc=Mainnet,
        addrType=AddressType.POINTER_KEY,
        spendingValue="m/44'/1815'/1'/0/0",
        stakingValue=pointer_to_str(1, 2, 3),
    ),
    DeriveAddressTestCase(
        name="Derive_address_pointer_with_wrong_spending_path",
        ledgerjs_name="pointer with wrong spending path",
        netDesc=Mainnet,
        addrType=AddressType.POINTER_KEY,
        spendingValue="m/1852'/1815'/1'/2/0",
        stakingValue=pointer_to_str(1, 2, 3),
    ),
    DeriveAddressTestCase(
        name="Derive_address_enterprise_with_Byron_spending_path",
        ledgerjs_name="enterprise with Byron spending path",
        netDesc=Mainnet,
        addrType=AddressType.ENTERPRISE_KEY,
        spendingValue="m/44'/1815'/1'/0/0",
    ),
    DeriveAddressTestCase(
        name="Derive_address_enterprise_with_wrong_spending_path",
        ledgerjs_name="enterprise with wrong spending path",
        netDesc=Mainnet,
        addrType=AddressType.ENTERPRISE_KEY,
        spendingValue="m/1852'/1815'/1'/2/0",
    ),
]

nav_review_2 = [NavInsID.USE_CASE_REVIEW_TAP] * 2 + [
    NavInsID.USE_CASE_ADDRESS_CONFIRMATION_TAP
]

nav_review_3 = [NavInsID.USE_CASE_REVIEW_TAP] * 3 + [
    NavInsID.USE_CASE_ADDRESS_CONFIRMATION_TAP
]

nav_review_1 = [NavInsID.USE_CASE_REVIEW_TAP] + [
    NavInsID.USE_CASE_ADDRESS_CONFIRMATION_TAP
]

shelleyTestCasesNoConfirm = [
    # LedgerJS: base address path/path 1
    DeriveAddressTestCase(
        name="Derive_address_shelley_fakenet_base_path_path_1",
        ledgerjs_name="base address path/path 1",
        netDesc=FakeNet,
        addrType=AddressType.BASE_PAYMENT_KEY_STAKE_KEY,
        spendingValue="m/1852'/1815'/0'/0/1",
        stakingValue="m/1852'/1815'/0'/2/0",
        result="addr1qdd9xypc9xnnstp2kas3r7mf7ylxn4sksfxxypvwgnc63vcayfawlf9hwv2fzuygt2km5v92kvf8e3s3mk7ynxw77cwqdquehe",
        result_hex="035a53103829a7382c2ab76111fb69f13e69d616824c62058e44f1a8b31d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c",
        nano_nav_show=nav_review_2,
    ),
    # LedgerJS: base address path/path 2
    DeriveAddressTestCase(
        name="Derive_address_shelley_testnet_base_path_path_2",
        ledgerjs_name="base address path/path 2",
        netDesc=Testnet,
        addrType=AddressType.BASE_PAYMENT_KEY_STAKE_KEY,
        spendingValue="m/1852'/1815'/0'/0/1",
        stakingValue="m/1852'/1815'/0'/2/0",
        result="addr_test1qpd9xypc9xnnstp2kas3r7mf7ylxn4sksfxxypvwgnc63vcayfawlf9hwv2fzuygt2km5v92kvf8e3s3mk7ynxw77cwq9nnhk4",
        result_hex="005a53103829a7382c2ab76111fb69f13e69d616824c62058e44f1a8b31d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c",
        nano_nav_show=nav_review_2,
    ),
    # LedgerJS: base address path/path multidelegation stake key usual
    DeriveAddressTestCase(
        name="Derive_address_shelley_testnet_base_path_path_multidelegation",
        ledgerjs_name="base address path/path multidelegation stake key usual",
        netDesc=Testnet,
        addrType=AddressType.BASE_PAYMENT_KEY_STAKE_KEY,
        spendingValue="m/1852'/1815'/0'/0/1",
        stakingValue="m/1852'/1815'/0'/2/60",
        result="addr_test1qpd9xypc9xnnstp2kas3r7mf7ylxn4sksfxxypvwgnc63vl404mjsaz2xyzvegxxrpx5ltrjgy4qws4ataqtv5lp2h3q30eyjm",
        result_hex="005a53103829a7382c2ab76111fb69f13e69d616824c62058e44f1a8b3f57d7728744a3104cca0c6184d4fac72412a0742bd5f40b653e155e2",
        nano_nav_show=nav_review_2,
    ),
    # LedgerJS: base address path/keyHash 1
    DeriveAddressTestCase(
        name="Derive_address_shelley_testnet_base_path_keyhash_1",
        ledgerjs_name="base address path/keyHash 1",
        netDesc=Testnet,
        addrType=AddressType.BASE_PAYMENT_KEY_STAKE_KEY,
        spendingValue="m/1852'/1815'/0'/0/1",
        stakingValue="1d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c",
        result="addr_test1qpd9xypc9xnnstp2kas3r7mf7ylxn4sksfxxypvwgnc63vcayfawlf9hwv2fzuygt2km5v92kvf8e3s3mk7ynxw77cwq9nnhk4",
        result_hex="005a53103829a7382c2ab76111fb69f13e69d616824c62058e44f1a8b31d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c",
        nano_nav_show=nav_review_2,
    ),
    # LedgerJS: base address path/keyHash 2
    DeriveAddressTestCase(
        name="Derive_address_shelley_fakenet_base_path_keyhash_2",
        ledgerjs_name="base address path/keyHash 2",
        netDesc=FakeNet,
        addrType=AddressType.BASE_PAYMENT_KEY_STAKE_KEY,
        spendingValue="m/1852'/1815'/0'/0/1",
        stakingValue="122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277",
        result="addr1qdd9xypc9xnnstp2kas3r7mf7ylxn4sksfxxypvwgnc63vcj922xhxkn6twlq2wn4q50q352annk3903tj00h45mgfmswz93l5",
        result_hex="035a53103829a7382c2ab76111fb69f13e69d616824c62058e44f1a8b3122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277",
        nano_nav_show=nav_review_2,
    ),
    # LedgerJS: base address scriptHash/path
    DeriveAddressTestCase(
        name="Derive_address_shelley_fakenet_base_scripthash_path",
        ledgerjs_name="base address scriptHash/path",
        netDesc=FakeNet,
        addrType=AddressType.BASE_PAYMENT_SCRIPT_STAKE_KEY,
        spendingValue="122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277",
        stakingValue="m/1852'/1815'/0'/2/0",
        result="addr1zvfz49rtntfa9h0s98f6s28sg69weemgjhc4e8hm66d5yacayfawlf9hwv2fzuygt2km5v92kvf8e3s3mk7ynxw77cwq8dxrpu",
        result_hex="13122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b42771d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c",
        nano_nav_show=nav_review_2,
    ),
    # LedgerJS: base address scriptHash/path multidelegation
    DeriveAddressTestCase(
        name="Derive_address_shelley_fakenet_base_scripthash_path_multidelegation",
        ledgerjs_name="base address scriptHash/path multidelegation",
        netDesc=FakeNet,
        addrType=AddressType.BASE_PAYMENT_SCRIPT_STAKE_KEY,
        spendingValue="122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277",
        stakingValue="m/1852'/1815'/0'/2/3",
        result="addr1zvfz49rtntfa9h0s98f6s28sg69weemgjhc4e8hm66d5yauc4nklr34kj8uk8kfgz3lkv6tu0ndr3x0rp3snqdayaxgqwrgxu2",
        result_hex="13122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b427798acedf1c6b691f963d928147f66697c7cda3899e30c613037a4e990",
        nano_nav_show=nav_review_2,
    ),
    # LedgerJS: base address path/scriptHash
    DeriveAddressTestCase(
        name="Derive_address_shelley_fakenet_base_path_scripthash",
        ledgerjs_name="base address path/scriptHash",
        netDesc=FakeNet,
        addrType=AddressType.BASE_PAYMENT_KEY_STAKE_SCRIPT,
        spendingValue="m/1852'/1815'/0'/0/1",
        stakingValue="122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277",
        result="addr1ydd9xypc9xnnstp2kas3r7mf7ylxn4sksfxxypvwgnc63vcj922xhxkn6twlq2wn4q50q352annk3903tj00h45mgfmssu7w24",
        result_hex="235a53103829a7382c2ab76111fb69f13e69d616824c62058e44f1a8b3122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277",
        nano_nav_show=nav_review_2,
    ),
    # LedgerJS: base address scripthash/scriptHash
    DeriveAddressTestCase(
        name="Derive_address_shelley_fakenet_base_scripthash_scripthash",
        ledgerjs_name="base address scriptHash/scriptHash",
        netDesc=FakeNet,
        addrType=AddressType.BASE_PAYMENT_SCRIPT_STAKE_SCRIPT,
        spendingValue="122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277",
        stakingValue="122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277",
        result="addr1xvfz49rtntfa9h0s98f6s28sg69weemgjhc4e8hm66d5yacj922xhxkn6twlq2wn4q50q352annk3903tj00h45mgfms63y5us",
        result_hex="33122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277",
        nano_nav_show=nav_review_2,
    ),
    DeriveAddressTestCase(
        name="Derive_address_shelley_testnet_enterprise_path_1",
        ledgerjs_name="enterprise path 1",
        netDesc=Testnet,
        addrType=AddressType.ENTERPRISE_KEY,
        spendingValue="m/1852'/1815'/0'/0/1",
        nano_nav_show=nav_review_1,
    ),
    DeriveAddressTestCase(
        name="Derive_address_shelley_fakenet_enterprise_path_2",
        ledgerjs_name="enterprise path 2",
        netDesc=FakeNet,
        addrType=AddressType.ENTERPRISE_KEY,
        spendingValue="m/1852'/1815'/0'/0/1",
        nano_nav_show=nav_review_1,
    ),
    DeriveAddressTestCase(
        name="Derive_address_shelley_testnet_enterprise_script_1",
        ledgerjs_name="enterprise script 1",
        netDesc=Testnet,
        addrType=AddressType.ENTERPRISE_SCRIPT,
        spendingValue="122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277",
        nano_nav_show=nav_review_2,
    ),
    DeriveAddressTestCase(
        name="Derive_address_shelley_fakenet_enterprise_script_2",
        ledgerjs_name="enterprise script 2",
        netDesc=FakeNet,
        addrType=AddressType.ENTERPRISE_SCRIPT,
        spendingValue="122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277",
        nano_nav_show=nav_review_2,
    ),
    DeriveAddressTestCase(
        name="Derive_address_shelley_testnet_pointer_path_1",
        ledgerjs_name="pointer path 1",
        netDesc=Testnet,
        addrType=AddressType.POINTER_KEY,
        spendingValue="m/1852'/1815'/0'/0/1",
        stakingValue=pointer_to_str(1, 2, 3),
        nano_nav_show=nav_review_1,
    ),
    DeriveAddressTestCase(
        name="Derive_address_shelley_fakenet_pointer_path_2",
        ledgerjs_name="pointer path 2",
        netDesc=FakeNet,
        addrType=AddressType.POINTER_KEY,
        spendingValue="m/1852'/1815'/0'/0/1",
        stakingValue=pointer_to_str(24157, 177, 42),
        nano_nav_show=nav_review_1,
    ),
    DeriveAddressTestCase(
        name="Derive_address_shelley_fakenet_pointer_path_3",
        ledgerjs_name="pointer path 3",
        netDesc=FakeNet,
        addrType=AddressType.POINTER_KEY,
        spendingValue="m/1852'/1815'/0'/0/1",
        stakingValue=pointer_to_str(0, 0, 0),
        nano_nav_show=nav_review_1,
    ),
    DeriveAddressTestCase(
        name="Derive_address_shelley_testnet_pointer_script_1",
        ledgerjs_name="pointer script 1",
        netDesc=Testnet,
        addrType=AddressType.POINTER_SCRIPT,
        spendingValue="122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277",
        stakingValue=pointer_to_str(1, 2, 3),
        nano_nav_show=nav_review_2,
    ),
    DeriveAddressTestCase(
        name="Derive_address_shelley_fakenet_pointer_script_2",
        ledgerjs_name="pointer script 2",
        netDesc=FakeNet,
        addrType=AddressType.POINTER_SCRIPT,
        spendingValue="122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277",
        stakingValue=pointer_to_str(24157, 177, 42),
        nano_nav_show=nav_review_2,
    ),
    DeriveAddressTestCase(
        name="Derive_address_shelley_fakenet_pointer_script_3",
        ledgerjs_name="pointer script 3",
        netDesc=FakeNet,
        addrType=AddressType.POINTER_SCRIPT,
        spendingValue="122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277",
        stakingValue=pointer_to_str(0, 0, 0),
        nano_nav_show=nav_review_2,
    ),
    DeriveAddressTestCase(
        name="Derive_address_shelley_testnet_reward_path_1",
        ledgerjs_name="reward path 1",
        netDesc=Testnet,
        addrType=AddressType.REWARD_KEY,
        spendingValue="",
        stakingValue="m/1852'/1815'/0'/2/0",
        nano_nav_show=nav_review_1,
    ),
    DeriveAddressTestCase(
        name="Derive_address_shelley_fakenet_reward_path_2",
        ledgerjs_name="reward path 2",
        netDesc=FakeNet,
        addrType=AddressType.REWARD_KEY,
        spendingValue="",
        stakingValue="m/1852'/1815'/0'/2/0",
        nano_nav_show=nav_review_1,
    ),
    # LedgerJS: reward multidelegation usual
    DeriveAddressTestCase(
        name="Derive_address_shelley_testnet_reward_multidelegation",
        ledgerjs_name="reward multidelegation usual",
        netDesc=Testnet,
        addrType=AddressType.REWARD_KEY,
        spendingValue="",
        stakingValue="m/1852'/1815'/0'/2/1",
        result="stake_test1uqktgr9psuz0fxggkx9ald8wu8kgpckr2d9kjfxrum6sm3qp87652",
        result_hex="e02cb40ca18704f49908b18bdfb4eee1ec80e2c3534b6924c3e6f50dc4",
        nano_nav_show=nav_review_1,
    ),
    DeriveAddressTestCase(
        name="Derive_address_shelley_testnet_reward_script_1",
        ledgerjs_name="reward script 1",
        netDesc=Testnet,
        addrType=AddressType.REWARD_SCRIPT,
        spendingValue="",
        stakingValue="122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277",
        nano_nav_show=nav_review_1,
    ),
    DeriveAddressTestCase(
        name="Derive_address_shelley_fakenet_reward_script_2",
        ledgerjs_name="reward script 2",
        netDesc=FakeNet,
        addrType=AddressType.REWARD_SCRIPT,
        spendingValue="",
        stakingValue="122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277",
        nano_nav_show=nav_review_1,
    ),
]

shelleyTestCasesWithConfirm = [
    # LedgerJS: base address path/path unusual spending path account
    DeriveAddressTestCase(
        name="Derive_address_shelley_fakenet_base_path_path_unusual_spending_account",
        ledgerjs_name="base address path/path unusual spending path account",
        netDesc=FakeNet,
        addrType=AddressType.BASE_PAYMENT_KEY_STAKE_KEY,
        spendingValue="m/1852'/1815'/101'/0/1",
        stakingValue="m/1852'/1815'/0'/2/0",
        result="addr1qv6dcymepkghuyt0za9jxg5hn89art9y8yjcvhxclxdhndsayfawlf9hwv2fzuygt2km5v92kvf8e3s3mk7ynxw77cwqdqq9xn",
        result_hex="0334dc13790d917e116f174b23229799cbd1aca43925865cd8f99b79b61d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c",
        nano_nav_confirm=nav_review_2,
        nano_nav_show=nav_review_2,
    ),
    # LedgerJS: base address path/path unusual spending path address index
    DeriveAddressTestCase(
        name="Derive_address_shelley_fakenet_base_path_path_unusual_spending_index",
        ledgerjs_name="base address path/path unusual spending path address index",
        netDesc=FakeNet,
        addrType=AddressType.BASE_PAYMENT_KEY_STAKE_KEY,
        spendingValue="m/1852'/1815'/1'/0/1000001",
        stakingValue="m/1852'/1815'/0'/2/0",
        result="addr1q08rwk27cdm6vcp272pqcwq3t3gzea0q5xws2z84zzejrkcayfawlf9hwv2fzuygt2km5v92kvf8e3s3mk7ynxw77cwq2cxp3q",
        result_hex="03ce37595ec377a6602af2820c38115c502cf5e0a19d0508f510b321db1d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c",
        nano_nav_confirm=nav_review_2,
        nano_nav_show=nav_review_2,
    ),
    # LedgerJS: base address path/path unusual staking path account
    DeriveAddressTestCase(
        name="Derive_address_shelley_fakenet_base_path_path_unusual_staking_account",
        ledgerjs_name="base address path/path unusual staking path account",
        netDesc=FakeNet,
        addrType=AddressType.BASE_PAYMENT_KEY_STAKE_KEY,
        spendingValue="m/1852'/1815'/10'/0/4",
        stakingValue="m/1852'/1815'/101'/2/0",
        result="addr1qwpug24twgud02405vncq9gmthq3r8e3a6l3855r8jpkgjnfwjwuljn5a0p37d4yvxevnte42mffrpmf4823vcdq62xqm8xq3j",
        result_hex="0383c42aab7238d7aaafa32780151b5dc1119f31eebf13d2833c83644a69749dcfca74ebc31f36a461b2c9af3556d2918769a9d51661a0d28c",
        nano_nav_confirm=nav_review_2,
        nano_nav_show=nav_review_2,
    ),
    # LedgerJS: base address path/path multidelegation stake key unusual account
    DeriveAddressTestCase(
        name="Derive_address_shelley_fakenet_base_path_path_multidelegation_unusual_account",
        ledgerjs_name="base address path/path multidelegation stake key unusual account",
        netDesc=FakeNet,
        addrType=AddressType.BASE_PAYMENT_KEY_STAKE_KEY,
        spendingValue="m/1852'/1815'/0'/0/1",
        stakingValue="m/1852'/1815'/101'/2/60",
        result="addr1qdd9xypc9xnnstp2kas3r7mf7ylxn4sksfxxypvwgnc63vmugd5zn06wnjkd3e4gz260kt832axwmcruch85mkpqnv2qzt38al",
        result_hex="035a53103829a7382c2ab76111fb69f13e69d616824c62058e44f1a8b37c436829bf4e9cacd8e6a812b4fb2cf1574cede07cc5cf4dd8209b14",
        nano_nav_confirm=nav_review_2,
        nano_nav_show=nav_review_2,
    ),
    # LedgerJS: base address path/path multidelegation stake key unusual index
    DeriveAddressTestCase(
        name="Derive_address_shelley_fakenet_base_path_path_multidelegation_unusual_index",
        ledgerjs_name="base address path/path multidelegation stake key unusual index",
        netDesc=FakeNet,
        addrType=AddressType.BASE_PAYMENT_KEY_STAKE_KEY,
        spendingValue="m/1852'/1815'/0'/0/1",
        stakingValue="m/1852'/1815'/0'/2/1000001",
        result="addr1qdd9xypc9xnnstp2kas3r7mf7ylxn4sksfxxypvwgnc63v7z7lu6g8ncaa9ksx9q5lg2676a59a93y6fv86qzzdx4k5qjp9hw2",
        result_hex="035a53103829a7382c2ab76111fb69f13e69d616824c62058e44f1a8b3c2f7f9a41e78ef4b6818a0a7d0ad7b5da17a58934961f40109a6ada8",
        nano_nav_confirm=nav_review_2,
        nano_nav_show=nav_review_2,
    ),
    # LedgerJS: base address path/keyHash unusual account
    DeriveAddressTestCase(
        name="Derive_address_shelley_testnet_base_path_keyhash_unusual_account",
        ledgerjs_name="base address path/keyHash unusual account",
        netDesc=Testnet,
        addrType=AddressType.BASE_PAYMENT_KEY_STAKE_KEY,
        spendingValue="m/1852'/1815'/101'/0/1",
        stakingValue="1d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c",
        result="addr_test1qq6dcymepkghuyt0za9jxg5hn89art9y8yjcvhxclxdhndsayfawlf9hwv2fzuygt2km5v92kvf8e3s3mk7ynxw77cwq9n0t8l",
        result_hex="0034dc13790d917e116f174b23229799cbd1aca43925865cd8f99b79b61d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c",
        nano_nav_confirm=nav_review_2,
        nano_nav_show=nav_review_3,
    ),
    # LedgerJS: base address path/keyHash unusual address index
    DeriveAddressTestCase(
        name="Derive_address_shelley_testnet_base_path_keyhash_unusual_index",
        ledgerjs_name="base address path/keyHash unusual address index",
        netDesc=Testnet,
        addrType=AddressType.BASE_PAYMENT_KEY_STAKE_KEY,
        spendingValue="m/1852'/1815'/0'/0/1'",
        stakingValue="1d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c",
        result="addr_test1qppn39wu9az8zv5c6k59ke0j2udmjzy42uelpsjjcadf0fgayfawlf9hwv2fzuygt2km5v92kvf8e3s3mk7ynxw77cwqelwlvz",
        result_hex="00433895dc2f44713298d5a85b65f2571bb908955733f0c252c75a97a51d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c",
        nano_nav_confirm=nav_review_2,
        nano_nav_show=nav_review_3,
    ),
    # LedgerJS: base address scripthash/path unusual account
    DeriveAddressTestCase(
        name="Derive_address_shelley_testnet_base_scripthash_path_unusual_account",
        ledgerjs_name="base address scriptHash/path unusual account",
        netDesc=Testnet,
        addrType=AddressType.BASE_PAYMENT_SCRIPT_STAKE_KEY,
        spendingValue="122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277",
        stakingValue="m/1852'/1815'/200'/2/0",
        result="addr_test1zqfz49rtntfa9h0s98f6s28sg69weemgjhc4e8hm66d5yaad7dqp9clvjdu902n5app3d70rnkax3wjy8n78fz29uhfqzs7q26",
        result_hex="10122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277adf34012e3ec937857aa74e84316f9e39dba68ba443cfc748945e5d2",
        nano_nav_confirm=nav_review_2,
        nano_nav_show=nav_review_3,
    ),
    # LedgerJS: base address path/scriptHash unusual account
    DeriveAddressTestCase(
        name="Derive_address_shelley_testnet_base_path_scripthash_unusual_account",
        ledgerjs_name="base address path/scriptHash unusual account",
        netDesc=Testnet,
        addrType=AddressType.BASE_PAYMENT_KEY_STAKE_SCRIPT,
        spendingValue="m/1852'/1815'/101'/0/1",
        stakingValue="122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277",
        result="addr_test1yq6dcymepkghuyt0za9jxg5hn89art9y8yjcvhxclxdhndsj922xhxkn6twlq2wn4q50q352annk3903tj00h45mgfmsc0du6n",
        result_hex="2034dc13790d917e116f174b23229799cbd1aca43925865cd8f99b79b6122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277",
        nano_nav_confirm=nav_review_2,
        nano_nav_show=nav_review_3,
    ),
    # LedgerJS: base address path/scriptHash unusual address index
    DeriveAddressTestCase(
        name="Derive_address_shelley_testnet_base_path_scripthash_unusual_index",
        ledgerjs_name="base address path/scriptHash unusual address index",
        netDesc=Testnet,
        addrType=AddressType.BASE_PAYMENT_KEY_STAKE_SCRIPT,
        spendingValue="m/1852'/1815'/0'/0/1'",
        stakingValue="122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277",
        result="addr_test1yppn39wu9az8zv5c6k59ke0j2udmjzy42uelpsjjcadf0fgj922xhxkn6twlq2wn4q50q352annk3903tj00h45mgfmsyrvg3w",
        result_hex="20433895dc2f44713298d5a85b65f2571bb908955733f0c252c75a97a5122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277",
        nano_nav_confirm=nav_review_2,
        nano_nav_show=nav_review_3,
    ),
    # LedgerJS: pointer address unusual account
    DeriveAddressTestCase(
        name="Derive_address_shelley_testnet_pointer_unusual_account",
        ledgerjs_name="pointer address unusual account",
        netDesc=Testnet,
        addrType=AddressType.POINTER_KEY,
        spendingValue="m/1852'/1815'/1000'/0/1",
        stakingValue=pointer_to_str(1, 0, 0),
        result="addr_test1gq8vvh30wke6m5wl2xgwg5luus7zl0pr8kewjzq0wyyga6gpqqqqze3mqg",
        result_hex="400ec65e2f75b3add1df5190e453fce43c2fbc233db2e9080f71088ee9010000",
        nano_nav_confirm=nav_review_2,
        nano_nav_show=nav_review_3,
    ),
    # LedgerJS: pointer address unusual address index
    DeriveAddressTestCase(
        name="Derive_address_shelley_testnet_pointer_unusual_index",
        ledgerjs_name="pointer address unusual address index",
        netDesc=Testnet,
        addrType=AddressType.POINTER_KEY,
        spendingValue="m/1852'/1815'/0'/0/1'",
        stakingValue=pointer_to_str(0, 7, 0),
        result="addr_test1gppn39wu9az8zv5c6k59ke0j2udmjzy42uelpsjjcadf0fgqquqqpn6uug",
        result_hex="40433895dc2f44713298d5a85b65f2571bb908955733f0c252c75a97a5000700",
        nano_nav_confirm=nav_review_2,
        nano_nav_show=nav_review_2,
    ),
    DeriveAddressTestCase(
        name="Derive_address_shelley_testnet_reward_multidelegation_unusual_account",
        ledgerjs_name="reward multidelegation unusual account",
        netDesc=Testnet,
        addrType=AddressType.REWARD_KEY,
        spendingValue="",
        stakingValue="m/1852'/1815'/101'/2/1",
        result="stake_test1up0umv478zejdvynrddaddjzcztnmm2phsqs77cghyuah6qnjw5hh",
        result_hex="e05fcdb2be38b326b0931b5bd6b642c0973ded41bc010f7b08b939dbe8",
        nano_nav_confirm=nav_review_2,
        nano_nav_show=nav_review_2,
    ),
    DeriveAddressTestCase(
        name="Derive_address_shelley_testnet_reward_multidelegation_unusual_index",
        ledgerjs_name="reward multidelegation unusual index",
        netDesc=Testnet,
        addrType=AddressType.REWARD_KEY,
        spendingValue="",
        stakingValue="m/1852'/1815'/0'/2/20000000",
        nano_nav_confirm=nav_review_2,
        nano_nav_show=nav_review_2,
    ),
    # LedgerJS: reward path unusual account
    DeriveAddressTestCase(
        name="Derive_address_shelley_fakenet_reward_unusual_account",
        ledgerjs_name="reward path unusual account",
        netDesc=FakeNet,
        addrType=AddressType.REWARD_KEY,
        spendingValue="",
        stakingValue="m/1852'/1815'/300'/2/0",
        result="stake1u08h6dxajsaatnakylrd4pdhfrv7z3lkzgsq60fhvejux0gpcrd2j",
        result_hex="e3cf7d34dd943bd5cfb627c6da85b748d9e147f612200d3d376665c33d",
        nano_nav_confirm=nav_review_2,
        nano_nav_show=nav_review_2,
    ),
]
