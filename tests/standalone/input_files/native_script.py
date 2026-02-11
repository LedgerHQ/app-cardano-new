# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2024 Ledger SAS
# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0

"""
This module provides Ragger tests for Derive Native Script Hash check
"""

from __future__ import annotations
from enum import IntEnum
from typing import List, Optional, Union
from dataclasses import dataclass, field

from application_client.status_words import StatusWord


class NativeScriptType(IntEnum):
    PUBKEY_DEVICE_OWNED = 0x00
    PUBKEY_THIRD_PARTY = 0xF0
    ALL = 0x01
    ANY = 0x02
    N_OF_K = 0x03
    INVALID_BEFORE = 0x04
    INVALID_HEREAFTER = 0x05


class NativeScriptHashDisplayFormat(IntEnum):
    BECH32 = 0x01
    POLICY_ID = 0x02


@dataclass
class NativeScript:
    type: NativeScriptType
    params: NativeScriptParams


@dataclass
class NativeScriptParamsPubkey:
    key: str


@dataclass
class NativeScriptParamsScripts:
    scripts: List[NativeScript] = field(default_factory=list)


@dataclass
class NativeScriptParamsNofK:
    requiredCount: int
    scripts: List[NativeScript] = field(default_factory=list)


@dataclass
class NativeScriptParamsInvalid:
    slot: int


NativeScriptParams = Union[
    NativeScriptParamsPubkey,
    NativeScriptParamsScripts,
    NativeScriptParamsNofK,
    NativeScriptParamsInvalid,
]


@dataclass
class SignedData:
    hash: Optional[str] = None
    sw: Optional[StatusWord] = StatusWord.SWO_SUCCESS


@dataclass(kw_only=True)
class ValidNativeScriptTestCase:
    name: str
    ledgerjs_name: Optional[str] = None
    script: Optional[NativeScript] = None
    expected_in_unit_test: Optional[SignedData] = None
    displayFormat: Optional[NativeScriptHashDisplayFormat] = (
        NativeScriptHashDisplayFormat.BECH32
    )
    nano_skip: Optional[bool] = False
    skip_expected_in_ragger: bool = False



# pylint: disable=line-too-long
ValidNativeScriptTestCases = [
    ValidNativeScriptTestCase(
        name="Native_script_PUBKEY_device_owned",
        ledgerjs_name="PUBKEY - device owned",
        script=NativeScript(
            NativeScriptType.PUBKEY_DEVICE_OWNED,
            NativeScriptParamsPubkey("m/1852'/1815'/0'/0/0"),
        ),
        expected_in_unit_test=SignedData("5102a193b3d5f0c256fcc425836ffb15e7d96d3389f5e57dc6bea726"),
        skip_expected_in_ragger=True,
    ),
    ValidNativeScriptTestCase(
        name="Native_script_PUBKEY_third_party",
        ledgerjs_name="PUBKEY - third party",
        script=NativeScript(
            NativeScriptType.PUBKEY_THIRD_PARTY,
            NativeScriptParamsPubkey(
                "3a55d9f68255dfbefa1efd711f82d005fae1be2e145d616c90cf0fa9"
            ),
        ),
        expected_in_unit_test=SignedData("855228f5ecececf9c85618007cc3c2e5bdf5e6d41ef8d6fa793fe0eb"),
    ),
    ValidNativeScriptTestCase(
        name="Native_script_PUBKEY_third_party_script_hash_displayed_as_policy_id",
        ledgerjs_name="PUBKEY - third party (script hash displayed as policy id)",
        script=NativeScript(
            NativeScriptType.PUBKEY_THIRD_PARTY,
            NativeScriptParamsPubkey(
                "3a55d9f68255dfbefa1efd711f82d005fae1be2e145d616c90cf0fa9"
            ),
        ),
        expected_in_unit_test=SignedData("855228f5ecececf9c85618007cc3c2e5bdf5e6d41ef8d6fa793fe0eb"),
        displayFormat=NativeScriptHashDisplayFormat.POLICY_ID,
    ),
    ValidNativeScriptTestCase(
        name="Native_script_ALL_script",
        ledgerjs_name="ALL script",
        script=NativeScript(
            NativeScriptType.ALL,
            NativeScriptParamsScripts(
                [
                    NativeScript(
                        NativeScriptType.PUBKEY_THIRD_PARTY,
                        NativeScriptParamsPubkey(
                            "c4b9265645fde9536c0795adbcc5291767a0c61fd62448341d7e0386"
                        ),
                    ),
                    NativeScript(
                        NativeScriptType.PUBKEY_THIRD_PARTY,
                        NativeScriptParamsPubkey(
                            "0241f2d196f52a92fbd2183d03b370c30b6960cfdeae364ffabac889"
                        ),
                    ),
                ]
            ),
        ),
        expected_in_unit_test=SignedData("af5c2ce476a6ede1c879f7b1909d6a0b96cb2081391712d4a355cef6"),
    ),
    ValidNativeScriptTestCase(
        name="Native_script_ALL_script_no_subscripts",
        ledgerjs_name="ALL script (no subscripts)",
        script=NativeScript(NativeScriptType.ALL, NativeScriptParamsScripts()),
        expected_in_unit_test=SignedData("d441227553a0f1a965fee7d60a0f724b368dd1bddbc208730fccebcf"),
    ),
    ValidNativeScriptTestCase(
        name="Native_script_ANY_script",
        ledgerjs_name="ANY script",
        script=NativeScript(
            NativeScriptType.ANY,
            NativeScriptParamsScripts(
                [
                    NativeScript(
                        NativeScriptType.PUBKEY_THIRD_PARTY,
                        NativeScriptParamsPubkey(
                            "c4b9265645fde9536c0795adbcc5291767a0c61fd62448341d7e0386"
                        ),
                    ),
                    NativeScript(
                        NativeScriptType.PUBKEY_THIRD_PARTY,
                        NativeScriptParamsPubkey(
                            "0241f2d196f52a92fbd2183d03b370c30b6960cfdeae364ffabac889"
                        ),
                    ),
                ]
            ),
        ),
        expected_in_unit_test=SignedData("d6428ec36719146b7b5fb3a2d5322ce702d32762b8c7eeeb797a20db"),
    ),
    ValidNativeScriptTestCase(
        name="Native_script_ANY_script_no_subscripts",
        ledgerjs_name="ANY script (no subscripts)",
        script=NativeScript(NativeScriptType.ANY, NativeScriptParamsScripts()),
        expected_in_unit_test=SignedData("52dc3d43b6d2465e96109ce75ab61abe5e9c1d8a3c9ce6ff8a3af528"),
    ),
    ValidNativeScriptTestCase(
        name="Native_script_N_OF_K_script",
        ledgerjs_name="N_OF_K script",
        script=NativeScript(
            NativeScriptType.N_OF_K,
            NativeScriptParamsNofK(
                2,
                [
                    NativeScript(
                        NativeScriptType.PUBKEY_THIRD_PARTY,
                        NativeScriptParamsPubkey(
                            "c4b9265645fde9536c0795adbcc5291767a0c61fd62448341d7e0386"
                        ),
                    ),
                    NativeScript(
                        NativeScriptType.PUBKEY_THIRD_PARTY,
                        NativeScriptParamsPubkey(
                            "0241f2d196f52a92fbd2183d03b370c30b6960cfdeae364ffabac889"
                        ),
                    ),
                ],
            ),
        ),
        expected_in_unit_test=SignedData("78963f8baf8e6c99ed03e59763b24cf560bf12934ec3793eba83377b"),
    ),
    ValidNativeScriptTestCase(
        name="Native_script_N_OF_K_script_no_subscripts",
        ledgerjs_name="N_OF_K script (no subscripts)",
        script=NativeScript(NativeScriptType.N_OF_K, NativeScriptParamsNofK(0)),
        expected_in_unit_test=SignedData("3530cc9ae7f2895111a99b7a02184dd7c0cea7424f1632d73951b1d7"),
    ),
    ValidNativeScriptTestCase(
        name="Native_script_INVALID_BEFORE_script",
        ledgerjs_name="INVALID_BEFORE script",
        script=NativeScript(NativeScriptType.INVALID_BEFORE, NativeScriptParamsInvalid(42)),
        expected_in_unit_test=SignedData("2a25e608a683057e32ea38b50ce8875d5b34496b393da8d25d314c4e"),
    ),
    ValidNativeScriptTestCase(
        name="Native_script_INVALID_BEFORE_script_slot_is_a_big_number",
        ledgerjs_name="INVALID_BEFORE script (slot is a big number)",
        script=NativeScript(
            NativeScriptType.INVALID_BEFORE,
            NativeScriptParamsInvalid(18446744073709551615),
        ),
        expected_in_unit_test=SignedData("d2469adac494849dd27d1b344b74cc6cd5bf31fbd01c879eae84c04b"),
    ),
    ValidNativeScriptTestCase(
        name="Native_script_INVALID_HEREAFTER_script",
        ledgerjs_name="INVALID_HEREAFTER script",
        script=NativeScript(NativeScriptType.INVALID_HEREAFTER, NativeScriptParamsInvalid(42)),
        expected_in_unit_test=SignedData("1620dc65993296335183f23ff2f7747268168fabbeecbf24c8a20194"),
    ),
    ValidNativeScriptTestCase(
        name="Native_script_INVALID_HEREAFTER_script_slot_is_a_big_number",
        ledgerjs_name="INVALID_HEREAFTER script (slot is a big number)",
        script=NativeScript(
            NativeScriptType.INVALID_HEREAFTER,
            NativeScriptParamsInvalid(18446744073709551615),
        ),
        expected_in_unit_test=SignedData("da60fa40290f93b889a88750eb141fd2275e67a1255efb9bac251005"),
    ),
    ValidNativeScriptTestCase(
        name="Native_script_Nested_native_scripts",
        ledgerjs_name="Nested native scripts",
        script=NativeScript(
            NativeScriptType.ALL,
            NativeScriptParamsScripts(
                [
                    NativeScript(
                        NativeScriptType.PUBKEY_THIRD_PARTY,
                        NativeScriptParamsPubkey(
                            "c4b9265645fde9536c0795adbcc5291767a0c61fd62448341d7e0386"
                        ),
                    ),
                    NativeScript(
                        NativeScriptType.ANY,
                        NativeScriptParamsScripts(
                            [
                                NativeScript(
                                    NativeScriptType.PUBKEY_THIRD_PARTY,
                                    NativeScriptParamsPubkey(
                                        "c4b9265645fde9536c0795adbcc5291767a0c61fd62448341d7e0386"
                                    ),
                                ),
                                NativeScript(
                                    NativeScriptType.PUBKEY_THIRD_PARTY,
                                    NativeScriptParamsPubkey(
                                        "0241f2d196f52a92fbd2183d03b370c30b6960cfdeae364ffabac889"
                                    ),
                                ),
                            ]
                        ),
                    ),
                    NativeScript(
                        NativeScriptType.N_OF_K,
                        NativeScriptParamsNofK(
                            2,
                            [
                                NativeScript(
                                    NativeScriptType.PUBKEY_THIRD_PARTY,
                                    NativeScriptParamsPubkey(
                                        "c4b9265645fde9536c0795adbcc5291767a0c61fd62448341d7e0386"
                                    ),
                                ),
                                NativeScript(
                                    NativeScriptType.PUBKEY_THIRD_PARTY,
                                    NativeScriptParamsPubkey(
                                        "0241f2d196f52a92fbd2183d03b370c30b6960cfdeae364ffabac889"
                                    ),
                                ),
                                NativeScript(
                                    NativeScriptType.PUBKEY_THIRD_PARTY,
                                    NativeScriptParamsPubkey(
                                        "cecb1d427c4ae436d28cc0f8ae9bb37501a5b77bcc64cd1693e9ae20"
                                    ),
                                ),
                            ],
                        ),
                    ),
                    NativeScript(
                        NativeScriptType.INVALID_BEFORE, NativeScriptParamsInvalid(100)
                    ),
                    NativeScript(
                        NativeScriptType.INVALID_HEREAFTER,
                        NativeScriptParamsInvalid(200),
                    ),
                ]
            ),
        ),
        expected_in_unit_test=SignedData("0d63e8d2c5a00cbcffbdf9112487c443466e1ea7d8c834df5ac5c425"),
        nano_skip=True,
    ),
    ValidNativeScriptTestCase(
        name="Native_script_Nested native scripts #2",
        ledgerjs_name="Native_script_Nested native scripts #2",
        script=NativeScript(
            NativeScriptType.ALL,
            NativeScriptParamsScripts(
                [
                    NativeScript(
                        NativeScriptType.ANY,
                        NativeScriptParamsScripts(
                            [
                                NativeScript(
                                    NativeScriptType.PUBKEY_THIRD_PARTY,
                                    NativeScriptParamsPubkey(
                                        "c4b9265645fde9536c0795adbcc5291767a0c61fd62448341d7e0386"
                                    ),
                                ),
                                NativeScript(
                                    NativeScriptType.PUBKEY_THIRD_PARTY,
                                    NativeScriptParamsPubkey(
                                        "0241f2d196f52a92fbd2183d03b370c30b6960cfdeae364ffabac889"
                                    ),
                                ),
                            ]
                        ),
                    )
                ]
            ),
        ),
        expected_in_unit_test=SignedData("903e52ef2421abb11562329130330763583bb87cd98006b70ecb1b1c"),
        nano_skip=True,
    ),
    ValidNativeScriptTestCase(
        name="Native_script_Nested native scripts #3",
        ledgerjs_name="Native_script_Nested native scripts #3",
        script=NativeScript(
            NativeScriptType.N_OF_K,
            NativeScriptParamsNofK(
                0,
                [
                    NativeScript(
                        NativeScriptType.ALL,
                        NativeScriptParamsScripts(
                            [
                                NativeScript(
                                    NativeScriptType.ANY,
                                    NativeScriptParamsScripts(
                                        [
                                            NativeScript(
                                                NativeScriptType.N_OF_K,
                                                NativeScriptParamsNofK(0),
                                            )
                                        ]
                                    ),
                                )
                            ]
                        ),
                    )
                ],
            ),
        ),
        expected_in_unit_test=SignedData("ed1dd7ef95caf389669c62618eb7f7aa7eadd08feb76618db2ae0cfc"),
        nano_skip=True,
    ),
]


InvalidScriptTestCases = [
    ValidNativeScriptTestCase(
        name="Native_script_PUBKEY invalid key path",
        ledgerjs_name=None,
        script=NativeScript(
            NativeScriptType.PUBKEY_DEVICE_OWNED,
            NativeScriptParamsPubkey("m/0/0/0/0/0/0"),
        ),
        expected_in_unit_test=SignedData(sw=StatusWord.SWO_NATIVE_SCRIPT_PARSING_FAIL_PUBKEY_CREDENTIAL),
    ),
    ValidNativeScriptTestCase(
        name="Native_script_N_OF_K invalid required count higher than number of scripts",
        ledgerjs_name=None,
        script=NativeScript(NativeScriptType.N_OF_K, NativeScriptParamsNofK(1)),
        expected_in_unit_test=SignedData(sw=StatusWord.SWO_NATIVE_SCRIPT_PARSING_FAIL_SCRIPT_COUNT),
    ),
]
