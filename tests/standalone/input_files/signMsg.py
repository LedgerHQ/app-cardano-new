# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2024 Ledger SAS
# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0

"""
This module provides Ragger tests for Sign Message
"""

from enum import IntEnum
from typing import List, Optional
from dataclasses import dataclass

from ragger.navigator import NavInsID

from standalone.input_files.derive_address import DeriveAddressTestCase
from application_client.app_def import AddressType, Mainnet
from application_client.status_words import StatusWord


class MessageAddressFieldType(IntEnum):
    ADDRESS = 0x01
    KEY_HASH = 0x02


@dataclass
class MessageData:
    """CIP-8 message signing"""

    messageHex: str
    signingPath: str
    hashPayload: bool
    isAscii: bool
    addressFieldType: MessageAddressFieldType
    addressDesc: Optional[DeriveAddressTestCase] = None


@dataclass
class NavigationData:
    init: List[NavInsID]
    chunk: List[NavInsID]
    confirm: List[NavInsID]


@dataclass
class SignMsgExpectedInUnitTest:
    signatureHex: str
    signingPublicKeyHex: str
    addressFieldHex: str


@dataclass(kw_only=True)
class SignMsgTestCase:
    name: str
    ledgerjs_name: Optional[str] = None
    msgData: Optional[MessageData] = None
    nav: Optional[NavigationData] = None
    expected_in_unit_test: Optional[SignMsgExpectedInUnitTest] = None
    has_warning: bool = False


@dataclass(kw_only=True)
class SignMsgDenyTestCase:
    name: str
    msgData: MessageData
    expected_status: StatusWord
    invalid_address_field_type: Optional[int] = None


def build_sign_msg_init_apdu_for_deny(test_case: SignMsgDenyTestCase) -> bytes:
    from application_client.command_builder import CommandBuilder

    transient_success_case = SignMsgTestCase(
        name=test_case.name,
        msgData=test_case.msgData,
    )
    init_apdu = bytearray(CommandBuilder().sign_msg_init(transient_success_case))

    if test_case.invalid_address_field_type is not None:
        # KEY_HASH has no trailing address params; addressFieldType is the last cdata byte.
        init_apdu[-1] = test_case.invalid_address_field_type

    return bytes(init_apdu)



# pylint: disable=line-too-long
signMsgTestCases = [
    SignMsgTestCase(
        name="Sign_msg_empty_message_with_keyhash_as_address_field",
        ledgerjs_name="msg01: Should correctly sign an empty message with keyhash as address field",
        msgData=MessageData(
            messageHex="",
            signingPath="m/1852'/1815'/0'/0/1",
            hashPayload=False,
            isAscii=False,
            addressFieldType=MessageAddressFieldType.KEY_HASH
        ),
        nav=NavigationData(
            init=[NavInsID.BOTH_CLICK] * 2 + [NavInsID.RIGHT_CLICK] + [NavInsID.BOTH_CLICK],
            chunk=[NavInsID.BOTH_CLICK],
            confirm=[NavInsID.BOTH_CLICK] * 2,
        ),
        expected_in_unit_test=SignMsgExpectedInUnitTest(
            signatureHex=(
                "4ac0d7422617cb794c166b7137a4f097d08bb01b58091ca8c6e0b3816288a286"
                "9c8121daddab958cdc58899cc6e1e564e36d35753f9e032f23df00b249149e06"
            ),
            signingPublicKeyHex="b3d5f4158f0c391ee2a28a2e285f218f3e895ff6ff59cb9369c64b03b5bab5eb",
            addressFieldHex="5a53103829a7382c2ab76111fb69f13e69d616824c62058e44f1a8b3",
        ),
    ),
    SignMsgTestCase(
        name="Sign_msg_short_nonhashed_ascii_message_with_keyhash_as_address_field",
        ledgerjs_name="msg02: Should correctly sign a short non-hashed ascii message with keyhash as address field",
        msgData=MessageData(
            messageHex="68656c6c6f20776f726c64",  # "hello world"
            signingPath="m/1852'/1815'/0'/0/1",
            hashPayload=False,
            isAscii=False,
            addressFieldType=MessageAddressFieldType.KEY_HASH,
        ),
        nav=NavigationData(
            init=[NavInsID.BOTH_CLICK] * 2 + [NavInsID.RIGHT_CLICK] + [NavInsID.BOTH_CLICK],
            chunk=[NavInsID.BOTH_CLICK] * 2,
            confirm=[NavInsID.RIGHT_CLICK] + [NavInsID.BOTH_CLICK] * 2,
        ),
        expected_in_unit_test=SignMsgExpectedInUnitTest(
            signatureHex=(
                "d1fc9388b6cc0d7e80f4f72267ef53caae6d53420997128004b6e44cc1618b90"
                "496f1f4bdb63dcf9d1311cf2633cfbb0ec759a715825c6d509154739beecb607"
            ),
            signingPublicKeyHex="b3d5f4158f0c391ee2a28a2e285f218f3e895ff6ff59cb9369c64b03b5bab5eb",
            addressFieldHex="5a53103829a7382c2ab76111fb69f13e69d616824c62058e44f1a8b3",
        ),
    ),
    SignMsgTestCase(
        name="Sign_msg_short_hashed_ascii_message_with_keyhash_as_address_field",
        ledgerjs_name="msg03: Should correctly sign a short hashed ascii message with keyhash as address field",
        msgData=MessageData(
            messageHex="68656c6c6f20776f726c64",  # "hello world"
            signingPath="m/1852'/1815'/0'/0/1",
            hashPayload=True,
            isAscii=False,
            addressFieldType=MessageAddressFieldType.KEY_HASH,
        ),
        nav=NavigationData(
            init=[NavInsID.BOTH_CLICK] * 2 + [NavInsID.RIGHT_CLICK] + [NavInsID.BOTH_CLICK],
            chunk=[NavInsID.BOTH_CLICK] * 2,
            confirm=[NavInsID.RIGHT_CLICK] + [NavInsID.BOTH_CLICK] * 2,
        ),
        expected_in_unit_test=SignMsgExpectedInUnitTest(
            signatureHex=(
                "8a77cbd7000ca92ac902b76822abfc502074151b183857afa179c043dacd1b92"
                "30c0daa55558e7e2d32e6c2f5a9c4d41ae13da90ce4e70637a5f80b841286a05"
            ),
            signingPublicKeyHex="b3d5f4158f0c391ee2a28a2e285f218f3e895ff6ff59cb9369c64b03b5bab5eb",
            addressFieldHex="5a53103829a7382c2ab76111fb69f13e69d616824c62058e44f1a8b3",
        ),
    ),
    SignMsgTestCase(
        name="Sign_msg_short_nonhashed_ascii_message_displayed_as_hex",
        ledgerjs_name="msg04: Should correctly sign a short non-hashed ascii message displayed as hex",
        msgData=MessageData(
            messageHex="68656c6c6f20776f726c64",  # "hello world"
            signingPath="m/1852'/1815'/0'/4/0",
            hashPayload=False,
            isAscii=False,
            addressFieldType=MessageAddressFieldType.KEY_HASH,
        ),
        nav=NavigationData(
            init=[NavInsID.BOTH_CLICK] * 3,
            chunk=[NavInsID.BOTH_CLICK] * 2,
            confirm=[NavInsID.RIGHT_CLICK] + [NavInsID.BOTH_CLICK] * 2,
        ),
        expected_in_unit_test=SignMsgExpectedInUnitTest(
            signatureHex=(
                "30ac6ab7f4ddc7779701324b163c52c68d4c0fd4af968122f1b43eea49b9586b"
                "366567395833ffb863ba1054863ab7191d09bdc5781f668db5c30b982fd37e07"
            ),
            signingPublicKeyHex="bc8c8a37d6ab41339bb073e72ce2e776cefed98d1a6d070ea5fada80dc7d6737",
            addressFieldHex="cf737588be6e9edeb737eb2e6d06e5cbd292bd8ee32e410c0bba1ba6",
        ),
    ),
    SignMsgTestCase(
        name="Sign_msg_short_nonhashed_hex_message_with_keyhash_as_address_field",
        ledgerjs_name="msg05: Should correctly sign a short non-hashed hex message with keyhash as address field",
        msgData=MessageData(
            messageHex="ff656c6c6f20776f726c64",
            signingPath="m/1853'/1815'/0'/0'",
            hashPayload=False,
            isAscii=False,
            addressFieldType=MessageAddressFieldType.KEY_HASH,
        ),
        nav=NavigationData(
            init=[NavInsID.BOTH_CLICK] * 2 + [NavInsID.RIGHT_CLICK] + [NavInsID.BOTH_CLICK],
            chunk=[NavInsID.BOTH_CLICK] * 2,
            confirm=[NavInsID.RIGHT_CLICK] + [NavInsID.BOTH_CLICK] * 2,
        ),
        expected_in_unit_test=SignMsgExpectedInUnitTest(
            signatureHex=(
                "3dcc9abb30584a15fd9ce39f790662a80331243d9f2978eca8549fba99740a89"
                "80c4bba73e6fc1cc1eee466e303c91542a13b9ee330c1c708cd04f9b093da403"
            ),
            signingPublicKeyHex="3d7e84dca8b4bc322401a2cc814af7c84d2992a22f99554fe340d7df7910768d",
            addressFieldHex="dbfee4665e58c8f8e9b9ff02b17f32e08a42c855476a5d867c2737b7",
        ),
    ),
    SignMsgTestCase(
        name="Sign_msg_short_hashed_hex_message_with_keyhash_as_address_field",
        ledgerjs_name="msg06: Should correctly sign a short hashed hex message with keyhash as address field",
        msgData=MessageData(
            messageHex="ff656c6c6f20776f726c64",
            signingPath="m/1853'/1815'/0'/0'",
            hashPayload=True,
            isAscii=False,
            addressFieldType=MessageAddressFieldType.KEY_HASH,
        ),
        nav=NavigationData(
            init=[NavInsID.BOTH_CLICK] * 2 + [NavInsID.RIGHT_CLICK] + [NavInsID.BOTH_CLICK],
            chunk=[NavInsID.BOTH_CLICK] * 2,
            confirm=[NavInsID.RIGHT_CLICK] + [NavInsID.BOTH_CLICK] * 2,
        ),
        expected_in_unit_test=SignMsgExpectedInUnitTest(
            signatureHex=(
                "0cd0dea4600a2eda7ab145bf600ca252d4a5911959a56fe0294e48e71a249db6"
                "e95ded5228e76c97b0add2aa1a8dfc0aed65acd46fc71ac0e99d4b917b1b870d"
            ),
            signingPublicKeyHex="3d7e84dca8b4bc322401a2cc814af7c84d2992a22f99554fe340d7df7910768d",
            addressFieldHex="dbfee4665e58c8f8e9b9ff02b17f32e08a42c855476a5d867c2737b7",
        ),
    ),
    SignMsgTestCase(
        name="Sign_msg_198_bytes_long_nonhashed_ascii_message_with_keyhash_as_address_field",
        ledgerjs_name="msg07: Should correctly sign a 198 bytes long non-hashed ascii message with keyhash as address field",
        msgData=MessageData(
            messageHex=f"{'6869' * 99}",
            signingPath="m/1852'/1815'/0'/3/0",
            hashPayload=True,
            isAscii=True,
            addressFieldType=MessageAddressFieldType.KEY_HASH,
        ),
        nav=NavigationData(
            init=[NavInsID.BOTH_CLICK] * 3,
            chunk=[NavInsID.BOTH_CLICK] + [NavInsID.RIGHT_CLICK] * 2 + [NavInsID.BOTH_CLICK],
            confirm=[NavInsID.RIGHT_CLICK] + [NavInsID.BOTH_CLICK] * 2,
        ),
        expected_in_unit_test=SignMsgExpectedInUnitTest(
            signatureHex=(
                "6659bb68075cbb5d5b5ab0c6290f87931f8c0dddd4b6bea2ecbdb9b8519109a3"
                "89f0408eeb917894c15db16019052f26da540fd29752d0f61285f78299770805"
            ),
            signingPublicKeyHex="7cc18df2fbd3ee1b16b76843b18446679ab95dbcd07b7833b66a9407c0709e37",
            addressFieldHex="ba41c59ac6e1a0e4ac304af98db801097d0bf8d2a5b28a54752426a1",
        ),
    ),
    SignMsgTestCase(
        name="Sign_msg_99_bytes_long_nonhashed_hex_message_with_keyhash_as_address_field",
        ledgerjs_name="msg08: Should correctly sign a 99 bytes long non-hashed hex message with keyhash as address field",
        msgData=MessageData(
            messageHex=f"{'de' * 99}",
            signingPath="m/1852'/1815'/0'/3/0",
            hashPayload=True,
            isAscii=False,
            addressFieldType=MessageAddressFieldType.KEY_HASH,
        ),
        nav=NavigationData(
            init=[NavInsID.BOTH_CLICK] * 3,
            chunk=[NavInsID.BOTH_CLICK] + [NavInsID.RIGHT_CLICK] * 3 + [NavInsID.BOTH_CLICK],
            confirm=[NavInsID.RIGHT_CLICK] + [NavInsID.BOTH_CLICK] * 2,
        ),
        expected_in_unit_test=SignMsgExpectedInUnitTest(
            signatureHex=(
                "4fadaf3541df071455d13d99da061b7b5056f19f88051c99ff59e7902ff15389"
                "eca1614c6e0faf9c29131c086b8fbb16d87e7ec7d19936c898fcbfdfb5d93602"
            ),
            signingPublicKeyHex="7cc18df2fbd3ee1b16b76843b18446679ab95dbcd07b7833b66a9407c0709e37",
            addressFieldHex="ba41c59ac6e1a0e4ac304af98db801097d0bf8d2a5b28a54752426a1",
        ),
    ),
    SignMsgTestCase(
        name="Sign_msg_1000_bytes_long_hashed_ascii_message_with_keyhash_as_address_field",
        ledgerjs_name="msg09: Should correctly sign a 1000 bytes long hashed ascii message with keyhash as address field",
        msgData=MessageData(
            messageHex=f"{'6869' * 500}",
            signingPath="m/1852'/1815'/0'/3/0",
            hashPayload=True,
            isAscii=True,
            addressFieldType=MessageAddressFieldType.KEY_HASH,
        ),
        nav=NavigationData(
            init=[NavInsID.BOTH_CLICK] * 3,
            chunk=[NavInsID.BOTH_CLICK] + [NavInsID.RIGHT_CLICK] * 2 + [NavInsID.BOTH_CLICK],
            confirm=[NavInsID.RIGHT_CLICK] + [NavInsID.BOTH_CLICK] * 2,
        ),
        expected_in_unit_test=SignMsgExpectedInUnitTest(
            signatureHex=(
                "87be8e7be2407ecb8324adb40d63cb4e7126378d0fa87f13e09226da896e1111"
                "5b15275368ede14cdb42ea13b076dadc7f0eccf49d745312e2366cfb5105b906"
            ),
            signingPublicKeyHex="7cc18df2fbd3ee1b16b76843b18446679ab95dbcd07b7833b66a9407c0709e37",
            addressFieldHex="ba41c59ac6e1a0e4ac304af98db801097d0bf8d2a5b28a54752426a1",
        ),
    ),
    SignMsgTestCase(
        name="Sign_msg_349_bytes_long_hashed_hex_message_with_keyhash_as_address_field",
        ledgerjs_name="msg10: Should correctly sign a 349 bytes long hashed hex message with keyhash as address field",
        msgData=MessageData(
            messageHex=f"{'fa' * 349}",
            signingPath="m/1852'/1815'/0'/3/0",
            hashPayload=True,
            isAscii=False,
            addressFieldType=MessageAddressFieldType.KEY_HASH,
        ),
        nav=NavigationData(
            init=[NavInsID.BOTH_CLICK] * 3,
            chunk=[NavInsID.BOTH_CLICK] + [NavInsID.RIGHT_CLICK] * 3 + [NavInsID.BOTH_CLICK],
            confirm=[NavInsID.RIGHT_CLICK] + [NavInsID.BOTH_CLICK] * 2,
        ),
        expected_in_unit_test=SignMsgExpectedInUnitTest(
            signatureHex=(
                "6fcc42c954ecaa143c8fab436a5cc1d0beb4f46c29c7e554d3593d5c4343b27e"
                "83a66b3df011c3197e88032a2e879730c67db71ed0f2d9cd3e9a0978990d3a02"
            ),
            signingPublicKeyHex="7cc18df2fbd3ee1b16b76843b18446679ab95dbcd07b7833b66a9407c0709e37",
            addressFieldHex="ba41c59ac6e1a0e4ac304af98db801097d0bf8d2a5b28a54752426a1",
        ),
    ),
    SignMsgTestCase(
        name="Sign_msg_short_nonhashed_hex_message_with_base_address_in_address_field",
        ledgerjs_name="msg11: Should correctly sign a short non-hashed hex message with base address in address field",
        msgData=MessageData(
            messageHex="deadbeef",
            signingPath="m/1852'/1815'/0'/5/0",
            hashPayload=False,
            isAscii=False,
            addressFieldType=MessageAddressFieldType.ADDRESS,
            addressDesc=DeriveAddressTestCase(
                name="",
                ledgerjs_name=None,
                netDesc=Mainnet,
                addrType=AddressType.BASE_PAYMENT_KEY_STAKE_KEY,
                spendingValue="m/1852'/1815'/0'/0/1",
                stakingValue="m/1852'/1815'/0'/2/0",
            ),
        ),
        nav=NavigationData(
            init=[NavInsID.BOTH_CLICK] * 2 + [NavInsID.RIGHT_CLICK] + [NavInsID.BOTH_CLICK],
            chunk=[NavInsID.BOTH_CLICK] * 2,
            confirm=[NavInsID.RIGHT_CLICK] + [NavInsID.BOTH_CLICK] * 2,
        ),
        expected_in_unit_test=SignMsgExpectedInUnitTest(
            signatureHex=(
                "92586e24a1a43b538720ea3915be0f6536f0894e4ea88713c01f948673865b6d"
                "2189a0306bbefc124954e578f8aa1d0f131b1d3e7af7827d1b4488d6fa0f6b07"
            ),
            signingPublicKeyHex="650eb87ddfffe7babd505f2d66c2db28b1c05ac54f9121589107acd6eb20cc2c",
            addressFieldHex=(
                "015a53103829a7382c2ab76111fb69f13e69d616824c62058e44f1a8b31d227a"
                "efa4b773149170885aadba30aab3127cc611ddbc4999def61c"
            ),
        ),
    ),
    SignMsgTestCase(
        name="Sign_msg_short_nonhashed_hex_message_with_reward_address_in_address_field",
        ledgerjs_name="msg12: Should correctly sign a short non-hashed hex message with reward address in address field",
        msgData=MessageData(
            messageHex="deadbeef",
            signingPath="m/1852'/1815'/0'/5/0",
            hashPayload=False,
            isAscii=False,
            addressFieldType=MessageAddressFieldType.ADDRESS,
            addressDesc=DeriveAddressTestCase(
                name="",
                ledgerjs_name=None,
                netDesc=Mainnet,
                addrType=AddressType.REWARD_KEY,
                spendingValue="",
                stakingValue="m/1852'/1815'/0'/2/0"
            ),
        ),
        nav=NavigationData(
            init=[NavInsID.BOTH_CLICK] * 2 + [NavInsID.RIGHT_CLICK] + [NavInsID.BOTH_CLICK],
            chunk=[NavInsID.BOTH_CLICK] * 2,
            confirm=[NavInsID.RIGHT_CLICK] + [NavInsID.BOTH_CLICK] * 2,
        ),
        expected_in_unit_test=SignMsgExpectedInUnitTest(
            signatureHex=(
                "95044039aafdfedbd7a16b323475076e4960b78eb8e1864671f05e822ec975c2"
                "19163ae7830103825777abe6e1bf854a302a96538ed129ff6131e29e8562b003"
            ),
            signingPublicKeyHex="650eb87ddfffe7babd505f2d66c2db28b1c05ac54f9121589107acd6eb20cc2c",
            addressFieldHex="e11d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c",
        ),
    ),
    # --- Long non-hashed messages (multi-chunk, tests dynamic allocation) ---
    SignMsgTestCase(
        name="Sign_msg_257_bytes_long_nonhashed_ascii_message_with_keyhash_as_address_field",
        msgData=MessageData(
            messageHex=("68" * 257),  # 257 bytes of 'h' — not a multiple of 250
            signingPath="m/1852'/1815'/0'/3/0",
            hashPayload=False,
            isAscii=True,
            addressFieldType=MessageAddressFieldType.KEY_HASH,
        ),
    ),
    SignMsgTestCase(
        name="Sign_msg_1000_bytes_long_nonhashed_ascii_message_with_keyhash_as_address_field",
        msgData=MessageData(
            messageHex=("6869" * 500),  # 1000 bytes of "hi" repeated
            signingPath="m/1852'/1815'/0'/3/0",
            hashPayload=False,
            isAscii=True,
            addressFieldType=MessageAddressFieldType.KEY_HASH,
        ),
    ),
    SignMsgTestCase(
        name="Sign_msg_257_bytes_long_nonhashed_hex_message_with_keyhash_as_address_field",
        msgData=MessageData(
            messageHex=("de" * 257),  # 257 bytes of 0xDE — not a multiple of 250
            signingPath="m/1852'/1815'/0'/3/0",
            hashPayload=False,
            isAscii=False,
            addressFieldType=MessageAddressFieldType.KEY_HASH,
        ),
    ),
    SignMsgTestCase(
        name="Sign_msg_1000_bytes_long_nonhashed_hex_message_with_keyhash_as_address_field",
        msgData=MessageData(
            messageHex=("fa" * 1000),  # 1000 bytes of 0xFA
            signingPath="m/1852'/1815'/0'/3/0",
            hashPayload=False,
            isAscii=False,
            addressFieldType=MessageAddressFieldType.KEY_HASH,
        ),
    ),
    # --- Test with unusual BIP44 path (WARNING_BIT_UNUSUAL_KEY_DERIVATION_PATH) ---
    SignMsgTestCase(
        name="Sign_msg_unusual_path_with_high_address_index",
        ledgerjs_name="msg13: Should correctly sign a message with unusual high address index and show warning",
        msgData=MessageData(
            messageHex="deadbeef",
            signingPath="m/1852'/1815'/0'/0/1000001",  # Address index > MAX_REASONABLE_ADDRESS (1000000)
            hashPayload=False,
            isAscii=False,
            addressFieldType=MessageAddressFieldType.KEY_HASH,
        ),
        has_warning=True,
    ),
]


signMsgDenyTestCases = [
    SignMsgDenyTestCase(
        name="Sign_msg_reject_nonexistent_address_field_type",
        msgData=MessageData(
            messageHex="deadbeef",
            signingPath="m/1852'/1815'/0'/0/1",
            hashPayload=False,
            isAscii=False,
            addressFieldType=MessageAddressFieldType.KEY_HASH,
        ),
        invalid_address_field_type=0x03,
        expected_status=StatusWord.SWO_SIGN_MSG_INVALID_ADDRESS_FIELD_TYPE,
    ),
]
