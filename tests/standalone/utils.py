# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0

from pathlib import Path
from typing import List, Sequence, Tuple, Union
import re
import hashlib

from ecdsa.curves import Ed25519
from ecdsa.keys import VerifyingKey

from bip_utils import Bip44, Bip44Coins, Bip44Changes, Bip39SeedGenerator
from bip_utils.bip.bip32.bip32_path import Bip32Path, Bip32PathParser

from ragger.bip import calculate_public_key_and_chaincode, CurveChoice
from ragger.navigator import Navigator, NavInsID, NavIns
from ragger.navigator.navigation_scenario import NavigateWithScenario
from ledgered.devices import Device

from ragger.bip.seed import SPECULOS_MNEMONIC

from application_client.app_def import AddressType

from standalone.input_files.derive_address import DeriveAddressTestCase
from standalone.input_files.pubkey import PubKeyTestCase
from standalone.input_files.cvote import CVoteTestCase
from standalone.input_files.signOpCert import OpCertTestCase
from standalone.input_files.signMsg import SignMsgTestCase


ROOT_SCREENSHOT_PATH = Path(__file__).parent.resolve()


# Check if a signature of a given message is valid
def verify_name(name: str) -> None:
    """Verify the app name, based on defines in Makefile

    Args:
        name (str): Name to be checked
    """

    name_str = ""
    lines = _read_makefile()
    name_re = re.compile(r"^APPNAME\s?=\s?\"?(?P<val>[^\"]+)\"?", re.I)
    for line in lines:
        info = name_re.match(line)
        if info:
            dinfo = info.groupdict()
            name_str = dinfo["val"]
    assert name == name_str


def verify_version(version: str) -> None:
    """Verify the app version, based on defines in Makefile

    Args:
        Version (str): Version to be checked
    """

    vers_dict = {}
    vers_str = ""
    lines = _read_makefile()
    version_re = re.compile(r"^APPVERSION_(?P<part>\w)\s?=\s?(?P<val>\d*)", re.I)
    for line in lines:
        info = version_re.match(line)
        if info:
            dinfo = info.groupdict()
            vers_dict[dinfo["part"]] = dinfo["val"]
    try:
        vers_str = f"{vers_dict['M']}.{vers_dict['N']}.{vers_dict['P']}"
    except KeyError:
        pass
    assert version == vers_str


def _read_makefile() -> List[str]:
    """Read lines from the parent Makefile """

    parent = Path(__file__).parent.parent.parent.resolve()
    makefile = f"{parent}/Makefile"
    with open(makefile, "r", encoding="utf-8") as f_p:
        lines = f_p.readlines()
    return lines



def idTestFunc(testCase: Union[DeriveAddressTestCase, PubKeyTestCase, CVoteTestCase, OpCertTestCase, SignMsgTestCase]) -> str:
    """Retrieve the test case name for friendly display

    Args:
        testCase (xxxTestCase): Targeted test case

    Returns:
        Test case name
    """
    return testCase.name


def review_approve_with_warning(device: Device,
                                navigator: Navigator,
                                scenario_navigator: NavigateWithScenario,
                                test_name: str,
                                target_text: str,
                                warnings: Sequence[object],
                                do_comparison: bool = True,
                                warning_path: str = "warning",
                                warning_clicks: int = 3) -> None:
    if not device.is_nano:
        detail_navigation = [NavInsID.RIGHT_HEADER_TAP]
        if len(warnings) > 3:
            detail_navigation += [
                NavIns(NavInsID.CHOICE_CHOOSE, (4, )),
                NavInsID.LEFT_HEADER_TAP,
            ]
        detail_navigation += [NavInsID.LEFT_HEADER_TAP]

        if do_comparison:
            navigator.navigate_and_compare(
                scenario_navigator.screenshot_path,
                f"{test_name}/{warning_path}/details",
                detail_navigation,
            )
            navigator.navigate_and_compare(
                scenario_navigator.screenshot_path,
                f"{test_name}/{warning_path}",
                [NavInsID.USE_CASE_CHOICE_REJECT],
                screen_change_before_first_instruction=False,
                screen_change_after_last_instruction=False,
            )
            navigator.navigate_until_text_and_compare(
                navigate_instruction=NavInsID.USE_CASE_REVIEW_NEXT,
                validation_instructions=[
                    NavInsID.USE_CASE_REVIEW_CONFIRM,
                    NavInsID.USE_CASE_STATUS_DISMISS,
                ],
                text=r"^Hold to sign$",
                path=scenario_navigator.screenshot_path,
                test_case_name=test_name,
                screen_change_before_first_instruction=True,
            )
        else:
            navigator.navigate(detail_navigation)
            navigator.navigate(
                [NavInsID.USE_CASE_CHOICE_REJECT],
                screen_change_before_first_instruction=False,
                screen_change_after_last_instruction=False,
            )
            navigator.navigate_until_text(
                navigate_instruction=NavInsID.USE_CASE_REVIEW_NEXT,
                validation_instructions=[
                    NavInsID.USE_CASE_REVIEW_CONFIRM,
                    NavInsID.USE_CASE_STATUS_DISMISS,
                ],
                text=r"^Hold to sign$",
                screen_change_before_first_instruction=True,
            )
        return

    if do_comparison:
        navigator.navigate_and_compare(
            scenario_navigator.screenshot_path,
            f"{test_name}/{warning_path}",
            [NavInsID.RIGHT_CLICK] * warning_clicks,
            screen_change_after_last_instruction=False,
        )
        navigator.navigate_until_text_and_compare(
            navigate_instruction=NavInsID.RIGHT_CLICK,
            validation_instructions=[NavInsID.BOTH_CLICK],
            text=target_text,
            path=scenario_navigator.screenshot_path,
            test_case_name=test_name,
            screen_change_before_first_instruction=False,
        )
    else:
        navigator.navigate(
            [NavInsID.RIGHT_CLICK] * warning_clicks,
            screen_change_after_last_instruction=False,
        )
        navigator.navigate_until_text(
            navigate_instruction=NavInsID.RIGHT_CLICK,
            validation_instructions=[NavInsID.BOTH_CLICK],
            text=target_text,
            screen_change_before_first_instruction=False,
        )




def derive_address(testCase: DeriveAddressTestCase) -> Union[bytes, str]:
    """Derive an address from a test case

    Args:
        testCase (DeriveAddressTestCase): The test case

    Returns:
        The derived address
    """

    if testCase.addrType == AddressType.BYRON:
        return _deriveAddressByron(testCase)
    return _deriveAddressShelley(testCase)


def _deriveAddressByron(testCase: DeriveAddressTestCase) -> str:
    """Derive the Byron address from the path"""
    if testCase.result:
        return testCase.result
    # Generate seed from mnemonic
    # Use the deterministic Speculos mnemonic for reproducible tests.
    seed_bytes = Bip39SeedGenerator(SPECULOS_MNEMONIC).Generate()

    # Construct from seed
    bip44_mst_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.CARDANO_BYRON_LEDGER)

    # Derive the key for the specified path
    bip32Path: Bip32Path = Bip32PathParser.Parse(testCase.spendingValue).ToList()
    bip44_acc = bip44_mst_ctx.Purpose().Coin().Account(bip32Path[2])
    bip44_chg = bip44_acc.Change(Bip44Changes.CHAIN_EXT if bip32Path[3] == 0 else Bip44Changes.CHAIN_INT)
    bip44_addr = bip44_chg.AddressIndex(bip32Path[4])

    # Get the address
    return bip44_addr.PublicKey().ToAddress()


def _deriveAddressShelley(testCase: DeriveAddressTestCase) -> bytes:
    """Derive the Shelley base address from the path"""
    key = f"{(int(testCase.addrType) << 4) | int(testCase.netDesc.networkId):02x}"
    if testCase.spendingValue.startswith("m/"):
        pk, _ = get_device_pubkey(testCase.spendingValue)
        key += hashlib.blake2b(pk, digest_size=28).digest().hex()
    else:
        key += testCase.spendingValue
    if testCase.addrType in (AddressType.POINTER_KEY,
                             AddressType.POINTER_SCRIPT):
        key += _appenduint32(int(testCase.stakingValue[0:8], 16))
        key += _appenduint32(int(testCase.stakingValue[8:16], 16))
        key += _appenduint32(int(testCase.stakingValue[16:24], 16))
    elif testCase.stakingValue.startswith("m/"):
        pk, _ = get_device_pubkey(testCase.stakingValue)
        key += hashlib.blake2b(pk, digest_size=28).digest().hex()
    else:
        key += testCase.stakingValue
    return bytes.fromhex(key)


def _appenduint32(value: int) -> str:
    """Append a Variable Length uint32 to a buffer"""

    if value == 0:
        return "00"

    chunks: list[int] = []
    while value:
        chunks.append(value & 0x7F)
        value >>= 7

    result = ""
    while len(chunks) > 1:
        result += f"{chunks.pop() | 0x80:02x}"
    result += f"{chunks.pop():02x}"
    return result


def get_device_pubkey(path: str) -> Tuple[bytes, str]:
    """ Retrieve the Public Key

    Args:
        path (str): Derivation path

    Returns:
        The Reference PK and the byte Chain Code
    """
    ref_pk, ref_chain_code = calculate_public_key_and_chaincode(CurveChoice.Ed25519Kholaw, path)
    return bytes.fromhex(ref_pk[2:]), ref_chain_code


def verify_signature(path: str, signature: bytes, data: bytes) -> None:
    """Check the signature validity

    Args:
        path (str): The derivation path
        signature (bytes): The received signature
        data (bytes): The signed data
    """

    ref_pk, _ = get_device_pubkey(path)
    pk: VerifyingKey = VerifyingKey.from_string(ref_pk, curve=Ed25519)
    assert pk.verify(signature, data, hashlib.sha512)
