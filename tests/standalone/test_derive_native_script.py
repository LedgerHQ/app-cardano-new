# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2024 Ledger SAS
# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0

"""
This module provides Ragger tests for Derive Native Script Hash check
"""

import hashlib

import cbor2  # type: ignore
import pytest

from ragger.backend import BackendInterface
from ledgered.devices import Device
from ragger.navigator import Navigator, NavInsID
from ragger.navigator.navigation_scenario import NavigateWithScenario

from application_client.status_words import StatusWord
from application_client.command_sender import CommandSender
from application_client.response_unpacker import unpack_derive_native_script_hash_response

from standalone.input_files.native_script import ValidNativeScriptTestCases, ValidNativeScriptTestCase
from standalone.input_files.native_script import NativeScript, NativeScriptType
from standalone.input_files.native_script import NativeScriptParamsScripts, NativeScriptParamsNofK

from standalone.utils import idTestFunc, get_device_pubkey


def _resolve_key_hash(script: NativeScript) -> bytes:
    """Resolve a PUBKEY script to its 28-byte key hash.

    PUBKEY_THIRD_PARTY: the key field is already a hex-encoded key hash.
    PUBKEY_DEVICE_OWNED: the key field is a BIP44 derivation path; derive
    the public key from the device mnemonic and blake2b-224 it.
    """
    if script.type == NativeScriptType.PUBKEY_THIRD_PARTY:
        return bytes.fromhex(script.params.key)

    # PUBKEY_DEVICE_OWNED — derive pubkey from path, then hash it
    pubkey_bytes, _ = get_device_pubkey(script.params.key)
    return hashlib.blake2b(pubkey_bytes, digest_size=28).digest()


def _native_script_to_cbor_structure(script: NativeScript) -> list:
    """Recursively build the CBOR-encodable structure for a NativeScript.

    Cardano native script encoding:
        sig(key_hash)        -> [0, key_hash]
        all(scripts)         -> [1, [scripts...]]
        any(scripts)         -> [2, [scripts...]]
        atLeast(n, scripts)  -> [3, n, [scripts...]]
        after(slot)          -> [4, slot]
        before(slot)         -> [5, slot]
    """
    if script.type in (NativeScriptType.PUBKEY_DEVICE_OWNED, NativeScriptType.PUBKEY_THIRD_PARTY):
        return [0, _resolve_key_hash(script)]

    if script.type == NativeScriptType.ALL:
        return [1, [_native_script_to_cbor_structure(s) for s in script.params.scripts]]

    if script.type == NativeScriptType.ANY:
        return [2, [_native_script_to_cbor_structure(s) for s in script.params.scripts]]

    if script.type == NativeScriptType.N_OF_K:
        return [3, script.params.requiredCount,
                [_native_script_to_cbor_structure(s) for s in script.params.scripts]]

    if script.type == NativeScriptType.INVALID_BEFORE:
        return [4, script.params.slot]

    if script.type == NativeScriptType.INVALID_HEREAFTER:
        return [5, script.params.slot]

    raise ValueError(f"Unknown NativeScriptType: {script.type}")


def _compute_expected_script_hash(script: NativeScript) -> str:
    """Compute the expected script hash: blake2b-224 of (language_tag || CBOR).

    Cardano script hashes are prefixed with a language tag byte before hashing.
    Native scripts use tag 0x00.
    """
    serialized = cbor2.dumps(_native_script_to_cbor_structure(script))
    return hashlib.blake2b(b'\x00' + serialized, digest_size=28).hexdigest()


@pytest.mark.parametrize(
    "testCase",
    ValidNativeScriptTestCases,
    ids=idTestFunc
)
def test_derive_native_script_hash(device: Device,
                                   backend: BackendInterface,
                                   navigator: Navigator,
                                   scenario_navigator: NavigateWithScenario,
                                   testCase: ValidNativeScriptTestCase) -> None:
    """Check Derive Native Script Hash"""

    if device.is_nano:
        pytest.skip("Navigation should be created for Nano")

    # Use the app interface instead of raw interface
    client = CommandSender(backend)

    _deriveNativeScriptHash_init(device, navigator, client)
    _deriveNativeScriptHash_addScript(device, navigator, client, testCase.script, False)

    _deriveNativeScriptHash_finishWholeNativeScript(device, navigator, scenario_navigator, client, testCase)

def _deriveNativeScriptHash_init(device: Device,
                                 navigator: Navigator,
                                 client: CommandSender) -> None:
    with client.derive_script_init_async():
        if not device.is_nano:
            navigator.navigate(
                [NavInsID.USE_CASE_REVIEW_TAP], screen_change_before_first_instruction=False
            )

    response = client.get_async_response()
    assert response and response.status == StatusWord.SWO_SUCCESS


def _deriveNativeScriptHash_addScript(device: Device,
                                      navigator: Navigator,
                                      client: CommandSender,
                                      script: NativeScript,
                                      complex_nav: bool) -> None:
    """Send the different add commands

    Args:
        firmware (Firmware): The firmware version
        navigator (Navigator): The navigator instance
        client (CommandSender): The command sender instance
        script (NativeScript): The test case
        complex_nav (bool): The complex navigation flag
    """

    if script.type in [NativeScriptType.ALL, NativeScriptType.ANY, NativeScriptType.N_OF_K]:
        _deriveScriptHash_startComplexScript(device, navigator, client, script, complex_nav)
        assert isinstance(script.params, (NativeScriptParamsScripts, NativeScriptParamsNofK))
        for subscript in script.params.scripts:
            _deriveNativeScriptHash_addScript(device, navigator, client, subscript, True)
    else:
        _deriveNativeScriptHash_addSimpleScript(device, navigator, client, script, complex_nav)


def _deriveNativeScriptHash_addSimpleScript(device: Device,
                                            navigator: Navigator,
                                            client: CommandSender,
                                            script: NativeScript,
                                            complex_nav: bool) -> None:
    """Send the add command for a simple script

    Args:
        firmware (Firmware): The firmware version
        navigator (Navigator): The navigator instance
        client (CommandSender): The command sender instance
        script (NativeScript): The script
        complex_nav (bool): The complex navigation flag
    """

    with client.derive_script_add_simple_async(script):
        """
            moves = []
            if device.is_nano:
                if complex_nav:
                    moves += [NavInsID.BOTH_CLICK]
                if complex_nav or script.type == NativeScriptType.PUBKEY_THIRD_PARTY:
                    moves += [NavInsID.RIGHT_CLICK]
                moves += [NavInsID.BOTH_CLICK]
                #navigator.navigate(moves)
            else:
                if complex_nav:
                    moves += [NavInsID.TAPPABLE_CENTER_TAP]
                moves += [NavInsID.SWIPE_CENTER_TO_LEFT]
                #navigator.navigate(moves,
                #                   screen_change_before_first_instruction=False,
                #                   screen_change_after_last_instruction=False)
        """

        moves = []
        moves += [NavInsID.USE_CASE_REVIEW_TAP]
        if not device.is_nano:
            navigator.navigate(
                moves, screen_change_before_first_instruction=False
            )

    # Check the status (Asynchronous)
    response = client.get_async_response()
    assert response and response.status == StatusWord.SWO_SUCCESS


def _deriveScriptHash_startComplexScript(device: Device,
                                         navigator: Navigator,
                                         client: CommandSender,
                                         script: NativeScript,
                                         complex_nav: bool) -> None:
    """Send the add command for a complex script

    Args:
        firmware (Firmware): The firmware version
        client (CommandSender): The command sender instance
        navigator (Navigator): The navigator instance
        script (NativeScript): The script
        complex_nav (bool): The complex navigation flag
    """

    with client.derive_script_add_complex_async(script):
        """
        moves = []
        if device.is_nano:
            if complex_nav:
                moves += [NavInsID.BOTH_CLICK]
            if complex_nav or isinstance(script.params, NativeScriptParamsPubkey):
                moves += [NavInsID.RIGHT_CLICK]
            moves += [NavInsID.BOTH_CLICK]
        else:
            if complex_nav:
                moves += [NavInsID.TAPPABLE_CENTER_TAP]
            moves += [NavInsID.SWIPE_CENTER_TO_LEFT]
        navigator.navigate(moves)
        """

        moves = []
        moves += [NavInsID.USE_CASE_REVIEW_TAP]
        if not device.is_nano:
            navigator.navigate(
                moves, screen_change_before_first_instruction=False
            )

    # Check the status (Asynchronous)

    response = client.get_async_response()
    assert response and response.status == StatusWord.SWO_SUCCESS


def _deriveNativeScriptHash_finishWholeNativeScript(device: Device,
                                                    navigator: Navigator,
                                                    scenario_navigator: NavigateWithScenario,
                                                    client: CommandSender,
                                                    testCase: ValidNativeScriptTestCase) -> None:
    """Send the finish command for the whole native script

    Args:
        firmware (Firmware): The firmware version
        navigator (Navigator): The navigator instance
        scenario_navigator (NavigateWithScenario): The scenario navigator instance
        client (CommandSender): The command sender instance
        testCase (ValidNativeScriptTestCase): The test case
    """

    with client.derive_script_finish_async(testCase.displayFormat):
        """
        if device.is_nano:
            moves = []
            if testCase.script.type in (NativeScriptType.INVALID_BEFORE, NativeScriptType.INVALID_HEREAFTER):
                if testCase.script.params.slot > 1000:
                    moves += [NavInsID.RIGHT_CLICK]
            elif testCase.displayFormat != NativeScriptHashDisplayFormat.POLICY_ID and \
                not (testCase.script.type == NativeScriptType.N_OF_K and testCase.script.params.requiredCount > 0):
                moves += [NavInsID.RIGHT_CLICK]
            moves += [NavInsID.BOTH_CLICK]

            navigator.navigate(moves)
        else:
            scenario_navigator.address_review_approve(do_comparison=False)
        """
        """
        moves = []
        if not device.is_nano:
            navigator.navigate(
                moves, screen_change_before_first_instruction=False
            )
        """
        moves = []
        moves += [NavInsID.USE_CASE_REVIEW_TAP]
        moves += [NavInsID.USE_CASE_REVIEW_CONFIRM]
        if not device.is_nano:
            navigator.navigate(
                moves, screen_change_before_first_instruction=False
            )
    # Check the status (Asynchronous)
    response = client.get_async_response()
    assert response and response.status == StatusWord.SWO_SUCCESS
    # Check the response
    script_hash = unpack_derive_native_script_hash_response(response.data)
    if not testCase.skip_expected_in_ragger:
        assert script_hash.hex() == testCase.expected_in_unit_test.hash
    # Independently verify the hash by serializing the script to CBOR and
    # hashing it.  For PUBKEY_DEVICE_OWNED scripts the key hash is derived
    # from the device mnemonic at runtime via get_device_pubkey().
    assert script_hash.hex() == _compute_expected_script_hash(testCase.script)
