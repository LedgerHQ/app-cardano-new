# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0

import pytest

from ledgered.devices import Device
from ragger.backend import BackendInterface
from ragger.navigator import Navigator
from ragger.navigator.navigation_scenario import NavigateWithScenario
from ragger.error import ExceptionRAPDU

from application_client.command_sender import CommandSender
from application_client.status_words import StatusWord
from application_client.response_unpacker import unpack_get_pubkey_response

from standalone.input_files.pubkey import PubKeyTestCase, denyTestCases, testsByron, testsShelleyUsual, testsShelleyUnusual, testsMultisig, testsColdKeys, testsCVoteKeysUsual, testsCVoteKeysUnusual, testsDRepKeys, testsCommitteeColdKeys, testsCommitteeHotKeys, testsMintKeys, testsSilentExport

from standalone.utils import idTestFunc, get_device_pubkey

@pytest.mark.parametrize(
    "testCase",
    testsByron + testsShelleyUsual + testsShelleyUnusual + testsMultisig + testsColdKeys +
    testsCVoteKeysUsual + testsCVoteKeysUnusual + testsDRepKeys +
    testsCommitteeColdKeys + testsCommitteeHotKeys + testsMintKeys,
    ids=idTestFunc
)
def test_pubkey_confirm(device: Device,
                        backend: BackendInterface,
                        navigator: Navigator,
                        scenario_navigator: NavigateWithScenario,
                        testCase: PubKeyTestCase) -> None:
    """Check Public Key with confirmation"""

    # TODO why are snapshots missing?

    # Use the app interface instead of raw interface
    client = CommandSender(backend)

    if device.is_nano:
        # TODO: navigation for pubkey export does not work for Nano yet.
        pytest.skip("TODO navigation for pubkey export does not work for Nano")

    # Turn off silent pubkey export via debug APDU, confirmation will be asked for each key
    # This only works with DEBUG builds; keeps expert mode in its default state (off)
    client.set_debug_settings(expert_mode=False, silent_export=False)
    with client.get_pubkey_async(testCase.path):
        if testCase.nav:
            scenario_navigator.address_review_approve(test_name=testCase.name, custom_screen_text="Export")
        else:
            pass
    # Check the status (Asynchronous)
    response = client.get_async_response()
    assert response and response.status == StatusWord.SWO_SUCCESS

    # Check the response
    _check_pubkey_result(response.data, testCase.path)


@pytest.mark.parametrize(
    "testCase",
    testsSilentExport,
    ids=idTestFunc
)
def test_pubkey_without_confirmation(backend: BackendInterface, testCase: PubKeyTestCase) -> None:
    """Check Public Key without confirmation"""

    # Use the app interface instead of raw interface
    client = CommandSender(backend)

    # Ensure silent export is enabled to avoid dependence on persistent settings.
    client.set_debug_settings(expert_mode=False, silent_export=True)

    with client.get_pubkey_async(testCase.path):
        pass

    # Check the status (Asynchronous)
    response = client.get_async_response()
    assert response and response.status == StatusWord.SWO_SUCCESS

    # Check the response
    _check_pubkey_result(response.data, testCase.path)


@pytest.mark.parametrize(
    "testCase",
    denyTestCases,
    ids=idTestFunc
)
def test_pubkey_deny(backend: BackendInterface,
                       testCase: PubKeyTestCase) -> None:
    """Check deny behavior for invalid public-key export inputs."""

    # Use the app interface instead of raw interface
    client = CommandSender(backend)

    with pytest.raises(ExceptionRAPDU) as err:
        with client.get_pubkey_async(testCase.path):
            pass
    assert err.value.status == StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED


def _check_pubkey_result(data: bytes, path: str) -> None:
    public_key, chain_code = unpack_get_pubkey_response(data)
    ref_pk, ref_chaincode = get_device_pubkey(path)
    assert public_key.hex() == ref_pk.hex()
    assert chain_code.hex() == ref_chaincode
