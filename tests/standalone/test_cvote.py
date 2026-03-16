# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2024 Ledger SAS
# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0

"""
This module provides Ragger tests for CIP36 check
"""

import pytest

from ragger.backend import BackendInterface
from ledgered.devices import Device
from ragger.navigator import Navigator
from ragger.navigator.navigation_scenario import NavigateWithScenario


from application_client.status_words import StatusWord
from application_client.command_sender import CommandSender
from application_client.response_unpacker import (
    unpack_sign_cip36_confirm_response
)

from standalone.input_files.cvote import cvoteTestCases, CVoteTestCase

from standalone.utils import idTestFunc, review_approve, verify_signature, NavContext


@pytest.mark.parametrize(
    "testCase",
    cvoteTestCases,
    ids=idTestFunc
)
def test_cvote(device: Device,
               backend: BackendInterface,
               navigator: Navigator,
               scenario_navigator: NavigateWithScenario,
               testCase: CVoteTestCase) -> None:
    """Check CIP36 Vote"""
    # Use the app interface instead of raw interface
    client = CommandSender(backend)

    # Save the original votecast data before it gets consumed by the APDU builder
    original_votecast_data = bytes.fromhex(testCase.cVote.voteCastDataHex)

    # Send the INIT APDU
    _cvote_init(client, testCase)

    # Send the CONFIRM APDU (which includes witness path and triggers signing)
    nav_ctx = NavContext(device, navigator, scenario_navigator)
    votecast_hash, signature = _cvote_confirm(nav_ctx, client, testCase)

    # Verify the hash matches the expected Blake2b-256 hash of the votecast data
    import hashlib
    expected_hash = hashlib.blake2b(original_votecast_data, digest_size=32).digest()
    assert votecast_hash == expected_hash, f"Hash mismatch: {votecast_hash.hex()} != {expected_hash.hex()}"

    # Check the signature validity
    # Note: The signature is over the hash, not the raw votecast data
    verify_signature(testCase.cVote.witnessPath, signature, votecast_hash)


def _cvote_init(client: CommandSender,
                testCase: CVoteTestCase) -> None:
    """cVOTE INIT

    Args:
        firmware (Firmware): The firmware version
        navigator (Navigator): The navigator instance
        client (CommandSender): The command sender instance
        testCase (CVoteTestCase): The test case
    """
    with client.sign_cip36_init_async(testCase):
        pass

    # Check the status (Asynchronous)
    response = client.get_async_response()
    assert response and response.status == StatusWord.SWO_SUCCESS

    if client.has_sign_cip36_chunks(testCase):
        # Send the CHUNK APDUs
        response = client.sign_cip36_chunk(testCase)
        # Check the status
        assert response and response.status == StatusWord.SWO_SUCCESS


def _cvote_confirm(nav_ctx: NavContext,
                   client: CommandSender,
                   testCase: CVoteTestCase) -> tuple[bytes, bytes]:
    """cVOTE CONFIRM and SIGN

    Args:
        nav_ctx (NavContext): Navigation context
        client (CommandSender): The command sender instance
        testCase (CVoteTestCase): The test case

    Return:
        tuple[bytes, bytes]: (votecast_hash, signature)
    """

    with client.sign_cip36_confirm_async(testCase):
        test_name = f"{testCase.name}/cvote_confirm"
        review_approve(
            nav_ctx,
            test_name=test_name,
            target_text="Sign vote",
            warnings=testCase.expected_warnings,
        )
    # Check the status (Asynchronous)
    response = client.get_async_response()
    assert response and response.status == StatusWord.SWO_SUCCESS
    votecast_hash, signature = unpack_sign_cip36_confirm_response(response.data)

    return votecast_hash, signature
