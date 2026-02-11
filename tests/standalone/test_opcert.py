# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2024 Ledger SAS
# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0

"""
This module provides Ragger tests for Operational Certificate check
"""

import pytest

from ledgered.devices import Device
from ragger.backend import BackendInterface
from ragger.navigator.navigation_scenario import NavigateWithScenario

from application_client.status_words import StatusWord
from application_client.command_sender import CommandSender
from application_client.response_unpacker import unpack_sign_opcert_response

from standalone.input_files.signOpCert import opCertTestCases, OpCertTestCase

from standalone.utils import idTestFunc, verify_signature


@pytest.mark.parametrize(
    "testCase",
    opCertTestCases,
    ids=idTestFunc
)
def test_opCert(device: Device,
                backend: BackendInterface,
                scenario_navigator: NavigateWithScenario,
                testCase: OpCertTestCase) -> None:
    """Check Sign Operational Certificate"""

    # Use the app interface instead of raw interface
    client = CommandSender(backend)

    with client.sign_opcert_async(testCase):
        test_name = testCase.name
        if testCase.has_warning:
            if device.is_nano:
                # TODO: navigation for warning does not work for Nano yet.
                pytest.skip("TODO navigation for warning does not work for Nano")
            scenario_navigator.review_approve_with_warning(
                test_name=test_name,
                custom_screen_text="Sign certificate",
            )
        else:
            scenario_navigator.review_approve(
                test_name=test_name,
                custom_screen_text="Sign certificate",
            )
    # Check the status (Asynchronous)
    response = client.get_async_response()
    assert response and response.status == StatusWord.SWO_SUCCESS

    signature = unpack_sign_opcert_response(response.data)

    msg = bytes()
    msg += bytes.fromhex(testCase.opCert.kesPublicKeyHex)
    msg += testCase.opCert.issueCounter.to_bytes(8, 'big')
    msg += testCase.opCert.kesPeriod.to_bytes(8, 'big')

    verify_signature(testCase.opCert.path, signature, msg)
