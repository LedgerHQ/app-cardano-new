# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2024 Ledger SAS
# SPDX-License-Identifier: LicenseRef-LEDGER
"""
This module provides Ragger tests for Derive Address check
"""

import pytest
import base58

from ledgered.devices import Device
from ragger.backend import BackendInterface
from ragger.navigator import Navigator, NavInsID
from ragger.navigator.navigation_scenario import NavigateWithScenario
from ragger.error import ExceptionRAPDU

from application_client.app_def import Testnet
from application_client.status_words import StatusWord
from application_client.command_sender import CommandSender
from application_client.command_builder import P1Type

from standalone.input_files.derive_address import DeriveAddressTestCase
from standalone.input_files.derive_address import byronTestCases
from standalone.input_files.derive_address import (
    shelleyTestCasesNoConfirm,
    shelleyTestCasesWithConfirm,
    denyTestCases,
)
from standalone.utils import idTestFunc, derive_address


@pytest.mark.parametrize(
    "mode",
    ["return", "display"],
    ids=["return", "display"]
)
@pytest.mark.parametrize(
    "testCase",
    byronTestCases + shelleyTestCasesNoConfirm + shelleyTestCasesWithConfirm,
    ids=idTestFunc
)
def test_derive_address(
    device: Device,
    backend: BackendInterface,
    navigator: Navigator,
    scenario_navigator: NavigateWithScenario,
    testCase: DeriveAddressTestCase,
    mode: str,
) -> None:
    """Check Derive Address Return and Display (Byron and Shelley)"""

    client = CommandSender(backend)

    p1_type = P1Type.P1_ADDRESS_RETURN if mode == "return" else P1Type.P1_ADDRESS_DISPLAY

    # Shelley test cases without confirmation don't require UI interaction (return mode only)
    if testCase in shelleyTestCasesNoConfirm and mode == "return":
        response = client.derive_address(p1_type, testCase)
        assert response and response.status == StatusWord.SWO_SUCCESS
        assert response.data == derive_address(testCase)
        return

    # Byron and Shelley with confirmation require navigation
    test_name = f"{testCase.name}-{mode}"
    with client.derive_address_async(p1_type, testCase):
        scenario_navigator.address_review_approve(
            test_name=test_name,
            do_comparison=True
        )

    response = client.get_async_response()
    assert response and response.status == StatusWord.SWO_SUCCESS

    if testCase in byronTestCases and mode == "return":
        encoded = base58.b58encode(response.data).decode()
        assert encoded == derive_address(testCase)
    elif mode == "return":
        assert response.data == derive_address(testCase)


@pytest.mark.parametrize(
    "testCase",
    denyTestCases,
    ids=idTestFunc
)
def test_derive_address_deny(backend: BackendInterface,
                               testCase: DeriveAddressTestCase) -> None:
    """Check deny behavior for invalid derive-address inputs."""

    client = CommandSender(backend)

    with pytest.raises(ExceptionRAPDU) as err:
        with client.derive_address_async(P1Type.P1_ADDRESS_RETURN, testCase):
            pass
    assert err.value.status == StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED
