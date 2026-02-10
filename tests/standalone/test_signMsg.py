# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2024 Ledger SAS
# SPDX-License-Identifier: LicenseRef-LEDGER
"""
This module provides Ragger tests for Sign Message check
"""

from hashlib import blake2b
import pytest
import cbor

from ragger.backend import BackendInterface
from ledgered.devices import Device
from ragger.navigator import Navigator
from ragger.navigator.navigation_scenario import NavigateWithScenario

from application_client.app_def import AddressType, Mainnet
from application_client.status_words import StatusWord
from application_client.command_sender import CommandSender
from application_client.response_unpacker import unpack_sign_message_response

from standalone.input_files.signMsg import signMsgTestCases, SignMsgTestCase, MessageAddressFieldType

from standalone.test_derive_address import DeriveAddressTestCase

from standalone.utils import idTestFunc, get_device_pubkey, verify_signature, derive_address


@pytest.mark.parametrize(
    "testCase",
    signMsgTestCases,
    ids=idTestFunc
)
def test_sign_message(device: Device,
                      backend: BackendInterface,
                      navigator: Navigator,
                      scenario_navigator: NavigateWithScenario,
                      testCase: SignMsgTestCase) -> None:
    """Check Sign Message"""

    # Use the app interface instead of raw interface
    client = CommandSender(backend)

    if device.is_nano:
        # TODO: navigation for sign msg does not work for Nano yet.
        pytest.skip("TODO navigation for sign msg does not work for Nano")

    def review_msg() -> None:
        scenario_navigator.review_approve(
            test_name=testCase.name,
        )

    signedData = client.sign_msg(testCase, on_review=review_msg)

    # Unpack the response
    signature, public_key, address_field = unpack_sign_message_response(signedData)

    # Check the response
    _check_result(testCase, signature, public_key, address_field)


def _check_result(testCase: SignMsgTestCase, signature: bytes, public_key: bytes, address_field: bytes) -> None:
    """Check the unpacked response values

    Args:
        testCase: The test case
        signature: ED25519 signature (64 bytes)
        public_key: Device public key (32 bytes)
        address_field: Address field (up to 128 bytes)
    """

    # Check the public key
    expected_pk, _ = get_device_pubkey(testCase.msgData.signingPath)
    assert public_key == expected_pk

    # Check the address field
    if testCase.msgData.addressFieldType == MessageAddressFieldType.ADDRESS:
        assert address_field == derive_address(testCase.msgData.addressDesc)
    else:
        address = derive_address(
            DeriveAddressTestCase(
                name="sign_message_keyhash",
                ledgerjs_name=None,
                netDesc=Mainnet,
                addrType=AddressType.BASE_PAYMENT_KEY_STAKE_KEY,
                spendingValue=testCase.msgData.signingPath,
            )
        )
        assert address_field == address[1:]

    # Check the signature
    payload = _generate_payload(testCase, address_field)
    verify_signature(testCase.msgData.signingPath, signature, payload)


def _generate_payload(testCase: SignMsgTestCase, addressField: bytes) -> bytes:
    """Generate the payload to sign

    Args:
        testCase (SignMsgTestCase): The test case

    Return:
        The payload
    """

    array = []
    dico = {
        1: -8,
        "address": addressField
    }

    array.append("Signature1")
    array.append(cbor.cbor.dumps_dict(dico))
    array.append(b'')
    if testCase.msgData.hashPayload:
        msgHash = blake2b(bytes.fromhex(testCase.msgData.messageHex), digest_size=28).hexdigest()
        array.append(bytes.fromhex(msgHash))
    else:
        array.append(bytes.fromhex(testCase.msgData.messageHex))

    return cbor.cbor.dumps_array(array)
