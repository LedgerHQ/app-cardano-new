# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2024 Ledger SAS
# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0

"""
This module provides Ragger tests for Sign Message check
"""

from hashlib import blake2b
import pytest
import cbor

from ragger.backend import BackendInterface
from ragger.error import ExceptionRAPDU
from ledgered.devices import Device
from ragger.navigator import Navigator, NavInsID
from ragger.navigator.navigation_scenario import NavigateWithScenario

from tests.application_client.command_builder import AddressType, Mainnet, MessageAddressFieldType
from tests.application_client.status_words import StatusWord
from tests.application_client.command_sender import CommandSender

from tests.standalone.input_files.signMsg import (
    signMsgTestCases,
    signMsgDenyTestCases,
    SignMsgTestCase,
    SignMsgDenyTestCase,
    build_sign_msg_init_apdu_for_deny,
)

from tests.application_client.command_builder import AddressParams
from tests.standalone.input_files.derive_address import DeriveAddressTestCase

from tests.standalone.utils import (
    idTestFunc,
    get_device_pubkey,
    verify_signature,
    derive_address,
    review_approve,
    NavContext,
)


@pytest.mark.parametrize("testCase", signMsgTestCases, ids=idTestFunc)
def test_sign_message(
    device: Device,
    backend: BackendInterface,
    navigator: Navigator,
    scenario_navigator: NavigateWithScenario,
    testCase: SignMsgTestCase,
) -> None:
    """Check Sign Message"""

    # Use the app interface instead of raw interface
    client = CommandSender(backend)
    nav_ctx = NavContext(device, navigator, scenario_navigator)

    def review_msg() -> None:
        review_approve(
            nav_ctx,
            test_name=testCase.name,
            target_text="Sign message"
            if not testCase.expected_warnings
            else r"^Reject operation$",
            warnings=testCase.expected_warnings,
            nano_review_instructions=(
                [NavInsID.LEFT_CLICK, NavInsID.BOTH_CLICK]
                if testCase.expected_warnings
                else None
            ),
        )

    signature, public_key, address_field = client.sign_msg(testCase, on_review=review_msg)

    # Check the response
    _check_result(testCase, signature, public_key, address_field)


@pytest.mark.parametrize("testCase", signMsgDenyTestCases, ids=idTestFunc)
def test_sign_message_deny(
    backend: BackendInterface, testCase: SignMsgDenyTestCase
) -> None:
    from tests.standalone.input_files.signMsg import (
        build_sign_msg_chunk_apdu_for_deny,
        build_sign_msg_confirm_apdu_for_deny,
    )

    # Handle multi-phase deny scenarios
    if testCase.send_chunk_without_init:
        # Try to send CHUNK without INIT
        chunk_apdu = build_sign_msg_chunk_apdu_for_deny(testCase, 0)
        with pytest.raises(ExceptionRAPDU) as err:
            backend.exchange_raw(chunk_apdu)
        assert err.value.status == testCase.expected_status
        return

    # Standard flow: always send INIT first
    init_apdu = build_sign_msg_init_apdu_for_deny(testCase)

    # If we expect failure during INIT, test that
    # Also check for implicit INIT failures from message length validation
    msg_len = len(bytes.fromhex(testCase.msgData.messageHex))
    expect_init_failure = (
        testCase.invalid_address_field_type is not None
        or testCase.invalid_msg_length is not None
        or testCase.truncate_init_apdu_at is not None
        or
        # Security policy deny (happens during INIT after parsing succeeds)
        testCase.expected_status == StatusWord.SWO_SECURITY_CONDITION_NOT_SATISFIED
        or
        # Address params parsing failure (happens during INIT)
        testCase.expected_status == StatusWord.SWO_SIGN_MSG_PARSING_FAIL_ADDRESS_PARAMS
        or
        # Memory overflow during INIT validation (SWO_INSUFFICIENT_MEMORY)
        (
            testCase.expected_status == StatusWord.SWO_INSUFFICIENT_MEMORY
            and (
                msg_len > 65535  # Exceeds UINT16_MAX
                or (
                    not testCase.msgData.isAscii and msg_len >= 32767
                )  # Non-ASCII hex buffer overflow
                or (not testCase.msgData.hashPayload and msg_len >= 65280)
            )
        )  # Non-hashed sig_structure overflow
    )

    if expect_init_failure:
        with pytest.raises(ExceptionRAPDU) as err:
            backend.exchange_raw(init_apdu)
        assert err.value.status == testCase.expected_status
        return

    # INIT succeeded, continue to CHUNK phase
    backend.exchange_raw(init_apdu)

    # Handle CHUNK-phase deny scenarios
    if testCase.invalid_chunk_size is not None or (
        testCase.msgData.isAscii
        and not all(32 <= b < 127 for b in bytes.fromhex(testCase.msgData.messageHex))
    ):
        # ASCII validation or chunk size validation happens during CHUNK
        chunk_apdu = build_sign_msg_chunk_apdu_for_deny(testCase, 0)
        with pytest.raises(ExceptionRAPDU) as err:
            backend.exchange_raw(chunk_apdu)
        assert err.value.status == testCase.expected_status
        return

    # Handle CONFIRM-phase deny scenarios
    if testCase.send_confirm_without_chunks:
        # For empty messages or when skipping CHUNK, go directly to CONFIRM
        confirm_apdu = build_sign_msg_confirm_apdu_for_deny(testCase)
        with pytest.raises(ExceptionRAPDU) as err:
            backend.exchange_raw(confirm_apdu)
        assert err.value.status == testCase.expected_status
        return

    if testCase.send_confirm_with_payload:
        # Send all normal chunks first
        from tests.application_client.command_builder import CommandBuilder
        from tests.standalone.input_files.signMsg import SignMsgTestCase

        transient_success_case = SignMsgTestCase(
            name=testCase.name,
            msgData=testCase.msgData,
        )
        chunk_apdus = CommandBuilder().sign_msg_chunks(transient_success_case)
        for chunk_apdu in chunk_apdus:
            backend.exchange_raw(chunk_apdu)

        # Now send CONFIRM with invalid payload
        confirm_apdu = build_sign_msg_confirm_apdu_for_deny(testCase)
        with pytest.raises(ExceptionRAPDU) as err:
            backend.exchange_raw(confirm_apdu)
        assert err.value.status == testCase.expected_status
        return

    # If we reach here, the test case configuration is incomplete
    raise ValueError(f"Deny test case {testCase.name} has no deny scenario configured")


def _check_result(
    testCase: SignMsgTestCase, signature: bytes, public_key: bytes, address_field: bytes
) -> None:
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
                params=AddressParams(
                    netDesc=Mainnet,
                    addrType=AddressType.BASE_PAYMENT_KEY_STAKE_KEY,
                    spendingValue=testCase.msgData.signingPath,
                ),
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
    dico = {1: -8, "address": addressField}

    array.append("Signature1")
    array.append(cbor.cbor.dumps_dict(dico))
    array.append(b"")
    if testCase.msgData.hashPayload:
        msgHash = blake2b(
            bytes.fromhex(testCase.msgData.messageHex), digest_size=28
        ).hexdigest()
        array.append(bytes.fromhex(msgHash))
    else:
        array.append(bytes.fromhex(testCase.msgData.messageHex))

    return cbor.cbor.dumps_array(array)
