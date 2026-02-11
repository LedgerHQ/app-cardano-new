# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2024 Ledger SAS
# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0

"""
This module provides Ragger tests for application metadata APDUs.
Tests app-level information commands: GET_APP_NAME, GET_VERSION, GET_SERIAL.
"""

from ragger.utils.misc import get_current_app_name_and_version
from ragger.backend.interface import BackendInterface

from application_client.command_sender import CommandSender
from application_client.response_unpacker import (
    unpack_get_app_name_response,
    unpack_get_version_response,
    unpack_get_serial_response,
)

from .utils import verify_name, verify_version


def test_get_app_name(backend: BackendInterface) -> None:
    """Check application name via GET_APP_NAME APDU and verify against OS."""
    client = CommandSender(backend)
    response = client.get_app_name()
    app_name = unpack_get_app_name_response(response.data)
    verify_name(app_name)

    # Verify app name matches what OS reports
    os_app_name, _ = get_current_app_name_and_version(backend)
    assert app_name == os_app_name, f"App name mismatch: app reports '{app_name}', OS reports '{os_app_name}'"


def test_get_version(backend: BackendInterface) -> None:
    """Check version returned by the app via GET_VERSION APDU and verify against OS."""
    client = CommandSender(backend)
    rapdu = client.get_version()

    # Parse the version response using the unpacker
    major, minor, patch = unpack_get_version_response(rapdu.data)
    vers_str = f"{major}.{minor}.{patch}"

    print(f" Version: {vers_str}")
    verify_version(vers_str)

    # Verify app version matches what OS reports
    _, os_version = get_current_app_name_and_version(backend)
    assert vers_str == os_version, f"Version mismatch: app reports '{vers_str}', OS reports '{os_version}'"


def test_get_serial(backend: BackendInterface) -> None:
    """Check application serial number via GET_SERIAL APDU."""
    client = CommandSender(backend)
    rapdu = client.get_serial()

    # Parse the serial response using the unpacker
    serial = unpack_get_serial_response(rapdu.data)

    print(f" Serial: {serial.hex()} -> {serial.decode()}")
