# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2024 Ledger SAS
# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0

"""
Ensures the Python test client defines the same command constants as the C app.
"""

from tests.standalone.client_constants_check import (
    assert_app_definition_constants_match,
    assert_app_status_words_match,
    assert_cla_constant_match,
    assert_cvote_credential_constants_match,
    assert_default_setting_values_match,
    assert_ins_constants_match,
    assert_max_sign_tx_chunk_size_match,
    assert_p1_p2_constants_match,
    assert_response_unpacker_constants_match,
    assert_sign_msg_and_native_script_constants_match,
    assert_sign_tx_related_constants_match,
    assert_settings_menu_constants_match,
    assert_setting_value_constants_match,
    assert_warning_bit_constants_match,
)


def test_ins_constants_match_src():
    assert_ins_constants_match()


def test_p1_p2_constants_match_src():
    assert_p1_p2_constants_match()


def test_cla_constant_match_src():
    assert_cla_constant_match()


def test_max_sign_tx_chunk_size():
    assert_max_sign_tx_chunk_size_match()


def test_cvote_credential_constants_match_src():
    assert_cvote_credential_constants_match()


def test_warning_bit_constants_match_src():
    assert_warning_bit_constants_match()


def test_setting_value_constants_match_src():
    assert_setting_value_constants_match()


def test_default_setting_values_match_src():
    assert_default_setting_values_match()


def test_settings_menu_constants_match_src():
    assert_settings_menu_constants_match()


def test_app_status_words_match_src():
    assert_app_status_words_match()


def test_app_definition_constants_match_src():
    assert_app_definition_constants_match()


def test_sign_tx_related_constants_match_src():
    assert_sign_tx_related_constants_match()


def test_sign_msg_and_native_script_constants_match_src():
    assert_sign_msg_and_native_script_constants_match()


def test_response_unpacker_constants_match_src():
    assert_response_unpacker_constants_match()
