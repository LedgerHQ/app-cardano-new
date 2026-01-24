# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2024 Ledger SAS
# SPDX-License-Identifier: LicenseRef-LEDGER
"""
Ensures the Python test client defines the same command constants as the C app.
"""

from tests.standalone.client_constants_check import (
    assert_cla_constant_match,
    assert_ins_constants_match,
    assert_max_sign_tx_chunk_size_match,
    assert_p1_p2_constants_match,
)


def test_ins_constants_match_src():
    assert_ins_constants_match()


def test_p1_p2_constants_match_src():
    assert_p1_p2_constants_match()


def test_cla_constant_match_src():
    assert_cla_constant_match()


def test_max_sign_tx_chunk_size():
    assert_max_sign_tx_chunk_size_match()
