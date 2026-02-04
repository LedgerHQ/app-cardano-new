# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2024 Ledger SAS
# SPDX-License-Identifier: LicenseRef-LEDGER
"""
This module provides Ragger tests for Sign Operational Certificate
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class operationalCertificate:
    kesPublicKeyHex: str
    kesPeriod: int
    issueCounter: int
    path: str


@dataclass(kw_only=True)
class OpCertTestCase:
    name: str
    opCert: operationalCertificate
    warning: bool = False
    ledgerjs_name: Optional[str] = None


# pylint: disable=line-too-long
opCertTestCases = [
    OpCertTestCase(
        name="Sign_opcert_should_correctly_sign_operational_certificate",
        ledgerjs_name="Should correctly sign a basic operational certificate",
        opCert=operationalCertificate(
            "3d24bc547388cf2403fd978fc3d3a93d1f39acf68a9c00e40512084dc05f2822",
            47,
            42,
            "m/1853'/1815'/0'/0'",
        ),
    ),
    OpCertTestCase(
        name="Sign_opcert_should_correctly_sign_operational_certificate_with_warning",
        ledgerjs_name=None,  # New test case added for warning path (no ledgerjs equivalent)
        opCert=operationalCertificate(
            "3d24bc547388cf2403fd978fc3d3a93d1f39acf68a9c00e40512084dc05f2822",
            47,
            42,
            "m/1853'/1815'/0'/1000001'",
        ),
        warning=True,
    ),
]
