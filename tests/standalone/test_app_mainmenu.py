# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0

from unittest.mock import Mock

import pytest
from ledgered.devices import Device
from ragger.navigator import Navigator, NavInsID

from tests.standalone.settings import SettingID, settings_toggle


# In this test we check the behavior of the device main menu
def test_app_mainmenu(device: Device, navigator: Navigator) -> None:
    if isinstance(navigator, Mock):
        pytest.skip("Menu test requires real navigation; skipping under --no-nav")

    # Toggle both settings to exercise the full menu
    settings_toggle(
        device,
        navigator,
        [
            SettingID.SILENT_PUBKEY_EXPORT,
            SettingID.EXPERT_MODE,
            SettingID.BLIND_SIGNING,
        ],
    )

    if not device.is_nano:
        # Touch devices need to navigate to the info page and back
        navigator.navigate(
            [
                NavInsID.USE_CASE_HOME_SETTINGS,
                NavInsID.USE_CASE_SETTINGS_NEXT,
                NavInsID.USE_CASE_SETTINGS_NEXT,
                NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT,
            ],
            screen_change_before_first_instruction=False,
        )
