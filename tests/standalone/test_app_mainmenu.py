# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0

from ledgered.devices import Device
from ragger.navigator import Navigator, NavInsID

from tests.standalone.settings import SettingID, settings_toggle


# In this test we check the behavior of the device main menu
def test_app_mainmenu(
    device: Device, navigator: Navigator, test_name: str, default_screenshot_path: str
) -> None:
    # Toggle both settings to exercise the full menu
    settings_toggle(
        device, navigator, [SettingID.SILENT_PUBKEY_EXPORT, SettingID.EXPERT_MODE]
    )

    if not device.is_nano:
        # Touch devices need to navigate to the info page and back
        navigator.navigate(
            [
                NavInsID.USE_CASE_HOME_SETTINGS,
                NavInsID.USE_CASE_SETTINGS_NEXT,
                NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT,
            ],
            screen_change_before_first_instruction=False,
        )
