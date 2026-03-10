# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0

# Settings toggle mechanism for ragger tests.
# Navigates the on-device settings menu to toggle switches,
# analogous to the eth app's settings.py approach.
# This works with both DEBUG and production builds (no debug APDUs needed).

from enum import Enum, IntEnum, auto
from typing import Mapping, Union
from unittest.mock import Mock
import pytest
from ledgered.devices import Device, DeviceType
from ragger.backend import BackendInterface

from ragger.navigator import Navigator, NavInsID, NavIns

from application_client.command_sender import CommandSender
from application_client.status_words import StatusWord


class SettingID(Enum):
    SILENT_PUBKEY_EXPORT = auto()
    EXPERT_MODE = auto()


class SettingValue(IntEnum):
    DISABLED = 0
    ENABLED = 1


# Settings positions per device type. Returns the tuple (page, x, y).
# Menu order: Silent public key export (top), Expert mode (bottom).
# Coordinates are approximate and may need adjustment.
# NBGL convention: origin (0,0) at top-left, +X right, +Y down.
SETTINGS_POSITIONS = {
    # Stax: 400x672 px
    DeviceType.STAX: {
        SettingID.SILENT_PUBKEY_EXPORT: (0, 350, 155),
        SettingID.EXPERT_MODE: (0, 350, 345),
    },
    # Flex: 480x600 px
    DeviceType.FLEX: {
        SettingID.SILENT_PUBKEY_EXPORT: (0, 420, 155),
        SettingID.EXPERT_MODE: (0, 420, 345),
    },
    # Apex P
    DeviceType.APEX_P: {
        SettingID.SILENT_PUBKEY_EXPORT: (0, 260, 90),
        SettingID.EXPERT_MODE: (0, 260, 235),
    },
    # Apex M
    DeviceType.APEX_M: {
        SettingID.SILENT_PUBKEY_EXPORT: (0, 260, 90),
        SettingID.EXPERT_MODE: (0, 260, 235),
    },
}

# The order of settings as they appear in the menu (used for Nano navigation)
SETTINGS_ORDER = [
    SettingID.SILENT_PUBKEY_EXPORT,
    SettingID.EXPERT_MODE,
]

DEFAULT_SETTING_VALUES: dict[SettingID, SettingValue] = {
    SettingID.SILENT_PUBKEY_EXPORT: SettingValue.ENABLED,
    SettingID.EXPERT_MODE: SettingValue.DISABLED,
}

_known_setting_values: dict[SettingID, SettingValue] = DEFAULT_SETTING_VALUES.copy()
_debug_settings_apdu_supported: bool | None = None
_last_backend_identity: int | None = None


def get_settings_moves(device: Device,
                       to_toggle: list[SettingID]) -> list[Union[NavIns, NavInsID]]:
    """Get the navigation instructions to toggle the given settings.

    Assumes the app is on the home page.
    For touch devices: opens settings, clicks the appropriate switches, exits.
    For Nano devices: navigates through settings menu items.
    """
    moves: list[Union[NavIns, NavInsID]] = []

    if device.is_nano:
        # Nano: right-click to Settings, both-click to enter
        moves += [NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK]
        for setting in SETTINGS_ORDER:
            if setting in to_toggle:
                moves += [NavInsID.BOTH_CLICK]
            moves += [NavInsID.RIGHT_CLICK]
        moves += [NavInsID.BOTH_CLICK]  # Back
    else:
        current_page = 0
        moves += [NavInsID.USE_CASE_HOME_SETTINGS]
        for setting in SETTINGS_ORDER:
            if setting in to_toggle:
                page, x, y = SETTINGS_POSITIONS[device.type][setting]
                moves += [NavInsID.USE_CASE_SETTINGS_NEXT] * (page - current_page)
                moves += [NavIns(NavInsID.TOUCH, (x, y))]
                current_page = page
        moves += [NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT]
    return moves


def settings_toggle(device: Device, navigator: Navigator, to_toggle: list[SettingID]):
    """Toggle the specified settings on the device.

    Navigates from the home screen into settings, toggles the requested
    switches, and exits back to the home screen.
    """
    moves = get_settings_moves(device, to_toggle)
    navigator.navigate(moves, screen_change_before_first_instruction=False)
    for setting in to_toggle:
        _known_setting_values[setting] = (
            SettingValue.DISABLED
            if _known_setting_values[setting] == SettingValue.ENABLED
            else SettingValue.ENABLED
        )


def settings_set(device: Device,
                 navigator: Navigator,
                 target_setting_values: Mapping[SettingID, SettingValue],
                 backend: BackendInterface) -> None:
    """Reach the requested setting values using the current known state.

    Prefer the debug APDU when available because it is a real "set" operation.
    Fall back to UI toggles for production builds where only menu navigation exists.
    """
    global _debug_settings_apdu_supported
    global _last_backend_identity

    if backend is None:
        raise AssertionError("settings_set requires backend to probe debug APDU support")

    backend_identity = id(backend)
    if _last_backend_identity != backend_identity:
        _known_setting_values.clear()
        _known_setting_values.update(DEFAULT_SETTING_VALUES)
        _debug_settings_apdu_supported = None
        _last_backend_identity = backend_identity

    effective_target_setting_values = _known_setting_values.copy()
    effective_target_setting_values.update(target_setting_values)

    if _debug_settings_apdu_supported is not False:
        client = CommandSender(backend)
        response = client.try_set_debug_settings(
            expert_mode=effective_target_setting_values[SettingID.EXPERT_MODE] == SettingValue.ENABLED,
            silent_export=effective_target_setting_values[SettingID.SILENT_PUBKEY_EXPORT] == SettingValue.ENABLED,
        )
        if response.status == StatusWord.SWO_SUCCESS:
            _debug_settings_apdu_supported = True
            _known_setting_values.update(effective_target_setting_values)
            return
        if response.status != StatusWord.SWO_INVALID_INS:
            raise AssertionError(f"Debug set settings failed: {hex(response.status)}")
        _debug_settings_apdu_supported = False

    if isinstance(navigator, Mock):
        pytest.skip(
            "Cannot apply app settings in this run: debug settings APDU is unavailable "
            "(likely non-DEBUG build) and navigation is disabled (--no-nav). Requested "
            "expert-mode/silent-export settings cannot be applied."
        )

    settings_to_toggle = [
        setting_id
        for setting_id, target_value in effective_target_setting_values.items()
        if _known_setting_values[setting_id] != target_value
    ]
    settings_toggle(device, navigator, settings_to_toggle)
    # Wait until the app is fully back on the home screen before the next APDU.
    backend.wait_for_home_screen()
