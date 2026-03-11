# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0
# ruff: noqa: E402

import sys
from pathlib import Path
import os

ROOT = Path(__file__).resolve().parents[2]
TESTS_ROOT = ROOT / "tests"
for extra_path in (ROOT, TESTS_ROOT):
    str_extra = str(extra_path)
    if str_extra not in sys.path:
        sys.path.insert(0, str_extra)

import pytest

from .client_constants_check import (
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
)

NANO_STREAMING_TIMEOUT_SECONDS = 600

###########################
### CONFIGURATION START ###
###########################

# You can configure optional parameters by overriding the value of ragger.configuration.OPTIONAL_CONFIGURATION
# Please refer to ragger/conftest/configuration.py for their descriptions and accepted values

# Ragger tests are supposed to run without any hardcoded seed / mnemonic.
# However, for debugging, we might want to fix the seed occasionally
# to a value corresponding to the unit test fixtures.
#configuration.OPTIONAL.CUSTOM_SEED = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

#########################
### CONFIGURATION END ###
#########################

@pytest.fixture(scope="session", autouse=True)
def enforce_client_constants() -> None:
    """Ensure the Python helpers stay aligned with the C dispatcher before raggers run."""
    assert_ins_constants_match()
    assert_p1_p2_constants_match()
    assert_cla_constant_match()
    assert_cvote_credential_constants_match()
    assert_max_sign_tx_chunk_size_match()
    assert_setting_value_constants_match()
    assert_default_setting_values_match()
    assert_settings_menu_constants_match()
    assert_app_status_words_match()
    assert_app_definition_constants_match()
    assert_sign_tx_related_constants_match()
    assert_sign_msg_and_native_script_constants_match()
    assert_response_unpacker_constants_match()


# Pull all features from the base ragger conftest using the overridden configuration
pytest_plugins = ("ragger.conftest.base_conftest", )


@pytest.fixture(scope="session")
def additional_speculos_arguments() -> list[str]:
    """Assign deterministic per-worker Speculos ports under pytest-xdist.

    Ragger's default "find a free port" logic races across xdist workers.
    Keep single-process runs unchanged and only pin ports when running under xdist.
    """
    worker_id = os.environ.get("PYTEST_XDIST_WORKER")
    if not worker_id:
        return []

    if not worker_id.startswith("gw"):
        raise AssertionError(f"Unexpected xdist worker id: {worker_id}")

    worker_index = int(worker_id[2:])
    api_port = 5000 + worker_index * 10
    apdu_port = api_port + 1
    return ["--api-port", str(api_port), "--apdu-port", str(apdu_port)]


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Apply targeted timeout overrides for slow parameterized scenarios."""
    for item in items:
        callspec = getattr(item, "callspec", None)
        if callspec is None:
            continue

        device_name = callspec.id.split("-", 1)[0]
        if not device_name.startswith("nano"):
            continue

        test_case = callspec.params.get("testCase")
        test_case_name = getattr(test_case, "name", None)
        if test_case_name is None:
            continue

        if "streaming" not in test_case_name.lower():
            continue

        item.add_marker(pytest.mark.timeout(NANO_STREAMING_TIMEOUT_SECONDS))
