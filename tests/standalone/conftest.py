import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TESTS_ROOT = ROOT / "tests"
for extra_path in (ROOT, TESTS_ROOT):
    str_extra = str(extra_path)
    if str_extra not in sys.path:
        sys.path.insert(0, str_extra)

import pytest

from .client_constants_check import (
    assert_cla_constant_match,
    assert_cvote_credential_constants_match,
    assert_ins_constants_match,
    assert_max_sign_tx_chunk_size_match,
    assert_p1_p2_constants_match,
)

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


# Pull all features from the base ragger conftest using the overridden configuration
pytest_plugins = ("ragger.conftest.base_conftest", )
