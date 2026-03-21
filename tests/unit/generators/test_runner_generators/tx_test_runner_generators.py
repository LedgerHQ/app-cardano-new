# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0

import re
from pathlib import Path
from typing import Sequence

from tests.unit.generators.common import (
    read_file_safe,
    write_generated_c_file,
    sanitize_c_identifier,
)
from tests.unit.generators.paths import GENERATED_SIGN_TX_DIR


# ======================================================================
# Compiled Regex Patterns (module level for performance)
# ======================================================================

# Match fixture declarations like: static const tx_fixture_t FIXTURE_NAME = { ... };
_FIXTURE_PATTERN = re.compile(
    r"static const tx_fixture_t (FIXTURE_[A-Z0-9_]+)\s*=\s*\{(.*?)\};", re.S
)

# Match .name fields within fixture bodies
_NAME_FIELD_PATTERN = re.compile(r'\.name\s*=\s*"([^"]+)"')
_AUX_INCLUDED_PATTERN = re.compile(r"\.include_aux_data_hash\s*=\s*(true|false)")
_AUX_TYPE_PATTERN = re.compile(r"\.aux_data_type\s*=\s*([A-Z0-9_]+|\d+)")


ERA_COMMENT_OVERRIDES = {
    "conway_without_certificates": "CONWAY_WITHOUT_CERTIFICATES Era Tests",
    "alonzo_catalyst": "ALONZO_CATALYST Era Tests",
    "alonzo_cip36": "ALONZO_CIP36 Era Tests",
}

ERA_TEST_FILE_MAP: dict[str, tuple[str, str, str]] = {
    "byron": ("test_sign_tx_fixtures_byron.h", "test_sign_tx_byron.c", "BYRON"),
    "shelley": ("test_sign_tx_fixtures_shelley.h", "test_sign_tx_shelley.c", "SHELLEY"),
    "mary": ("test_sign_tx_fixtures_mary.h", "test_sign_tx_mary.c", "MARY"),
    "allegra": ("test_sign_tx_fixtures_allegra.h", "test_sign_tx_allegra.c", "ALLEGRA"),
    "alonzo": ("test_sign_tx_fixtures_alonzo.h", "test_sign_tx_alonzo.c", "ALONZO"),
    "babbage": ("test_sign_tx_fixtures_babbage.h", "test_sign_tx_babbage.c", "BABBAGE"),
    "alonzo_catalyst": (
        "test_sign_tx_fixtures_alonzo_catalyst.h",
        "test_sign_tx_alonzo_catalyst.c",
        "ALONZO_CATALYST",
    ),
    "alonzo_cip36": (
        "test_sign_tx_fixtures_alonzo_cip36.h",
        "test_sign_tx_alonzo_cip36.c",
        "ALONZO_CIP36",
    ),
    "conway": ("test_sign_tx_fixtures_conway.h", "test_sign_tx_conway.c", "CONWAY"),
    "conway_voting": (
        "test_sign_tx_fixtures_conway_voting.h",
        "test_sign_tx_conway_voting.c",
        "CONWAY_VOTING",
    ),
    "conway_without_certificates": (
        "test_sign_tx_fixtures_conway_without_certificates.h",
        "test_sign_tx_conway_without_certificates.c",
        "CONWAY_WITHOUT_CERTIFICATES",
    ),
    "shelley_certificates": (
        "test_sign_tx_fixtures_shelley_certificates.h",
        "test_sign_tx_shelley_certificates.c",
        "SHELLEY_CERTIFICATES",
    ),
    "multisig": (
        "test_sign_tx_fixtures_multisig.h",
        "test_sign_tx_multisig.c",
        "MULTISIG",
    ),
    "pool_registration": (
        "test_sign_tx_fixtures_pool_registration.h",
        "test_sign_tx_pool_registration.c",
        "POOL_REGISTRATION",
    ),
    "streaming": (
        "test_sign_tx_fixtures_streaming.h",
        "test_sign_tx_streaming.c",
        "STREAMING",
    ),
}


def _fixture_has_cvote_aux_data(fixture_body: str) -> bool:
    aux_included_match = _AUX_INCLUDED_PATTERN.search(fixture_body)
    aux_type_match = _AUX_TYPE_PATTERN.search(fixture_body)
    if aux_included_match is None or aux_type_match is None:
        return False

    include_aux_data = aux_included_match.group(1) == "true"
    aux_type_token = aux_type_match.group(1)
    return include_aux_data and aux_type_token in {
        "1",
        "AUX_DATA_TYPE_CVOTE_REGISTRATION",
    }


def _build_test_functions(
    fixtures: Sequence[tuple[str, str, bool]],
) -> tuple[list[str], list[str]]:
    functions: list[str] = []
    names: list[str] = []
    for fixture_name, display_name, has_cvote_aux_data in fixtures:
        func_suffix = sanitize_c_identifier(display_name, uppercase=False)
        if not func_suffix:
            raise ValueError(f"Unable to sanitize fixture name {display_name}")
        test_name = f"test_{func_suffix}"
        for suffix, expert_flag in [("expert_off", "false"), ("expert_on", "true")]:
            function_name = f"{test_name}_{suffix}"
            functions.append(
                "static void {function_name}(void **state) {{\n"
                "    (void) state;\n"
                "    run_fixture_with_expert_mode(&{fixture_name}, {expert_flag});\n"
                "}}".format(
                    function_name=function_name,
                    fixture_name=fixture_name,
                    expert_flag=expert_flag,
                )
            )
            names.append(function_name)

            reject_tx_function_name = f"{test_name}_reject_tx_{suffix}"
            functions.append(
                "static void {function_name}(void **state) {{\n"
                "    (void) state;\n"
                "    run_fixture_reject_tx_with_expert_mode(&{fixture_name}, {expert_flag});\n"
                "}}".format(
                    function_name=reject_tx_function_name,
                    fixture_name=fixture_name,
                    expert_flag=expert_flag,
                )
            )
            names.append(reject_tx_function_name)

            if has_cvote_aux_data:
                reject_aux_function_name = f"{test_name}_reject_aux_{suffix}"
                functions.append(
                    "static void {function_name}(void **state) {{\n"
                    "    (void) state;\n"
                    "    run_fixture_reject_aux_with_expert_mode(&{fixture_name}, {expert_flag});\n"
                    "}}".format(
                        function_name=reject_aux_function_name,
                        fixture_name=fixture_name,
                        expert_flag=expert_flag,
                    )
                )
                names.append(reject_aux_function_name)
    return functions, names


def _build_main_function(test_names: Sequence[str], test_c_file: str) -> str:
    registrations = ",\n        ".join(
        f"cmocka_unit_test({name})" for name in test_names
    )
    return (
        "// ======================================================================\n"
        "// Main\n"
        "// ======================================================================\n\n"
        "int main(void) {\n"
        "    const struct CMUnitTest tests[] = {\n"
        f"        {registrations},\n"
        "    };\n"
        f'    return _cmocka_run_group_tests("{Path(test_c_file).stem}", '
        "tests, ARRAY_LEN(tests), NULL, assert_no_pending_apdu_response);\n"
        "}\n"
    )


def _extract_fixtures_from_header(fixture_path: Path) -> list[tuple[str, str, bool]]:
    content = read_file_safe(fixture_path)
    fixtures: list[tuple[str, str, bool]] = []
    for match in _FIXTURE_PATTERN.finditer(content):
        fixture_name = match.group(1)
        body = match.group(2)
        name_match = _NAME_FIELD_PATTERN.search(body)
        if not name_match:
            continue
        display_name = name_match.group(1)
        fixtures.append((fixture_name, display_name, _fixture_has_cvote_aux_data(body)))
    return fixtures


def _build_common_header(fixture_file: str) -> str:
    """Generate the standard header for sign_tx test files."""
    return (
        "// Unit tests for transaction signing (auto-generated)\n"
        "// DO NOT EDIT - regenerate using generators/generate_unit_tests_from_ragger.py\n"
        "\n"
        "#include <stdarg.h>\n"
        "#include <stddef.h>\n"
        "#include <setjmp.h>\n"
        "#include <stdint.h>\n"
        "#include <stdbool.h>\n"
        "#include <string.h>\n"
        "\n"
        "#include <cmocka.h>\n"
        "\n"
        '#include "apdu/dispatcher.h"\n'
        '#include "handler/sign_tx.h"\n'
        '#include "buffer.h"\n'
        '#include "cardano_swo.h"\n'
        '#include "cardano_constants.h"\n'
        '#include "globals.h"\n'
        '#include "tx.h"\n'
        '#include "tx_parse.h"\n'
        '#include "securityPolicy/securityPolicy.h"\n'
        '#include "hexUtils.h"\n'
        '#include "utils/utils.h"\n'
        '#include "blake2b.h"\n'
        '#include "init_apdu.h"\n'
        '#include "io_capture.h"\n'
        '#include "apdu_finalization_check.h"\n'
        "\n"
        f'#include "{fixture_file}"\n'
        "\n"
        '#include "test_sign_tx_common.h"\n'
        '#include "app_mem_utils.h"\n'
        "\n"
        "// ======================================================================\n"
        "// UI code: using REAL ui_display_*.c with mocked NBGL\n"
        "// ======================================================================\n"
        "// The real UI code from ../src/ui/ui_display_tx.c and ui_display_witness.c\n"
        "// is included in cardano_sign_tx_core library. It calls NBGL functions which\n"
        "// are mocked in mock_sources/nbgl_mock.c to auto-approve for testing.\n"
        "// This way we test the actual UI formatting, tag-value pair generation,\n"
        "// and state management logic.\n"
    )


def _generate_complete_test_file(
    era: str, fixture_file: str, test_c_file: str, era_upper: str
) -> int:
    fixture_path = GENERATED_SIGN_TX_DIR / fixture_file
    test_path = GENERATED_SIGN_TX_DIR / test_c_file

    if not fixture_path.exists():
        raise FileNotFoundError(f"Missing fixture header: {fixture_path}")

    era_heading = ERA_COMMENT_OVERRIDES.get(era, f"{era_upper} Era Tests")

    fixtures = _extract_fixtures_from_header(fixture_path)
    if not fixtures:
        raise ValueError(f"No fixtures found in {fixture_file}")

    test_functions, test_names = _build_test_functions(fixtures)
    expected_test_count = 0
    for _, _, has_cvote_aux_data in fixtures:
        expected_test_count += 4
        if has_cvote_aux_data:
            expected_test_count += 2
    if len(test_names) != expected_test_count:
        raise ValueError(
            f"Test count mismatch for {test_c_file}: expected {expected_test_count}, got {len(test_names)}"
        )

    common_header = _build_common_header(fixture_file)
    tests_block = "\n\n".join(test_functions)
    main_block = _build_main_function(test_names, test_c_file)

    era_comment_block = (
        "// ======================================================================\n"
        f"// {era_heading}\n"
        "// ======================================================================\n\n"
    )

    complete_file = (
        common_header.rstrip()
        + "\n\n"
        + era_comment_block
        + tests_block
        + "\n\n"
        + main_block
    )

    write_generated_c_file(test_path, complete_file)
    print(f"Generated {test_c_file}: {len(test_names)} tests")
    return len(test_names)


def generate_tx_test_runners() -> int:

    total_tests = 0
    for era, (fixture_file, test_c_file, era_upper) in ERA_TEST_FILE_MAP.items():
        total_tests += _generate_complete_test_file(
            era, fixture_file, test_c_file, era_upper
        )

    print("\nAll test files generated successfully!")
    return total_tests
