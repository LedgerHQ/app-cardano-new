from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import types
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, Type

from common import (
    read_file_safe,
    write_file_safe,
    sanitize_c_identifier,
    UNIT_TESTS_DIR,
)

ERA_COMMENT_OVERRIDES = {
    "conway_without_certificates": "CONWAY_WITHOUT_CERTIFICATES Era Tests",
    "alonzo_catalyst": "ALONZO_CATALYST Era Tests",
    "alonzo_cip36": "ALONZO_CIP36 Era Tests",
}

ERA_TEST_FILE_MAP: Dict[str, Tuple[str, str, str]] = {
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
}



def _build_test_functions(
    fixtures: Sequence[Tuple[str, str]],
) -> Tuple[List[str], List[str]]:
    functions: List[str] = []
    names: List[str] = []
    for fixture_name, display_name in fixtures:
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
        "tests, ARRAY_LEN(tests), NULL, NULL);\n"
        "}\n"
    )


def _extract_fixtures_from_header(fixture_path: Path) -> List[Tuple[str, str]]:
    content = read_file_safe(fixture_path)
    fixtures: List[Tuple[str, str]] = []
    pattern = re.compile(
        r"static const tx_fixture_t (FIXTURE_[A-Z0-9_]+)\s*=\s*\{(.*?)\};", re.S
    )
    for match in pattern.finditer(content):
        fixture_name = match.group(1)
        body = match.group(2)
        name_match = re.search(r'\.name\s*=\s*"([^"]+)"', body)
        if not name_match:
            continue
        display_name = name_match.group(1)
        fixtures.append((fixture_name, display_name))
    return fixtures


def _generate_complete_test_file(
    era: str, fixture_file: str, test_c_file: str, era_upper: str
) -> None:
    fixture_path = UNIT_TESTS_DIR / fixture_file
    test_path = UNIT_TESTS_DIR / test_c_file

    if not fixture_path.exists():
        raise FileNotFoundError(f"Missing fixture header: {fixture_path}")

    existing = read_file_safe(test_path)

    era_block_match = re.search(
        r"^// =+\n// ([^\n]+ Era Tests)\n// =+\n", existing, re.MULTILINE
    )
    if era_block_match:
        boilerplate = existing[: era_block_match.start()]
        era_heading = era_block_match.group(1)
    else:
        placeholder_match = re.search(
            r"^// Placeholder test - actual tests are generated from fixtures",
            existing,
            re.MULTILINE,
        )
        if not placeholder_match:
            raise ValueError(f"Could not find test section marker in {test_c_file}")
        boilerplate = existing[: placeholder_match.start()]
        era_heading = ERA_COMMENT_OVERRIDES.get(era, f"{era_upper} Era Tests")

    fixtures = _extract_fixtures_from_header(fixture_path)
    if not fixtures:
        raise ValueError(f"No fixtures found in {fixture_file}")

    test_functions, test_names = _build_test_functions(fixtures)
    expected_test_count = len(fixtures) * 2
    if len(test_names) != expected_test_count:
        raise ValueError(
            f"Test count mismatch for {test_c_file}: expected {expected_test_count}, got {len(test_names)}"
        )

    tests_block = "\n\n".join(test_functions)
    main_block = _build_main_function(test_names, test_c_file)

    era_comment_block = (
        "// ======================================================================\n"
        f"// {era_heading}\n"
        "// ======================================================================\n\n"
    )

    complete_file = (
        boilerplate.rstrip()
        + "\n\n"
        + era_comment_block
        + tests_block
        + "\n\n"
        + main_block
    )

    write_file_safe(test_path, complete_file)
    print(f"Generated {test_c_file}: {len(fixtures)} tests")


def generate_tx_test_runners() -> None:

    for era, (fixture_file, test_c_file, era_upper) in ERA_TEST_FILE_MAP.items():
        _generate_complete_test_file(era, fixture_file, test_c_file, era_upper)

    print("\nAll test files generated successfully!")
