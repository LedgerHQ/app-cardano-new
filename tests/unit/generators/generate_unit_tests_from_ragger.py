#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0

"""
Unified generator for unit-test fixtures derived from ragger sources.
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

_THIS_FILE = Path(__file__).resolve()
_GENERATORS_DIR = _THIS_FILE.parent
_UNIT_TESTS_DIR = _GENERATORS_DIR.parent
_REPO_ROOT = _UNIT_TESTS_DIR.parent
_TESTS_DIR = _REPO_ROOT / "tests"

for import_root in (_UNIT_TESTS_DIR, _REPO_ROOT, _TESTS_DIR):
    import_root_str = str(import_root)
    if import_root_str not in sys.path:
        sys.path.insert(0, import_root_str)

from common import UNIT_TESTS_DIR
from paths import (
    REPO_ROOT,
    GENERATED_DIR,
    GENERATED_SIGN_TX_DIR,
    GENERATED_SIGN_MSG_DIR,
    GENERATED_CVOTE_DIR,
    GENERATED_OPCERT_DIR,
    GENERATED_PUBKEY_DIR,
    GENERATED_DERIVE_ADDRESS_DIR,
    GENERATED_NATIVE_SCRIPT_DIR,
)
from mock_data_utils import regenerate_mock_data


# Match deny fixtures array for counting individual deny cases
_SIGN_TX_DENY_FIXTURES_PATTERN = re.compile(
    r"static const sign_tx_deny_fixture_t SIGN_TX_DENY_FIXTURES\[\]\s*=\s*\{(.*?)\n\};",
    flags=re.DOTALL,
)

# Match individual deny fixture entries inside the array
_SIGN_TX_DENY_ENTRY_PATTERN = re.compile(r"\.name\s*=")
_TX_FIXTURE_PATTERN = re.compile(
    r"static const tx_fixture_t (FIXTURE_[A-Z0-9_]+)\s*=\s*\{(.*?)\};",
    flags=re.DOTALL,
)
_TX_AUX_INCLUDED_PATTERN = re.compile(r"\.include_aux_data_hash\s*=\s*(true|false)")
_TX_AUX_TYPE_PATTERN = re.compile(r"\.aux_data_type\s*=\s*([A-Z0-9_]+|\d+)")

# Import fixture generators
from fixture_generators.tx_generators import (
    generate_tx_fixtures,
)

from fixture_generators.derive_address_generators import (
    generate_address_derivation_fixtures,
)

from fixture_generators.derive_native_script_generators import (
    generate_derive_native_script_fixtures,
)
from fixture_generators.pubkey_generators import (
    generate_pubkey_fixtures,
)
from fixture_generators.sign_msg_generators import (
    generate_sign_msg_fixtures,
)
from fixture_generators.opcert_generators import (
    generate_opcert_fixtures,
)
from fixture_generators.cvote_generators import (
    generate_cvote_fixtures,
)

# Import deny generators
from deny_fixture_generators.tx_deny_generators import (
    generate_tx_deny_fixtures,
)

from deny_fixture_generators.derive_address_deny_generators import (
    generate_address_derivation_deny_fixtures,
)

from deny_fixture_generators.derive_native_script_deny_generators import (
    generate_derive_native_script_deny_fixtures,
)
from deny_fixture_generators.pubkey_deny_generators import (
    generate_pubkey_deny_fixtures,
)
from deny_fixture_generators.opcert_deny_generators import (
    generate_opcert_deny_fixtures,
)
from deny_fixture_generators.cvote_deny_generators import (
    generate_cvote_deny_fixtures,
)

# Import test runners
from test_runner_generators.tx_test_runner_generators import (
    generate_tx_test_runners,
)

from test_runner_generators.derive_address_test_runner_generators import (
    generate_address_derivation_test_runners,
)

from test_runner_generators.derive_native_script_runner_generators import (
    generate_native_script_test_runners,
)
from test_runner_generators.derive_address_deny_runner_generators import (
    generate_address_derivation_deny_test_runners,
)
from test_runner_generators.pubkey_test_runner_generators import (
    generate_pubkey_test_runners,
)
from test_runner_generators.pubkey_deny_runner_generators import (
    generate_pubkey_deny_test_runners,
)
from test_runner_generators.sign_msg_test_runner_generators import (
    generate_sign_msg_test_runners,
)
from test_runner_generators.opcert_test_runner_generators import (
    generate_opcert_test_runners,
)
from test_runner_generators.opcert_deny_runner_generators import (
    generate_opcert_deny_test_runners,
)
from test_runner_generators.cvote_test_runner_generators import (
    generate_cvote_test_runners,
)
from test_runner_generators.cvote_deny_runner_generators import (
    generate_cvote_deny_test_runners,
)
from test_runner_generators.native_script_deny_runner_generators import (
    generate_native_script_deny_test_runners,
)

def _log_stage(message: str) -> None:
    print(f"\n--- {message} ---")


def _count_sign_tx_deny_fixtures() -> int:
    """Return the number of fixtures in sign_tx deny suite to account for per-test coverage."""
    fixtures_file = GENERATED_SIGN_TX_DIR / "test_sign_tx_fixtures_deny.h"
    if not fixtures_file.exists():
        return 0

    try:
        content = fixtures_file.read_text(encoding="utf-8")
    except OSError:
        return 0

    match = _SIGN_TX_DENY_FIXTURES_PATTERN.search(content)
    if not match:
        return 0

    fixture_body = match.group(1)
    return len(_SIGN_TX_DENY_ENTRY_PATTERN.findall(fixture_body))


def _fixture_has_cvote_aux_data(fixture_body: str) -> bool:
    aux_included_match = _TX_AUX_INCLUDED_PATTERN.search(fixture_body)
    aux_type_match = _TX_AUX_TYPE_PATTERN.search(fixture_body)
    if aux_included_match is None or aux_type_match is None:
        return False

    include_aux_data = aux_included_match.group(1) == "true"
    aux_type_token = aux_type_match.group(1)
    return include_aux_data and aux_type_token in {"1", "AUX_DATA_TYPE_CVOTE_REGISTRATION"}


def _count_sign_tx_fine_grained_entries_from_fixtures() -> int:
    """
    Count fine-grained sign-tx entries from fixture headers on disk.

    This mirrors tx runner generation granularity:
    - 4 entries per tx fixture (approve/reject-tx x expert-off/on)
    - +2 entries when fixture has CIP36 aux data (reject-aux x expert-off/on)
    - plus deny fixtures from SIGN_TX_DENY_FIXTURES
    """
    total_entries = 0
    fixture_headers = sorted(
        p
        for p in GENERATED_SIGN_TX_DIR.glob("test_sign_tx_fixtures_*.h")
        if p.name != "test_sign_tx_fixtures_deny.h"
    )

    for fixture_header_path in fixture_headers:
        try:
            header_content = fixture_header_path.read_text(encoding="utf-8")
        except OSError:
            continue

        for fixture_match in _TX_FIXTURE_PATTERN.finditer(header_content):
            fixture_body = fixture_match.group(2)
            total_entries += 4
            if _fixture_has_cvote_aux_data(fixture_body):
                total_entries += 2

    total_entries += _count_sign_tx_deny_fixtures()
    return total_entries


_COMMAND_ORDER = [
    "sign_tx",
    "sign_msg",
    "sign_cvote",
    "sign_opcert",
    "pubkey_export",
    "derive_address",
    "derive_native_script",
]

_COMMAND_DISPLAY_NAMES = {
    "sign_tx": "Sign Transaction",
    "sign_msg": "Sign Message",
    "sign_cvote": "Sign CVote",
    "sign_opcert": "Sign Opcert",
    "pubkey_export": "Pubkey Export",
    "derive_address": "Derive Address",
    "derive_native_script": "Derive Native Script",
}

_RAGGER_FILE_TO_COMMAND = {
    "test_sign_tx.py": "sign_tx",
    "test_signMsg.py": "sign_msg",
    "test_cvote.py": "sign_cvote",
    "test_opcert.py": "sign_opcert",
    "test_pubkey.py": "pubkey_export",
    "test_derive_address.py": "derive_address",
    "test_derive_native_script.py": "derive_native_script",
}

_CMOCKA_TEST_PATTERN = re.compile(r"cmocka_unit_test\(\s*([^)]+?)\s*\)")

_GENERATED_BY_SCRIPT = "tests/unit/generators/generate_unit_tests_from_ragger.py"


def _normalize_generated_output_headers() -> None:
    """Ensure generated unit-test outputs carry SPDX and generator provenance comments."""
    generated_paths = sorted(GENERATED_DIR.rglob("test_*.[ch]"))
    generated_paths.append(UNIT_TESTS_DIR / "mock_crypto" / "crypto_mock_data.h")

    spdx_line_pattern = re.compile(r"^\s*(//|/\*)\s*SPDX-(FileCopyrightText|License-Identifier):")
    generated_by_line_pattern = re.compile(r"^\s*//\s*Generated by:")

    for file_path in generated_paths:
        if not file_path.exists():
            continue

        content = file_path.read_text(encoding="utf-8")
        lower_content = content.lower()
        is_generated = (
            file_path.name == "crypto_mock_data.h"
            or "auto-generated" in lower_content
        )
        if not is_generated:
            continue

        lines = content.splitlines()
        start_idx = 0
        while start_idx < len(lines):
            stripped_line = lines[start_idx].strip()
            if stripped_line == "":
                start_idx += 1
                continue
            if spdx_line_pattern.match(lines[start_idx]) or generated_by_line_pattern.match(lines[start_idx]):
                start_idx += 1
                continue
            break

        body_lines = lines[start_idx:]
        body_lines = [
            line
            for index, line in enumerate(body_lines)
            if not (index < 40 and generated_by_line_pattern.match(line))
        ]
        while body_lines and body_lines[0].strip() in {"", "//"}:
            body_lines.pop(0)
        normalized_lines = [
            "// SPDX-FileCopyrightText: 2025-2026 Vacuumlabs",
            "// SPDX-License-Identifier: Apache-2.0",
            "",
            f"// Generated by: {_GENERATED_BY_SCRIPT}",
            "",
            *body_lines,
        ]
        normalized_content = "\n".join(normalized_lines).rstrip() + "\n"
        file_path.write_text(normalized_content, encoding="utf-8")


def _candidate_function_names_for_coverage_match(function_name: str) -> set[str]:
    """Return function-name variants used when matching generated unit tests."""
    candidate_names = {function_name}
    if function_name.endswith("_hash"):
        candidate_names.add(function_name[:-5])
    return candidate_names


def _extract_cmocka_test_names(file_path: Path) -> tuple[list[str], str]:
    """Return cmocka-registered test names plus the raw file content for coverage checks."""
    try:
        content = file_path.read_text(encoding="utf-8")
    except OSError:
        print(f"WARNING: Could not read {file_path} for counting cmocka tests")
        return [], ""
    names = [match.group(1).strip() for match in _CMOCKA_TEST_PATTERN.finditer(content)]
    return names, content


def _count_unit_tests_by_command() -> tuple[dict[str, int], int, set[str], str]:
    """
    Count unit-test entries per command and return the data along with total generated functions.

    The count is based on cmocka_unit_test() registrations so the reporting stays
    independent of the generator output formatting.
    IMPORTANT: this reads test sources from disk and does not depend on in-memory
    generation-phase counters/state from earlier steps in this script.

    Returns:
        (command_counts, total_funcs, registered_names, combined_content)
        registered_names: set of all function names registered via cmocka_unit_test()
        combined_content: concatenated raw source text (used only for A-vs-B sanity check)
    """
    command_counts: dict[str, int] = {command: 0 for command in _COMMAND_ORDER}
    total_funcs = 0
    registered_names: set[str] = set()
    command_file_contents: list[str] = []

    def _add_file_content_only(path: Path) -> None:
        if not path.exists():
            raise FileNotFoundError(f"Unit test source missing: {path}")
        try:
            command_file_contents.append(path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise OSError(f"Failed reading {path}") from exc

    def _add_file_counts(path: Path, command: str) -> None:
        nonlocal total_funcs
        if not path.exists():
            raise FileNotFoundError(f"Unit test source missing: {path}")
        names, content = _extract_cmocka_test_names(path)
        command_counts[command] += len(names)
        total_funcs += len(names)
        registered_names.update(names)
        command_file_contents.append(content)

    tx_test_files = sorted(
        p for p in GENERATED_SIGN_TX_DIR.glob("test_sign_tx_*.c") if p.name != "test_sign_tx_deny_tests.c"
    )
    for path in tx_test_files:
        _add_file_counts(path, "sign_tx")
    # Keep sign-tx deny runner out of cmocka-based counting (counted via fixtures),
    # but include its source for function-name coverage matching.
    _add_file_content_only(GENERATED_SIGN_TX_DIR / "test_sign_tx_deny_tests.c")

    unit_file_map = {
        "sign_msg": [GENERATED_SIGN_MSG_DIR / "test_sign_msg.c"],
        "sign_cvote": [
            GENERATED_CVOTE_DIR / "test_cvote.c",
            GENERATED_CVOTE_DIR / "test_cvote_deny_tests.c",
        ],
        "sign_opcert": [
            GENERATED_OPCERT_DIR / "test_opcert.c",
            GENERATED_OPCERT_DIR / "test_opcert_deny_tests.c",
        ],
        "pubkey_export": [
            GENERATED_PUBKEY_DIR / "test_pubkey.c",
            GENERATED_PUBKEY_DIR / "test_pubkey_deny_tests.c",
        ],
        "derive_address": [
            GENERATED_DERIVE_ADDRESS_DIR / "test_derive_address.c",
            GENERATED_DERIVE_ADDRESS_DIR / "test_derive_address_deny_tests.c",
        ],
        "derive_native_script": [
            GENERATED_NATIVE_SCRIPT_DIR / "test_native_script.c",
            GENERATED_NATIVE_SCRIPT_DIR / "test_native_script_deny_tests.c",  # regenerated with static registrations
        ],
    }
    for command, file_paths in unit_file_map.items():
        for file_path in file_paths:
            _add_file_counts(file_path, command)

    combined_content = "\n".join(command_file_contents)
    return command_counts, total_funcs, registered_names, combined_content


def _is_covered_by_registered_names(candidate_names: set[str], registered_names: set[str]) -> bool:
    """Option B: check coverage against the authoritative set of cmocka-registered names."""
    return any(
        candidate_name in registered_names
        or any(n.startswith(candidate_name + "_") for n in registered_names)
        for candidate_name in candidate_names
    )


def _is_covered_by_substring(candidate_names: set[str], unit_tests_content: str) -> bool:
    """Option A: word-boundary regex check against raw source text."""
    return any(
        bool(re.search(rf"\b{re.escape(candidate_name)}\b", unit_tests_content))
        for candidate_name in candidate_names
    )


def _verify_ragger_test_coverage() -> None:
    """Verify that all ragger tests have corresponding unit test coverage."""
    # Collect ragger test names using pytest --collect-only
    ragger_tests_dir = REPO_ROOT / "tests" / "standalone"
    if not ragger_tests_dir.exists():
        print("WARNING: Ragger tests directory not found, skipping coverage check")
        return

    venv_pytest = REPO_ROOT / "tests" / "venv" / "bin" / "pytest"
    pytest_cmd = str(venv_pytest) if venv_pytest.exists() else "pytest"

    try:
        # Try to collect with a device parameter (ragger tests require --device)
        result = subprocess.run(
            [pytest_cmd, "--collect-only", "-q", "--device", "stax", str(ragger_tests_dir)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        # Check for collection errors (non-zero return code indicates failure)
        if result.returncode != 0:
            print(f"ERROR: pytest collection failed with return code {result.returncode}")
            if result.stderr:
                print("STDERR output:")
                print(result.stderr)
            if result.stdout:
                print("STDOUT output:")
                print(result.stdout)
            sys.exit(1)
        # Parse test names from pytest output (format: test_file.py::test_name[...])
        ragger_tests = [
            line.strip() for line in result.stdout.split("\n")
            if "::" in line and "test_" in line
        ]
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        print(f"ERROR: Could not collect ragger tests: {exc}")
        sys.exit(1)

    if not ragger_tests:
        print("ERROR: No ragger tests found - check that test files are present and importable")
        sys.exit(1)

    # Count total test cases (including parameterized variants)
    total_ragger_test_cases = len(ragger_tests)

    if not UNIT_TESTS_DIR.exists():
        print(f"ERROR: Unit test directory not found at {UNIT_TESTS_DIR}")
        sys.exit(1)

    ragger_command_counts = {command: 0 for command in _COMMAND_ORDER}
    comparable_ragger_command_counts = {command: 0 for command in _COMMAND_ORDER}
    skip_counts: dict[str, int] = defaultdict(int)
    unmapped_counts: dict[str, int] = defaultdict(int)

    skip_test_files = {
        "test_client_constants.py",
        "test_app_mainmenu.py",
        "test_error_cmd.py",
        "test_mock_key_derivation.py",
        "test_get_app_info.py",
    }
    skip_test_funcs = {
        "test_wrong_data_length",
        # test_sign_tx_deny coverage is tracked via _count_sign_tx_deny_fixtures() /
        # SIGN_TX_DENY_FIXTURES; the unit-test runner (test_sign_tx_deny_fixture) is
        # a fixture-driven loop, not a per-case cmocka registration, so it will never
        # appear in registered_unit_test_names under its ragger name.
        "test_sign_tx_deny",
    }
    ragger_test_funcs = set()

    for test_line in ragger_tests:
        if "::" not in test_line:
            continue
        module_part, func_part = test_line.split("::", 1)
        module_name = Path(module_part).name
        if module_name in skip_test_files:
            skip_counts[module_name] += 1
            continue
        command = _RAGGER_FILE_TO_COMMAND.get(module_name)
        if command:
            ragger_command_counts[command] += 1
            comparable_ragger_command_counts[command] += 1
        else:
            unmapped_counts[module_name] += 1
        func_name = func_part.split("[", 1)[0]
        if func_name and func_name not in skip_test_funcs:
            ragger_test_funcs.add(func_name)

    # Coverage/counting is intentionally filesystem-based and independent from
    # generation-phase bookkeeping; it scans current unit-test files on disk.
    unit_command_counts, total_unit_test_funcs, registered_unit_test_names, unit_tests_content = _count_unit_tests_by_command()
    deny_fixture_count = _count_sign_tx_deny_fixtures()
    if deny_fixture_count:
        unit_command_counts["sign_tx"] += deny_fixture_count
    expanded_unit_test_count = total_unit_test_funcs + deny_fixture_count
    # For sign_tx, compare against fine-grained expected entries (same granularity
    # as generated unit tests), not raw pytest parameterized-case count.
    comparable_ragger_command_counts["sign_tx"] = _count_sign_tx_fine_grained_entries_from_fixtures()

    # Extract unique test function names from ragger tests
    # Format: test_file.py::test_func_name[param] -> extract test_func_name
    missing_coverage = []
    covered_coverage = []
    for func_name in sorted(ragger_test_funcs):
        # Some ragger tests expand into indexed unit tests. Match both the exact
        # function name and generated prefixes.
        candidate_function_names = _candidate_function_names_for_coverage_match(func_name)
        # Primary check (B): coverage is determined by cmocka_unit_test() registrations only.
        found_by_registered = _is_covered_by_registered_names(candidate_function_names, registered_unit_test_names)
        # Sanity check (A): word-boundary regex over raw source text.
        found_by_substring = _is_covered_by_substring(candidate_function_names, unit_tests_content)
        if found_by_substring and not found_by_registered:
            print(
                f"WARNING: coverage inconsistency for '{func_name}': "
                f"found as word-boundary match in source text but NOT in cmocka registrations — "
                f"function may be defined but not registered as a test"
            )
        if found_by_registered:
            covered_coverage.append(func_name)
        else:
            missing_coverage.append(func_name)

    deny_note = ""
    if deny_fixture_count:
        deny_note = (f", includes {deny_fixture_count} fixtures sampled through "
                     f"`SIGN_TX_DENY_FIXTURES`")
    print(f"\nRagger test coverage check:")
    print(f"  Ragger: {total_ragger_test_cases} total test cases from {len(ragger_tests)} parameterized variants")
    print(f"  Unit tests: {expanded_unit_test_count} total test entries "
          f"({total_unit_test_funcs} generated functions{deny_note})")
    print(f"  Command breakdown:")
    for command in _COMMAND_ORDER:
        ragger_count = comparable_ragger_command_counts.get(command, 0)
        unit_count = unit_command_counts.get(command, 0)
        delta = unit_count - ragger_count
        delta_note = f" (Δ {delta:+d})" if delta else ""
        print(f"    - {_COMMAND_DISPLAY_NAMES[command]}: {ragger_count} Ragger -> {unit_count} unit entries{delta_note}")
    if comparable_ragger_command_counts["sign_tx"] != ragger_command_counts["sign_tx"]:
        print(
            "  Note: Sign Transaction uses fine-grained fixture-based counting for comparison "
            f"(raw pytest cases: {ragger_command_counts['sign_tx']})."
        )
    if skip_counts:
        skip_total = sum(skip_counts.values())
        skip_details = ", ".join(f"{name}({count})" for name, count in sorted(skip_counts.items()))
        print(f"  Ignored {skip_total} pytest cases from auxiliary modules ({skip_details})")
    if unmapped_counts:
        unmapped_total = sum(unmapped_counts.values())
        unmapped_details = ", ".join(f"{name}({count})" for name, count in sorted(unmapped_counts.items()))
        print(f"  Unmapped pytest modules ({unmapped_total} cases): {unmapped_details}")
    insufficient_commands = []
    for command in _COMMAND_ORDER:
        ragger_count = comparable_ragger_command_counts.get(command, 0)
        unit_count = unit_command_counts.get(command, 0)
        if unit_count < ragger_count:
            insufficient_commands.append(
                f"{_COMMAND_DISPLAY_NAMES[command]} (Ragger {ragger_count}, Unit {unit_count})"
            )
    if insufficient_commands:
        print(f"  ERROR: insufficient per-command coverage detected: {', '.join(insufficient_commands)}")
    print(f"  Found {len(ragger_test_funcs)} unique ragger test functions to cover")
    print(f"  Coverage: {len(covered_coverage)} functions covered, {len(missing_coverage)} missing")

    if missing_coverage:
        print(f"\n  WARNING: {len(missing_coverage)} test function(s) lack unit test coverage:")
        for test in missing_coverage:
            print(f"    - {test}")

        # Show which test cases are missing for each uncovered function
        print(f"\n  Missing test cases by function:")
        for func_name in missing_coverage:
            # Find all ragger test cases for this function
            missing_test_cases = [
                line.strip() for line in ragger_tests
                if f"::{func_name}[" in line
            ]
            if missing_test_cases:
                print(f"    {func_name}: ({len(missing_test_cases)} cases)")
                for case in missing_test_cases:
                    # Extract just the test case name part for readability
                    if "::" in case:
                        _, test_case = case.split("::", 1)
                        print(f"      - {test_case}")
        print("\n" + "=" * 88)
        print("COVERAGE FAILURE: missing unit-test coverage for one or more ragger test functions.")
        print("The generator run is unsuccessful until all missing functions above are covered.")
        print("=" * 88)
        sys.exit(1)
    else:
        print(f"\n  OK All ragger test functions have unit test coverage")

    # Show breakdown of covered tests
    if covered_coverage:
        print(f"\n  Covered test functions:")
        for test in covered_coverage:
            print(f"    + {test}")


def run_all() -> None:
    _log_stage("Generating fixtures")
    generate_tx_fixtures()
    generate_address_derivation_fixtures()
    generate_derive_native_script_fixtures()
    generate_pubkey_fixtures()
    generate_sign_msg_fixtures()
    generate_opcert_fixtures()
    generate_cvote_fixtures()
    _log_stage("Generating test runners")
    generate_tx_test_runners()
    generate_address_derivation_test_runners()
    generate_native_script_test_runners()
    generate_address_derivation_deny_test_runners()
    generate_pubkey_test_runners()
    generate_sign_msg_test_runners()
    generate_opcert_test_runners()
    generate_cvote_test_runners()
    _log_stage("Generating deny fixtures")
    generate_tx_deny_fixtures()
    generate_address_derivation_deny_fixtures()
    generate_derive_native_script_deny_fixtures()
    generate_pubkey_deny_fixtures()
    generate_pubkey_deny_test_runners()
    generate_opcert_deny_fixtures()
    generate_opcert_deny_test_runners()
    generate_cvote_deny_fixtures()
    generate_cvote_deny_test_runners()
    generate_native_script_deny_test_runners()
    _log_stage("Regenerating mock data")
    regenerate_mock_data()
    _log_stage("Normalizing generated file headers")
    _normalize_generated_output_headers()
    _log_stage("Verifying Ragger coverage")
    # Final coverage/counting is an independent read-back from files on disk.
    _verify_ragger_test_coverage()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate unit-test fixtures from ragger sources."
    )
    subparsers = parser.add_subparsers(dest="command")
    subparsers.add_parser("all", help="Run all generators (default).")
    subparsers.add_parser("fixtures", help="Generate sign-tx fixture headers.")
    subparsers.add_parser(
        "generate-test-runners", help="Regenerate test_sign_tx_*.c files."
    )
    subparsers.add_parser("deny_tests", help="Generate deny fixture headers.")
    subparsers.add_parser("mock-data", help="Regenerate mocks/crypto_mock_data.h.")

    args = parser.parse_args()

    print(f"Unit tests directory: {UNIT_TESTS_DIR}")

    if args.command in (None, "all"):
        run_all()
    elif args.command == "fixtures":
        _log_stage("Generating fixtures")
        generate_tx_fixtures()
        generate_address_derivation_fixtures()
        generate_derive_native_script_fixtures()
        generate_pubkey_fixtures()
        generate_sign_msg_fixtures()
        generate_opcert_fixtures()
        generate_cvote_fixtures()
        _log_stage("Normalizing generated file headers")
        _normalize_generated_output_headers()
    elif args.command == "generate-test-runners":
        _log_stage("Generating test runners")
        generate_tx_test_runners()
        generate_address_derivation_test_runners()
        generate_native_script_test_runners()
        generate_address_derivation_deny_test_runners()
        generate_pubkey_test_runners()
        generate_sign_msg_test_runners()
        generate_opcert_test_runners()
        generate_cvote_test_runners()
        generate_pubkey_deny_test_runners()
        generate_opcert_deny_test_runners()
        generate_cvote_deny_test_runners()
        generate_native_script_deny_test_runners()
        _log_stage("Normalizing generated file headers")
        _normalize_generated_output_headers()
    elif args.command == "deny_tests":
        _log_stage("Generating deny fixtures")
        generate_tx_deny_fixtures()
        generate_address_derivation_deny_fixtures()
        generate_derive_native_script_deny_fixtures()
        generate_pubkey_deny_fixtures()
        generate_opcert_deny_fixtures()
        generate_opcert_deny_test_runners()
        generate_cvote_deny_fixtures()
        generate_cvote_deny_test_runners()
        generate_native_script_deny_test_runners()
        _log_stage("Normalizing generated file headers")
        _normalize_generated_output_headers()
    elif args.command == "mock-data":
        _log_stage("Regenerating mock data")
        regenerate_mock_data()
        _log_stage("Normalizing generated file headers")
        _normalize_generated_output_headers()
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
