#!/usr/bin/env python3
"""
Unified generator for unit-test fixtures derived from ragger/LedgerJS sources.
"""
from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, List

from common import (
    UNIT_TESTS_DIR,
)

REPO_ROOT = Path(__file__).resolve().parents[2]


# ======================================================================
# Compiled Regex Patterns (module level for performance)
# ======================================================================

# Match MOCK_PATHS array definition
_MOCK_PATHS_PATTERN = re.compile(
    r'(static\s+const\s+mock_path_data_t\s+MOCK_PATHS\[\]\s*=\s*\{)(.*?)(\};)',
    flags=re.DOTALL,
)

# Match MOCK_SIGNATURES array definition
_MOCK_SIGNATURES_PATTERN = re.compile(
    r'(static\s+const\s+mock_signature_data_t\s+MOCK_SIGNATURES\[\]\s*=\s*\{)(.*?)(\};)',
    flags=re.DOTALL,
)

# Match entry start pattern like: { .path =
_ENTRY_START_PATTERN = re.compile(r"\{\s*\.path\s*=")

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

# Import reject generators
from reject_fixture_generators.tx_reject_generators import (
    generate_tx_reject_fixtures,
)

from reject_fixture_generators.derive_address_reject_generators import (
    generate_address_derivation_reject_fixtures,
)

from reject_fixture_generators.derive_native_script_reject_generators import (
    generate_derive_native_script_reject_fixtures,
)
from reject_fixture_generators.pubkey_reject_generators import (
    generate_pubkey_reject_fixtures,
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
from test_runner_generators.derive_address_reject_runner_generators import (
    generate_address_derivation_reject_test_runners,
)
from test_runner_generators.pubkey_test_runner_generators import (
    generate_pubkey_test_runners,
)
from test_runner_generators.pubkey_reject_runner_generators import (
    generate_pubkey_reject_test_runners,
)

def _log_stage(message: str) -> None:
    print(f"\n--- {message} ---")


def regenerate_mock_data() -> None:
    try:
        from ragger.bip import calculate_public_key_and_chaincode, CurveChoice  # type: ignore
        from ragger.conftest import configuration as ragger_configuration  # type: ignore
        from bip_utils import Bip39SeedGenerator, Bip32Ed25519Kholaw  # type: ignore
        from nacl import bindings  # type: ignore
    except ImportError as exc:
        print(f"ERROR: missing dependency: {exc}")
        print("Please activate the venv: source ../tests/standalone/venv/bin/activate")
        sys.exit(1)

    default_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

    def resolve_mnemonic() -> str:
        if ragger_configuration is not None:
            optional_seed = getattr(ragger_configuration.OPTIONAL, "CUSTOM_SEED", "")
            if optional_seed:
                return optional_seed
        return default_mnemonic

    mnemonic = resolve_mnemonic()

    def parse_bip32_path_from_c_array(
        path_array_str: str, path_len: int | None = None
    ) -> str:
        hex_values = re.findall(r"0x[0-9a-fA-F]+", path_array_str)
        if path_len is not None:
            hex_values = hex_values[:path_len]
        path_parts = ["m"]
        for hex_val in hex_values:
            val = int(hex_val, 16)
            if val & 0x80000000:
                path_parts.append(f"{val & 0x7FFFFFFF}'")
            else:
                path_parts.append(str(val))
        return "/".join(path_parts)

    def format_c_array(data: bytes, indent: str = "      ") -> str:
        chunks = [data[i : i + 8] for i in range(0, len(data), 8)]
        lines = []
        for i, chunk in enumerate(chunks):
            prefix = "" if i == 0 else indent + " "
            lines.append(prefix + "0x" + ", 0x".join(f"{b:02x}" for b in chunk))
        return (",\n" + indent).join(lines)

    def format_c_array_block(
        data: bytes,
        inner_indent: str = "          ",
    ) -> list[str]:
        """Return multi-line lines for a C array, one chunk per line."""
        if not data:
            return [f"{inner_indent}0x00,"]

        chunks = [data[i : i + 8] for i in range(0, len(data), 8)]
        lines = []
        for chunk in chunks:
            hex_values = ", ".join(f"0x{b:02x}" for b in chunk)
            lines.append(f"{inner_indent}{hex_values},")
        return lines

    input_file = UNIT_TESTS_DIR / "mock_crypto" / "crypto_mock_data.h"
    temp_output_file = UNIT_TESTS_DIR / "mock_crypto" / "crypto_mock_data_regenerated.h"

    if not input_file.exists():
        print(f"ERROR: Mock data input file not found: {input_file}")
        sys.exit(1)

    try:
        content = input_file.read_text()
    except Exception as exc:
        print(f"ERROR: Failed to read mock data input file {input_file}: {exc}")
        sys.exit(1)

    print("Regenerating mock data from standard test mnemonic...")
    print(f"Input:  {input_file}")
    print(f"Output: {temp_output_file}\n")

    mock_paths_match = _MOCK_PATHS_PATTERN.search(content)
    if not mock_paths_match:
        raise ValueError("MOCK_PATHS definition not found in mock_crypto/crypto_mock_data.h")

    mock_paths_body = mock_paths_match.group(2)

    def _extract_entries(body: str) -> List[str]:
        entries: List[str] = []
        search_pos = 0
        while True:
            match = _ENTRY_START_PATTERN.search(body, search_pos)
            if not match:
                break
            start = match.start()
            depth = 0
            idx = start
            while idx < len(body):
                char = body[idx]
                if char == "{":
                    depth += 1
                elif char == "}":
                    depth -= 1
                    if depth == 0:
                        end_idx = idx + 1
                        break
                idx += 1
            else:
                raise ValueError("Unbalanced braces while parsing mock entries")
            while end_idx < len(body) and body[end_idx] in " \t\r\n,":
                end_idx += 1
            entries.append(body[start:end_idx])
            search_pos = end_idx
        return entries

    def _build_path_entry(entry_text: str) -> str:
        path_match = re.search(r'\.path\s*=\s*(\{[^}]+\})', entry_text)
        path_len_match = re.search(r'\.path_len\s*=\s*(\d+)', entry_text)
        if not path_match or not path_len_match:
            raise ValueError("Failed to parse path information in mock entry")
        path_array = path_match.group(1)
        path_len = int(path_len_match.group(1))
        path_desc = parse_bip32_path_from_c_array(path_array, path_len)
        base_indent = "    "
        field_indent = base_indent + "      "
        array_indent = field_indent + "    "

        try:
            derived_pk_hex, derived_cc_hex = calculate_public_key_and_chaincode(
                CurveChoice.Ed25519Kholaw, path_desc, mnemonic=mnemonic
            )
            derived_pk = bytes.fromhex(derived_pk_hex[2:])
            derived_cc = bytes.fromhex(derived_cc_hex)
            derived_kh = hashlib.blake2b(derived_pk, digest_size=28).digest()

            print(f"OK {path_desc}")

            lines: List[str] = []
            lines.append(f"{base_indent}/* Path \"{path_desc}\" */")
            lines.append("")
            lines.extend([
                f"{base_indent}{{ .path = {path_array}, .path_len = {path_len},",
                f'{field_indent}/* Public key (hex): "{derived_pk.hex()}" */',
                f"{field_indent}.public_key = {{",
                *format_c_array_block(derived_pk, inner_indent=array_indent),
                f"{field_indent}}},",
                f'{field_indent}/* Chain code (hex): "{derived_cc.hex()}" */',
                f"{field_indent}.chain_code = {{",
                *format_c_array_block(derived_cc, inner_indent=array_indent),
                f"{field_indent}}},",
                f'{field_indent}/* Blake2b-224 key hash: {derived_kh.hex()} */',
                f"{field_indent}.key_hash = {{",
                *format_c_array_block(derived_kh, inner_indent=array_indent),
                f"{field_indent}}},",
                f"{base_indent}}},",
                "",
            ])
            return "\n".join(lines)
        except Exception as exc:
            print(f"ERROR: Failed to derive key for {path_desc}: {exc}")
            sys.exit(1)

    path_entries = _extract_entries(mock_paths_body)
    if not path_entries:
        raise ValueError("No mock path entries were found")
    print(f"Regenerating {len(path_entries)} mock path entries...")
    regenerated_paths = [_build_path_entry(entry) for entry in path_entries]
    new_mock_body = "\n".join(regenerated_paths).rstrip()
    content = (
        content[: mock_paths_match.start(2)]
        + "\n"
        + new_mock_body
        + "\n"
        + content[mock_paths_match.end(2) :]
    )
    print(f"Regenerated {len(regenerated_paths)} mock path entries.")

    message_pattern = r"static const uint8_t (\w+)\[\] = \{([^}]+)\};"
    messages: Dict[str, bytes] = {}
    for match in re.finditer(message_pattern, content, flags=re.DOTALL):
        name = match.group(1)
        hex_values = re.findall(r"0x[0-9a-fA-F]{2}", match.group(2))
        if not hex_values:
            continue
        messages[name] = bytes(int(value, 16) for value in hex_values)

    seed = Bip39SeedGenerator(mnemonic).Generate()

    def sign_with_extended_key(extended_key: bytes, message: bytes) -> bytes:
        if len(extended_key) != 64:
            raise ValueError(f"Unexpected extended key length {len(extended_key)}")
        secret_scalar = extended_key[:32]
        prefix = extended_key[32:64]

        r_hash = hashlib.sha512(prefix + message).digest()
        r_scalar = bindings.crypto_core_ed25519_scalar_reduce(r_hash)
        r_point = bindings.crypto_scalarmult_ed25519_base_noclamp(r_scalar)

        public_key = bindings.crypto_scalarmult_ed25519_base_noclamp(secret_scalar)
        k_hash = hashlib.sha512(r_point + public_key + message).digest()
        k_scalar = bindings.crypto_core_ed25519_scalar_reduce(k_hash)

        k_times_a = bindings.crypto_core_ed25519_scalar_mul(k_scalar, secret_scalar)
        s_scalar = bindings.crypto_core_ed25519_scalar_add(r_scalar, k_times_a)

        return r_point + s_scalar

    def derive_signature(path_array: str, message_name: str) -> bytes:
        if message_name not in messages:
            raise ValueError(f"Missing message buffer {message_name}")
        bip32_path = parse_bip32_path_from_c_array(path_array)
        child = Bip32Ed25519Kholaw.FromSeed(seed).DerivePath(bip32_path)
        extended_key = child.PrivateKey().Raw().ToBytes()
        return sign_with_extended_key(extended_key, messages[message_name])

    signature_match = _MOCK_SIGNATURES_PATTERN.search(content)
    if not signature_match:
        raise ValueError(
            "MOCK_SIGNATURES definition not found in mock_crypto/crypto_mock_data.h"
        )

    signature_body = signature_match.group(2)
    signature_entries = _extract_entries(signature_body)
    if not signature_entries:
        raise ValueError("No mock signature entries were found")
    print(f"\nRegenerating {len(signature_entries)} mock signature entries...")

    def _build_signature_entry(entry_text: str) -> str:
        path_match = re.search(r'\.path\s*=\s*(\{[^}]+\})', entry_text)
        path_len_match = re.search(r'\.path_len\s*=\s*(\d+)', entry_text)
        message_match = re.search(r'\.message\s*=\s*([A-Z0-9_]+)', entry_text)
        if not path_match or not path_len_match or not message_match:
            raise ValueError("Failed to parse information from mock signature entry")
        path_array = path_match.group(1)
        path_len = int(path_len_match.group(1))
        message_name = message_match.group(1)
        path_desc = parse_bip32_path_from_c_array(path_array, path_len)
        base_indent = "    "
        field_indent = base_indent + "      "
        array_indent = field_indent + "    "
        base_indent = "    "
        field_indent = base_indent + "      "
        array_indent = field_indent + "    "

        message_bytes = messages.get(message_name)
        if message_bytes is None:
            raise ValueError(f"Missing message buffer {message_name}")
        message_hex = message_bytes.hex()
        bip32_path = parse_bip32_path_from_c_array(path_array, path_len)

        signature = derive_signature(path_array, message_name)
        signature_hex = signature.hex()

        print(f"OK Signature {message_name} ({bip32_path})")
        print(f"  message={message_hex}")

        lines: List[str] = []
        lines.append(
            f'{base_indent}/* Path "{path_desc}" message {message_name} (hex "{message_hex}") */'
        )
        lines.append("")
        lines.extend([
            f"{base_indent}{{ .path = {path_array}, .path_len = {path_len},",
            f"{field_indent}.message = {message_name}, .message_len = sizeof({message_name}),",
            f'{field_indent}/* Signature (hex): "{signature_hex}" */',
            f"{field_indent}.signature = {{",
            *format_c_array_block(signature, inner_indent=array_indent),
            f"{field_indent}}},",
            f"{base_indent}}},",
            "",
        ])
        return "\n".join(lines)

    try:
        regenerated_signatures = [_build_signature_entry(entry) for entry in signature_entries]
    except Exception as exc:
        print(f"ERROR: Failed to regenerate mock signatures: {exc}")
        sys.exit(1)
    new_signature_body = "\n".join(regenerated_signatures).rstrip()
    new_content = (
        content[: signature_match.start(2)]
        + "\n"
        + new_signature_body
        + "\n"
        + content[signature_match.end(2) :]
    )

    try:
        temp_output_file.write_text(new_content)
    except Exception as exc:
        print(f"ERROR: Failed to write temporary mock data file {temp_output_file}: {exc}")
        sys.exit(1)

    try:
        temp_output_file.replace(input_file)
    except Exception as exc:
        print(f"ERROR: Failed to replace {input_file} with regenerated content: {exc}")
        sys.exit(1)

    print(f"\nOK Regenerated mock data written to: {input_file}")


def _verify_ragger_test_coverage() -> None:
    """Verify that all ragger tests have corresponding unit test coverage."""
    # Collect ragger test names using pytest --collect-only
    ragger_tests_dir = REPO_ROOT / "tests" / "standalone"
    if not ragger_tests_dir.exists():
        print("WARNING: Ragger tests directory not found, skipping coverage check")
        return

    try:
        # Try to collect with a device parameter (ragger tests require --device)
        result = subprocess.run(
            ["pytest", "--collect-only", "-q", "--device", "stax", str(ragger_tests_dir)],
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

    # Check unit tests for coverage (C test files in UNIT_TESTS_DIR)
    if not UNIT_TESTS_DIR.exists():
        print(f"ERROR: Unit test directory not found at {UNIT_TESTS_DIR}")
        sys.exit(1)

    try:
        result = subprocess.run(
            ["grep", "-r", "test_", str(UNIT_TESTS_DIR)],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode not in (0, 1):  # 0 = found, 1 = not found, anything else is error
            print(f"ERROR: grep command failed with return code {result.returncode}")
            if result.stderr:
                print(f"STDERR: {result.stderr}")
            sys.exit(1)
        unit_tests_content = result.stdout
    except subprocess.TimeoutExpired:
        print("ERROR: grep timeout while checking unit tests (exceeded 10 seconds)")
        sys.exit(1)
    except Exception as exc:
        print(f"ERROR: Failed to search unit test files: {exc}")
        sys.exit(1)

    # Count unit test cases from generated test files only
    # Generated files: test_sign_tx_*.c, test_derive_address.c, test_native_script.c, etc.
    generated_test_patterns = [
        "test_sign_tx_",
        "test_derive_address.c",
        "test_native_script.c",
        "test_derive_address_rejects.c",
        "test_native_script_rejects.c",
        "test_pubkey.c",
        "test_pubkey_rejects.c",
        "test_opcert_message.c",
        "test_message_signing.c",
    ]

    total_unit_test_funcs = 0
    try:
        result = subprocess.run(
            ["find", str(UNIT_TESTS_DIR), "-maxdepth", "1", "-name", "*.c", "-type", "f"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            print(f"ERROR: find command failed with return code {result.returncode}")
            if result.stderr:
                print(f"STDERR: {result.stderr}")
            sys.exit(1)

        generated_files = []
        for file_path in result.stdout.split("\n"):
            if file_path.strip():
                file_name = Path(file_path).name
                if any(pattern in file_name for pattern in generated_test_patterns):
                    generated_files.append(file_path.strip())

        if generated_files:
            result = subprocess.run(
                ["grep", "-h", "static void test_"] + generated_files,
                capture_output=True,
                text=True,
                timeout=10,
            )
            # grep returns 1 if no matches found, which is OK
            if result.returncode not in (0, 1):
                print(f"ERROR: grep command failed with return code {result.returncode}")
                if result.stderr:
                    print(f"STDERR: {result.stderr}")
                sys.exit(1)
            total_unit_test_funcs = len([line for line in result.stdout.split("\n") if line.strip()])
    except subprocess.TimeoutExpired as exc:
        print(f"ERROR: Command timed out while scanning unit tests: {exc}")
        sys.exit(1)
    except Exception as exc:
        print(f"ERROR: Failed to scan unit test files: {exc}")
        sys.exit(1)

    # Extract unique test function names from ragger tests
    # Format: test_file.py::test_func_name[param] -> extract test_func_name
    # Skip tests that don't need C unit test fixtures
    skip_test_files = {"test_client_constants.py", "test_app_mainmenu.py", "test_error_cmd.py", "test_mock_key_derivation.py"}
    skip_test_funcs = {"test_wrong_data_length"}
    ragger_test_funcs = set()
    for test_line in ragger_tests:
        if "::" in test_line:
            # Skip tests from certain files that don't need C fixtures
            if any(skip_file in test_line for skip_file in skip_test_files):
                continue
            # Extract test function name (between :: and [ or end of line)
            parts = test_line.split("::")
            if len(parts) >= 2:
                func_with_params = parts[1]
                func_name = func_with_params.split("[")[0]
                if func_name and func_name not in skip_test_funcs:
                    ragger_test_funcs.add(func_name)

    missing_coverage = []
    covered_coverage = []
    for func_name in sorted(ragger_test_funcs):
        # Check if the ragger test function name appears in unit tests
        # Some functions like test_derive_native_script_hash expand to test_derive_native_script_*
        # So we check for both exact match and prefix match (with underscore)
        found = (func_name in unit_tests_content or
                 f"{func_name}_" in unit_tests_content or
                 func_name.rstrip("_hash") in unit_tests_content or
                 func_name.rstrip("_rejects") in unit_tests_content)
        if found:
            covered_coverage.append(func_name)
        else:
            missing_coverage.append(func_name)

    print(f"\nRagger test coverage check:")
    print(f"  Ragger: {total_ragger_test_cases} total test cases from {len(ragger_tests)} parameterized variants")
    print(f"  Unit tests: {total_unit_test_funcs} test functions generated")
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
    _log_stage("Generating test runners")
    generate_tx_test_runners()
    generate_address_derivation_test_runners()
    generate_native_script_test_runners()
    generate_address_derivation_reject_test_runners()
    generate_pubkey_test_runners()
    _log_stage("Generating reject fixtures")
    generate_tx_reject_fixtures()
    generate_address_derivation_reject_fixtures()
    generate_derive_native_script_reject_fixtures()
    generate_pubkey_reject_fixtures()
    generate_pubkey_reject_test_runners()
    _log_stage("Regenerating mock data")
    regenerate_mock_data()
    _log_stage("Verifying Ragger coverage")
    _verify_ragger_test_coverage()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate unit-test fixtures from ragger/LedgerJS sources."
    )
    subparsers = parser.add_subparsers(dest="command")
    subparsers.add_parser("all", help="Run all generators (default).")
    subparsers.add_parser("fixtures", help="Generate sign-tx fixture headers.")
    subparsers.add_parser(
        "generate-test-runners", help="Regenerate test_sign_tx_*.c files."
    )
    subparsers.add_parser("rejects", help="Generate reject fixture headers.")
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
    elif args.command == "generate-test-runners":
        _log_stage("Generating test runners")
        generate_tx_test_runners()
        generate_address_derivation_test_runners()
        generate_native_script_test_runners()
        generate_address_derivation_reject_test_runners()
        generate_pubkey_test_runners()
        generate_pubkey_reject_fixtures()
        generate_pubkey_reject_test_runners()
    elif args.command == "rejects":
        _log_stage("Generating reject fixtures")
        generate_tx_reject_fixtures()
        generate_address_derivation_reject_fixtures()
        generate_derive_native_script_reject_fixtures()
        generate_pubkey_reject_fixtures()
    elif args.command == "mock-data":
        _log_stage("Regenerating mock data")
        regenerate_mock_data()
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
