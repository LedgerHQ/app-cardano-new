#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0

"""
Mock crypto data regeneration utilities.

Extracts BIP32 paths and signatures from the existing crypto_mock_data.h
template, re-derives all keys and signatures from the standard test mnemonic,
and writes the result back in place.
"""

from __future__ import annotations

import hashlib
import re
import sys

from tests.unit.generators.common import (
    extract_brace_delimited_entries,
    format_bytes_as_c_array,
    resolve_mnemonic,
)
from tests.unit.generators.paths import UNIT_TESTS_DIR


# ======================================================================
# Compiled Regex Patterns (module level for performance)
# ======================================================================

# Match MOCK_PATHS array definition
_MOCK_PATHS_PATTERN = re.compile(
    r"(static\s+const\s+mock_path_data_t\s+MOCK_PATHS\[\]\s*=\s*\{)(.*?)(\};)",
    flags=re.DOTALL,
)

# Match MOCK_SIGNATURES array definition
_MOCK_SIGNATURES_PATTERN = re.compile(
    r"(static\s+const\s+mock_signature_data_t\s+MOCK_SIGNATURES\[\]\s*=\s*\{)(.*?)(\};)",
    flags=re.DOTALL,
)

# Match entry start pattern like: { .path =
_ENTRY_START_PATTERN = re.compile(r"\{\s*\.path\s*=")
_GENERATED_SIGN_TX_MESSAGE_NAME_PATTERN = re.compile(
    r"MOCK_SIGN_TX_TX_HASH_[A-F0-9]{64}"
)

# These hashes are exercised by sign-tx deny fixtures that currently do not expose
# expected_hash_hex in generated metadata, but still reach witness signing.
_DENY_ONLY_REQUIRED_SIGN_TX_MOCKS: tuple[tuple[bytes, tuple[tuple[int, ...], ...]], ...] = (
    (
        bytes.fromhex("3E8C777ECFCCB9DB4772E43CE958C6CAB0E131CD957953026A075D16341D0828"),
        ((0x8000073C, 0x80000717, 0x80000000, 0x00000002, 0x00000000),),
    ),
    (
        bytes.fromhex("BC678441767B195382F00F9F4C4BDDC046F73E6116FA789035105ECDDFDEE949"),
        ((0x8000073C, 0x80000717, 0x80000000, 0x00000002, 0x00000000),),
    ),
)


def _load_sign_tx_generator_helpers() -> tuple[object, object, object, object]:
    try:
        from tests.application_client.command_builder import gather_witness_paths  # type: ignore
        from tests.unit.generators.fixture_generators.sign_tx_generators import (  # type: ignore
            _cbor_hex_to_bytes,
            _compute_blake2b_256,
            _load_sign_tx_tests,
        )
    except ImportError as exc:
        print(f"ERROR: missing dependency: {exc}")
        print("Please activate the venv: source tests/venv/bin/activate")
        sys.exit(1)

    return gather_witness_paths, _cbor_hex_to_bytes, _compute_blake2b_256, _load_sign_tx_tests


def parse_witness_path_to_words(witness_path: str) -> tuple[int, ...]:
    path_parts = witness_path.split("/")
    if path_parts[0] == "m":
        path_parts = path_parts[1:]

    path_words: list[int] = []
    for path_part in path_parts:
        is_hardened = path_part.endswith("'")
        path_index = int(path_part[:-1] if is_hardened else path_part)
        if is_hardened:
            path_index |= 0x80000000
        path_words.append(path_index)
    return tuple(path_words)


def collect_required_sign_tx_signature_keys() -> list[tuple[tuple[int, ...], bytes]]:
    (
        gather_witness_paths,
        _cbor_hex_to_bytes,
        _compute_blake2b_256,
        _load_sign_tx_tests,
    ) = _load_sign_tx_generator_helpers()

    required_signature_keys: list[tuple[tuple[int, ...], bytes]] = []
    seen_signature_keys: set[tuple[tuple[int, ...], bytes]] = set()

    sign_tx_data = _load_sign_tx_tests()
    for sign_tx_test_cases in sign_tx_data["era_tests"].values():
        for test_case in sign_tx_test_cases:
            if getattr(test_case, "unit_test_expect", None) is None:
                continue

            expected_hash_bytes = bytes.fromhex(
                _compute_blake2b_256(
                    _cbor_hex_to_bytes(test_case.unit_test_expect.txBodyHex)
                )
            )

            for witness_path in gather_witness_paths(
                test_case.tx,
                test_case.signingMode,
                getattr(test_case, "additionalWitnessPaths", []),
            ):
                signature_key = (
                    parse_witness_path_to_words(witness_path),
                    expected_hash_bytes,
                )
                if signature_key in seen_signature_keys:
                    continue
                seen_signature_keys.add(signature_key)
                required_signature_keys.append(signature_key)

    for deny_only_hash_bytes, deny_only_paths in _DENY_ONLY_REQUIRED_SIGN_TX_MOCKS:
        for path_words in deny_only_paths:
            signature_key = (path_words, deny_only_hash_bytes)
            if signature_key in seen_signature_keys:
                continue
            seen_signature_keys.add(signature_key)
            required_signature_keys.append(signature_key)

    return required_signature_keys


def regenerate_mock_data() -> None:
    regenerate_mock_data_with_options(verbose=True, report_summary=True)


def regenerate_mock_data_with_options(*, verbose: bool, report_summary: bool) -> None:
    try:
        from ragger.bip import calculate_public_key_and_chaincode, CurveChoice  # type: ignore
        from bip_utils import Bip39SeedGenerator, Bip32Ed25519Kholaw  # type: ignore
        from nacl import bindings  # type: ignore
        from tests.unit.generators.fixture_generators.sign_tx_generators import (  # type: ignore
            _derive_witness_signature,
        )
    except ImportError as exc:
        print(f"ERROR: missing dependency: {exc}")
        print("Please activate the venv: source tests/venv/bin/activate")
        sys.exit(1)

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
        content = input_file.read_text(encoding="utf-8")
    except Exception as exc:
        print(f"ERROR: Failed to read mock data input file {input_file}: {exc}")
        sys.exit(1)

    if verbose:
        print("Regenerating mock data from standard test mnemonic...")
        print(f"Input:  {input_file}")
        print(f"Output: {temp_output_file}\n")

    mock_paths_match = _MOCK_PATHS_PATTERN.search(content)
    if not mock_paths_match:
        raise ValueError(
            "MOCK_PATHS definition not found in mock_crypto/crypto_mock_data.h"
        )

    mock_paths_body = mock_paths_match.group(2)

    path_entries = extract_brace_delimited_entries(
        mock_paths_body, _ENTRY_START_PATTERN
    )
    if not path_entries:
        raise ValueError("No mock path entries were found")
    if verbose:
        print(f"Regenerating {len(path_entries)} mock path entries...")

    def _build_path_entry(entry_text: str) -> str:
        path_match = re.search(r"\.path\s*=\s*(\{[^}]+\})", entry_text)
        path_len_match = re.search(r"\.path_len\s*=\s*(\d+)", entry_text)
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

            if verbose:
                print(f"OK {path_desc}")

            lines: list[str] = []
            lines.append(f'{base_indent}/* Path "{path_desc}" */')
            lines.append("")
            lines.extend(
                [
                    f"{base_indent}{{ .path = {path_array}, .path_len = {path_len},",
                    f'{field_indent}/* Public key (hex): "{derived_pk.hex()}" */',
                    f"{field_indent}.public_key = {{",
                    *format_c_array_block(derived_pk, inner_indent=array_indent),
                    f"{field_indent}}},",
                    f'{field_indent}/* Chain code (hex): "{derived_cc.hex()}" */',
                    f"{field_indent}.chain_code = {{",
                    *format_c_array_block(derived_cc, inner_indent=array_indent),
                    f"{field_indent}}},",
                    f"{field_indent}/* Blake2b-224 key hash: {derived_kh.hex()} */",
                    f"{field_indent}.key_hash = {{",
                    *format_c_array_block(derived_kh, inner_indent=array_indent),
                    f"{field_indent}}},",
                    f"{base_indent}}},",
                    "",
                ]
            )
            return "\n".join(lines)
        except Exception as exc:
            print(f"ERROR: Failed to derive key for {path_desc}: {exc}")
            sys.exit(1)

    regenerated_paths = [_build_path_entry(entry) for entry in path_entries]
    new_mock_body = "\n".join(regenerated_paths).rstrip()
    content = (
        content[: mock_paths_match.start(2)]
        + "\n"
        + new_mock_body
        + "\n"
        + content[mock_paths_match.end(2) :]
    )
    if verbose:
        print(f"Regenerated {len(regenerated_paths)} mock path entries.")

    message_pattern = r"static const uint8_t (\w+)\[\] = \{([^}]+)\};"
    messages: dict[str, bytes] = {}
    for match in re.finditer(message_pattern, content, flags=re.DOTALL):
        name = match.group(1)
        if _GENERATED_SIGN_TX_MESSAGE_NAME_PATTERN.fullmatch(name):
            continue
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
        message_bytes = messages.get(message_name)
        if message_bytes is None:
            supplemental_hash_match = re.fullmatch(
                r"MOCK_SIGN_TX_TX_HASH_([A-F0-9]{64})", message_name
            )
            if supplemental_hash_match is not None:
                message_bytes = bytes.fromhex(supplemental_hash_match.group(1))
                messages[message_name] = message_bytes
        if message_bytes is None:
            raise ValueError(f"Missing message buffer {message_name}")
        bip32_path = parse_bip32_path_from_c_array(path_array)
        child = Bip32Ed25519Kholaw.FromSeed(seed).DerivePath(bip32_path)
        extended_key = child.PrivateKey().Raw().ToBytes()
        return sign_with_extended_key(extended_key, message_bytes)

    def format_path_words(path_words: tuple[int, ...]) -> str:
        return "{ " + ", ".join(f"0x{word:08x}" for word in path_words) + " }"

    generated_sign_tx_hashes: set[bytes] = set()
    supplemental_message_arrays: list[str] = []
    supplemental_signature_entries: list[str] = []
    for path_words, expected_hash_bytes in collect_required_sign_tx_signature_keys():
        message_name = f"MOCK_SIGN_TX_TX_HASH_{expected_hash_bytes.hex().upper()}"
        if expected_hash_bytes not in generated_sign_tx_hashes:
            generated_sign_tx_hashes.add(expected_hash_bytes)
            supplemental_message_arrays.append(
                "\n".join(
                    format_bytes_as_c_array(
                        expected_hash_bytes, message_name
                    ).split("\n")
                )
            )

        witness_path = parse_bip32_path_from_c_array(format_path_words(path_words))
        signature = _derive_witness_signature(witness_path, expected_hash_bytes)
        path_array = format_path_words(path_words)
        base_indent = "    "
        field_indent = base_indent + "      "
        array_indent = field_indent + "    "
        supplemental_signature_entries.append(
            "\n".join(
                [
                    f'{base_indent}/* Path "{witness_path}" message {message_name} (hex "{expected_hash_bytes.hex()}") */',
                    "",
                    f"{base_indent}{{ .path = {path_array}, .path_len = {len(path_words)},",
                    f"{field_indent}.message = {message_name}, .message_len = sizeof({message_name}),",
                    f'{field_indent}/* Signature (hex): "{signature.hex()}" */',
                    f"{field_indent}.signature = {{",
                    *format_c_array_block(signature, inner_indent=array_indent),
                    f"{field_indent}}},",
                    f"{base_indent}}},",
                    "",
                ]
            )
        )

    signature_match = _MOCK_SIGNATURES_PATTERN.search(content)
    if not signature_match:
        raise ValueError(
            "MOCK_SIGNATURES definition not found in mock_crypto/crypto_mock_data.h"
        )

    signature_body = signature_match.group(2)
    signature_entries = extract_brace_delimited_entries(
        signature_body, _ENTRY_START_PATTERN
    )
    signature_entries = [
        entry
        for entry in signature_entries
        if not _GENERATED_SIGN_TX_MESSAGE_NAME_PATTERN.search(entry)
    ]
    if not signature_entries:
        raise ValueError("No mock signature entries were found")
    if verbose:
        print(f"\nRegenerating {len(signature_entries)} mock signature entries...")

    def _build_signature_entry(entry_text: str) -> str:
        path_match = re.search(r"\.path\s*=\s*(\{[^}]+\})", entry_text)
        path_len_match = re.search(r"\.path_len\s*=\s*(\d+)", entry_text)
        message_match = re.search(r"\.message\s*=\s*([A-Z0-9_]+)", entry_text)
        if not path_match or not path_len_match or not message_match:
            raise ValueError("Failed to parse information from mock signature entry")
        path_array = path_match.group(1)
        path_len = int(path_len_match.group(1))
        message_name = message_match.group(1)
        path_desc = parse_bip32_path_from_c_array(path_array, path_len)
        base_indent = "    "
        field_indent = base_indent + "      "
        array_indent = field_indent + "    "

        message_bytes = messages.get(message_name)
        if message_bytes is None:
            supplemental_hash_match = re.fullmatch(
                r"MOCK_SIGN_TX_TX_HASH_([A-F0-9]{64})", message_name
            )
            if supplemental_hash_match is not None:
                message_bytes = bytes.fromhex(supplemental_hash_match.group(1))
        if message_bytes is None:
            raise ValueError(f"Missing message buffer {message_name}")
        message_hex = message_bytes.hex()
        bip32_path = parse_bip32_path_from_c_array(path_array, path_len)

        signature = derive_signature(path_array, message_name)
        signature_hex = signature.hex()

        if verbose:
            print(f"OK Signature {message_name} ({bip32_path})")
            print(f"  message={message_hex}")

        lines: list[str] = []
        lines.append(
            f'{base_indent}/* Path "{path_desc}" message {message_name} (hex "{message_hex}") */'
        )
        lines.append("")
        lines.extend(
            [
                f"{base_indent}{{ .path = {path_array}, .path_len = {path_len},",
                f"{field_indent}.message = {message_name}, .message_len = sizeof({message_name}),",
                f'{field_indent}/* Signature (hex): "{signature_hex}" */',
                f"{field_indent}.signature = {{",
                *format_c_array_block(signature, inner_indent=array_indent),
                f"{field_indent}}},",
                f"{base_indent}}},",
                "",
            ]
        )
        return "\n".join(lines)

    try:
        regenerated_signatures = [
            _build_signature_entry(entry) for entry in signature_entries
        ]
        if supplemental_signature_entries:
            regenerated_signatures.extend(supplemental_signature_entries)
    except Exception as exc:
        print(f"ERROR: Failed to regenerate mock signatures: {exc}")
        sys.exit(1)
    new_signature_body = "\n".join(regenerated_signatures).rstrip()
    prefix_before_signatures = content[: signature_match.start(0)]
    if generated_sign_tx_hashes:
        prefix_before_signatures = re.sub(
            r"\n*static const uint8_t MOCK_SIGN_TX_TX_HASH_[A-F0-9]{64}\[\] = \{.*?\n\};\n+",
            "\n",
            prefix_before_signatures,
            flags=re.DOTALL,
        )
    prefix_before_signatures = prefix_before_signatures.rstrip()
    supplemental_message_body = "\n\n".join(supplemental_message_arrays).rstrip()
    if supplemental_message_body:
        prefix_before_signatures += f"\n\n{supplemental_message_body}\n\n"
    else:
        prefix_before_signatures += "\n\n"
    new_content = (
        prefix_before_signatures
        + content[signature_match.start(0) : signature_match.start(2)]
        + "\n"
        + new_signature_body
        + "\n"
        + content[signature_match.end(2) :]
    )

    try:
        temp_output_file.write_text(new_content)
    except Exception as exc:
        print(
            f"ERROR: Failed to write temporary mock data file {temp_output_file}: {exc}"
        )
        sys.exit(1)

    try:
        temp_output_file.replace(input_file)
    except Exception as exc:
        print(f"ERROR: Failed to replace {input_file} with regenerated content: {exc}")
        sys.exit(1)

    if verbose:
        print(f"\nOK Regenerated mock data written to: {input_file}")
    elif report_summary:
        generated_sign_tx_signature_count = len(supplemental_signature_entries)
        static_signature_count = (
            len(regenerated_signatures) - generated_sign_tx_signature_count
        )
        print(
            "Mock data OK: "
            f"{len(regenerated_paths)} paths, "
            f"{len(regenerated_signatures)} signatures "
            f"({static_signature_count} static, "
            f"{generated_sign_tx_signature_count} generated sign-tx)"
        )
