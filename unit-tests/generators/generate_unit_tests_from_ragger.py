#!/usr/bin/env python3
"""
Unified generator for unit-test fixtures derived from ragger/LedgerJS sources.
"""
from __future__ import annotations

import argparse
import hashlib
import re
import sys
from typing import Dict

from common import (
    UNIT_TESTS_DIR,
)

# Import fixture generators
from fixture_generators.tx_generators import (
    generate_tx_fixtures,
)

from fixture_generators.derive_address_generators import (
    generate_address_derivation_fixtures,
)

# Import reject generators
from reject_fixture_generators.tx_reject_generators import (
    generate_tx_reject_fixtures,
)

from reject_fixture_generators.derive_address_reject_generators import (
    generate_address_derivation_reject_fixtures,
)

# Import test runners
from test_runner_generators.tx_test_runner_generators import (
    generate_tx_test_runners,
)
from test_runner_generators.derive_address_test_runner_generators import (
    generate_address_derivation_test_runners,
)   

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

    def parse_bip32_path_from_c_array(path_array_str: str) -> str:
        hex_values = re.findall(r"0x[0-9a-fA-F]+", path_array_str)
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

    input_file = UNIT_TESTS_DIR / "mock_crypto" / "crypto_mock_data.h"
    temp_output_file = UNIT_TESTS_DIR / "mock_crypto" / "crypto_mock_data_regenerated.h"

    content = input_file.read_text()

    print("Regenerating mock data from standard test mnemonic...")
    print(f"Input:  {input_file}")
    print(f"Output: {temp_output_file}\n")

    entry_match_count = 0

    def regenerate_entry(match: re.Match[str]) -> str:
        nonlocal entry_match_count
        entry_match_count += 1
        path_desc = match.group(2)
        path_array = match.group(3)

        bip32_path = parse_bip32_path_from_c_array(path_array)

        try:
            derived_pk_hex, derived_cc_hex = calculate_public_key_and_chaincode(
                CurveChoice.Ed25519Kholaw, bip32_path, mnemonic=mnemonic
            )

            derived_pk = bytes.fromhex(derived_pk_hex[2:])
            derived_cc = bytes.fromhex(derived_cc_hex)
            derived_kh = hashlib.blake2b(derived_pk, digest_size=28).digest()

            print(f"✓ {path_desc} ({bip32_path})")

            entry_text = match.group(0)
            entry_text = re.sub(
                r'/\* Public key \(hex\): "[^"]*" \*/',
                f'/* Public key (hex): "{derived_pk.hex()}" */',
                entry_text,
            )
            entry_text = re.sub(
                r"\.public_key = \{[^}]+\}",
                f".public_key = {{{format_c_array(derived_pk)}}}",
                entry_text,
            )
            entry_text = re.sub(
                r'/\* Chain code \(hex\): "[^"]*" \*/',
                f'/* Chain code (hex): "{derived_cc.hex()}" */',
                entry_text,
            )
            entry_text = re.sub(
                r"\.chain_code = \{[^}]+\}",
                f".chain_code = {{{format_c_array(derived_cc)}}}",
                entry_text,
            )
            entry_text = re.sub(
                r"/\* Blake2b-224 key hash: [a-f0-9]+ \*/",
                f"/* Blake2b-224 key hash: {derived_kh.hex()} */",
                entry_text,
            )
            entry_text = re.sub(
                r"\.key_hash = \{[^}]+\}",
                f".key_hash = {{{format_c_array(derived_kh)}}}",
                entry_text,
            )
            return entry_text

        except Exception as exc:
            print(f"✗ {path_desc} ({bip32_path}): {exc}")
            return match.group(0)

    pattern = r'(/\* Path "([^"]+)"[^{]+\{ \.path = (\{[^}]+\}).*?\.key_hash = \{[^}]+\},\n    \},)'
    new_content = re.sub(pattern, regenerate_entry, content, flags=re.DOTALL)

    if entry_match_count == 0:
        raise ValueError("No mock path entries were regenerated")

    message_pattern = r"static const uint8_t (\w+)\[\] = \{([^}]+)\};"
    messages: Dict[str, bytes] = {}
    for match in re.finditer(message_pattern, new_content, flags=re.DOTALL):
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

    signature_pattern = (
        r'(/\* Path "([^"]+)" message ([^*]+?) \*/\s*'
        r"\{ \.path = (\{[^}]+\}), \.path_len = [^,]+,\s*"
        r"\.message = ([^,]+),\s*\.message_len = [^,]+,\s*"
        r'/\* Signature \(hex\): "([^"]*)" \*/\s*'
        r"\.signature = \{([^}]+)\},\s*"
        r"\},)"
    )

    signature_match_count = 0

    def regenerate_signature_entry(match: re.Match[str]) -> str:
        nonlocal signature_match_count
        signature_match_count += 1
        message_desc = match.group(3)
        message_name = message_desc.split()[0]
        path_array = match.group(4)
        bip32_path = parse_bip32_path_from_c_array(path_array)

        message_bytes = messages.get(message_name, b"")
        message_hex = message_bytes.hex()
        print(f"✓ Signature {message_name} ({bip32_path})")
        print(f"  message={message_hex}")

        signature = derive_signature(path_array, message_name)
        signature_hex = signature.hex()

        entry_text = match.group(0)
        entry_text = re.sub(
            r'/\* Signature \(hex\): "[^"]*" \*/',
            f'/* Signature (hex): "{signature_hex}" */',
            entry_text,
        )
        entry_text = re.sub(
            r"\.signature = \{[^}]+\}",
            f".signature = {{{format_c_array(signature)}}}",
            entry_text,
        )
        return entry_text

    new_content = re.sub(
        signature_pattern, regenerate_signature_entry, new_content, flags=re.DOTALL
    )

    if signature_match_count == 0:
        raise ValueError("No signature entries were regenerated")

    temp_output_file.write_text(new_content)
    temp_output_file.replace(input_file)

    print(f"\n✓ Regenerated mock data written to: {input_file}")


def run_all() -> None:
    # Generate fixtures
    generate_tx_fixtures()
    generate_address_derivation_fixtures()
    # Generate test runners
    generate_tx_test_runners()
    generate_address_derivation_test_runners()
    # Generate reject fixtures
    generate_tx_reject_fixtures()
    generate_address_derivation_reject_fixtures()
    # Regenerate mock data
    regenerate_mock_data()


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
        generate_tx_fixtures()
        generate_address_derivation_fixtures()
    elif args.command == "generate-test-runners":
        generate_tx_test_runners()
        generate_address_derivation_test_runners()
    elif args.command == "rejects":
        generate_tx_reject_fixtures()
        generate_address_derivation_reject_fixtures()
    elif args.command == "mock-data":
        regenerate_mock_data()
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
