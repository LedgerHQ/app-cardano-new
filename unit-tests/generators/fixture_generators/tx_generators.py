# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0

import hashlib
import re
from typing import Any, Sequence

from common import (
    _ensure_base58_module,
    _add_tests_to_sys_path,
    read_file_safe,
    write_file_safe,
    sanitize_c_identifier,
    extract_apdu_payload,
    format_bytes_as_c_array,
)
from paths import GENERATED_SIGN_TX_DIR, UNIT_TESTS_DIR


# ======================================================================
# Compiled Regex Patterns (module level for performance)
# ======================================================================

# Match tx_fixture_t declarations
_TX_FIXTURE_PATTERN = re.compile(r"static const tx_fixture_t [A-Z0-9_]+\s*=\s*\{")


def _split_hex_string(hex_str: str, chunk_size: int = 1024) -> list[str]:
    return [hex_str[i : i + chunk_size] for i in range(0, len(hex_str), chunk_size)]


def _compute_blake2b_256(data: bytes) -> str:
    return hashlib.blake2b(data, digest_size=32).hexdigest()


_MOCK_SIGNATURE_LOOKUP: dict[tuple[tuple[int, ...], bytes], bytes] | None = None


def _parse_path_to_words(path: str) -> tuple[int, ...]:
    path_parts = path.split("/")
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


def _extract_braced_entries(body: str) -> list[str]:
    entries: list[str] = []
    start_index = 0
    while True:
        entry_start = body.find("{ .path =", start_index)
        if entry_start == -1:
            break
        depth = 0
        cursor = entry_start
        while cursor < len(body):
            char = body[cursor]
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    entries.append(body[entry_start:cursor + 1])
                    start_index = cursor + 1
                    break
            cursor += 1
        else:
            raise ValueError("Unbalanced braces while parsing mock signature entries")
    return entries


def _load_mock_signature_lookup() -> dict[tuple[tuple[int, ...], bytes], bytes]:
    global _MOCK_SIGNATURE_LOOKUP
    if _MOCK_SIGNATURE_LOOKUP is not None:
        return _MOCK_SIGNATURE_LOOKUP

    mock_data_path = UNIT_TESTS_DIR / "mock_crypto" / "crypto_mock_data.h"
    mock_data_content = read_file_safe(mock_data_path)

    message_lookup: dict[str, bytes] = {}
    for message_match in re.finditer(
        r"static const uint8_t (\w+)\[\] = \{([^}]+)\};",
        mock_data_content,
        flags=re.DOTALL,
    ):
        message_name = message_match.group(1)
        message_hex_values = re.findall(r"0x[0-9a-fA-F]{2}", message_match.group(2))
        if not message_hex_values:
            continue
        message_lookup[message_name] = bytes(int(value, 16) for value in message_hex_values)

    signatures_match = re.search(
        r"static const mock_signature_data_t MOCK_SIGNATURES\[\]\s*=\s*\{(.*?)\n\};",
        mock_data_content,
        flags=re.DOTALL,
    )
    if signatures_match is None:
        raise ValueError("MOCK_SIGNATURES array not found in mock_crypto/crypto_mock_data.h")

    signature_lookup: dict[tuple[tuple[int, ...], bytes], bytes] = {}
    for signature_entry in _extract_braced_entries(signatures_match.group(1)):
        path_match = re.search(r"\.path\s*=\s*(\{[^}]+\})", signature_entry)
        path_len_match = re.search(r"\.path_len\s*=\s*(\d+)", signature_entry)
        message_name_match = re.search(r"\.message\s*=\s*(\w+)", signature_entry)
        signature_match = re.search(r"\.signature\s*=\s*\{([^}]*)\}", signature_entry, flags=re.DOTALL)
        if (
            path_match is None
            or path_len_match is None
            or message_name_match is None
            or signature_match is None
        ):
            continue

        path_hex_values = re.findall(r"0x[0-9a-fA-F]+", path_match.group(1))
        path_len = int(path_len_match.group(1))
        path_words = tuple(int(value, 16) for value in path_hex_values[:path_len])
        message_name = message_name_match.group(1)
        if message_name not in message_lookup:
            continue
        signature_hex_values = re.findall(r"0x[0-9a-fA-F]{2}", signature_match.group(1))
        signature_bytes = bytes(int(value, 16) for value in signature_hex_values)
        signature_lookup[(path_words, message_lookup[message_name])] = signature_bytes

    _MOCK_SIGNATURE_LOOKUP = signature_lookup
    return signature_lookup


def _compute_fallback_mock_signature(path_words: tuple[int, ...], message: bytes) -> bytes:
    signature = bytearray(64)
    for signature_index in range(64):
        signature_byte = message[signature_index % len(message)]
        if len(path_words) > 0:
            path_word = path_words[signature_index % len(path_words)]
            signature_byte ^= (path_word >> ((signature_index % 4) * 8)) & 0xFF
        signature[signature_index] = signature_byte ^ ((0xA5 + signature_index) & 0xFF)
    return bytes(signature)


def _derive_witness_signature(witness_path: str, message: bytes) -> bytes:
    path_words = _parse_path_to_words(witness_path)
    signature_lookup = _load_mock_signature_lookup()
    return signature_lookup.get(
        (path_words, message),
        _compute_fallback_mock_signature(path_words, message),
    )


def _bool_to_c(value: bool) -> str:
    return "true" if value else "false"


def _cbor_hex_to_bytes(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str.replace(" ", "").replace("\n", ""))


def _extract_aux_data_hash_from_tx_body(hex_str: str) -> str | None:
    import cbor2  # type: ignore

    try:
        parsed = cbor2.loads(_cbor_hex_to_bytes(hex_str))
    except Exception:
        return None

    if not isinstance(parsed, dict):
        return None

    aux_hash = parsed.get(7)
    if isinstance(aux_hash, (bytes, bytearray)) and len(aux_hash) == 32:
        return aux_hash.hex()
    return None


def _count_fixture_structs(header_text: str) -> int:
    return len(_TX_FIXTURE_PATTERN.findall(header_text))


def _generate_fixtures_for_era(
    era_key: str,
    tests: Sequence[Any],
    aux_data_classes: dict[str, Any],
) -> None:
    from application_client.command_builder import CommandBuilder, gather_witness_paths  # type: ignore

    TxAuxiliaryDataCIP36 = aux_data_classes["TxAuxiliaryDataCIP36"]
    TxAuxiliaryDataType = aux_data_classes["TxAuxiliaryDataType"]
    TxAuxiliaryDataHash = aux_data_classes["TxAuxiliaryDataHash"]

    print(f"Generating C fixtures for {era_key.upper()} era ({len(tests)} tests)...")
    print()

    header_lines = [
        f"// Auto-generated file - DO NOT EDIT",
        "//",
        f"// Generated by: unit-tests/generators/generate_unit_tests_from_ragger.py",
        "// Generator: fixture_generators/tx_generators.py",
        f"// Source: tests/standalone/input_files/signTx.py ({era_key} era tests)",
        "//",
        "// To regenerate:",
        "//   cd unit-tests",
        "//   python3 generators/generate_unit_tests_from_ragger.py",
        "//",
        "// Each fixture includes source traceability comments showing:",
        "//   - Source file and era",
        "//   - Original Ragger test name",
        "//",
        f"// Total tests in this era: {len(tests)}",
        "",
        "#pragma once",
        "",
        "#include <stdint.h>",
        "#include <stddef.h>",
        '#include "test_fixture_types.h"',
        "",
        "// ======================================================================",
        "// Fixtures",
        "// ======================================================================",
        "",
        "#if defined(__clang__)",
        "#pragma clang diagnostic push",
        '#pragma clang diagnostic ignored "-Woverlength-strings"',
        "#elif defined(__GNUC__)",
        "#pragma GCC diagnostic push",
        '#pragma GCC diagnostic ignored "-Woverlength-strings"',
        "#endif",
        "",
    ]

    for test_index, test_case in enumerate(tests):
        print(f"  [{test_index + 1}/{len(tests)}] {test_case.name}...")

        tx = test_case.tx
        builder = CommandBuilder()
        raw_tx_bytes = builder._serialize_transaction_unpacked_raw(tx)

        if test_case.txBody is None:
            raise ValueError(
                f"Test case '{test_case.name}' is missing txBody. "
                "Every sign-tx fixture must supply the expected CBOR-encoded transaction body hex. "
                "The fallback of using the raw APDU wire format is incorrect and was removed."
            )
        expected_cbor_hex = test_case.txBody
        cbor_bytes = _cbor_hex_to_bytes(expected_cbor_hex)
        expected_hash_hex = _compute_blake2b_256(cbor_bytes)
        body_aux_data_hash = _extract_aux_data_hash_from_tx_body(expected_cbor_hex)

        safe_name = sanitize_c_identifier(test_case.name)
        fixture_prefix = f"FIXTURE_{era_key.upper()}_{safe_name}"

        include_aux_data_hash = tx.auxiliaryData is not None
        aux_data_type = 0
        aux_data_hash_hex = body_aux_data_hash
        aux_data_init_payload = b""
        aux_data_delegation_payloads: list[bytes] = []
        if include_aux_data_hash:
            if tx.auxiliaryData.type == TxAuxiliaryDataType.ARBITRARY_HASH:
                aux_data_type = int(TxAuxiliaryDataType.ARBITRARY_HASH)
                aux_params = tx.auxiliaryData.params
                if isinstance(aux_params, TxAuxiliaryDataHash):
                    aux_data_hash_hex = aux_params.hashHex
                else:
                    include_aux_data_hash = False
            elif tx.auxiliaryData.type == TxAuxiliaryDataType.CIP36_REGISTRATION:
                aux_data_type = int(TxAuxiliaryDataType.CIP36_REGISTRATION)
                aux_params = tx.auxiliaryData.params
                if isinstance(aux_params, TxAuxiliaryDataCIP36):
                    aux_data_init_apdu = builder.sign_tx_aux_data_init(tx, aux_params)
                    aux_data_init_payload = extract_apdu_payload(aux_data_init_apdu)
                    for delegation in aux_params.delegations:
                        reg_apdu = builder.sign_tx_aux_data_delegation(delegation)
                        aux_data_delegation_payloads.append(
                            extract_apdu_payload(reg_apdu)
                        )
                else:
                    include_aux_data_hash = False

        if not hasattr(tx, "scriptDataHash"):
            print(
                f"WARNING: tx {test_case.name} missing scriptDataHash; "
                "defaulting include_script_data_hash=False"
            )
        include_script_data_hash = getattr(tx, "scriptDataHash", None) is not None

        options_value = (
            "TX_OPTIONS_TAG_CBOR_SETS" if "d90102" in expected_cbor_hex.lower() else "0"
        )
        network_id_value = int(test_case.tx.network.networkId)
        protocol_magic_value = int(test_case.tx.network.protocol)

        header_lines.append(f"// Test {test_index}: {test_case.name}")
        header_lines.append(f"// Source: tests/standalone/input_files/signTx.py > {era_key} era tests")
        header_lines.append("//")

        array_lines = format_bytes_as_c_array(
            raw_tx_bytes,
            f"{fixture_prefix}_RAW_TX",
        ).split("\n")
        header_lines.extend(array_lines)
        header_lines.append("")
        if include_aux_data_hash and aux_data_type == int(
            TxAuxiliaryDataType.CIP36_REGISTRATION
        ):
            init_payload_name = f"{fixture_prefix}_AUX_DATA_INIT_PAYLOAD"
            init_payload_lines = format_bytes_as_c_array(
                aux_data_init_payload,
                init_payload_name,
            ).split("\n")
            header_lines.extend(init_payload_lines)
            header_lines.append("")

            delegations_name = f"{fixture_prefix}_AUX_DATA_DELEGATIONS"
            if aux_data_delegation_payloads:
                delegation_entries = []
                for reg_index, payload in enumerate(aux_data_delegation_payloads):
                    entry_name = f"{fixture_prefix}_AUX_DATA_DELEGATION_{reg_index}"
                    reg_lines = format_bytes_as_c_array(payload, entry_name).split(
                        "\n"
                    )
                    header_lines.extend(reg_lines)
                    header_lines.append("")
                    delegation_entries.append(
                        f"    {{ .payload = {entry_name}, .payload_len = sizeof({entry_name}) }},"
                    )
                header_lines.append(
                    f"static const aux_data_payload_t {delegations_name}[] = {{"
                )
                header_lines.extend(delegation_entries)
                header_lines.append("};")
            header_lines.append("")
        witness_paths = gather_witness_paths(
            tx,
            test_case.signingMode,
            getattr(test_case, "additionalWitnessPaths", []),
        )
        witness_declaration_lines = []
        witness_payload_entries = []
        witness_payloads_name = f"{fixture_prefix}_WITNESS_PAYLOADS"
        expected_hash_bytes = bytes.fromhex(expected_hash_hex)
        for witness_index, witness_path in enumerate(witness_paths):
            witness_payload_name = f"{fixture_prefix}_WITNESS_{witness_index}_PAYLOAD"
            witness_signature_name = f"{fixture_prefix}_WITNESS_{witness_index}_EXPECTED_SIGNATURE"
            witness_apdu = builder.sign_tx_witness(witness_path)
            witness_payload = extract_apdu_payload(witness_apdu)
            witness_signature = _derive_witness_signature(
                witness_path,
                expected_hash_bytes,
            )
            witness_lines = format_bytes_as_c_array(
                witness_payload,
                witness_payload_name,
            ).split("\n")
            witness_declaration_lines.extend(witness_lines)
            witness_declaration_lines.append("")
            witness_signature_lines = format_bytes_as_c_array(
                witness_signature,
                witness_signature_name,
            ).split("\n")
            witness_declaration_lines.extend(witness_signature_lines)
            witness_declaration_lines.append("")
            witness_payload_entries.append(
                "    { .payload = "
                f"{witness_payload_name}, .payload_len = sizeof({witness_payload_name}), "
                f".expected_signature = {witness_signature_name} }},"
            )
        if witness_payload_entries:
            witness_declaration_lines.append(f"static const witness_payload_t {witness_payloads_name}[] = {{")
            witness_declaration_lines.extend(witness_payload_entries)
            witness_declaration_lines.append("};")
            witness_declaration_lines.append("")

        header_lines.extend(witness_declaration_lines)
        header_lines.append(f"static const tx_fixture_t {fixture_prefix} = {{")
        header_lines.append(f'    .name = "{test_case.name}",')
        header_lines.append(f"    .raw_tx = {fixture_prefix}_RAW_TX,")
        header_lines.append(f"    .raw_tx_len = sizeof({fixture_prefix}_RAW_TX),")
        tx_body_chunks = _split_hex_string(expected_cbor_hex, chunk_size=1024)
        if len(tx_body_chunks) == 1:
            header_lines.append(f'    .tx_body_cbor_hex = "{tx_body_chunks[0]}",')
        else:
            header_lines.append(f'    .tx_body_cbor_hex = "{tx_body_chunks[0]}"')
            for chunk in tx_body_chunks[1:-1]:
                header_lines.append(f'                         "{chunk}"')
            header_lines.append(f'                         "{tx_body_chunks[-1]}",')
        header_lines.append(f'    .expected_hash_hex = "{expected_hash_hex}",')
        header_lines.append(f"    .signing_mode = {int(test_case.signingMode)},")
        header_lines.append(f"    .network_id = {network_id_value},")
        header_lines.append(f"    .protocol_magic = {protocol_magic_value},")
        header_lines.append(f"    .num_inputs = {len(tx.inputs)},")
        header_lines.append(f"    .num_outputs = {len(tx.outputs)},")
        header_lines.append(f"    .num_witnesses = {len(witness_paths)},")
        if witness_payload_entries:
            header_lines.append(f"    .witness_payloads = {witness_payloads_name},")
            header_lines.append(
                f"    .witness_payload_count = {len(witness_payload_entries)},"
            )
        else:
            header_lines.append("    .witness_payloads = NULL,")
            header_lines.append("    .witness_payload_count = 0,")
        header_lines.append(
            f"    .num_certificates = {len(tx.certificates) if tx.certificates else 0},"
        )
        header_lines.append(
            f"    .num_withdrawals = {len(tx.withdrawals) if tx.withdrawals else 0},"
        )
        header_lines.append(
            f"    .num_mint_asset_groups = {len(tx.mint) if tx.mint else 0},"
        )
        header_lines.append(f"    .include_ttl = {_bool_to_c(tx.ttl is not None)},")
        header_lines.append(
            f"    .include_validity_interval_start = "
            f"{_bool_to_c(tx.validityIntervalStart is not None)},"
        )
        header_lines.append(
            f"    .include_aux_data_hash = {_bool_to_c(include_aux_data_hash)},"
        )
        header_lines.append(f"    .aux_data_type = {aux_data_type},")
        if include_aux_data_hash and aux_data_type == int(
            TxAuxiliaryDataType.CIP36_REGISTRATION
        ):
            header_lines.append(f"    .aux_data_init_payload = {init_payload_name},")
            header_lines.append(
                f"    .aux_data_init_payload_len = sizeof({init_payload_name}),"
            )
            if aux_data_delegation_payloads:
                header_lines.append(f"    .aux_data_delegations = {delegations_name},")
                header_lines.append(
                    f"    .aux_data_delegation_count = {len(aux_data_delegation_payloads)},"
                )
            else:
                header_lines.append("    .aux_data_delegations = NULL,")
                header_lines.append("    .aux_data_delegation_count = 0,")
        else:
            header_lines.append("    .aux_data_init_payload = NULL,")
            header_lines.append("    .aux_data_init_payload_len = 0,")
            header_lines.append("    .aux_data_delegations = NULL,")
            header_lines.append("    .aux_data_delegation_count = 0,")
        header_lines.append(
            f"    .include_script_data_hash = {_bool_to_c(include_script_data_hash)},"
        )
        header_lines.append(
            f"    .num_collateral_inputs = "
            f"{len(tx.collateralInputs) if hasattr(tx, 'collateralInputs') and tx.collateralInputs else 0},"
        )
        header_lines.append(
            f"    .num_required_signers = "
            f"{len(tx.requiredSigners) if hasattr(tx, 'requiredSigners') and tx.requiredSigners else 0},"
        )
        header_lines.append(
            f"    .include_network_id = "
            f"{_bool_to_c(getattr(tx, 'includeNetworkId', False) if hasattr(tx, 'includeNetworkId') else False)},"
        )
        header_lines.append(
            f"    .include_collateral_output = "
            f"{_bool_to_c(getattr(tx, 'collateralOutput', None) is not None)},"
        )
        header_lines.append(
            f"    .include_total_collateral = "
            f"{_bool_to_c(getattr(tx, 'totalCollateral', None) is not None)},"
        )
        header_lines.append(
            f"    .num_reference_inputs = "
            f"{len(tx.referenceInputs) if hasattr(tx, 'referenceInputs') and tx.referenceInputs else 0},"
        )
        header_lines.append(
            f"    .num_voters = "
            f"{len(tx.votingProcedures) if hasattr(tx, 'votingProcedures') and tx.votingProcedures else 0},"
        )
        treasury_value = getattr(tx, "treasury", None)
        donation_value = getattr(tx, "donation", None)
        header_lines.append(
            f"    .include_treasury = {_bool_to_c(treasury_value is not None)},"
        )
        header_lines.append(
            f"    .treasury = {treasury_value if treasury_value is not None else 0},"
        )
        header_lines.append(
            f"    .include_donation = {_bool_to_c(donation_value is not None)},"
        )
        header_lines.append(
            f"    .donation = {donation_value if donation_value is not None else 0},"
        )

        if include_aux_data_hash and aux_data_hash_hex is not None:
            header_lines.append(f'    .aux_data_hash_hex = "{aux_data_hash_hex}",')
        else:
            header_lines.append("    .aux_data_hash_hex = NULL,")
        header_lines.append(f"    .options = {options_value},")

        expected_warnings = getattr(test_case, "expected_warnings", [])
        if expected_warnings:
            warning_expr = " | ".join(
                f"((warning_bits_t)1 << {bit.name})" for bit in expected_warnings
            )
        else:
            warning_expr = "0"
        header_lines.append(f"    .expected_warning_bits = {warning_expr},")

        header_lines.append("};")
        header_lines.append("")

    header_lines.append("#if defined(__clang__)")
    header_lines.append("#pragma clang diagnostic pop")
    header_lines.append("#elif defined(__GNUC__)")
    header_lines.append("#pragma GCC diagnostic pop")
    header_lines.append("#endif")
    header_lines.append("")

    header_content = "\n".join(header_lines)
    output_file = GENERATED_SIGN_TX_DIR / f"test_sign_tx_fixtures_{era_key.lower()}.h"
    write_file_safe(output_file, header_content)

    fixture_count = _count_fixture_structs(header_content)
    if fixture_count != len(tests):
        raise ValueError(
            f"Fixture count mismatch for {era_key}: expected {len(tests)}, got {fixture_count}"
        )

    print()
    print(f"Generated: {output_file}")
    print(f"Total fixtures: {len(tests)}")


def _load_sign_tx_tests() -> dict[str, Any]:
    _ensure_base58_module()
    _add_tests_to_sys_path()
    from standalone.input_files.signTx import (  # type: ignore
        testsMary,
        testsShelleyNoCertificates,
        testsShelleyWithCertificates,
        testsAllegra,
        testsByron,
        testsAlonzo,
        testsAlonzoTrezorComparison,
        testsStreaming,
        testsBabbage,
        testsBabbageTrezorComparison,
        testsConwayWithCertificates,
        testsConwayWithoutCertificates,
        testsConwayVotingProcedures,
        testsMultidelegation,
        testsCatalystRegistration,
        testsCVoteRegistrationCIP36,
        testsMultisig,
        poolRegistrationOwnerTestCases,
        poolRegistrationOperatorTestCases,
        TxAuxiliaryDataCIP36,
        TxAuxiliaryDataType,
        TxAuxiliaryDataHash,
    )

    era_tests = {
        "byron": testsByron,
        "shelley": testsShelleyNoCertificates,
        "shelley_certificates": testsShelleyWithCertificates,
        "allegra": testsAllegra,
        "mary": testsMary,
        "alonzo": testsAlonzo + testsAlonzoTrezorComparison + testsMultidelegation,
        "streaming": testsStreaming,
        "babbage": testsBabbage + testsBabbageTrezorComparison,
        "conway": testsConwayWithCertificates,
        "conway_without_certificates": testsConwayWithoutCertificates,
        "conway_voting": testsConwayVotingProcedures,
        "multisig": testsMultisig,
        "alonzo_catalyst": testsCatalystRegistration,
        "alonzo_cip36": testsCVoteRegistrationCIP36,
        "pool_registration": poolRegistrationOwnerTestCases
        + poolRegistrationOperatorTestCases,
    }

    return {
        "era_tests": era_tests,
        "TxAuxiliaryDataCIP36": TxAuxiliaryDataCIP36,
        "TxAuxiliaryDataType": TxAuxiliaryDataType,
        "TxAuxiliaryDataHash": TxAuxiliaryDataHash,
    }


def generate_tx_fixtures() -> None:
    sign_tx_data = _load_sign_tx_tests()
    era_tests = sign_tx_data["era_tests"]
    aux_data_classes = {
        "TxAuxiliaryDataCIP36": sign_tx_data["TxAuxiliaryDataCIP36"],
        "TxAuxiliaryDataType": sign_tx_data["TxAuxiliaryDataType"],
        "TxAuxiliaryDataHash": sign_tx_data["TxAuxiliaryDataHash"],
    }

    for era_key in sorted(era_tests.keys()):
        tests = era_tests[era_key]
        _generate_fixtures_for_era(era_key, tests, aux_data_classes)
