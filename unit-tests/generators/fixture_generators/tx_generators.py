from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, List, Optional, Sequence

from common import (
    _ensure_base58_module,
    _add_tests_to_sys_path,
    UNIT_TESTS_DIR,
)

def _format_bytes_as_c_array(data: bytes, name: str, bytes_per_line: int = 16) -> str:
    lines = []
    for i in range(0, len(data), bytes_per_line):
        chunk = data[i : i + bytes_per_line]
        hex_bytes = ", ".join(f"0x{b:02X}" for b in chunk)
        lines.append(f"    {hex_bytes},")

    result = f"static const uint8_t {name}[] = {{\n"
    result += "\n".join(lines)
    result += "\n};"
    return result


def _extract_apdu_payload(apdu: bytes) -> bytes:
    if len(apdu) < 5:
        raise ValueError("APDU too short")
    lc = apdu[4]
    payload = apdu[5 : 5 + lc]
    if len(payload) != lc:
        raise ValueError("APDU payload length mismatch")
    return payload


def _split_hex_string(hex_str: str, chunk_size: int = 1024) -> List[str]:
    return [hex_str[i : i + chunk_size] for i in range(0, len(hex_str), chunk_size)]


def _compute_blake2b_256(data: bytes) -> str:
    return hashlib.blake2b(data, digest_size=32).hexdigest()


def _sanitize_name_for_c(name: str) -> str:
    safe = "".join(c if c.isalnum() else "_" for c in name)
    while "__" in safe:
        safe = safe.replace("__", "_")
    return safe.upper()


def _bool_to_c(value: bool) -> str:
    return "true" if value else "false"


def _cbor_hex_to_bytes(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str.replace(" ", "").replace("\n", ""))


def _extract_aux_data_hash_from_tx_body(hex_str: str) -> Optional[str]:
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
    pattern = re.compile(r"static const tx_fixture_t [A-Z0-9_]+\s*=\s*\{")
    return len(pattern.findall(header_text))


def _generate_fixtures_for_era(
    era_key: str,
    tests: Sequence[Any],
    aux_data_classes: Dict[str, Any],
) -> None:
    from application_client.command_builder import CommandBuilder, gather_witness_paths  # type: ignore

    TxAuxiliaryDataCIP36 = aux_data_classes["TxAuxiliaryDataCIP36"]
    TxAuxiliaryDataType = aux_data_classes["TxAuxiliaryDataType"]
    TxAuxiliaryDataHash = aux_data_classes["TxAuxiliaryDataHash"]

    print(f"Generating C fixtures for {era_key.upper()} era ({len(tests)} tests)...")
    print()

    header_lines = [
        f"// Auto-generated fixtures for {era_key.upper()} era transaction tests",
        "// Generated from LedgerJS signTx.ts test cases",
        "//",
        f"// Total tests: {len(tests)}",
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

        expected_cbor_hex = test_case.txBody
        cbor_bytes = _cbor_hex_to_bytes(expected_cbor_hex)
        expected_hash_hex = _compute_blake2b_256(cbor_bytes)
        body_aux_data_hash = _extract_aux_data_hash_from_tx_body(expected_cbor_hex)

        safe_name = _sanitize_name_for_c(test_case.name)
        fixture_prefix = f"FIXTURE_{era_key.upper()}_{safe_name}"

        include_aux_data_hash = tx.auxiliaryData is not None
        aux_data_type = 0
        aux_data_hash_hex = body_aux_data_hash
        aux_data_init_payload = b""
        aux_data_delegation_payloads: List[bytes] = []
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
                    aux_data_init_payload = _extract_apdu_payload(aux_data_init_apdu)
                    for delegation in aux_params.delegations:
                        reg_apdu = builder.sign_tx_aux_data_delegation(delegation)
                        aux_data_delegation_payloads.append(
                            _extract_apdu_payload(reg_apdu)
                        )
                else:
                    include_aux_data_hash = False

        include_script_data_hash = getattr(tx, "scriptDataHash", None) is not None

        options_value = (
            "TX_OPTIONS_TAG_CBOR_SETS" if "d90102" in expected_cbor_hex.lower() else "0"
        )
        network_id_value = int(test_case.tx.network.networkId)
        protocol_magic_value = int(test_case.tx.network.protocol)

        header_lines.append(f"// Test {test_index}: {test_case.name}")
        header_lines.append("//")

        array_lines = _format_bytes_as_c_array(
            raw_tx_bytes,
            f"{fixture_prefix}_RAW_TX",
        ).split("\n")
        header_lines.extend(array_lines)
        header_lines.append("")
        if include_aux_data_hash and aux_data_type == int(
            TxAuxiliaryDataType.CIP36_REGISTRATION
        ):
            init_payload_name = f"{fixture_prefix}_AUX_DATA_INIT_PAYLOAD"
            init_payload_lines = _format_bytes_as_c_array(
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
                    reg_lines = _format_bytes_as_c_array(payload, entry_name).split(
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
        witness_paths = gather_witness_paths(
            tx,
            test_case.signingMode,
            getattr(test_case, "additionalWitnessPaths", []),
        )
        header_lines.append(f"    .num_witnesses = {len(witness_paths)},")
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
        header_lines.append("};")
        header_lines.append("")

    header_lines.append("#if defined(__clang__)")
    header_lines.append("#pragma clang diagnostic pop")
    header_lines.append("#elif defined(__GNUC__)")
    header_lines.append("#pragma GCC diagnostic pop")
    header_lines.append("#endif")
    header_lines.append("")

    header_content = "\n".join(header_lines)
    output_file = UNIT_TESTS_DIR / f"test_sign_tx_fixtures_{era_key.lower()}.h"
    output_file.write_text(header_content)

    fixture_count = _count_fixture_structs(header_content)
    if fixture_count != len(tests):
        raise ValueError(
            f"Fixture count mismatch for {era_key}: expected {len(tests)}, got {fixture_count}"
        )

    print()
    print(f"Generated: {output_file}")
    print(f"Total fixtures: {len(tests)}")


def _load_sign_tx_tests() -> Dict[str, Any]:
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
