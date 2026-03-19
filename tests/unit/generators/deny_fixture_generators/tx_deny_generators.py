# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0

from dataclasses import dataclass
from typing import Any

from common import (
    write_file_safe,
    _add_tests_to_sys_path,
)
from paths import GENERATED_SIGN_TX_DIR

SET_ORDER = [
    "transactionInitDenyTestCases",
    "addressParamsDenyTestCases",
    "certificateDenyTestCases",
    "certificateStakingDenyTestCases",
    "certificateStakePoolRetirementDenyTestCases",
    "withdrawalDenyTestCases",
    "witnessDenyTestCases",
    "singleAccountDenyTestCases",
    "collateralOutputDenyTestCases",
    "testsInvalidTokenBundleOrdering",
    "poolRegistrationOwnerDenyTestCases",
    "stakePoolRegistrationPoolIdDenyTestCases",
    "stakePoolRegistrationOwnerDenyTestCases",
    "outputDenyTestCases",
    "testsCVoteRegistrationDenies",
    "invalidCertificates",
    "invalidPoolMetadataTestCases",
    "invalidRelayTestCases",
]

SET_PREFIX = {
    "transactionInitDenyTestCases": "DENY_INIT",
    "addressParamsDenyTestCases": "DENY_ADDRESS",
    "certificateDenyTestCases": "DENY_CERT",
    "certificateStakingDenyTestCases": "DENY_CERT_STAKING",
    "certificateStakePoolRetirementDenyTestCases": "DENY_CERT_POOL_RETIRE",
    "withdrawalDenyTestCases": "DENY_WITHDRAWAL",
    "witnessDenyTestCases": "DENY_WITNESS",
    "singleAccountDenyTestCases": "DENY_SINGLE_ACCOUNT",
    "collateralOutputDenyTestCases": "DENY_COLLATERAL_OUTPUT",
    "testsInvalidTokenBundleOrdering": "DENY_MULTIASSET",
    "poolRegistrationOwnerDenyTestCases": "DENY_POOL_OWNER",
    "stakePoolRegistrationPoolIdDenyTestCases": "DENY_POOL_ID",
    "stakePoolRegistrationOwnerDenyTestCases": "DENY_POOL_OWNER",
    "outputDenyTestCases": "DENY_OUTPUT",
    "testsCVoteRegistrationDenies": "DENY_CVOTE",
    "invalidCertificates": "DENY_CERT_INVALID",
    "invalidPoolMetadataTestCases": "DENY_POOL_METADATA",
    "invalidRelayTestCases": "DENY_RELAY",
}

GENERATED_DENY_HEADER = GENERATED_SIGN_TX_DIR / "test_sign_tx_fixtures_deny.h"


def _build_deny_fixtures() -> str:
    _add_tests_to_sys_path()
    from application_client.command_builder import (  # type: ignore
        CommandBuilder,
        P1Type,
        P2Type,
        gather_witness_paths,
    )
    from standalone.input_files.signTx import TxAuxiliaryDataCIP36, TxAuxiliaryDataType  # type: ignore
    from application_client.status_words import StatusWord  # type: ignore
    from standalone.input_files.signTx import (  # type: ignore
        transactionInitDenyTestCases,
        addressParamsDenyTestCases,
        certificateDenyTestCases,
        certificateStakingDenyTestCases,
        certificateStakePoolRetirementDenyTestCases,
        withdrawalDenyTestCases,
        witnessDenyTestCases,
        singleAccountDenyTestCases,
        collateralOutputDenyTestCases,
        testsInvalidTokenBundleOrdering,
        poolRegistrationOwnerDenyTestCases,
        stakePoolRegistrationPoolIdDenyTestCases,
        stakePoolRegistrationOwnerDenyTestCases,
        outputDenyTestCases,
        testsCVoteRegistrationDenies,
        invalidCertificates,
        invalidPoolMetadataTestCases,
        invalidRelayTestCases,
    )

    fixtures_by_set: dict[str, list[Any]] = {
        "transactionInitDenyTestCases": transactionInitDenyTestCases,
        "addressParamsDenyTestCases": addressParamsDenyTestCases,
        "certificateDenyTestCases": certificateDenyTestCases,
        "certificateStakingDenyTestCases": certificateStakingDenyTestCases,
        "certificateStakePoolRetirementDenyTestCases": certificateStakePoolRetirementDenyTestCases,
        "withdrawalDenyTestCases": withdrawalDenyTestCases,
        "witnessDenyTestCases": witnessDenyTestCases,
        "singleAccountDenyTestCases": singleAccountDenyTestCases,
        "collateralOutputDenyTestCases": collateralOutputDenyTestCases,
        "testsInvalidTokenBundleOrdering": testsInvalidTokenBundleOrdering,
        "poolRegistrationOwnerDenyTestCases": poolRegistrationOwnerDenyTestCases,
        "stakePoolRegistrationPoolIdDenyTestCases": stakePoolRegistrationPoolIdDenyTestCases,
        "stakePoolRegistrationOwnerDenyTestCases": stakePoolRegistrationOwnerDenyTestCases,
        "outputDenyTestCases": outputDenyTestCases,
        "testsCVoteRegistrationDenies": testsCVoteRegistrationDenies,
        "invalidCertificates": invalidCertificates,
        "invalidPoolMetadataTestCases": invalidPoolMetadataTestCases,
        "invalidRelayTestCases": invalidRelayTestCases,
    }

    def sanitize_name(name: str) -> str:
        result = []
        for char in name.replace("-", "_"):
            if char.isalnum():
                result.append(char.upper())
            else:
                result.append("_")
        cleaned = "_".join(part for part in "".join(result).split("_") if part)
        return cleaned

    def format_display_name(prefix: str, test_name: str) -> str:
        cleaned = test_name.replace("-", "_").replace(" ", "_")
        cleaned = "_".join(part for part in cleaned.split("_") if part)
        return f"[{prefix}] {cleaned}"

    def to_hex_lines(hex_str: str, indent: int = 4, append_comma: bool = False) -> list[str]:
        chunk_size = 64
        lines = []
        for i in range(0, len(hex_str), chunk_size):
            segment = hex_str[i:i + chunk_size]
            lines.append(" " * indent + f"\"{segment}\"")
        if append_comma and lines:
            lines[-1] = lines[-1] + ","
        return lines

    @dataclass(frozen=True)
    class ChunkInfo:
        p1: int
        p2: int
        more: bool
        hex_payload: str

    @dataclass(frozen=True)
    class FixtureInfo:
        name: str
        display_name: str
        prefix: str
        sanitized_name: str
        init_hex: str
        chunks: list[ChunkInfo]
        expected_sw: str
        expect_init_failure: bool
        source_set: str
        source_file: str

    def build_fixture(test_case: Any, prefix: str, source_set: str) -> FixtureInfo:
        tx = test_case.tx
        signing_mode = test_case.signingMode
        additional_paths = list(test_case.additionalWitnessPaths or [])
        builder = CommandBuilder()
        if prefix == "DENY_WITNESS":
            witness_paths = list(additional_paths)
        else:
            witness_paths = gather_witness_paths(tx, signing_mode, additional_paths)
        init_params = builder.build_tx_init_params(
            tx=tx,
            signing_mode=signing_mode,
            witness_paths=witness_paths,
        )
        init_payload = builder.sign_tx_init(init_params)[5:]
        chunks = [
            ChunkInfo(
                p1=chunk[2],
                p2=chunk[3],
                more=chunk[2] != P1Type.P1_TX_CONFIRM,
                hex_payload=chunk[5:].hex().upper(),
            )
            for chunk in builder.serialize_transaction_chunks(tx)
        ]
        if tx.auxiliaryData is not None and tx.auxiliaryData.type == TxAuxiliaryDataType.CIP36_REGISTRATION:
            aux_params = tx.auxiliaryData.params
            if not isinstance(aux_params, TxAuxiliaryDataCIP36):
                raise ValueError("Expected TxAuxiliaryDataCIP36 params for CIP36 registration")
            aux_chunks: list[ChunkInfo] = []
            aux_init_apdu = builder.sign_tx_aux_data_init(tx, aux_params)
            aux_chunks.append(
                ChunkInfo(
                    p1=aux_init_apdu[2],
                    p2=aux_init_apdu[3],
                    more=False,
                    hex_payload=aux_init_apdu[5:].hex().upper(),
                )
            )
            for delegation in aux_params.delegations:
                delegation_apdu = builder.sign_tx_aux_data_delegation(delegation)
                aux_chunks.append(
                    ChunkInfo(
                        p1=delegation_apdu[2],
                        p2=delegation_apdu[3],
                        more=False,
                        hex_payload=delegation_apdu[5:].hex().upper(),
                    )
                )
            chunks = aux_chunks + chunks
        for path in witness_paths:
            witness_apdu = builder.sign_tx_witness(path)
            chunks.append(
                ChunkInfo(
                    p1=P1Type.P1_TX_SIGN_WITNESS,
                    p2=P2Type.P2_UNUSED,
                    more=False,
                    hex_payload=witness_apdu[5:].hex().upper(),
                )
            )
        expected_sw = test_case.expected_sw or StatusWord.SWO_SUCCESS
        expected_sw_name = expected_sw.name
        expect_init_failure = prefix == "DENY_INIT"
        if prefix == "DENY_ADDRESS":
            normalized_name = sanitize_name(test_case.name)
            if "POOL_OPERATOR_SPENDING_CHOICE_NOT_PATH" in normalized_name or "POOL_OWNER_UNCONDITIONALLY" in normalized_name:
                expect_init_failure = True

        display_name = format_display_name(prefix, test_case.name)
        return FixtureInfo(
            name=test_case.name,
            display_name=display_name,
            prefix=prefix,
            sanitized_name=sanitize_name(test_case.name),
            init_hex=init_payload.hex().upper(),
            chunks=chunks,
            expected_sw=expected_sw_name,
            expect_init_failure=expect_init_failure,
            source_set=source_set,
            source_file="tests/standalone/input_files/signTx.py",
        )

    # Map P1/P2 values to symbolic constants from command_builder/dispatcher.h
    P1_CONSTANTS = {
        int(P1Type.P1_TX_INIT): "P1_TX_INIT",
        int(P1Type.P1_TX_CHUNK): "P1_TX_CHUNK",
        int(P1Type.P1_TX_CONFIRM): "P1_TX_CONFIRM",
        int(P1Type.P1_TX_AUX_DATA): "P1_TX_AUX_DATA",
        int(P1Type.P1_TX_SIGN_WITNESS): "P1_TX_SIGN_WITNESS",
    }
    P2_CONSTANTS = {
        int(P2Type.P2_UNUSED): "P2_UNUSED",
        int(P2Type.P2_AUX_DATA_INIT): "P2_AUX_DATA_INIT",
        int(P2Type.P2_AUX_DATA_DELEGATION): "P2_AUX_DATA_DELEGATION",
    }

    def generate_header(fixtures: dict[str, list[FixtureInfo]]) -> str:
        lines = [
            "// Auto-generated file - DO NOT EDIT",
            "//",
            "// Generated by: tests/unit/generators/generate_unit_tests_from_ragger.py",
            "// Generator: deny_fixture_generators/tx_deny_generators.py",
            "// Source: tests/standalone/input_files/signTx.py (deny test cases)",
            "//",
            "// To regenerate:",
            "//   cd tests/unit",
            "//   python3 generators/generate_unit_tests_from_ragger.py",
            "//",
            "// Each fixture includes source traceability comments showing:",
            "//   - Source file and test set name",
            "//   - Original Ragger test name",
            "",
            "#pragma once",
            "",
            "#include <stdint.h>",
            "#include <stdbool.h>",
            "#include \"dispatcher.h\"  // For P1 constants",
            "",
        ]
        for set_name in SET_ORDER:
            prefix = SET_PREFIX.get(set_name)
            if not prefix or set_name not in fixtures:
                continue
            for fixture in fixtures[set_name]:
                if not fixture.chunks:
                    continue
                lines.append(f"// Source: {fixture.source_file} > {fixture.source_set} > {fixture.name}")
                lines.append(f"static const apdu_segment_t SIGN_TX_SEGMENTS_{prefix}_{fixture.sanitized_name}[] = {{")
                for chunk in fixture.chunks:
                    lines.append("    {")
                    lines.append("        .hex_payload =")
                    lines.extend(to_hex_lines(chunk.hex_payload, append_comma=True))
                    p1_constant = P1_CONSTANTS.get(chunk.p1, f"0x{chunk.p1:02X}")
                    p2_constant = P2_CONSTANTS.get(chunk.p2, f"0x{chunk.p2:02X}")
                    lines.append(f"        .p1 = {p1_constant},")
                    lines.append(f"        .p2 = {p2_constant},")
                    lines.append(f"        .more = {'true' if chunk.more else 'false'},")
                    lines.append("    },")
                lines.append("};")
                lines.append("")
            lines.append("")
        lines.append("static const sign_tx_deny_fixture_t SIGN_TX_DENY_FIXTURES[] = {")
        for set_name in SET_ORDER:
            prefix = SET_PREFIX.get(set_name)
            if not prefix or set_name not in fixtures:
                continue
            for fixture in fixtures[set_name]:
                lines.append(f"    // Source: {fixture.source_file} > {fixture.source_set} > {fixture.name}")
                lines.append("    {")
                lines.append(f'        .name = "{fixture.display_name}",')
                lines.append("        .init_hex =")
                lines.extend(to_hex_lines(fixture.init_hex, indent=8, append_comma=True))
                if fixture.chunks:
                    array_name = f"SIGN_TX_SEGMENTS_{prefix}_{fixture.sanitized_name}"
                    lines.append(f"        .chunks = {array_name},")
                    lines.append(f"        .chunk_count = ARRAY_LEN({array_name}),")
                else:
                    lines.append("        .chunks = NULL,")
                    lines.append("        .chunk_count = 0,")
                lines.append(f"        .expected_sw = {fixture.expected_sw},")
                lines.append(f"        .expect_init_failure = {'true' if fixture.expect_init_failure else 'false'},")
                lines.append("        .skip_reason = NULL,")
                lines.append("    },")
        lines.append("};")
        lines.append("")
        return "\n".join(lines)

    fixtures: dict[str, list[FixtureInfo]] = {}
    for set_name, entries in fixtures_by_set.items():
        prefix = SET_PREFIX.get(set_name)
        if not prefix:
            continue
        fixtures.setdefault(set_name, [])
        for entry in entries:
            fixtures[set_name].append(build_fixture(entry, prefix, set_name))

    return generate_header(fixtures)


def generate_tx_deny_fixtures() -> None:
    header = _build_deny_fixtures()
    write_file_safe(GENERATED_DENY_HEADER, header)
    print(f"Generated {GENERATED_DENY_HEADER}")
