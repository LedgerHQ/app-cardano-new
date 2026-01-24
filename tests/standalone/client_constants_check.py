from __future__ import annotations

import sys
from pathlib import Path
import re
from typing import Mapping

from enum import IntEnum

ROOT = Path(__file__).resolve().parents[2]
TESTS_ROOT = ROOT / "tests"
for extra_path in (ROOT, TESTS_ROOT):
    str_extra = str(extra_path)
    if str_extra not in sys.path:
        sys.path.insert(0, str_extra)

from application_client.command_builder import CLA, InsType, P1Type, P2Type
from standalone.input_files.signTx import MAX_SIGN_TX_CHUNK_SIZE


def _parse_defines(path: Path) -> Mapping[str, int]:
    defines: dict[str, int] = {}
    for line in path.read_text().splitlines():
        match = re.match(r"#define\s+(\w+)\s+(0x[0-9A-Fa-f]+|\d+)", line)
        if match:
            defines[match.group(1)] = int(match.group(2), 0)
    return defines


def _parse_enum(path: Path) -> Mapping[str, int]:
    values: dict[str, int] = {}
    for line in path.read_text().splitlines():
        for match in re.finditer(r"(\w+)\s*=\s*(0x[0-9A-Fa-f]+|\d+)", line):
            values[match.group(1)] = int(match.group(2), 0)
    return values


def _dispatcher_header_path() -> Path:
    return Path(__file__).resolve().parents[2] / "src" / "apdu" / "dispatcher.h"


def _handler_sign_tx_path() -> Path:
    return Path(__file__).resolve().parents[2] / "src" / "handler" / "sign_tx.h"


def _assert_dispatcher_enum_prefix(prefix: str,
                                   enum_cls: type[IntEnum],
                                   dispatcher_values: Mapping[str, int]) -> None:
    for name, value in dispatcher_values.items():
        if not name.startswith(prefix):
            continue
        if not hasattr(enum_cls, name):
            raise AssertionError(f"{name} missing from {enum_cls.__name__}")
        attr_value = getattr(enum_cls, name)
        if int(attr_value) != value:
            raise AssertionError(f"{name} mismatch: {int(attr_value)} != {value}")


def assert_ins_constants_match() -> None:
    dispatcher_values = _parse_enum(_dispatcher_header_path())
    _assert_dispatcher_enum_prefix("INS_", InsType, dispatcher_values)


def assert_p1_p2_constants_match() -> None:
    dispatcher_values = _parse_enum(_dispatcher_header_path())
    _assert_dispatcher_enum_prefix("P1_", P1Type, dispatcher_values)
    _assert_dispatcher_enum_prefix("P2_", P2Type, dispatcher_values)


def assert_cla_constant_match() -> None:
    defines = _parse_defines(_dispatcher_header_path())
    if defines.get("CLA") != CLA:
        raise AssertionError(f"CLA mismatch: {defines.get('CLA')} != {CLA}")


def assert_max_sign_tx_chunk_size_match() -> None:
    defines = _parse_defines(_handler_sign_tx_path())
    if defines.get("MAX_SIGN_TX_CHUNK_SIZE") != MAX_SIGN_TX_CHUNK_SIZE:
        raise AssertionError("MAX_SIGN_TX_CHUNK_SIZE mismatch")
