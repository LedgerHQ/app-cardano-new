# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from pathlib import Path

import pytest


TEST_CLIENT_CONSTANTS_PATH = (
    Path(__file__).resolve().parent / "standalone" / "test_client_constants.py"
)


@pytest.hookimpl(tryfirst=True)
def pytest_collection_modifyitems(session, config, items):
    """Run `test_client_constants` modules before any other tests."""
    constants_items = []
    remaining_items = []
    for item in items:
        if Path(item.fspath).resolve() == TEST_CLIENT_CONSTANTS_PATH:
            constants_items.append(item)
        else:
            remaining_items.append(item)
    if constants_items:
        items[:] = constants_items + remaining_items
