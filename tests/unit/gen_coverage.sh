#!/bin/bash
# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0

set -x
set -e

BUILD_DIRECTORY=$(realpath build/)

lcov --directory . -b "${BUILD_DIRECTORY}" --capture --initial -o coverage.base &&
lcov --rc lcov_branch_coverage=1 --directory . -b "${BUILD_DIRECTORY}" --capture -o coverage.capture &&
lcov --directory . -b "${BUILD_DIRECTORY}" --add-tracefile coverage.base --add-tracefile coverage.capture -o coverage.info &&
lcov --directory . -b "${BUILD_DIRECTORY}" --remove coverage.info '*/unit/*' '/opt/ledger-secure-sdk/*' '/usr/include/*' -o coverage.info &&
echo "Generated 'coverage.info'." &&
genhtml coverage.info -o coverage

rm -f coverage.base coverage.capture
