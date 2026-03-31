/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

// Mock global context for unit tests
#include "globals.h"

global_ctx_t G_context;
const internal_storage_t N_storage_real = {
    .expert_mode_enabled = 0,
    .silent_pubkey_export_enabled = 0,
    .blind_signing_enabled = 0,
    .initialized = 0,
};
bool unit_test_expert_mode_enabled = false;
bool unit_test_silent_pubkey_export_enabled = false;
bool unit_test_blind_signing_enabled = false;

// Keep this translation unit visible to gcov/lcov even though it mostly
// provides global definitions referenced from other objects.
__attribute__((constructor)) static void mock_globals_coverage_anchor(void) {
}
