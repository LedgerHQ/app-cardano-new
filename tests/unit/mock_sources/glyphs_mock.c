/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include "glyphs.h"

const nbgl_icon_details_t WARNING_ICON = {0};
const nbgl_icon_details_t MOCK_APP_ICON = {0};
const nbgl_icon_details_t C_icon_ada_nanox = {0};
const nbgl_icon_details_t C_icon_warning = {0};

// Keep this translation unit visible to gcov/lcov even though it only exports
// icon definitions consumed by other objects.
__attribute__((constructor)) static void glyphs_mock_coverage_anchor(void) {
}
