/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include "securityPolicy.h"
#include "nbgl_use_case.h"
#include "ui_utils.h"

/**
 * Build a human-readable summary string from an array of warning definitions.
 *
 * Iterates warning_defs[start_index..warning_count) and concatenates entries as:
 *   - include_descriptions=false: "Title1. Title2. "
 *   - include_descriptions=true:  "Title1: Desc1\nTitle2: Desc2"
 *
 * Allocates *out via APP_MEM_CALLOC; caller must free it.
 * Useful for TRACE output and unit tests.
 *
 * @return true on success, false on allocation failure
 */
bool build_warning_summary_text(const warning_definition_t *const *warning_defs,
                                size_t start_index,
                                size_t warning_count,
                                bool include_descriptions,
                                char **out);

/**
 * Build NBGL warning structure from warning bits.
 * Handles 0, 1, or multiple warnings.
 *
 * Memory is allocated and must be freed via ui_free_warnings().
 *
 * @param warnings Warning bits to convert to NBGL warnings
 * @return UI_STATUS_SUCCESS on success, UI_STATUS_OUT_OF_MEMORY on failure
 */
ui_status_t ui_build_warnings(warning_bits_t warnings);

/**
 * Get the prepared warning structure for use with nbgl_useCaseAdvancedReview.
 * Must be called after ui_build_warnings().
 *
 * @return Pointer to warning structure, or NULL if no warnings
 */
const nbgl_warning_t *ui_get_warnings(void);

/**
 * Free warning structure.
 * Idempotent - safe to call multiple times or when no warnings were built.
 */
void ui_free_warnings(void);
