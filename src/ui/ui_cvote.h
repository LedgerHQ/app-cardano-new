/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include "securityPolicy.h"

/**
 * Display voting confirmation and signature
 *
 * @param securityPolicy Security policy result
 * @param warnings Warning bits to display in review flow
 */
void ui_display_cvote_confirm(security_policy_t securityPolicy, warning_bits_t warnings);
