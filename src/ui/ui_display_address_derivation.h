/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include "securityPolicy.h"

/**
 * Display address derivation
 *
 * @param securityPolicy Security policy result
 * @param warnings Warning bits
 */
void ui_deriveAddress_handleDisplay(security_policy_t securityPolicy, warning_bits_t warnings);

/**
 * Return address derivation
 *
 * @param securityPolicy Security policy result
 * @param warnings Warning bits
 */
void ui_deriveAddress_handleReturn(security_policy_t securityPolicy, warning_bits_t warnings);
