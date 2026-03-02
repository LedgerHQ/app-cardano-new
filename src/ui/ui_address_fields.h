/* SPDX-FileCopyrightText: 2025 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include <stdint.h>

#include "addressUtilsShelley.h"

/**
 * Add payment credential UI pair for device-owned address.
 * Pure renderer — no policy awareness.
 */
void addPaymentInfoUIPairs(const address_params_t *address_params);

/**
 * Add staking credential UI pair for device-owned address.
 * Pure renderer — no policy awareness.
 */
void addStakingInfoUIPairs(const address_params_t *address_params);
