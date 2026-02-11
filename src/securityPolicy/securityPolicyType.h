/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include "os.h"

typedef enum {
    POLICY_DENY = 1,
    POLICY_SHOW = 2,  // element is displayed to the user
    POLICY_HIDE = 3   // element is silently approved (no UI)
} security_policy_t;
