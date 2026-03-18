/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "nbgl_use_case.h"

void nbgl_mock_reset(void);
void nbgl_mock_set_final_decisions(const bool *decisions, size_t decision_count);
void nbgl_mock_reject_next_final_decision_for_operation(nbgl_opType_t operation_type);
void nbgl_mock_set_streaming_start_auto_complete(bool enabled, bool confirm);
const char *nbgl_mock_last_status_message(void);
bool nbgl_mock_last_status_success(void);
