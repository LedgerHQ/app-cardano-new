/* SPDX-FileCopyrightText: 2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include <stdbool.h>

void swap_test_stubs_reset(void);
void swap_test_stubs_set_initialized(bool initialized);
void swap_test_stubs_set_validation_results(bool fee_ok, bool destination_ok, bool amount_ok);

extern unsigned int g_swap_stub_fee_check_calls;
extern unsigned int g_swap_stub_destination_check_calls;
extern unsigned int g_swap_stub_amount_check_calls;
