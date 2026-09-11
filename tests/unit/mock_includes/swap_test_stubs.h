/* SPDX-FileCopyrightText: 2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include <stdbool.h>
#include <setjmp.h>
#include <stdint.h>

void swap_test_stubs_reset(void);
void swap_test_stubs_set_initialized(bool initialized);
void swap_test_stubs_set_validation_results(bool fee_ok, bool destination_ok, bool amount_ok);
void swap_test_stubs_set_reject_jmp_buf(jmp_buf *jmp_buffer);
void swap_test_stubs_set_os_lib_end_jmp_buf(jmp_buf *jmp_buffer);

extern unsigned int g_swap_stub_fee_check_calls;
extern unsigned int g_swap_stub_destination_check_calls;
extern unsigned int g_swap_stub_amount_check_calls;
extern uint16_t g_swap_reject_common_error_code;
extern uint8_t g_swap_reject_app_error_code;
extern jmp_buf *g_swap_reject_jmp_buf;
extern jmp_buf *g_swap_os_lib_end_jmp_buf;
