/* SPDX-FileCopyrightText: 2016-2025 Ledger */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>

#include "app_mem_utils.h"

void *app_mem_get_buffer(void);
size_t app_mem_get_buffer_size(void);
bool mem_utils_reset_app_heap(void);
