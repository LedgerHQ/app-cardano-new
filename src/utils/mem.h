/*******************************************************************************
 *   Ledger Cardano App
 *   (c) 2016-2025 Ledger
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ********************************************************************************/

#pragma once

#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>

#include "app_mem_utils.h"

void *app_mem_get_buffer(void);
size_t app_mem_get_buffer_size(void);
bool mem_utils_reset_app_heap(void);
