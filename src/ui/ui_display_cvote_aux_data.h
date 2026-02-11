/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "cvote_parser.h"

void ui_cvote_aux_data_init_vars(cvote_aux_data_t *aux_data);
bool ui_cvote_aux_data_init_non_streaming(cvote_aux_data_t *aux_data);
void ui_cvote_aux_data_streaming_show_initial_page(cvote_aux_data_t *aux_data);
void ui_cvote_aux_data_add_delegation_non_streaming(cvote_aux_data_t *aux_data,
                                                     const cvote_credential_t *credential,
                                                     uint32_t weight);
bool ui_cvote_aux_data_add_delegation_streaming(cvote_aux_data_t *aux_data,
                                                  const cvote_credential_t *credential,
                                                  uint32_t weight);
void ui_cvote_aux_data_show_non_streaming_final_review(cvote_aux_data_t *aux_data);
