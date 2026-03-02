/* SPDX-FileCopyrightText: 2025 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include <stdint.h>

#include "tx_certificate_types.h"
#include "tx_credential_types.h"
#include "tx_parse.h"

/**
 * Handle UI planning and rendering for a single certificate.
 *
 * Covers all certificate types except CERTIFICATE_STAKE_POOL_REGISTRATION,
 * which is handled separately by tx_processing_pool_registration.c.
 *
 * On the planning pass (mode->ui_count_pairs), adds the appropriate pair count
 * to G_context.tx_info.planned_ui_pairs.
 * On the rendering pass (mode->ui_render), renders all UI pairs for the
 * certificate.
 */
void tx_ui_plan_or_render_certificate(const tx_processing_mode_t *mode,
                                      const certificate_data_t *certificate_data);

// ---------------------------------------------------------------------------
// Pool registration plan/render helpers (no policy awareness)
// Intended for use by tx_processing_pool_registration.c.
// ---------------------------------------------------------------------------

void plan_or_render_pool_registration_header(const tx_processing_mode_t *mode,
                                             certificate_type_t type);
void plan_or_render_pool_id(const tx_processing_mode_t *mode, const pool_id_t *pool_id);
void plan_or_render_pool_vrf_key_hash(const tx_processing_mode_t *mode,
                                      const uint8_t *vrf_key_hash);
void plan_or_render_pool_financials(const tx_processing_mode_t *mode,
                                    const pool_registration_data_t *pool_registration);
void plan_or_render_pool_reward_account(const tx_processing_mode_t *mode,
                                        uint8_t network_id,
                                        const pool_reward_account_t *reward_account);
void plan_or_render_pool_owner(const tx_processing_mode_t *mode,
                               uint8_t network_id,
                               const ext_credential_t *owner_credential);
void plan_or_render_pool_no_owners(const tx_processing_mode_t *mode);
void plan_or_render_pool_relay(const tx_processing_mode_t *mode,
                               uint16_t relay_index,
                               const pool_relay_t *relay);
void plan_or_render_pool_no_relays(const tx_processing_mode_t *mode);
void plan_or_render_pool_metadata(const tx_processing_mode_t *mode,
                                  const pool_metadata_t *pool_metadata);
void plan_or_render_pool_no_metadata(const tx_processing_mode_t *mode);
