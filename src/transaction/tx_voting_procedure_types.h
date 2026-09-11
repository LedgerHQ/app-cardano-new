/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include <stdint.h>
#include "tx_certificate_types.h"  // For ext_voter_t, vote_t, gov_action_id_t, anchor_t

// A single vote: gov_action_id + voting_procedure
typedef struct {
    gov_action_id_t govActionId;  // Tx hash (pointer) + index
    vote_t voteOption;            // NO=0, YES=1, ABSTAIN=2
    anchor_t anchor;              // Optional anchor (URL + hash)
} vote_item_t;
