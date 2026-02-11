/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include <stdint.h>
#include "tx_certificate_types.h"  // For ext_voter_t, vote_t, gov_action_id_t, anchor_t
#include "lists.h"

// A single vote: gov_action_id + voting_procedure
typedef struct {
    gov_action_id_t govActionId;      // Tx hash (pointer) + index
    vote_t voteOption;                 // NO=0, YES=1, ABSTAIN=2
    anchor_t anchor;                   // Optional anchor (URL + hash)
} vote_item_t;

// List node for individual votes (inner map entries)
typedef struct {
    flist_node_t flist_node;
    vote_item_t vote_data;
} vote_node_t;

// A voter with their votes
typedef struct {
    ext_voter_t voter;                 // Voter (key_path, key_hash, or script_hash)
    uint16_t numVotes;                 // Number of votes for this voter
    flist_node_t* votes;               // Linked list of vote_node_t
} voter_votes_t;

// List node for voters (outer map entries)
typedef struct {
    flist_node_t flist_node;
    voter_votes_t voter_votes_data;
} voter_votes_node_t;
