/* SPDX-FileCopyrightText: 2025 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include "assert.h"
#include "globals.h"

/**
 * Accessor for the CVote aux-data stage context.
 * Valid only during TX_STATE_AUX_DATA.
 */
static inline __attribute__((always_inline))
typeof(G_context.tx_info.aux_data) *tx_aux_data_ctx(void) {
    LEDGER_ASSERT(G_context.state.tx_state == TX_STATE_AUX_DATA,
                  "tx_aux_data_ctx called in wrong state: %d",
                  G_context.state.tx_state);
    return &G_context.tx_info.aux_data;
}

/**
 * Accessor for the transaction body stage context.
 * Valid during TX_STATE_CHUNKS through TX_STATE_UI_PREPARED.
 */
static inline __attribute__((always_inline))
typeof(G_context.tx_info.body) *tx_body_ctx(void) {
    LEDGER_ASSERT(G_context.state.tx_state == TX_STATE_CHUNKS ||
                  G_context.state.tx_state == TX_STATE_RECEIVED ||
                  G_context.state.tx_state == TX_STATE_HASHED ||
                  G_context.state.tx_state == TX_STATE_UI_PREPARED,
                  "tx_body_ctx called in wrong state: %d",
                  G_context.state.tx_state);
    return &G_context.tx_info.body;
}

/**
 * Accessor for the witness stage context.
 * Valid only during TX_STATE_APPROVED.
 */
static inline __attribute__((always_inline))
typeof(G_context.tx_info.witness) *tx_witness_ctx(void) {
    LEDGER_ASSERT(G_context.state.tx_state == TX_STATE_APPROVED,
                  "tx_witness_ctx called in wrong state: %d",
                  G_context.state.tx_state);
    return &G_context.tx_info.witness;
}
