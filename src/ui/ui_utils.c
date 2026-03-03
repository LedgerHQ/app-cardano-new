/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <string.h>

#include "nbgl_use_case.h"
#include "ui_utils.h"
#include "mem.h"
#include "io.h"
#include "cardano_swo.h"
#include "utils.h"
#include "assert.h"
#include "ui_warnings.h"

nbgl_contentTagValue_t *g_pairs = NULL;
nbgl_contentTagValueList_t *g_pairsList = NULL;

ui_status_t g_ui_error_status = UI_STATUS_UNINITIALIZED;

static uint16_t g_next_pair_index = 0;
static bool g_pending_force_page_start = false;
static ui_render_session_t *g_active_render_session = NULL;

void ui_render_session_begin(ui_render_session_t *session,
                             uint16_t render_from_pair_index) {
    LEDGER_ASSERT(session != NULL, "NULL render session");
    LEDGER_ASSERT(g_active_render_session == NULL, "UI render session already active");
    explicit_bzero(session, SIZEOF(*session));
    session->render_from_pair_index = render_from_pair_index;
    g_active_render_session = session;
}

void ui_render_session_end(void) {
    LEDGER_ASSERT(g_active_render_session != NULL, "No active UI render session");
    g_active_render_session = NULL;
}

bool ui_render_should_skip(void) {
    LEDGER_ASSERT(g_active_render_session != NULL,
                  "UI_ADD_* called without active render session");
    uint16_t current = g_active_render_session->next_pair_index;
    g_active_render_session->next_pair_index++;
    // Skip if before the window
    if (current < g_active_render_session->render_from_pair_index) {
        // Clear any pending force-new-page: the pair was already rendered previously.
        g_pending_force_page_start = false;
        return true;
    }
    LEDGER_ASSERT(g_ui_error_status != UI_STATUS_UNINITIALIZED,
                  "ui_reset_error_status() must be called before UI_ADD_* macros");
    // Skip if chunk is full or a real OOM occurred
    if (g_ui_error_status == UI_STATUS_CHUNK_FULL || g_ui_error_status == UI_STATUS_OUT_OF_MEMORY) {
        // Clear pending flag: this pair won't be rendered in this chunk.
        g_pending_force_page_start = false;
        return true;
    }
    return false;
}

void ui_check_expected_pair_delta(uint16_t pairs_before, uint16_t expected) {
    LEDGER_ASSERT(g_active_render_session != NULL,
                  "CHECK_COUNT called without active render session");
    if (g_ui_error_status == UI_STATUS_SUCCESS &&
        g_active_render_session->render_from_pair_index == 0) {
        uint16_t actual_delta = ui_pairs_get_count() - pairs_before;
        LEDGER_ASSERT(actual_delta == expected,
                      "UI pairs mismatch: expected %d, actual %d",
                      expected, actual_delta);
    }
}

/**
 * Initialize UI error status to SUCCESS before starting UI formatting
 */
void ui_reset_error_status(void) {
    g_ui_error_status = UI_STATUS_SUCCESS;
}

/**
 * Get final UI error status
 * Asserts if status was never initialized
 */
ui_status_t ui_get_error_status(void) {
    LEDGER_ASSERT(g_ui_error_status != UI_STATUS_UNINITIALIZED, "UI error status not initialized - must call ui_reset_error_status first");
    return g_ui_error_status;
}

/**
 * Set UI error status.
 * Cannot change from non-SUCCESS state back to success (use direct assignment in streaming reset).
 * CHUNK_FULL and OUT_OF_MEMORY are mutually exclusive: once the chunk is full,
 * ui_render_should_skip() gates all further macro calls, so OUT_OF_MEMORY must never follow.
 */
void ui_set_error_status(ui_status_t status) {
    LEDGER_ASSERT(status != UI_STATUS_UNINITIALIZED, "Cannot set UI status to UNINITIALIZED");
    LEDGER_ASSERT(g_ui_error_status != UI_STATUS_UNINITIALIZED, "UI error status not initialized - must call ui_reset_error_status first");
    // Once non-SUCCESS, cannot go back to success via this function
    LEDGER_ASSERT(g_ui_error_status == UI_STATUS_SUCCESS || status != UI_STATUS_SUCCESS,
                  "Cannot change UI error status from non-success back to success");
    // CHUNK_FULL and OUT_OF_MEMORY must not mix in either direction
    LEDGER_ASSERT(!(g_ui_error_status == UI_STATUS_CHUNK_FULL && status == UI_STATUS_OUT_OF_MEMORY),
                  "Cannot set OUT_OF_MEMORY when CHUNK_FULL is already set");
    LEDGER_ASSERT(!(g_ui_error_status == UI_STATUS_OUT_OF_MEMORY && status == UI_STATUS_CHUNK_FULL),
                  "Cannot set CHUNK_FULL when OUT_OF_MEMORY is already set");
    g_ui_error_status = status;
    // On OOM the pending flag can no longer be consumed by a subsequent UI_ADD_* (the macro would
    // have set OOM before calling add_static_label, or add_static_label itself set OOM on shrink
    // failure). Clear it here so ui_free_pairs does not false-alarm.
    if (status == UI_STATUS_OUT_OF_MEMORY) {
        g_pending_force_page_start = false;
    }
}


/**
 * Cleanup pairs array (g_pairs and g_pairsList)
 */
void ui_free_pairs(void) {
    // A dangling flag here always means ui_pairs_force_new_page() was called without a subsequent
    // UI_ADD_* in any code path (skips always clear it in ui_render_should_skip).
    LEDGER_ASSERT(!g_pending_force_page_start,
                  "ui_pairs_force_new_page() called but no pair was added after it");
    g_pending_force_page_start = false;
    if (g_pairs != NULL) {
        for (uint16_t i = 0; i < g_next_pair_index; i++) {
            if (g_pairs[i].value != NULL) {
                APP_MEM_FREE((void *) g_pairs[i].value);
            }
        }
        APP_MEM_FREE_AND_NULL((void **) &g_pairs);
    }
    if (g_pairsList != NULL) {
        APP_MEM_FREE_AND_NULL((void **) &g_pairsList);
    }
    g_next_pair_index = 0;
}

void ui_all_cleanup(void) {
    ui_free_pairs();
    ui_free_warnings();
}

uint16_t ui_pairs_get_count(void) {
    LEDGER_ASSERT(g_next_pair_index <= MAX_UI_PAIRS, "g_next_pair_index overflow");
    return g_next_pair_index;
}

void ui_pairs_force_new_page(void) {
    g_pending_force_page_start = true;
}

bool ui_pairs_add_static_label_impl(const char* label, char* tmp_buf, bool shrink) {
    LEDGER_ASSERT(label != NULL && label[0] != '\0', "Invalid UI label");
    LEDGER_ASSERT(tmp_buf != NULL && tmp_buf[0] != '\0', "Invalid UI value");

    #ifdef DEBUG
    {
        size_t len = strlen(tmp_buf);
        const size_t preview_len = 256;
        char value_preview[257] = {0};  // 256 chars + null terminator
        memcpy(value_preview, tmp_buf, len > preview_len ? preview_len : len);

        TRACE("Adding pair %u: label='%s' value='%s%s (length = %u)'",
              g_next_pair_index,
              label,
              value_preview,
              len > preview_len ? "..." : "",
              len);
    }
    #endif

    // Always consume the pending flag, regardless of whether the pair is successfully inserted.
    bool force_page_start = g_pending_force_page_start;
    g_pending_force_page_start = false;

    if (g_pairs == NULL || g_pairsList == NULL) {
        TRACE("Pairs storage not initialized");
        ui_set_error_status(UI_STATUS_OUT_OF_MEMORY);
        APP_MEM_FREE(tmp_buf);
        return false;
    }

    if (g_next_pair_index >= g_pairsList->nbPairs) {
        TRACE("Pairs list overflow: %u/%u", g_next_pair_index, g_pairsList->nbPairs);
        ui_set_error_status(UI_STATUS_CHUNK_FULL);
        APP_MEM_FREE(tmp_buf);
        return false;
    }

    char *value_ptr = tmp_buf;

    if (shrink) {
        size_t len = strlen(tmp_buf);
        char *shrinked = NULL;
        if (!allocate_zeroed((void **) &shrinked, len + 1)) {
            TRACE("Failed to allocate shrunk string");
            ui_set_error_status(UI_STATUS_OUT_OF_MEMORY);
            APP_MEM_FREE(tmp_buf);
            return false;
        }
        memcpy(shrinked, tmp_buf, len + 1);
        APP_MEM_FREE(tmp_buf);
        value_ptr = shrinked;
    }

    g_pairs[g_next_pair_index].item = label;
    g_pairs[g_next_pair_index].value = value_ptr;
    g_pairs[g_next_pair_index].forcePageStart = force_page_start ? 1 : 0;
    g_next_pair_index++;
    return true;
}

bool ui_pairs_add_static_label(const char* label, char* tmp_buf) {
    return ui_pairs_add_static_label_impl(label, tmp_buf, true);
}

/**
 * Initialize the buffers
 *
 * @return whether the initialization was successful
 */
bool ui_pairs_init(uint16_t nbPairs) {
    // Allocate the pairsList memory
    APP_MEM_FREE_AND_NULL((void **) &g_pairsList);
    if (!allocate_zeroed((void **) &g_pairsList, sizeof(nbgl_contentTagValueList_t))) {
        goto error;
    }

    // Allocate the pairs memory (nbgl_contentTagValue_t for individual pairs, not List_t)
    APP_MEM_FREE_AND_NULL((void **) &g_pairs);
    if (!allocate_zeroed((void **) &g_pairs, nbPairs * sizeof(nbgl_contentTagValue_t))) {
        goto error;
    }
    STATIC_ASSERT(MAX_UI_PAIRS <= UINT8_MAX, "MAX_UI_PAIRS must fit in uint8_t");
    LEDGER_ASSERT(nbPairs <= MAX_UI_PAIRS, "nbPairs exceeds MAX_UI_PAIRS");
    g_pairsList->nbPairs = (uint8_t) nbPairs;
    g_pairsList->pairs = g_pairs;
    g_pairsList->wrapping = true;
    g_next_pair_index = 0;
    return true;
error:
    ui_free_pairs();
    return false;
}
