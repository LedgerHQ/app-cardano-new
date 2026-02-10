#include <string.h>

#include "nbgl_use_case.h"
#include "ui_utils.h"
#include "mem.h"
#include "io.h"
#include "cardano_swo.h"
#include "utils.h"
#include "assert.h"

nbgl_contentTagValue_t *g_pairs = NULL;
nbgl_contentTagValueList_t *g_pairsList = NULL;

ui_status_t g_ui_error_status = UI_STATUS_UNINITIALIZED;

static uint16_t g_next_pair_index = 0;

static bool ui_allocate_zeroed(void **result, size_t allocation_size) {
    if (allocation_size > UINT16_MAX) {
        return false;
    }
    *result = NULL;
    return APP_MEM_CALLOC(result, (uint16_t) allocation_size);
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
 * Set UI error status
 * Cannot change from error state back to success
 */
void ui_set_error_status(ui_status_t status) {
    LEDGER_ASSERT(status != UI_STATUS_UNINITIALIZED, "Cannot set UI status to UNINITIALIZED");
    LEDGER_ASSERT(g_ui_error_status != UI_STATUS_UNINITIALIZED, "UI error status not initialized - must call ui_reset_error_status first");
    // Once error is set, cannot change back to success
    LEDGER_ASSERT(g_ui_error_status == UI_STATUS_SUCCESS || status != UI_STATUS_SUCCESS, "Cannot change UI error status from error back to success");
    g_ui_error_status = status;
}


/**
 * Cleanup pairs array (g_pairs and g_pairsList)
 */
void ui_free_pairs(void) {
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

uint16_t ui_pairs_get_count(void) {
    return g_next_pair_index;
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

    if (g_pairs == NULL || g_pairsList == NULL) {
        TRACE("Pairs storage not initialized");
        APP_MEM_FREE(tmp_buf);
        return false;
    }

    if (g_next_pair_index >= g_pairsList->nbPairs) {
        TRACE("Pairs list overflow: %u/%u", g_next_pair_index, g_pairsList->nbPairs);
        APP_MEM_FREE(tmp_buf);
        return false;
    }

    char *value_ptr = tmp_buf;

    if (shrink) {
        size_t len = strlen(tmp_buf);
        char *shrinked = NULL;
        if (!ui_allocate_zeroed((void **) &shrinked, len + 1)) {
            TRACE("Failed to allocate shrunk string");
            APP_MEM_FREE(tmp_buf);
            return false;
        }
        memcpy(shrinked, tmp_buf, len + 1);
        APP_MEM_FREE(tmp_buf);
        value_ptr = shrinked;
    }

    g_pairs[g_next_pair_index].item = label;
    g_pairs[g_next_pair_index].value = value_ptr;
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
bool ui_pairs_init(uint8_t nbPairs) {
    // Allocate the pairsList memory
    APP_MEM_FREE_AND_NULL((void **) &g_pairsList);
    if (!ui_allocate_zeroed((void **) &g_pairsList, sizeof(nbgl_contentTagValueList_t))) {
        goto error;
    }

    // Allocate the pairs memory (nbgl_contentTagValue_t for individual pairs, not List_t)
    APP_MEM_FREE_AND_NULL((void **) &g_pairs);
    if (!ui_allocate_zeroed((void **) &g_pairs, nbPairs * sizeof(nbgl_contentTagValue_t))) {
        goto error;
    }
    g_pairsList->nbPairs = nbPairs;
    g_pairsList->pairs = g_pairs;
    g_next_pair_index = 0;
    return true;
error:
    ui_free_pairs();
    return false;
}
