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

/**
 * Allocation tracker for UI buffers to prevent memory leaks
 * Tracks all dynamically allocated buffers for centralized cleanup
 */
typedef struct {
    void *ptrs[MAX_UI_PAIRS];  /// Array of allocated pointers
    uint16_t count;             /// Number of tracked allocations
} allocation_tracker_t;

static allocation_tracker_t g_allocation_tracker = {0};

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
    LEDGER_ASSERT(g_ui_error_status != UI_STATUS_UNINITIALIZED,
                  "UI error status not initialized - must call ui_reset_error_status first");
    return g_ui_error_status;
}

/**
 * Set UI error status
 * Cannot change from error state back to success
 */
void ui_set_error_status(ui_status_t status) {
    LEDGER_ASSERT(status != UI_STATUS_UNINITIALIZED,
                  "Cannot set UI status to UNINITIALIZED");
    LEDGER_ASSERT(g_ui_error_status != UI_STATUS_UNINITIALIZED,
                  "UI error status not initialized - must call ui_reset_error_status first");
    // Once error is set, cannot change back to success
    LEDGER_ASSERT(g_ui_error_status == UI_STATUS_SUCCESS || status != UI_STATUS_SUCCESS,
                  "Cannot change UI error status from error back to success");
    g_ui_error_status = status;
}

/**
 * Track an allocated buffer for later cleanup
 *
 * @param ptr pointer to allocated buffer (can be NULL)
 */
void ui_track_allocation(void *ptr) {
    if (ptr == NULL) {
        return;
    }
    LEDGER_ASSERT(g_allocation_tracker.count < MAX_UI_PAIRS,
                  "UI allocation tracker overflow");
    g_allocation_tracker.ptrs[g_allocation_tracker.count++] = ptr;
}

/**
 * Cleanup all tracked allocations and reset tracker
 */
void ui_cleanup_tracked_allocations(void) {
    // Idempotent: resetting count ensures multiple calls do nothing after the first.
    for (uint16_t i = 0; i < g_allocation_tracker.count; i++) {
        if (g_allocation_tracker.ptrs[i] != NULL) {
            APP_MEM_FREE(g_allocation_tracker.ptrs[i]);
            g_allocation_tracker.ptrs[i] = NULL;
        }
    }
    g_allocation_tracker.count = 0;
}

/**
 * Allocate memory and automatically track it for cleanup
 * This ensures UI buffers are cleaned up even if allocated in loops
 * or on error paths where manual cleanup might be forgotten.
 *
 * @param size number of bytes to allocate
 * @return pointer to allocated memory, or NULL on failure
 */
void *ui_mem_alloc(size_t size) {
    void *ptr = APP_MEM_ALLOC_ZEROED(size);
    if (ptr != NULL) {
        ui_track_allocation(ptr);
    }
    return ptr;
}

/**
 * Cleanup pairs array (g_pairs and g_pairsList)
 */
void ui_pairs_cleanup(void) {
    if (g_pairs != NULL) {
        APP_MEM_FREE(g_pairs);
        g_pairs = NULL;
    }
    if (g_pairsList != NULL) {
        APP_MEM_FREE(g_pairsList);
        g_pairsList = NULL;
    }
    g_next_pair_index = 0;
}

uint16_t ui_pairs_get_count(void) {
    return g_next_pair_index;
}

bool ui_pairs_add_static_label_impl(const char* label, char* tmp_buf, bool shrink) {
    LEDGER_ASSERT(label != NULL, "NULL label");
    LEDGER_ASSERT(label[0] != '\0', "Empty UI label");
    LEDGER_ASSERT(tmp_buf != NULL, "NULL buffer");
    LEDGER_ASSERT(tmp_buf[0] != '\0', "Empty UI value");

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
        char *shrinked = (char *) ui_mem_alloc(len + 1);
        if (shrinked == NULL) {
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
    if (g_pairsList != NULL) {
        APP_MEM_FREE(g_pairsList);
        g_pairsList = NULL;
    }
    g_pairsList = (nbgl_contentTagValueList_t *) APP_MEM_ALLOC_ZEROED(sizeof(nbgl_contentTagValueList_t));
    if (g_pairsList == NULL) {
        goto error;
    }

    // Allocate the pairs memory (nbgl_contentTagValue_t for individual pairs, not List_t)
    if (g_pairs != NULL) {
        APP_MEM_FREE(g_pairs);
        g_pairs = NULL;
    }
    g_pairs = (nbgl_contentTagValue_t *) APP_MEM_ALLOC_ZEROED(nbPairs * sizeof(nbgl_contentTagValue_t));
    if (g_pairs == NULL) {
        goto error;
    }
    g_pairsList->nbPairs = nbPairs;
    g_pairsList->pairs = g_pairs;
    g_next_pair_index = 0;
    return true;
error:
    ui_pairs_cleanup();
    return false;
}
