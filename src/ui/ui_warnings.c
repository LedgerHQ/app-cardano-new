/* SPDX-FileCopyrightText: 2025 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include "ui_warnings.h"
#include "ui_utils.h"
#include "ui_constants.h"
#include "nbgl_use_case.h"
#include "assert.h"
#include "io.h"
#include "cardano_swo.h"
#include "glyphs.h"

static nbgl_warning_t *g_warning = NULL;
static char *g_warning_summary_text = NULL;
static char *g_warning_overflow_text = NULL;

static const char SECURITY_WARNING_TITLE[] = "Security warning";

#ifdef SCREEN_SIZE_WALLET
static const char SECURITY_WARNING_REVIEW_TEXT[] = "Review all warnings before proceeding.";
static const char SEE_MORE_WARNINGS_TITLE[] = "See more warnings";
#define MAX_WARNING_BARS_PER_PAGE 3
#endif

static void free_warning_dynamic_strings(void) {
    APP_MEM_FREE_AND_NULL((void **) &g_warning_summary_text);
    APP_MEM_FREE_AND_NULL((void **) &g_warning_overflow_text);
}

static bool build_warning_summary_text(const warning_definition_t *const *warning_defs,
                                       size_t start_index,
                                       size_t warning_count,
                                       bool include_descriptions,
                                       char **out) {
    LEDGER_ASSERT(warning_defs != NULL, "NULL warning_defs");
    LEDGER_ASSERT(start_index < warning_count, "Invalid warning summary range");
    LEDGER_ASSERT(out != NULL, "NULL out");

    size_t total_length = 1;  // null terminator
    for (size_t i = start_index; i < warning_count; i++) {
        const warning_definition_t *def = (const warning_definition_t *) PIC(warning_defs[i]);
        LEDGER_ASSERT(def != NULL && def->title != NULL, "NULL warning title");

        total_length += strlen((const char *) PIC(def->title));
        total_length += 2;  // ": " or ". "
        if (include_descriptions) {
            LEDGER_ASSERT(def->description != NULL, "NULL warning description");
            total_length += strlen((const char *) PIC(def->description));
        }
        total_length += 1;  // newline
    }
    LEDGER_ASSERT(total_length < BUFFER_SIZE_PARANOIA,
                  "Warning summary buffer too large: %u",
                  (unsigned) total_length);

    char *buffer = NULL;
    if (!allocate_zeroed((void **) &buffer, total_length) || buffer == NULL) {
        return false;
    }

    char *write_ptr = buffer;
    size_t remaining = total_length;
    for (size_t i = start_index; i < warning_count; i++) {
        const warning_definition_t *def = (const warning_definition_t *) PIC(warning_defs[i]);
        const char *title = (const char *) PIC(def->title);
        size_t title_length = strlen(title);

        LEDGER_ASSERT(title_length + 2 <= remaining, "Warning summary buffer too small");
        memmove(write_ptr, title, title_length);
        write_ptr += title_length;
        if (include_descriptions) {
            const char *description = (const char *) PIC(def->description);
            size_t description_length = strlen(description);

            *write_ptr++ = ':';
            *write_ptr++ = ' ';
            LEDGER_ASSERT(description_length + 1 <= remaining - (title_length + 2),
                          "Warning summary buffer too small for description");
            memmove(write_ptr, description, description_length);
            write_ptr += description_length;
            *write_ptr++ = '\n';
            remaining -= title_length + description_length + 3;
        } else {
            *write_ptr++ = '.';
            *write_ptr++ = ' ';
            remaining -= title_length + 2;
        }
    }
    LEDGER_ASSERT(remaining > 0, "No space left for warning terminator");
    if (include_descriptions && write_ptr > buffer) {
        write_ptr[-1] = '\0';
    } else {
        *write_ptr = '\0';
    }

    *out = buffer;
    return true;
}

#ifdef SCREEN_SIZE_WALLET
static bool build_wallet_warning_details_page(const warning_definition_t *const *warning_defs,
                                              size_t warning_count,
                                              nbgl_warningDetails_t *page) {
    LEDGER_ASSERT(warning_defs != NULL, "NULL warning_defs");
    LEDGER_ASSERT(page != NULL, "NULL page");

    nbgl_warningDetails_t *details = NULL;
    const nbgl_icon_details_t **icons = NULL;
    const char **titles = NULL;
    const char **subtexts = NULL;
    size_t warnings_on_page = (warning_count < MAX_WARNING_BARS_PER_PAGE) ? warning_count
                                                                          : MAX_WARNING_BARS_PER_PAGE;
    bool has_more_warnings = warning_count > warnings_on_page;
    size_t row_count = warnings_on_page + (has_more_warnings ? 1 : 0);

    if (!allocate_zeroed((void **) &icons, sizeof(nbgl_icon_details_t *) * row_count) ||
        !allocate_zeroed((void **) &titles, sizeof(const char *) * row_count) ||
        !allocate_zeroed((void **) &subtexts, sizeof(const char *) * row_count) ||
        !allocate_zeroed((void **) &details, sizeof(nbgl_warningDetails_t) * row_count)) {
        if (icons != NULL) APP_MEM_FREE((void *) icons);
        if (titles != NULL) APP_MEM_FREE((void *) titles);
        if (subtexts != NULL) APP_MEM_FREE((void *) subtexts);
        if (details != NULL) APP_MEM_FREE(details);
        return false;
    }

    for (size_t i = 0; i < warnings_on_page; i++) {
        const warning_definition_t *def = (const warning_definition_t *) PIC(warning_defs[i]);
        const char *title = (const char *) PIC(def->title);
        const char *description = (const char *) PIC(def->description);

        titles[i] = title;
        subtexts[i] = NULL;
        icons[i] = &WARNING_ICON;

        details[i].title = title;
        details[i].type = CENTERED_INFO_WARNING;
        details[i].centeredInfo.icon = &WARNING_ICON;
        details[i].centeredInfo.title = title;
        details[i].centeredInfo.description = description;
    }

    if (has_more_warnings) {
        size_t more_index = warnings_on_page;
        titles[more_index] = (const char *) PIC(SEE_MORE_WARNINGS_TITLE);
        subtexts[more_index] = NULL;
        icons[more_index] = &WARNING_ICON;

        if (!build_warning_summary_text(
                warning_defs,
                warnings_on_page,
                warning_count,
                false,
                &g_warning_overflow_text)) {
            if (icons != NULL) APP_MEM_FREE((void *) icons);
            if (titles != NULL) APP_MEM_FREE((void *) titles);
            if (subtexts != NULL) APP_MEM_FREE((void *) subtexts);
            if (details != NULL) APP_MEM_FREE(details);
            return false;
        }

        details[more_index].title = (const char *) PIC(SECURITY_WARNING_TITLE);
        details[more_index].type = CENTERED_INFO_WARNING;
        details[more_index].centeredInfo.icon = &WARNING_ICON;
        details[more_index].centeredInfo.title = g_warning_overflow_text;
        details[more_index].centeredInfo.description = NULL;
    }

    page->title = (const char *) PIC(SECURITY_WARNING_TITLE);
    page->type = BAR_LIST_WARNING;
    page->barList.nbBars = row_count;
    page->barList.icons = icons;
    page->barList.texts = titles;
    page->barList.subTexts = subtexts;
    page->barList.details = details;
    return true;
}

static void free_wallet_warning_details_page(const nbgl_warningDetails_t *page) {
    if (page == NULL) {
        return;
    }

    if (page->type == BAR_LIST_WARNING) {
        if (page->barList.icons != NULL) {
            APP_MEM_FREE((void *) page->barList.icons);
        }
        if (page->barList.texts != NULL) {
            APP_MEM_FREE((void *) page->barList.texts);
        }
        if (page->barList.subTexts != NULL) {
            APP_MEM_FREE((void *) page->barList.subTexts);
        }
        if (page->barList.details != NULL) {
            APP_MEM_FREE((void *) page->barList.details);
        }
    }
    APP_MEM_FREE((void *) page);
}
#endif

ui_status_t ui_build_warnings(warning_bits_t warnings) {
    LEDGER_ASSERT(g_warning == NULL, "Warnings already built");
    const warning_definition_t *warning_defs[WARNING_BIT_COUNT];
    size_t warning_count =
        warning_bits_to_definitions(warnings, warning_defs, WARNING_BIT_COUNT);

    if (warning_count == 0) {
        g_warning = NULL;
        return UI_STATUS_SUCCESS;
    }

    nbgl_contentCenter_t *info = NULL;
    g_warning = NULL;

    if (!allocate_zeroed((void **) &info, sizeof(nbgl_contentCenter_t)) ||
        !allocate_zeroed((void **) &g_warning, sizeof(nbgl_warning_t))) {
        if (info != NULL) {
            APP_MEM_FREE(info);
        }
        if (g_warning != NULL) {
            APP_MEM_FREE(g_warning);
            g_warning = NULL;
        }
        free_warning_dynamic_strings();
        return UI_STATUS_OUT_OF_MEMORY;
    }

#ifdef SCREEN_SIZE_WALLET
    nbgl_warningDetails_t *intro = NULL;

    if (!allocate_zeroed((void **) &intro, sizeof(nbgl_warningDetails_t)) ||
        !build_wallet_warning_details_page(warning_defs, warning_count, intro)) {
        if (intro != NULL) {
            APP_MEM_FREE(intro);
        }
        ui_free_warnings();
        return UI_STATUS_OUT_OF_MEMORY;
    }

    info->icon = &WARNING_ICON;
    info->title = (const char *) PIC(SECURITY_WARNING_TITLE);
    info->description = (const char *) PIC(SECURITY_WARNING_REVIEW_TEXT);

    g_warning->info = info;
    g_warning->introDetails = intro;
    g_warning->introTopRightIcon = &WARNING_ICON;
#else
    nbgl_warningDetails_t *intro = NULL;

    if (!allocate_zeroed((void **) &intro, sizeof(nbgl_warningDetails_t)) ||
        !build_warning_summary_text(warning_defs, 0, warning_count, false, &g_warning_summary_text)) {
        ui_free_warnings();
        return UI_STATUS_OUT_OF_MEMORY;
    }

    info->icon = &WARNING_ICON;
    info->title = (const char *) PIC(SECURITY_WARNING_TITLE);
    info->description = NULL;

    intro->title = (const char *) PIC(SECURITY_WARNING_TITLE);
    intro->type = CENTERED_INFO_WARNING;
    intro->centeredInfo.icon = &WARNING_ICON;
    intro->centeredInfo.title = g_warning_summary_text;
    intro->centeredInfo.description = NULL;

    g_warning->info = info;
    g_warning->introDetails = intro;
#endif

    return UI_STATUS_SUCCESS;
}

const nbgl_warning_t* ui_get_warnings(void) {
    // Returns NULL if no warnings were built (warning count was 0)
    return g_warning;
}

void ui_free_warnings(void) {
    if (g_warning == NULL) {
        free_warning_dynamic_strings();
        return;
    }

    if (g_warning->introDetails != NULL) {
#ifdef SCREEN_SIZE_WALLET
        if (g_warning->introDetails->type == BAR_LIST_WARNING) {
            free_wallet_warning_details_page(g_warning->introDetails);
        } else
#endif
        APP_MEM_FREE((void *) g_warning->introDetails);
    }
    if (g_warning->reviewDetails != NULL) {
        APP_MEM_FREE((void *) g_warning->reviewDetails);
    }
    if (g_warning->info != NULL) {
        APP_MEM_FREE((void *) g_warning->info);
    }

    APP_MEM_FREE_AND_NULL((void **) &g_warning);
    free_warning_dynamic_strings();
}
