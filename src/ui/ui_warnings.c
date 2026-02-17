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

ui_status_t ui_build_warnings(warning_bits_t warnings) {
    LEDGER_ASSERT(g_warning == NULL, "Warnings already built");
    const warning_definition_t *warning_defs[WARNING_BIT_COUNT];
    size_t warning_count =
        warning_bits_to_definitions(warnings, warning_defs, WARNING_BIT_COUNT);

    if (warning_count == 0) {
        g_warning = NULL;
        return UI_STATUS_SUCCESS;
    }

    const nbgl_icon_details_t **icons = NULL;
    const char **titles = NULL;
    const char **subtexts = NULL;
    nbgl_warningDetails_t *details = NULL;
    nbgl_warningDetails_t *intro = NULL;
    nbgl_warningDetails_t *review = NULL;
    nbgl_contentCenter_t *info = NULL;
    g_warning = NULL;

    if (!allocate_zeroed((void **) &icons, sizeof(nbgl_icon_details_t *) * warning_count) ||
        !allocate_zeroed((void **) &titles, sizeof(const char *) * warning_count) ||
        !allocate_zeroed((void **) &subtexts, sizeof(const char *) * warning_count) ||
        !allocate_zeroed((void **) &details, sizeof(nbgl_warningDetails_t) * warning_count) ||
        !allocate_zeroed((void **) &intro, sizeof(nbgl_warningDetails_t)) ||
        !allocate_zeroed((void **) &review, sizeof(nbgl_warningDetails_t)) ||
        !allocate_zeroed((void **) &info, sizeof(nbgl_contentCenter_t)) ||
        !allocate_zeroed((void **) &g_warning, sizeof(nbgl_warning_t))) {
        if (icons != NULL) {
            APP_MEM_FREE((void *) icons);
        }
        if (titles != NULL) {
            APP_MEM_FREE((void *) titles);
        }
        if (subtexts != NULL) {
            APP_MEM_FREE((void *) subtexts);
        }
        if (details != NULL) {
            APP_MEM_FREE(details);
        }
        if (intro != NULL) {
            APP_MEM_FREE(intro);
        }
        if (review != NULL) {
            APP_MEM_FREE(review);
        }
        if (info != NULL) {
            APP_MEM_FREE(info);
        }
        if (g_warning != NULL) {
            APP_MEM_FREE(g_warning);
        }
        g_warning = NULL;
        return UI_STATUS_OUT_OF_MEMORY;
    }

    for (size_t i = 0; i < warning_count; i++) {
        const warning_definition_t *def = (const warning_definition_t *) PIC(warning_defs[i]);
        const char *title = (const char *) PIC(def->title);
        const char *description = (const char *) PIC(def->description);
        titles[i] = title;
        subtexts[i] = description;
        icons[i] = &WARNING_ICON;

        details[i].title = title;
        details[i].type = CENTERED_INFO_WARNING;
        details[i].centeredInfo.icon = &WARNING_ICON;
        details[i].centeredInfo.title = title;
        details[i].centeredInfo.description = description;
    }

    const char *const warning_intro_title = (const char *) PIC("Security report");
    const char *const warning_review_title = (const char *) PIC("Warning details");
    const char *const warning_info_title = (const char *) PIC("Security warning");
    const char *const warning_info_desc = (const char *) PIC("Please review the security warnings before proceeding.");

    intro->title = warning_intro_title;
    intro->type = BAR_LIST_WARNING;
    intro->barList.nbBars = warning_count;
    intro->barList.icons = icons;
    intro->barList.texts = titles;
    intro->barList.subTexts = subtexts;
    intro->barList.details = details;

    review->title = warning_review_title;
    review->type = BAR_LIST_WARNING;
    review->barList.nbBars = warning_count;
    review->barList.icons = icons;
    review->barList.texts = titles;
    review->barList.subTexts = subtexts;
    review->barList.details = details;

    info->icon = &WARNING_ICON;
    info->title = warning_info_title;
    info->description = warning_info_desc;

    g_warning->introDetails = intro;
    g_warning->reviewDetails = review;
    g_warning->info = info;
    g_warning->introTopRightIcon = &WARNING_ICON;
    g_warning->reviewTopRightIcon = &WARNING_ICON;

    return UI_STATUS_SUCCESS;
}

const nbgl_warning_t* ui_get_warnings(void) {
    // Returns NULL if no warnings were built (warning count was 0)
    return g_warning;
}

void ui_free_warnings(void) {
    if (g_warning == NULL) {
        return;
    }

    const nbgl_warningDetails_t *intro = g_warning->introDetails;
    const nbgl_warningDetails_t *review = g_warning->reviewDetails;
    const nbgl_warningDetails_t *details_owner = (intro != NULL) ? intro : review;

    if (details_owner != NULL) {
        if (details_owner->barList.icons != NULL) {
            APP_MEM_FREE((void *) details_owner->barList.icons);
        }
        if (details_owner->barList.texts != NULL) {
            APP_MEM_FREE((void *) details_owner->barList.texts);
        }
        if (details_owner->barList.subTexts != NULL) {
            APP_MEM_FREE((void *) details_owner->barList.subTexts);
        }
        if (details_owner->barList.details != NULL) {
            APP_MEM_FREE((void *) details_owner->barList.details);
        }
    }

    if (g_warning->introDetails != NULL) {
        APP_MEM_FREE((void *) g_warning->introDetails);
    }
    if (g_warning->reviewDetails != NULL) {
        APP_MEM_FREE((void *) g_warning->reviewDetails);
    }
    if (g_warning->info != NULL) {
        APP_MEM_FREE((void *) g_warning->info);
    }

    APP_MEM_FREE_AND_NULL((void **) &g_warning);
}
