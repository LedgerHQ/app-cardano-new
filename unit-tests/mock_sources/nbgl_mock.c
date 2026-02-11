/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

/**
 * Centralized NBGL mock implementations for unit tests.
 *
 * All NBGL use-case functions auto-confirm by calling their choice/quit
 * callbacks synchronously. This lets unit tests exercise the real app UI
 * code (formatting, state validation, cleanup) without pulling in the
 * actual NBGL rendering stack.
 */

#include "nbgl_use_case.h"
#include "nbgl_mock.h"
#include "menu.h"

#define NBGL_MOCK_MAX_FINAL_DECISIONS 16

static bool g_final_decisions_storage[NBGL_MOCK_MAX_FINAL_DECISIONS];
static size_t g_final_decision_count = 0;
static size_t g_final_decision_index = 0;
static bool g_reject_next_final_decision_enabled = false;
static bool g_reject_next_final_decision_consumed = false;
static nbgl_opType_t g_reject_next_operation_type = TYPE_TRANSACTION;
static nbgl_operationType_t g_last_streaming_operation_type = TYPE_TRANSACTION;

void nbgl_mock_reset(void) {
    g_final_decision_count = 0;
    g_final_decision_index = 0;
    g_reject_next_final_decision_enabled = false;
    g_reject_next_final_decision_consumed = false;
    g_reject_next_operation_type = TYPE_TRANSACTION;
    g_last_streaming_operation_type = TYPE_TRANSACTION;
}

void nbgl_mock_set_final_decisions(const bool *decisions, size_t decision_count) {
    if (decisions == NULL || decision_count == 0) {
        g_final_decision_count = 0;
        g_final_decision_index = 0;
        return;
    }

    if (decision_count > NBGL_MOCK_MAX_FINAL_DECISIONS) {
        decision_count = NBGL_MOCK_MAX_FINAL_DECISIONS;
    }

    for (size_t i = 0; i < decision_count; i++) {
        g_final_decisions_storage[i] = decisions[i];
    }

    g_final_decision_count = decision_count;
    g_final_decision_index = 0;
}

void nbgl_mock_reject_next_final_decision_for_operation(nbgl_opType_t operation_type) {
    g_reject_next_final_decision_enabled = true;
    g_reject_next_final_decision_consumed = false;
    g_reject_next_operation_type = operation_type;
}

static nbgl_opType_t nbgl_mock_operation_base_type(nbgl_operationType_t operation_type) {
    return (nbgl_opType_t) (operation_type & 0x0F);
}

static bool nbgl_mock_next_final_decision(void) {
    if (g_final_decision_index < g_final_decision_count) {
        return g_final_decisions_storage[g_final_decision_index++];
    }
    return true;
}

static bool nbgl_mock_final_decision_for_operation(nbgl_operationType_t operation_type) {
    const nbgl_opType_t operation_base_type = nbgl_mock_operation_base_type(operation_type);

    if (g_reject_next_final_decision_enabled &&
        !g_reject_next_final_decision_consumed &&
        operation_base_type == g_reject_next_operation_type) {
        g_reject_next_final_decision_consumed = true;
        return false;
    }

    return nbgl_mock_next_final_decision();
}

// ======================================================================
// No-op functions
// ======================================================================

void nbgl_useCaseSpinner(const char *text) {
    (void) text;
}

void nbgl_useCaseHomeAndSettings(const char                   *appName,
                                 const nbgl_icon_details_t    *appIcon,
                                 const char                   *tagline,
                                 const uint8_t                 initSettingPage,
                                 const nbgl_genericContents_t *settingContents,
                                 const nbgl_contentInfoList_t *infosList,
                                 const nbgl_homeAction_t      *action,
                                 nbgl_callback_t               quitCallback) {
    (void) appName;
    (void) appIcon;
    (void) tagline;
    (void) initSettingPage;
    (void) settingContents;
    (void) infosList;
    (void) action;
    (void) quitCallback;
}

// ======================================================================
// Status functions (call quit callback)
// ======================================================================

void nbgl_useCaseStatus(const char *message, bool isSuccess, nbgl_callback_t quitCallback) {
    (void) message;
    (void) isSuccess;
    if (quitCallback != NULL) {
        quitCallback();
    }
}

void nbgl_useCaseReviewStatus(nbgl_reviewStatusType_t reviewStatusType,
                              nbgl_callback_t         quitCallback) {
    (void) reviewStatusType;
    if (quitCallback != NULL) {
        quitCallback();
    }
}

// ======================================================================
// Review/choice functions (auto-confirm with true)
// ======================================================================

void nbgl_useCaseAdvancedReview(nbgl_operationType_t              operationType,
                                const nbgl_contentTagValueList_t *tagValueList,
                                const nbgl_icon_details_t        *icon,
                                const char                       *reviewTitle,
                                const char                       *reviewSubTitle,
                                const char                       *finishTitle,
                                const nbgl_tipBox_t              *tipBox,
                                const nbgl_warning_t             *warning,
                                nbgl_choiceCallback_t             choiceCallback) {
    (void) operationType;
    (void) tagValueList;
    (void) icon;
    (void) reviewTitle;
    (void) reviewSubTitle;
    (void) finishTitle;
    (void) tipBox;
    (void) warning;
    if (choiceCallback != NULL) {
        choiceCallback(nbgl_mock_final_decision_for_operation(operationType));
    }
}

void nbgl_useCaseChoice(const nbgl_icon_details_t *icon,
                        const char                *message,
                        const char                *subMessage,
                        const char                *confirmText,
                        const char                *rejectString,
                        nbgl_choiceCallback_t      callback) {
    (void) icon;
    (void) message;
    (void) subMessage;
    (void) confirmText;
    (void) rejectString;
    if (callback != NULL) {
        callback(nbgl_mock_next_final_decision());
    }
}

void nbgl_useCaseAddressReview(const char                       *address,
                               const nbgl_contentTagValueList_t *additionalTagValueList,
                               const nbgl_icon_details_t        *icon,
                               const char                       *reviewTitle,
                               const char                       *reviewSubTitle,
                               nbgl_choiceCallback_t             choiceCallback) {
    (void) address;
    (void) additionalTagValueList;
    (void) icon;
    (void) reviewTitle;
    (void) reviewSubTitle;
    if (choiceCallback != NULL) {
        choiceCallback(nbgl_mock_next_final_decision());
    }
}

// ======================================================================
// Streaming review functions (auto-confirm with true)
// ======================================================================

void nbgl_useCaseReviewStreamingStart(nbgl_operationType_t       operationType,
                                      const nbgl_icon_details_t *icon,
                                      const char                *reviewTitle,
                                      const char                *reviewSubTitle,
                                      nbgl_choiceCallback_t      choiceCallback) {
    g_last_streaming_operation_type = operationType;
    (void) operationType;
    (void) icon;
    (void) reviewTitle;
    (void) reviewSubTitle;
    (void) choiceCallback;
}

void nbgl_useCaseAdvancedReviewStreamingStart(nbgl_operationType_t       operationType,
                                              const nbgl_icon_details_t *icon,
                                              const char                *reviewTitle,
                                              const char                *reviewSubTitle,
                                              const nbgl_warning_t      *warning,
                                              nbgl_choiceCallback_t      choiceCallback) {
    g_last_streaming_operation_type = operationType;
    (void) operationType;
    (void) icon;
    (void) reviewTitle;
    (void) reviewSubTitle;
    (void) warning;
    (void) choiceCallback;
}

void nbgl_useCaseReviewStreamingContinue(const nbgl_contentTagValueList_t *tagValueList,
                                         nbgl_choiceCallback_t             choiceCallback) {
    (void) tagValueList;
    if (choiceCallback != NULL) {
        choiceCallback(true);
    }
}

void nbgl_useCaseReviewStreamingFinish(const char           *finishTitle,
                                       nbgl_choiceCallback_t choiceCallback) {
    (void) finishTitle;
    if (choiceCallback != NULL) {
        choiceCallback(nbgl_mock_final_decision_for_operation(g_last_streaming_operation_type));
    }
}

// ======================================================================
// UI menu stub (replaces per-test duplicates)
// ======================================================================

void ui_menu_main(void) {
    // no-op in unit tests
}
