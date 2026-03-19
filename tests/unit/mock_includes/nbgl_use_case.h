/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "glyphs.h"

// ======================================================================
// Callback typedefs
// ======================================================================

typedef void (*nbgl_callback_t)(void);
typedef void (*nbgl_choiceCallback_t)(bool confirm);

// ======================================================================
// Operation types
// ======================================================================

typedef enum {
    TYPE_TRANSACTION = 0,
    TYPE_MESSAGE,
    TYPE_OPERATION
} nbgl_opType_t;

#define SKIPPABLE_OPERATION (1 << 4)
#define BLIND_OPERATION     (1 << 5)

typedef uint32_t nbgl_operationType_t;

// ======================================================================
// Review status types
// ======================================================================

typedef enum {
    STATUS_TYPE_TRANSACTION_SIGNED = 0,
    STATUS_TYPE_TRANSACTION_REJECTED,
    STATUS_TYPE_MESSAGE_SIGNED,
    STATUS_TYPE_MESSAGE_REJECTED,
    STATUS_TYPE_OPERATION_SIGNED,
    STATUS_TYPE_OPERATION_REJECTED,
    STATUS_TYPE_ADDRESS_VERIFIED,
    STATUS_TYPE_ADDRESS_REJECTED,
} nbgl_reviewStatusType_t;

// ======================================================================
// Content types (minimal stubs for types used in function signatures)
// ======================================================================

typedef struct {
    const char *item;
    const char *value;
    int8_t forcePageStart : 1;  ///< if set to 1, the tag will be displayed at the top of a new
                                ///< review page
    int8_t centeredInfo : 1;    ///< if set to 1, the tag will be displayed as a centered info
    int8_t aliasValue : 1;      ///< if set to 1, the value represents an alias
} nbgl_contentTagValue_t;

typedef nbgl_contentTagValue_t *(*nbgl_contentTagValueCallback_t)(uint8_t pairIndex);
typedef void (*nbgl_contentActionCallback_t)(int token, uint8_t index, int page);

typedef struct {
    const nbgl_contentTagValue_t *pairs;
    nbgl_contentTagValueCallback_t callback;
    uint8_t nbPairs;
    uint8_t startIndex;
    bool hideEndOfLastLine;
    uint8_t nbMaxLinesForValue;
    uint8_t token;
    bool smallCaseForValue;
    bool wrapping;
    nbgl_contentActionCallback_t actionCallback;
} nbgl_contentTagValueList_t;

// Opaque types only passed as NULL by our app code
typedef struct nbgl_tipBox_s nbgl_tipBox_t;
typedef struct nbgl_homeAction_s nbgl_homeAction_t;
typedef struct nbgl_genericContents_s nbgl_genericContents_t;
typedef struct nbgl_contentInfoList_s nbgl_contentInfoList_t;

// ======================================================================
// Warning types (used by ui_warnings.c)
// ======================================================================

typedef enum {
    CENTERED_INFO_WARNING = 0,
    BAR_LIST_WARNING = 1,
} nbgl_warning_type_e;

typedef enum {
    W3C_ISSUE_WARN = 0,
    W3C_RISK_DETECTED_WARN,
    W3C_THREAT_DETECTED_WARN,
    W3C_NO_THREAT_WARN,
    BLIND_SIGNING_WARN,
    GATED_SIGNING_WARN,
    NB_WARNING_TYPES
} nbgl_predefined_warning_t;

typedef struct {
    const nbgl_icon_details_t *icon;
    const char *title;
    const char *description;
} nbgl_centered_info_t;

typedef struct nbgl_warningDetails_s {
    const char *title;
    nbgl_warning_type_e type;
    nbgl_centered_info_t centeredInfo;
    struct {
        size_t nbBars;
        const nbgl_icon_details_t **icons;
        const char **texts;
        const char **subTexts;
        struct nbgl_warningDetails_s *details;
    } barList;
} nbgl_warningDetails_t;

typedef struct {
    const char *title;
    const nbgl_icon_details_t *icon;
    const char *description;
} nbgl_contentCenter_t;

typedef struct {
    uint32_t predefinedSet;
    nbgl_warningDetails_t *introDetails;
    nbgl_warningDetails_t *reviewDetails;
    nbgl_contentCenter_t *info;
    const nbgl_icon_details_t *introTopRightIcon;
    const nbgl_icon_details_t *reviewTopRightIcon;
} nbgl_warning_t;

// ======================================================================
// NBGL use case function declarations
// ======================================================================

void nbgl_useCaseSpinner(const char *text);

void nbgl_useCaseStatus(const char *message, bool isSuccess, nbgl_callback_t quitCallback);

void nbgl_useCaseReviewStatus(nbgl_reviewStatusType_t reviewStatusType,
                              nbgl_callback_t         quitCallback);

void nbgl_useCaseAdvancedReview(nbgl_operationType_t              operationType,
                                const nbgl_contentTagValueList_t *tagValueList,
                                const nbgl_icon_details_t        *icon,
                                const char                       *reviewTitle,
                                const char                       *reviewSubTitle,
                                const char                       *finishTitle,
                                const nbgl_tipBox_t              *tipBox,
                                const nbgl_warning_t             *warning,
                                nbgl_choiceCallback_t             choiceCallback);

void nbgl_useCaseChoice(const nbgl_icon_details_t *icon,
                        const char                *message,
                        const char                *subMessage,
                        const char                *confirmText,
                        const char                *rejectString,
                        nbgl_choiceCallback_t      callback);

void nbgl_useCaseAddressReview(const char                       *address,
                               const nbgl_contentTagValueList_t *additionalTagValueList,
                               const nbgl_icon_details_t        *icon,
                               const char                       *reviewTitle,
                               const char                       *reviewSubTitle,
                               nbgl_choiceCallback_t             choiceCallback);

void nbgl_useCaseReviewStreamingStart(nbgl_operationType_t       operationType,
                                      const nbgl_icon_details_t *icon,
                                      const char                *reviewTitle,
                                      const char                *reviewSubTitle,
                                      nbgl_choiceCallback_t      choiceCallback);

void nbgl_useCaseAdvancedReviewStreamingStart(nbgl_operationType_t       operationType,
                                              const nbgl_icon_details_t *icon,
                                              const char                *reviewTitle,
                                              const char                *reviewSubTitle,
                                              const nbgl_warning_t      *warning,
                                              nbgl_choiceCallback_t      choiceCallback);

void nbgl_useCaseReviewStreamingContinue(const nbgl_contentTagValueList_t *tagValueList,
                                         nbgl_choiceCallback_t             choiceCallback);

void nbgl_useCaseReviewStreamingFinish(const char           *finishTitle,
                                       nbgl_choiceCallback_t choiceCallback);

void nbgl_useCaseHomeAndSettings(const char                   *appName,
                                 const nbgl_icon_details_t    *appIcon,
                                 const char                   *tagline,
                                 const uint8_t                 initSettingPage,
                                 const nbgl_genericContents_t *settingContents,
                                 const nbgl_contentInfoList_t *infosList,
                                 const nbgl_homeAction_t      *action,
                                 nbgl_callback_t               quitCallback);
