/* SPDX-FileCopyrightText: 2025 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

/* Optional module-specific tracing for debugging.
 * Enabled via -DTRACE_UI_DISPLAY to trace address field UI rendering.
 */
#ifdef TRACE_UI_DISPLAY
#define TRACE_MODULE(...) TRACE("[ui_address_fields] " __VA_ARGS__)
#else
#define TRACE_MODULE(...) (void)0  // Compiled out
#endif

#include "ui_address_fields.h"
#include "ui_utils.h"
#include "ui_constants.h"
#include "ui_formatters.h"
#include "tx_ui_pair_counts.h"
#include "addressUtilsShelley.h"
#include "bip44.h"
#include "bech32.h"
#include "keyDerivation.h"
#include "assert.h"
#include "ipUtils.h"

void addPaymentInfoUIPairs(const address_params_t* address_params) {
    TRACE_MODULE("addPaymentInfoUIPairs: address_type=%u", (unsigned) address_params->type);
    START_COUNT();
    switch (determinePaymentChoice(address_params->type)) {
        case PAYMENT_PATH: {
            LEDGER_ASSERT(addressParams_getPaymentPartType(address_params) == PAYMENT_PART_KEY_PATH, "Payment credential must be KEY_PATH");
            UI_ADD_FORMAT1(UI_LABEL_BY_SCREEN("Payment key path", "Pay path"), MAX_BIP44_PATH_STRING_LENGTH, format_bip44_path, &address_params->paymentKeyPath);
            break;
        }

        case PAYMENT_SCRIPT_HASH: {
            LEDGER_ASSERT(addressParams_getPaymentPartType(address_params) == PAYMENT_PART_SCRIPT_HASH, "Payment credential must be SCRIPT_HASH");
            LEDGER_ASSERT(address_params->paymentScriptHash != NULL, "NULL payment script hash");
            UI_ADD_FORMAT3(UI_LABEL_BY_SCREEN("Payment script hash", "Pay script"), MAX_BECH32_STRING_LENGTH, format_bech32, BECH32_PREFIX_SCRIPT_HASH, address_params->paymentScriptHash, SCRIPT_HASH_LENGTH);
            break;
        }

        // LCOV_EXCL_START
        default:
            // includes PAYMENT_NONE
            LEDGER_ASSERT(false, "Invalid payment choice");
        // LCOV_EXCL_STOP
    }
    CHECK_COUNT(UI_PAIRS_PAYMENT_INFO);
}

void addStakingInfoUIPairs(const address_params_t* address_params) {
    TRACE_MODULE("addStakingInfoUIPairs: staking_part_type=%u", (unsigned) addressParams_getStakingPartType(address_params));
    START_COUNT();
    switch (addressParams_getStakingPartType(address_params)) {
        case STAKING_PART_NONE: {
            switch (address_params->type) {
                case BYRON:
                    UI_ADD_STATIC(UI_STATIC_LABEL("Warning:"), UI_LABEL_BY_SCREEN("Legacy Byron address (no staking rewards)", "Byron (no staking)"));
                    break;

                case ENTERPRISE_KEY:
                case ENTERPRISE_SCRIPT:
                    UI_ADD_STATIC(UI_STATIC_LABEL("Warning:"), UI_STATIC_LABEL("no staking rewards"));
                    break;

                // LCOV_EXCL_START
                default:
                    LEDGER_ASSERT(false, "Invalid payment choice");
                // LCOV_EXCL_STOP
            }
            break;
        }

        case STAKING_PART_KEY_PATH: {
            LEDGER_ASSERT(addressParams_getStakingPartType(address_params) == STAKING_PART_KEY_PATH, "Staking credential must be KEY_PATH");
            UI_ADD_FORMAT1(UI_STATIC_LABEL("Staking path"), MAX_BIP44_PATH_STRING_LENGTH, format_bip44_path, &address_params->stakingKeyPath);
            break;
        }

        case STAKING_PART_KEY_HASH: {
            LEDGER_ASSERT(addressParams_getStakingPartType(address_params) == STAKING_PART_KEY_HASH, "Staking credential must be KEY_HASH");
            LEDGER_ASSERT(address_params->stakingKeyHash != NULL, "NULL staking key hash");
            UI_ADD_FORMAT3(UI_LABEL_BY_SCREEN("Stake key hash", "Stake key"), MAX_BECH32_STRING_LENGTH, format_bech32, BECH32_PREFIX_STAKE_KEY_HASH, address_params->stakingKeyHash, ADDRESS_KEY_HASH_LENGTH);
            break;
        }

        case STAKING_PART_SCRIPT_HASH: {
            LEDGER_ASSERT(addressParams_getStakingPartType(address_params) == STAKING_PART_SCRIPT_HASH, "Staking credential must be SCRIPT_HASH");
            LEDGER_ASSERT(address_params->stakingScriptHash != NULL, "NULL staking script hash");
            UI_ADD_FORMAT3(UI_LABEL_BY_SCREEN("Stake script hash", "Stake hash"), MAX_BECH32_STRING_LENGTH, format_bech32, BECH32_PREFIX_SCRIPT_HASH, address_params->stakingScriptHash, SCRIPT_HASH_LENGTH);
            break;
        }

        case STAKING_PART_BLOCKCHAIN_POINTER: {
            UI_ADD_FORMAT1(UI_LABEL_BY_SCREEN("Stake key pointer", "Stake ptr"), MAX_BIP44_PATH_STRING_LENGTH, format_blockchain_pointer, address_params->stakingKeyBlockchainPointer);
            break;
        }

        // LCOV_EXCL_START
        default:
            LEDGER_ASSERT(false, "Invalid staking data source");
        // LCOV_EXCL_STOP
    }
    CHECK_COUNT(UI_PAIRS_STAKING_INFO);
}
