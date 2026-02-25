/* SPDX-FileCopyrightText: 2025 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <string.h>
#include <stdio.h>

#include "tx_ui_helpers.h"
#include "ui_utils.h"
#include "ui_constants.h"
#include "ui_formatters.h"
#include "cardano_swo.h"
#include "tx_ui_plan.h"
#include "addressUtilsShelley.h"
#include "bip44.h"
#include "bech32.h"
#include "keyDerivation.h"
#include "securityPolicy.h"
#include "securityWarnings.h"
#include "tx_utils.h"
#include "assert.h"
#include "ipUtils.h"
#include "globals.h"
#include "mem.h"

void addCredentialUIPairs(const ext_credential_t *credential,
                        const char *keyPathLabel,
                        const char *keyHashLabel,
                        const char *keyHashPrefix,
                        const char *scriptHashLabel,
                        const char *scriptHashPrefix) {
    LEDGER_ASSERT(credential != NULL, "NULL credential");
    LEDGER_ASSERT(keyPathLabel != NULL && keyPathLabel[0] != '\0', "Invalid keyPathLabel");
    LEDGER_ASSERT(keyHashLabel != NULL && keyHashLabel[0] != '\0', "Invalid keyHashLabel");
    LEDGER_ASSERT(keyHashPrefix != NULL && keyHashPrefix[0] != '\0', "Invalid keyHashPrefix");
    LEDGER_ASSERT(scriptHashLabel != NULL && scriptHashLabel[0] != '\0', "Invalid scriptHashLabel");
    LEDGER_ASSERT(scriptHashPrefix != NULL && scriptHashPrefix[0] != '\0', "Invalid scriptHashPrefix");

    START_COUNT();
    switch (credential->type) {
        case EXT_CREDENTIAL_KEY_PATH: {
            UI_ADD_FORMAT1(keyPathLabel, MAX_BIP44_PATH_STRING_LENGTH, format_bip44_path, &credential->keyPath);
            break;
        }
        case EXT_CREDENTIAL_KEY_HASH: {
            UI_ADD_FORMAT3(keyHashLabel, MAX_BECH32_STRING_LENGTH, format_bech32, keyHashPrefix, credential->keyHash, ADDRESS_KEY_HASH_LENGTH);
            break;
        }
        case EXT_CREDENTIAL_SCRIPT_HASH: {
            UI_ADD_FORMAT3(scriptHashLabel, MAX_BECH32_STRING_LENGTH, format_bech32, scriptHashPrefix, credential->scriptHash, SCRIPT_HASH_LENGTH);
            break;
        }
        default:
            LEDGER_ASSERT(false, "Unknown credential type");
    }
    CHECK_COUNT(1);
}

void addVoterUIPairs(const ext_voter_t *voter) {
    LEDGER_ASSERT(voter != NULL, "NULL voter");

    START_COUNT();
    switch (voter->type) {
        case EXT_VOTER_COMMITTEE_HOT_KEY_PATH:
            UI_ADD_FORMAT1(UI_LABEL_BY_SCREEN("Committee hot key", "Cmte hot key"),
                           MAX_BIP44_PATH_STRING_LENGTH,
                           format_bip44_path,
                           &voter->keyPath);
            break;
        case EXT_VOTER_COMMITTEE_HOT_KEY_HASH:
            LEDGER_ASSERT(voter->keyHash != NULL, "NULL committee hot key hash voter");
            UI_ADD_FORMAT3(UI_LABEL_BY_SCREEN("Committee hot key hash", "Cmte hot key"),
                           MAX_BECH32_STRING_LENGTH,
                           format_bech32,
                           "cc_hot_vkh",
                           voter->keyHash,
                           ADDRESS_KEY_HASH_LENGTH);
            break;
        case EXT_VOTER_COMMITTEE_HOT_SCRIPT_HASH:
            LEDGER_ASSERT(voter->scriptHash != NULL, "NULL committee hot script hash voter");
            UI_ADD_FORMAT3(UI_LABEL_BY_SCREEN("Committee hot script hash", "Cmte hot script"),
                           MAX_BECH32_STRING_LENGTH,
                           format_bech32,
                           "cc_hot_script",
                           voter->scriptHash,
                           SCRIPT_HASH_LENGTH);
            break;
        case EXT_VOTER_DREP_KEY_PATH:
            UI_ADD_FORMAT1(UI_STATIC_LABEL("DRep key"),
                           MAX_BIP44_PATH_STRING_LENGTH,
                           format_bip44_path,
                           &voter->keyPath);
            break;
        case EXT_VOTER_DREP_KEY_HASH:
            LEDGER_ASSERT(voter->keyHash != NULL, "NULL drep key hash voter");
            UI_ADD_FORMAT3(UI_LABEL_BY_SCREEN("DRep key hash", "DRep key hash"),
                           MAX_BECH32_STRING_LENGTH,
                           format_bech32,
                           "drep_vkh",
                           voter->keyHash,
                           ADDRESS_KEY_HASH_LENGTH);
            break;
        case EXT_VOTER_DREP_SCRIPT_HASH:
            LEDGER_ASSERT(voter->scriptHash != NULL, "NULL drep script hash voter");
            UI_ADD_FORMAT3(UI_LABEL_BY_SCREEN("DRep script hash", "DRep scrpt hash"),
                           MAX_BECH32_STRING_LENGTH,
                           format_bech32,
                           "drep_script",
                           voter->scriptHash,
                           SCRIPT_HASH_LENGTH);
            break;
        case EXT_VOTER_STAKE_POOL_KEY_PATH:
            UI_ADD_FORMAT1(UI_STATIC_LABEL("Stake pool key"),
                           MAX_BIP44_PATH_STRING_LENGTH,
                           format_bip44_path,
                           &voter->keyPath);
            break;
        case EXT_VOTER_STAKE_POOL_KEY_HASH:
            LEDGER_ASSERT(voter->keyHash != NULL, "NULL stake pool key hash voter");
            UI_ADD_FORMAT3(UI_LABEL_BY_SCREEN("Stake pool key hash", "Pool key hash"),
                           MAX_BECH32_STRING_LENGTH,
                           format_bech32,
                           "pool",
                           voter->keyHash,
                           ADDRESS_KEY_HASH_LENGTH);
            break;
        default:
            LEDGER_ASSERT(false, "Unknown voter type");
            break;
    }
    CHECK_COUNT(UI_PAIRS_VOTER);
}

void addDRepUIPairs(const ext_drep_t *drep, const char *label) {
    LEDGER_ASSERT(drep != NULL, "NULL drep");
    LEDGER_ASSERT(label != NULL, "NULL label");

    switch (drep->type) {
        case EXT_DREP_KEY_PATH: {
            UI_ADD_FORMAT1(label, MAX_BIP44_PATH_STRING_LENGTH, format_bip44_path, &drep->keyPath);
            break;
        }
        case EXT_DREP_KEY_HASH: {
            LEDGER_ASSERT(drep->keyHash != NULL, "NULL drep->keyHash");
            UI_ADD_FORMAT3(label, MAX_BECH32_STRING_LENGTH, format_bech32, "drep_vkh", drep->keyHash, ADDRESS_KEY_HASH_LENGTH);
            break;
        }
        case EXT_DREP_SCRIPT_HASH: {
            LEDGER_ASSERT(drep->scriptHash != NULL, "NULL drep->scriptHash");
            UI_ADD_FORMAT3(label, MAX_BECH32_STRING_LENGTH, format_bech32, "drep_script", drep->scriptHash, SCRIPT_HASH_LENGTH);
            break;
        }
        case EXT_DREP_ABSTAIN:
        case EXT_DREP_NO_CONFIDENCE: {
            UI_ADD_FORMAT1(label, MAX_DREP_OPTION_LENGTH, format_constant_drep, drep->type);
            break;
        }
        default:
            LEDGER_ASSERT(false, "Unknown DRep type");
    }
}

static void addStakeCredentialUIPairs(const ext_credential_t* credential) {
    addCredentialUIPairs(
        credential,
        UI_STATIC_LABEL("Stake key"),
        UI_STATIC_LABEL("Stake key hash"),
        "stake_vkh",
        UI_LABEL_BY_SCREEN("Stake script hash", "Stake script"),
        "script"
    );
}

static void addDRepCredentialUIPairs(const ext_credential_t* credential) {
    addCredentialUIPairs(
        credential,
        UI_STATIC_LABEL("DRep key"),
        UI_STATIC_LABEL("DRep key hash"),
        "drep_vkh",
        UI_LABEL_BY_SCREEN("DRep script hash", "DRep script"),
        "drep_script"
    );
}

static void addCommitteeColdCredentialUIPairs(const ext_credential_t* credential) {
    addCredentialUIPairs(
        credential,
        UI_LABEL_BY_SCREEN("Committee cold key", "Cmte cold key"),
        UI_LABEL_BY_SCREEN("Committee cold key hash", "Cmte cold key"),
        "cc_cold_vkh",
        UI_LABEL_BY_SCREEN("Committee cold script hash", "Cmte cold script"),
        "cc_cold_script"
    );
}

static void addCommitteeHotCredentialUIPairs(const ext_credential_t* credential) {
    addCredentialUIPairs(
        credential,
        UI_LABEL_BY_SCREEN("Committee hot key", "Cmte hot key"),
        UI_LABEL_BY_SCREEN("Committee hot key hash", "Cmte hot key"),
        "cc_hot_vkh",
        UI_LABEL_BY_SCREEN("Committee hot script hash", "Cmte hot script"),
        "cc_hot_script"
    );
}

static void addVoterCredentialUIPairs(const ext_credential_t* credential) {
    addCredentialUIPairs(
        credential,
        UI_STATIC_LABEL("Voter"),
        UI_STATIC_LABEL("Voter hash"),
        "stake_vkh",
        UI_LABEL_BY_SCREEN("Voter script hash", "Voter script"),
        "script"
    );
}

static void addPoolRetirementUIPairs(const certificate_data_t* certificate_data) {
    const ext_credential_t* pool_credential = &certificate_data->poolCredential;
    uint8_t pool_key_hash[POOL_KEY_HASH_LENGTH];

    switch (pool_credential->type) {
        case EXT_CREDENTIAL_KEY_PATH:
            keyPathToKeyHash(&pool_credential->keyPath, pool_key_hash, sizeof(pool_key_hash));
            break;
        case EXT_CREDENTIAL_KEY_HASH: {
            STATIC_ASSERT(ADDRESS_KEY_HASH_LENGTH == POOL_KEY_HASH_LENGTH,
                          "pool credential hash size mismatch");
            memcpy(pool_key_hash, pool_credential->keyHash, POOL_KEY_HASH_LENGTH);
            break;
        }
        default:
            LEDGER_ASSERT(false, "Unsupported pool credential type for retirement");
    }

    UI_ADD_FORMAT3(UI_STATIC_LABEL("Pool ID"),
                   MAX_BECH32_STRING_LENGTH,
                   format_bech32,
                   "pool",
                   pool_key_hash,
                   POOL_KEY_HASH_LENGTH);

    UI_ADD_FORMAT1(UI_LABEL_BY_SCREEN("Retirement epoch", "Retire epoch"),
                   MAX_UINT64_STRING_LENGTH,
                   format_uint64,
                   certificate_data->retirementEpoch);
}

void addAnchorUIPairs(const anchor_t *anchor) {
    LEDGER_ASSERT(anchor != NULL, "NULL anchor");

    if (!anchor->isIncluded) {
        return;
    }

    warning_bits_t anchor_warnings = 0;
    security_policy_t anchor_policy = policyForSignTxAnchor(anchor, &anchor_warnings);
    LEDGER_ASSERT(anchor_policy != POLICY_DENY, "Anchor security policy denied");
    LEDGER_ASSERT(warning_bits_except_mask(anchor_warnings, G_context.tx_info.warning_bits) == 0, "Anchor warnings mismatch between validation and UI");

    START_COUNT();
    if (anchor->urlLength == 0) {
        LEDGER_ASSERT( warning_bits_has( G_context.tx_info.warning_bits, WARNING_BIT_EMPTY_ANCHOR_URL ), "Empty anchor URL warning missing" );
        UI_ADD_STATIC(UI_STATIC_LABEL("Anchor URL"), UI_STATIC_LABEL("(empty)"));
    } else {
        UI_ADD_FORMAT2(UI_STATIC_LABEL("Anchor URL"),
                       MAX_ANCHOR_URL_LENGTH,
                       format_url,
                       anchor->url,
                       anchor->urlLength);
    }
    UI_ADD_FORMAT3(UI_STATIC_LABEL("Anchor hash"), MAX_BECH32_STRING_LENGTH, format_bech32, "anchor", anchor->hash, ANCHOR_HASH_LENGTH);
    CHECK_COUNT(UI_PAIRS_ANCHOR);
}

void addWithdrawalUIPairs(uint8_t networkId, const withdrawal_t *withdrawal) {
    LEDGER_ASSERT(withdrawal != NULL, "NULL withdrawal");

    START_COUNT();
    UI_ADD_FORMAT1(UI_LABEL_BY_SCREEN("Withdrawal amount", "Withdraw amount"), MAX_ADA_AMOUNT_STRING_LENGTH, format_ada_amount, withdrawal->amount);

    const ext_credential_t *credential = &withdrawal->stakeCredential;

    switch (credential->type) {
        case EXT_CREDENTIAL_KEY_PATH: {
            UI_ADD_FORMAT1(UI_LABEL_BY_SCREEN("Withdrawal key path", "Withdraw key"), MAX_BIP44_PATH_STRING_LENGTH, format_bip44_path, &credential->keyPath);
            break;
        }
        case EXT_CREDENTIAL_KEY_HASH:
        case EXT_CREDENTIAL_SCRIPT_HASH: {
            break;
        }
        default:
            LEDGER_ASSERT(false, "Unknown credential type");
    }

    UI_ADD_FORMAT2(UI_LABEL_BY_SCREEN("Withdraw from", "Withdraw"),
                   MAX_HUMAN_ADDRESS_LENGTH,
                   format_reward_account_from_credential,
                   networkId,
                   credential);

    CHECK_COUNT(credential->type == EXT_CREDENTIAL_KEY_PATH ? UI_PAIRS_WITHDRAWAL_KEY_PATH : UI_PAIRS_WITHDRAWAL_OTHER);
}

void addCertificateUIPairs(const certificate_data_t* certificate_data) {
    LEDGER_ASSERT(certificate_data != NULL, "NULL certificate data");

    TRACE("Formatting certificate type=%u", certificate_data->type);
    START_COUNT();
    UI_ADD_FORMAT1(UI_STATIC_LABEL("Certificate"),
                   MAX_CERTIFICATE_TYPE_LENGTH,
                   format_certificate_type,
                   certificate_data->type);

    switch (certificate_data->type) {
        case CERTIFICATE_STAKE_REGISTRATION: {
            addStakeCredentialUIPairs(&certificate_data->stakeCredential);
            CHECK_COUNT(UI_PAIRS_CERTIFICATE_STAKE_REGISTRATION);
            break;
        }

        case CERTIFICATE_STAKE_DEREGISTRATION: {
            addStakeCredentialUIPairs(&certificate_data->stakeCredential);
            CHECK_COUNT(UI_PAIRS_CERTIFICATE_STAKE_DEREGISTRATION);
            break;
        }

        case CERTIFICATE_STAKE_DELEGATION: {
            addStakeCredentialUIPairs(&certificate_data->stakeCredential);
            UI_ADD_FORMAT3(UI_STATIC_LABEL("Pool"),
                           MAX_BECH32_STRING_LENGTH,
                           format_bech32,
                           "pool",
                           certificate_data->poolKeyHash,
                           POOL_KEY_HASH_LENGTH);
            CHECK_COUNT(UI_PAIRS_CERTIFICATE_STAKE_DELEGATION);
            break;
        }

        case CERTIFICATE_STAKE_REGISTRATION_CONWAY: {
            addStakeCredentialUIPairs(&certificate_data->stakeCredential);
            UI_ADD_FORMAT1(UI_STATIC_LABEL("Deposit"),
                           MAX_ADA_AMOUNT_STRING_LENGTH,
                           format_ada_amount,
                           certificate_data->deposit);
            CHECK_COUNT(UI_PAIRS_CERTIFICATE_STAKE_REGISTRATION_CONWAY);
            break;
        }

        case CERTIFICATE_STAKE_DEREGISTRATION_CONWAY: {
            addStakeCredentialUIPairs(&certificate_data->stakeCredential);
            UI_ADD_FORMAT1(UI_STATIC_LABEL("Deposit"),
                           MAX_ADA_AMOUNT_STRING_LENGTH,
                           format_ada_amount,
                           certificate_data->deposit);
            CHECK_COUNT(UI_PAIRS_CERTIFICATE_STAKE_DEREGISTRATION_CONWAY);
            break;
        }

        case CERTIFICATE_STAKE_POOL_RETIREMENT: {
            addPoolRetirementUIPairs(certificate_data);
            CHECK_COUNT(UI_PAIRS_CERTIFICATE_POOL_RETIREMENT);
            break;
        }

        case CERTIFICATE_VOTE_DELEGATION: {
            addVoterCredentialUIPairs(&certificate_data->stakeCredential);
            addDRepUIPairs(&certificate_data->drep, UI_STATIC_LABEL("DRep"));
            CHECK_COUNT(UI_PAIRS_CERTIFICATE_VOTE_DELEGATION);
            break;
        }

        case CERTIFICATE_STAKE_POOL_AND_DREP_DELEGATION: {
            addStakeCredentialUIPairs(&certificate_data->stakeCredential);
            LEDGER_ASSERT(certificate_data->combinedDelegPoolKeyHash != NULL, "Missing combined delegation pool hash");
            UI_ADD_FORMAT3(UI_STATIC_LABEL("Pool"),
                           MAX_BECH32_STRING_LENGTH,
                           format_bech32,
                           "pool",
                           certificate_data->combinedDelegPoolKeyHash,
                           POOL_KEY_HASH_LENGTH);
            addDRepUIPairs(&certificate_data->drep, UI_STATIC_LABEL("DRep"));
            CHECK_COUNT(UI_PAIRS_CERTIFICATE_STAKE_POOL_AND_DREP_DELEGATION);
            break;
        }

        case CERTIFICATE_ACCOUNT_REGISTRATION_DELEGATION_TO_STAKE_POOL: {
            addStakeCredentialUIPairs(&certificate_data->stakeCredential);
            LEDGER_ASSERT(certificate_data->combinedDelegPoolKeyHash != NULL, "Missing combined delegation pool hash");
            UI_ADD_FORMAT3(UI_STATIC_LABEL("Pool"),
                           MAX_BECH32_STRING_LENGTH,
                           format_bech32,
                           "pool",
                           certificate_data->combinedDelegPoolKeyHash,
                           POOL_KEY_HASH_LENGTH);
            UI_ADD_FORMAT1(UI_STATIC_LABEL("Deposit"),
                           MAX_ADA_AMOUNT_STRING_LENGTH,
                           format_ada_amount,
                           certificate_data->deposit);
            CHECK_COUNT(UI_PAIRS_CERTIFICATE_ACCOUNT_REGISTRATION_DELEGATION_TO_STAKE_POOL);
            break;
        }

        case CERTIFICATE_ACCOUNT_REGISTRATION_DELEGATION_TO_DREP: {
            addStakeCredentialUIPairs(&certificate_data->stakeCredential);
            addDRepUIPairs(&certificate_data->drep, UI_STATIC_LABEL("DRep"));
            UI_ADD_FORMAT1(UI_STATIC_LABEL("Deposit"),
                           MAX_ADA_AMOUNT_STRING_LENGTH,
                           format_ada_amount,
                           certificate_data->deposit);
            CHECK_COUNT(UI_PAIRS_CERTIFICATE_ACCOUNT_REGISTRATION_DELEGATION_TO_DREP);
            break;
        }

        case CERTIFICATE_ACCOUNT_REGISTRATION_DELEGATION_TO_STAKE_POOL_AND_DREP: {
            addStakeCredentialUIPairs(&certificate_data->stakeCredential);
            LEDGER_ASSERT(certificate_data->combinedDelegPoolKeyHash != NULL, "Missing combined delegation pool hash");
            UI_ADD_FORMAT3(UI_STATIC_LABEL("Pool"),
                           MAX_BECH32_STRING_LENGTH,
                           format_bech32,
                           "pool",
                           certificate_data->combinedDelegPoolKeyHash,
                           POOL_KEY_HASH_LENGTH);
            addDRepUIPairs(&certificate_data->drep, UI_STATIC_LABEL("DRep"));
            UI_ADD_FORMAT1(UI_STATIC_LABEL("Deposit"),
                           MAX_ADA_AMOUNT_STRING_LENGTH,
                           format_ada_amount,
                           certificate_data->deposit);
            CHECK_COUNT(UI_PAIRS_CERTIFICATE_ACCOUNT_REGISTRATION_DELEGATION_TO_STAKE_POOL_AND_DREP);
            break;
        }

        case CERTIFICATE_AUTHORIZE_COMMITTEE_HOT: {
            addCommitteeColdCredentialUIPairs(&certificate_data->coldCredential);
            addCommitteeHotCredentialUIPairs(&certificate_data->hotCredential);
            CHECK_COUNT(UI_PAIRS_CERTIFICATE_AUTHORIZE_COMMITTEE_HOT);
            break;
        }

        case CERTIFICATE_RESIGN_COMMITTEE_COLD: {
            addCommitteeColdCredentialUIPairs(&certificate_data->coldCredential);
            CHECK_COUNT(UI_PAIRS_CERTIFICATE_RESIGN_COMMITTEE_COLD);
            addAnchorUIPairs(&certificate_data->anchor);
            break;
        }

        case CERTIFICATE_DREP_REGISTRATION: {
            addDRepCredentialUIPairs(&certificate_data->dRepCredential);
            UI_ADD_FORMAT1(UI_STATIC_LABEL("Deposit"),
                           MAX_ADA_AMOUNT_STRING_LENGTH,
                           format_ada_amount,
                           certificate_data->deposit);
            CHECK_COUNT(UI_PAIRS_CERTIFICATE_DREP_REGISTRATION);
            addAnchorUIPairs(&certificate_data->anchor);
            break;
        }

        case CERTIFICATE_DREP_DEREGISTRATION: {
            addDRepCredentialUIPairs(&certificate_data->dRepCredential);
            UI_ADD_FORMAT1(UI_STATIC_LABEL("Deposit"),
                           MAX_ADA_AMOUNT_STRING_LENGTH,
                           format_ada_amount,
                           certificate_data->deposit);
            CHECK_COUNT(UI_PAIRS_CERTIFICATE_DREP_DEREGISTRATION);
            break;
        }

        case CERTIFICATE_DREP_UPDATE: {
            addDRepCredentialUIPairs(&certificate_data->dRepCredential);
            CHECK_COUNT(UI_PAIRS_CERTIFICATE_DREP_UPDATE);
            addAnchorUIPairs(&certificate_data->anchor);
            break;
        }

        case CERTIFICATE_STAKE_POOL_REGISTRATION:
            LEDGER_ASSERT(false, "CERTIFICATE_STAKE_POOL_REGISTRATION should be treated separately");
            break;

        default:
            TRACE("Unknown certificate type in UI helper: %u", certificate_data->type);
            LEDGER_ASSERT(false, "Unknown certificate type");
    }
}

void addPaymentInfoUIPairs(const address_params_t* address_params) {
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
            UI_ADD_FORMAT3(UI_LABEL_BY_SCREEN("Payment script hash", "Pay script"), MAX_BECH32_STRING_LENGTH, format_bech32, "script", address_params->paymentScriptHash, SCRIPT_HASH_LENGTH);
            break;
        }

        default:
            // includes PAYMENT_NONE
            LEDGER_ASSERT(false, "Invalid payment choice");
    }
    CHECK_COUNT(UI_PAIRS_PAYMENT_INFO);
}

void addStakingInfoUIPairs(const address_params_t* address_params) {
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

                default:
                    LEDGER_ASSERT(false, "Invalid payment choice");
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
            UI_ADD_FORMAT3(UI_LABEL_BY_SCREEN("Stake key hash", "Stake key"), MAX_BECH32_STRING_LENGTH, format_bech32, "stake_vkh", address_params->stakingKeyHash, ADDRESS_KEY_HASH_LENGTH);
            break;
        }

        case STAKING_PART_SCRIPT_HASH: {
            LEDGER_ASSERT(addressParams_getStakingPartType(address_params) == STAKING_PART_SCRIPT_HASH, "Staking credential must be SCRIPT_HASH");
            LEDGER_ASSERT(address_params->stakingScriptHash != NULL, "NULL staking script hash");
            UI_ADD_FORMAT3(UI_LABEL_BY_SCREEN("Stake script hash", "Stake hash"), MAX_BECH32_STRING_LENGTH, format_bech32, "script", address_params->stakingScriptHash, SCRIPT_HASH_LENGTH);
            break;
        }

        case STAKING_PART_BLOCKCHAIN_POINTER: {
            UI_ADD_FORMAT1(UI_LABEL_BY_SCREEN("Stake key pointer", "Stake ptr"), MAX_BIP44_PATH_STRING_LENGTH, format_blockchain_pointer, address_params->stakingKeyBlockchainPointer);
            break;
        }

        default:
            LEDGER_ASSERT(false, "Invalid staking data source");
    }
    CHECK_COUNT(UI_PAIRS_STAKING_INFO);
}
