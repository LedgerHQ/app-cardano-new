/* SPDX-FileCopyrightText: 2025 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdint.h>
#include <string.h>

#include "assert.h"
#include "addressUtilsShelley.h"
#include "bech32.h"
#include "cardano_constants.h"
#include "globals.h"
#include "keyDerivation.h"
#include "mem.h"
#include "tx_certificate_types.h"
#include "tx_credential_types.h"
#include "tx_ui_plan.h"
#include "tx_ui_strings_certificates.h"
#include "ui_constants.h"
#include "ui_formatters.h"
#include "ui_utils.h"

// ---------------------------------------------------------------------------
// Credential render helpers (pure renderers, no policy awareness)
// ---------------------------------------------------------------------------

static void render_credential(const ext_credential_t *credential,
                               const char *key_path_label,
                               const char *key_hash_label,
                               const char *key_hash_prefix,
                               const char *script_hash_label,
                               const char *script_hash_prefix) {
    LEDGER_ASSERT(credential != NULL, "NULL credential");

    switch (credential->type) {
        case EXT_CREDENTIAL_KEY_PATH:
            UI_ADD_FORMAT1(key_path_label,
                           MAX_BIP44_PATH_STRING_LENGTH,
                           format_bip44_path,
                           &credential->keyPath);
            break;
        case EXT_CREDENTIAL_KEY_HASH:
            UI_ADD_FORMAT3(key_hash_label,
                           MAX_BECH32_STRING_LENGTH,
                           format_bech32,
                           key_hash_prefix,
                           credential->keyHash,
                           ADDRESS_KEY_HASH_LENGTH);
            break;
        case EXT_CREDENTIAL_SCRIPT_HASH:
            UI_ADD_FORMAT3(script_hash_label,
                           MAX_BECH32_STRING_LENGTH,
                           format_bech32,
                           script_hash_prefix,
                           credential->scriptHash,
                           SCRIPT_HASH_LENGTH);
            break;
        default:
            LEDGER_ASSERT(false, "Unknown credential type");
    }
}

static void render_stake_credential(const ext_credential_t *credential) {
    render_credential(credential,
                      UI_STATIC_LABEL("Stake key"),
                      UI_STATIC_LABEL("Stake key hash"),
                      "stake_vkh",
                      UI_LABEL_BY_SCREEN("Stake script hash", "Stake script"),
                      "script");
}

static void render_voter_credential(const ext_credential_t *credential) {
    render_credential(credential,
                      UI_STATIC_LABEL("Voter"),
                      UI_STATIC_LABEL("Voter hash"),
                      "stake_vkh",
                      UI_LABEL_BY_SCREEN("Voter script hash", "Voter script"),
                      "script");
}

static void render_drep_credential(const ext_credential_t *credential) {
    render_credential(credential,
                      UI_STATIC_LABEL("DRep key"),
                      UI_STATIC_LABEL("DRep key hash"),
                      "drep_vkh",
                      UI_LABEL_BY_SCREEN("DRep script hash", "DRep script"),
                      "drep_script");
}

static void render_committee_cold_credential(const ext_credential_t *credential) {
    render_credential(credential,
                      UI_LABEL_BY_SCREEN("Committee cold key", "Cmte cold key"),
                      UI_LABEL_BY_SCREEN("Committee cold key hash", "Cmte cold key"),
                      "cc_cold_vkh",
                      UI_LABEL_BY_SCREEN("Committee cold script hash", "Cmte cold script"),
                      "cc_cold_script");
}

static void render_committee_hot_credential(const ext_credential_t *credential) {
    render_credential(credential,
                      UI_LABEL_BY_SCREEN("Committee hot key", "Cmte hot key"),
                      UI_LABEL_BY_SCREEN("Committee hot key hash", "Cmte hot key"),
                      "cc_hot_vkh",
                      UI_LABEL_BY_SCREEN("Committee hot script hash", "Cmte hot script"),
                      "cc_hot_script");
}

static void render_drep(const ext_drep_t *drep, const char *label) {
    LEDGER_ASSERT(drep != NULL, "NULL drep");
    LEDGER_ASSERT(label != NULL, "NULL label");

    switch (drep->type) {
        case EXT_DREP_KEY_PATH:
            UI_ADD_FORMAT1(label, MAX_BIP44_PATH_STRING_LENGTH, format_bip44_path, &drep->keyPath);
            break;
        case EXT_DREP_KEY_HASH:
            LEDGER_ASSERT(drep->keyHash != NULL, "NULL drep->keyHash");
            UI_ADD_FORMAT3(label,
                           MAX_BECH32_STRING_LENGTH,
                           format_bech32,
                           "drep_vkh",
                           drep->keyHash,
                           ADDRESS_KEY_HASH_LENGTH);
            break;
        case EXT_DREP_SCRIPT_HASH:
            LEDGER_ASSERT(drep->scriptHash != NULL, "NULL drep->scriptHash");
            UI_ADD_FORMAT3(label,
                           MAX_BECH32_STRING_LENGTH,
                           format_bech32,
                           "drep_script",
                           drep->scriptHash,
                           SCRIPT_HASH_LENGTH);
            break;
        case EXT_DREP_ABSTAIN:
        case EXT_DREP_NO_CONFIDENCE:
            UI_ADD_FORMAT1(label, MAX_DREP_OPTION_LENGTH, format_constant_drep, drep->type);
            break;
        default:
            LEDGER_ASSERT(false, "Unknown DRep type");
    }
}

// ---------------------------------------------------------------------------
// Anchor planning/rendering helper (pure, no policy evaluation)
// ---------------------------------------------------------------------------

static void plan_or_render_anchor(const parse_tx_mode_t *mode, const anchor_t *anchor) {
    LEDGER_ASSERT(mode != NULL, "NULL mode");
    LEDGER_ASSERT(anchor != NULL, "NULL anchor");
    LEDGER_ASSERT(anchor->isIncluded, "plan_or_render_anchor called with anchor not included");

    if (mode->run_ui_planning) {
        G_context.tx_info.planned_ui_pairs += UI_PAIRS_ANCHOR;
    } else if (mode->run_ui_rendering) {
        START_COUNT();
        if (anchor->urlLength == 0) {
            LEDGER_ASSERT(
                warning_bits_has(G_context.tx_info.warning_bits, WARNING_BIT_EMPTY_ANCHOR_URL),
                "Empty anchor URL warning missing");
            UI_ADD_STATIC(UI_STATIC_LABEL("Anchor URL"), UI_STATIC_LABEL("(empty)"));
        } else {
            UI_ADD_FORMAT2(UI_STATIC_LABEL("Anchor URL"),
                           MAX_ANCHOR_URL_LENGTH,
                           format_url,
                           anchor->url,
                           anchor->urlLength);
        }
        UI_ADD_FORMAT3(UI_STATIC_LABEL("Anchor hash"),
                       MAX_BECH32_STRING_LENGTH,
                       format_bech32,
                       "anchor",
                       anchor->hash,
                       ANCHOR_HASH_LENGTH);
        CHECK_COUNT(UI_PAIRS_ANCHOR);
    }
}

// ---------------------------------------------------------------------------
// Certificate type render helpers
// ---------------------------------------------------------------------------

static void render_deposit(uint64_t deposit) {
    UI_ADD_FORMAT1(UI_STATIC_LABEL("Deposit"),
                   MAX_ADA_AMOUNT_STRING_LENGTH,
                   format_ada_amount,
                   deposit);
}

static void render_certificate_header(certificate_type_t type) {
    UI_ADD_FORMAT1(UI_STATIC_LABEL("Certificate"),
                   MAX_CERTIFICATE_TYPE_LENGTH,
                   format_certificate_type,
                   type);
}

static void plan_or_render_certificate_stake_registration(
    const parse_tx_mode_t *mode, const certificate_data_t *certificate_data) {
    if (mode->run_ui_planning) {
        G_context.tx_info.planned_ui_pairs += UI_PAIRS_CERTIFICATE_STAKE_REGISTRATION;
    } else if (mode->run_ui_rendering) {
        START_COUNT();
        render_certificate_header(certificate_data->type);
        render_stake_credential(&certificate_data->stakeCredential);
        CHECK_COUNT(UI_PAIRS_CERTIFICATE_STAKE_REGISTRATION);
    }
}

static void plan_or_render_certificate_stake_deregistration(
    const parse_tx_mode_t *mode, const certificate_data_t *certificate_data) {
    if (mode->run_ui_planning) {
        G_context.tx_info.planned_ui_pairs += UI_PAIRS_CERTIFICATE_STAKE_DEREGISTRATION;
    } else if (mode->run_ui_rendering) {
        START_COUNT();
        render_certificate_header(certificate_data->type);
        render_stake_credential(&certificate_data->stakeCredential);
        CHECK_COUNT(UI_PAIRS_CERTIFICATE_STAKE_DEREGISTRATION);
    }
}

static void plan_or_render_certificate_stake_registration_conway(
    const parse_tx_mode_t *mode, const certificate_data_t *certificate_data) {
    if (mode->run_ui_planning) {
        G_context.tx_info.planned_ui_pairs += UI_PAIRS_CERTIFICATE_STAKE_REGISTRATION_CONWAY;
    } else if (mode->run_ui_rendering) {
        START_COUNT();
        render_certificate_header(certificate_data->type);
        render_stake_credential(&certificate_data->stakeCredential);
        render_deposit(certificate_data->deposit);
        CHECK_COUNT(UI_PAIRS_CERTIFICATE_STAKE_REGISTRATION_CONWAY);
    }
}

static void plan_or_render_certificate_stake_deregistration_conway(
    const parse_tx_mode_t *mode, const certificate_data_t *certificate_data) {
    if (mode->run_ui_planning) {
        G_context.tx_info.planned_ui_pairs += UI_PAIRS_CERTIFICATE_STAKE_DEREGISTRATION_CONWAY;
    } else if (mode->run_ui_rendering) {
        START_COUNT();
        render_certificate_header(certificate_data->type);
        render_stake_credential(&certificate_data->stakeCredential);
        render_deposit(certificate_data->deposit);
        CHECK_COUNT(UI_PAIRS_CERTIFICATE_STAKE_DEREGISTRATION_CONWAY);
    }
}

static void plan_or_render_certificate_stake_delegation(
    const parse_tx_mode_t *mode, const certificate_data_t *certificate_data) {
    if (mode->run_ui_planning) {
        G_context.tx_info.planned_ui_pairs += UI_PAIRS_CERTIFICATE_STAKE_DELEGATION;
    } else if (mode->run_ui_rendering) {
        START_COUNT();
        render_certificate_header(certificate_data->type);
        render_stake_credential(&certificate_data->stakeCredential);
        UI_ADD_FORMAT3(UI_STATIC_LABEL("Pool"),
                       MAX_BECH32_STRING_LENGTH,
                       format_bech32,
                       "pool",
                       certificate_data->poolKeyHash,
                       POOL_KEY_HASH_LENGTH);
        CHECK_COUNT(UI_PAIRS_CERTIFICATE_STAKE_DELEGATION);
    }
}

static void plan_or_render_certificate_vote_delegation(
    const parse_tx_mode_t *mode, const certificate_data_t *certificate_data) {
    if (mode->run_ui_planning) {
        G_context.tx_info.planned_ui_pairs += UI_PAIRS_CERTIFICATE_VOTE_DELEGATION;
    } else if (mode->run_ui_rendering) {
        START_COUNT();
        render_certificate_header(certificate_data->type);
        render_voter_credential(&certificate_data->stakeCredential);
        render_drep(&certificate_data->drep, UI_STATIC_LABEL("DRep"));
        CHECK_COUNT(UI_PAIRS_CERTIFICATE_VOTE_DELEGATION);
    }
}

static void plan_or_render_certificate_stake_pool_and_drep_delegation(
    const parse_tx_mode_t *mode, const certificate_data_t *certificate_data) {
    LEDGER_ASSERT(certificate_data->combinedDelegPoolKeyHash != NULL,
                  "Missing combined delegation pool hash");
    if (mode->run_ui_planning) {
        G_context.tx_info.planned_ui_pairs += UI_PAIRS_CERTIFICATE_STAKE_POOL_AND_DREP_DELEGATION;
    } else if (mode->run_ui_rendering) {
        START_COUNT();
        render_certificate_header(certificate_data->type);
        render_stake_credential(&certificate_data->stakeCredential);
        UI_ADD_FORMAT3(UI_STATIC_LABEL("Pool"),
                       MAX_BECH32_STRING_LENGTH,
                       format_bech32,
                       "pool",
                       certificate_data->combinedDelegPoolKeyHash,
                       POOL_KEY_HASH_LENGTH);
        render_drep(&certificate_data->drep, UI_STATIC_LABEL("DRep"));
        CHECK_COUNT(UI_PAIRS_CERTIFICATE_STAKE_POOL_AND_DREP_DELEGATION);
    }
}

static void plan_or_render_certificate_account_registration_delegation_to_stake_pool(
    const parse_tx_mode_t *mode, const certificate_data_t *certificate_data) {
    LEDGER_ASSERT(certificate_data->combinedDelegPoolKeyHash != NULL,
                  "Missing combined delegation pool hash");
    if (mode->run_ui_planning) {
        G_context.tx_info.planned_ui_pairs +=
            UI_PAIRS_CERTIFICATE_ACCOUNT_REGISTRATION_DELEGATION_TO_STAKE_POOL;
    } else if (mode->run_ui_rendering) {
        START_COUNT();
        render_certificate_header(certificate_data->type);
        render_stake_credential(&certificate_data->stakeCredential);
        UI_ADD_FORMAT3(UI_STATIC_LABEL("Pool"),
                       MAX_BECH32_STRING_LENGTH,
                       format_bech32,
                       "pool",
                       certificate_data->combinedDelegPoolKeyHash,
                       POOL_KEY_HASH_LENGTH);
        render_deposit(certificate_data->deposit);
        CHECK_COUNT(UI_PAIRS_CERTIFICATE_ACCOUNT_REGISTRATION_DELEGATION_TO_STAKE_POOL);
    }
}

static void plan_or_render_certificate_account_registration_delegation_to_drep(
    const parse_tx_mode_t *mode, const certificate_data_t *certificate_data) {
    if (mode->run_ui_planning) {
        G_context.tx_info.planned_ui_pairs +=
            UI_PAIRS_CERTIFICATE_ACCOUNT_REGISTRATION_DELEGATION_TO_DREP;
    } else if (mode->run_ui_rendering) {
        START_COUNT();
        render_certificate_header(certificate_data->type);
        render_stake_credential(&certificate_data->stakeCredential);
        render_drep(&certificate_data->drep, UI_STATIC_LABEL("DRep"));
        render_deposit(certificate_data->deposit);
        CHECK_COUNT(UI_PAIRS_CERTIFICATE_ACCOUNT_REGISTRATION_DELEGATION_TO_DREP);
    }
}

static void plan_or_render_certificate_account_registration_delegation_to_stake_pool_and_drep(
    const parse_tx_mode_t *mode, const certificate_data_t *certificate_data) {
    LEDGER_ASSERT(certificate_data->combinedDelegPoolKeyHash != NULL,
                  "Missing combined delegation pool hash");
    if (mode->run_ui_planning) {
        G_context.tx_info.planned_ui_pairs +=
            UI_PAIRS_CERTIFICATE_ACCOUNT_REGISTRATION_DELEGATION_TO_STAKE_POOL_AND_DREP;
    } else if (mode->run_ui_rendering) {
        START_COUNT();
        render_certificate_header(certificate_data->type);
        render_stake_credential(&certificate_data->stakeCredential);
        UI_ADD_FORMAT3(UI_STATIC_LABEL("Pool"),
                       MAX_BECH32_STRING_LENGTH,
                       format_bech32,
                       "pool",
                       certificate_data->combinedDelegPoolKeyHash,
                       POOL_KEY_HASH_LENGTH);
        render_drep(&certificate_data->drep, UI_STATIC_LABEL("DRep"));
        render_deposit(certificate_data->deposit);
        CHECK_COUNT(UI_PAIRS_CERTIFICATE_ACCOUNT_REGISTRATION_DELEGATION_TO_STAKE_POOL_AND_DREP);
    }
}

static void plan_or_render_certificate_authorize_committee_hot(
    const parse_tx_mode_t *mode, const certificate_data_t *certificate_data) {
    if (mode->run_ui_planning) {
        G_context.tx_info.planned_ui_pairs += UI_PAIRS_CERTIFICATE_AUTHORIZE_COMMITTEE_HOT;
    } else if (mode->run_ui_rendering) {
        START_COUNT();
        render_certificate_header(certificate_data->type);
        render_committee_cold_credential(&certificate_data->coldCredential);
        render_committee_hot_credential(&certificate_data->hotCredential);
        CHECK_COUNT(UI_PAIRS_CERTIFICATE_AUTHORIZE_COMMITTEE_HOT);
    }
}

static void plan_or_render_certificate_resign_committee_cold(
    const parse_tx_mode_t *mode, const certificate_data_t *certificate_data) {
    if (mode->run_ui_planning) {
        G_context.tx_info.planned_ui_pairs += UI_PAIRS_CERTIFICATE_RESIGN_COMMITTEE_COLD;
    } else if (mode->run_ui_rendering) {
        START_COUNT();
        render_certificate_header(certificate_data->type);
        render_committee_cold_credential(&certificate_data->coldCredential);
        CHECK_COUNT(UI_PAIRS_CERTIFICATE_RESIGN_COMMITTEE_COLD);
    }
}

static void plan_or_render_certificate_drep_registration(
    const parse_tx_mode_t *mode, const certificate_data_t *certificate_data) {
    if (mode->run_ui_planning) {
        G_context.tx_info.planned_ui_pairs += UI_PAIRS_CERTIFICATE_DREP_REGISTRATION;
    } else if (mode->run_ui_rendering) {
        START_COUNT();
        render_certificate_header(certificate_data->type);
        render_drep_credential(&certificate_data->dRepCredential);
        render_deposit(certificate_data->deposit);
        CHECK_COUNT(UI_PAIRS_CERTIFICATE_DREP_REGISTRATION);
    }
}

static void plan_or_render_certificate_drep_deregistration(
    const parse_tx_mode_t *mode, const certificate_data_t *certificate_data) {
    if (mode->run_ui_planning) {
        G_context.tx_info.planned_ui_pairs += UI_PAIRS_CERTIFICATE_DREP_DEREGISTRATION;
    } else if (mode->run_ui_rendering) {
        START_COUNT();
        render_certificate_header(certificate_data->type);
        render_drep_credential(&certificate_data->dRepCredential);
        render_deposit(certificate_data->deposit);
        CHECK_COUNT(UI_PAIRS_CERTIFICATE_DREP_DEREGISTRATION);
    }
}

static void plan_or_render_certificate_drep_update(
    const parse_tx_mode_t *mode, const certificate_data_t *certificate_data) {
    if (mode->run_ui_planning) {
        G_context.tx_info.planned_ui_pairs += UI_PAIRS_CERTIFICATE_DREP_UPDATE;
    } else if (mode->run_ui_rendering) {
        START_COUNT();
        render_certificate_header(certificate_data->type);
        render_drep_credential(&certificate_data->dRepCredential);
        CHECK_COUNT(UI_PAIRS_CERTIFICATE_DREP_UPDATE);
    }
}

static void plan_or_render_certificate_pool_retirement(
    const parse_tx_mode_t *mode, const certificate_data_t *certificate_data) {
    if (mode->run_ui_planning) {
        G_context.tx_info.planned_ui_pairs += UI_PAIRS_CERTIFICATE_POOL_RETIREMENT;
    } else if (mode->run_ui_rendering) {
        const ext_credential_t *pool_credential = &certificate_data->poolCredential;
        uint8_t pool_key_hash[POOL_KEY_HASH_LENGTH] = {0};
        STATIC_ASSERT(ADDRESS_KEY_HASH_LENGTH == POOL_KEY_HASH_LENGTH,
                      "pool credential hash size mismatch");

        switch (pool_credential->type) {
            case EXT_CREDENTIAL_KEY_PATH:
                keyPathToKeyHash(&pool_credential->keyPath, pool_key_hash, sizeof(pool_key_hash));
                break;
            case EXT_CREDENTIAL_KEY_HASH:
                memcpy(pool_key_hash, pool_credential->keyHash, POOL_KEY_HASH_LENGTH);
                break;
            default:
                LEDGER_ASSERT(false, "Unsupported pool credential type for retirement");
        }

        START_COUNT();
        render_certificate_header(certificate_data->type);
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
        CHECK_COUNT(UI_PAIRS_CERTIFICATE_POOL_RETIREMENT);
    }
}

// ---------------------------------------------------------------------------
// Pool registration plan/render helpers (no policy awareness)
// ---------------------------------------------------------------------------

void plan_or_render_pool_registration_header(const parse_tx_mode_t *mode,
                                             certificate_type_t type) {
    if (mode->run_ui_planning) {
        G_context.tx_info.planned_ui_pairs += UI_PAIRS_CERTIFICATE_POOL_REGISTRATION_BASE;
    } else if (mode->run_ui_rendering) {
        START_COUNT();
        render_certificate_header(type);
        CHECK_COUNT(UI_PAIRS_CERTIFICATE_POOL_REGISTRATION_BASE);
    }
}

void plan_or_render_pool_id(const parse_tx_mode_t *mode, const pool_id_t *pool_id) {
    LEDGER_ASSERT(pool_id != NULL, "NULL pool_id");
    if (mode->run_ui_planning) {
        G_context.tx_info.planned_ui_pairs += UI_PAIRS_POOL_ID;
    } else if (mode->run_ui_rendering) {
        START_COUNT();
        uint8_t pool_key_hash[POOL_KEY_HASH_LENGTH] = {0};
        switch (pool_id->keyReferenceType) {
            case KEY_REFERENCE_PATH:
                keyPathToKeyHash(&pool_id->path, pool_key_hash, SIZEOF(pool_key_hash));
                break;
            case KEY_REFERENCE_HASH:
                LEDGER_ASSERT(pool_id->hash != NULL, "NULL pool ID hash");
                memmove(pool_key_hash, pool_id->hash, SIZEOF(pool_key_hash));
                break;
            default:
                LEDGER_ASSERT(false, "Unknown pool ID key reference type");
        }
        UI_ADD_FORMAT3(UI_STATIC_LABEL("Pool ID"),
                       MAX_BECH32_STRING_LENGTH,
                       format_bech32,
                       "pool",
                       pool_key_hash,
                       POOL_KEY_HASH_LENGTH);
        CHECK_COUNT(UI_PAIRS_POOL_ID);
    }
}

void plan_or_render_pool_vrf_key_hash(const parse_tx_mode_t *mode, const uint8_t *vrf_key_hash) {
    LEDGER_ASSERT(vrf_key_hash != NULL, "NULL vrf_key_hash");
    if (mode->run_ui_planning) {
        G_context.tx_info.planned_ui_pairs += UI_PAIRS_POOL_VRF_KEY;
    } else if (mode->run_ui_rendering) {
        START_COUNT();
        UI_ADD_FORMAT3(UI_STATIC_LABEL("VRF key hash"),
                       MAX_BECH32_STRING_LENGTH,
                       format_bech32,
                       "vrf_vk",
                       vrf_key_hash,
                       VRF_KEY_HASH_LENGTH);
        CHECK_COUNT(UI_PAIRS_POOL_VRF_KEY);
    }
}

void plan_or_render_pool_financials(const parse_tx_mode_t *mode,
                                    const pool_registration_data_t *pool_registration) {
    LEDGER_ASSERT(pool_registration != NULL, "NULL pool_registration");
    if (mode->run_ui_planning) {
        G_context.tx_info.planned_ui_pairs += UI_PAIRS_POOL_FIXED;
    } else if (mode->run_ui_rendering) {
        START_COUNT();
        UI_ADD_FORMAT1(UI_STATIC_LABEL("Pledge"),
                       MAX_ADA_AMOUNT_STRING_LENGTH,
                       format_ada_amount,
                       pool_registration->pledge);
        UI_ADD_FORMAT1(UI_STATIC_LABEL("Cost"),
                       MAX_ADA_AMOUNT_STRING_LENGTH,
                       format_ada_amount,
                       pool_registration->cost);
        UI_ADD_FORMAT2(UI_STATIC_LABEL("Profit margin"),
                       MAX_PROFIT_MARGIN_STRING_LENGTH,
                       format_pool_margin,
                       pool_registration->marginNumerator,
                       pool_registration->marginDenominator);
        CHECK_COUNT(UI_PAIRS_POOL_FIXED);
    }
}

void plan_or_render_pool_reward_account(const parse_tx_mode_t *mode,
                                        uint8_t network_id,
                                        const pool_reward_account_t *reward_account) {
    LEDGER_ASSERT(reward_account != NULL, "NULL reward_account");
    if (mode->run_ui_planning) {
        G_context.tx_info.planned_ui_pairs += UI_PAIRS_POOL_REWARD_ACCOUNT;
    } else if (mode->run_ui_rendering) {
        START_COUNT();
        UI_ADD_FORMAT2(UI_LABEL_BY_SCREEN("Pool reward address", "Reward addr"),
                       MAX_HUMAN_ADDRESS_LENGTH,
                       format_pool_reward_account,
                       network_id,
                       reward_account);
        CHECK_COUNT(UI_PAIRS_POOL_REWARD_ACCOUNT);
    }
}

void plan_or_render_pool_owner(const parse_tx_mode_t *mode,
                               uint8_t network_id,
                               const ext_credential_t *owner_credential) {
    LEDGER_ASSERT(owner_credential != NULL, "NULL owner_credential");
    if (mode->run_ui_planning) {
        G_context.tx_info.planned_ui_pairs += UI_PAIRS_POOL_OWNER;
    } else if (mode->run_ui_rendering) {
        START_COUNT();
        UI_ADD_FORMAT2(UI_LABEL_BY_SCREEN("Owner reward address", "Owner addr"),
                       MAX_HUMAN_ADDRESS_LENGTH,
                       format_reward_account_from_credential,
                       network_id,
                       owner_credential);
        CHECK_COUNT(UI_PAIRS_POOL_OWNER);
    }
}

void plan_or_render_pool_no_owners(const parse_tx_mode_t *mode) {
    if (mode->run_ui_planning) {
        G_context.tx_info.planned_ui_pairs += UI_PAIRS_POOL_NO_OWNERS;
    } else if (mode->run_ui_rendering) {
        START_COUNT();
        UI_ADD_STATIC(UI_STATIC_LABEL("Pool owners"), UI_STATIC_LABEL("(none)"));
        CHECK_COUNT(UI_PAIRS_POOL_NO_OWNERS);
    }
}

static uint16_t count_pool_relay_ui_pairs(const pool_relay_t *relay) {
    uint16_t pairs = UI_PAIRS_POOL_RELAY_HEADER;
    switch (relay->format) {
        case RELAY_SINGLE_HOST_IP:
            if (!relay->ipv4.isNull) pairs += UI_PAIRS_POOL_RELAY_IPV4;
            if (!relay->ipv6.isNull) pairs += UI_PAIRS_POOL_RELAY_IPV6;
            if (!relay->port.isNull) pairs += UI_PAIRS_POOL_RELAY_PORT;
            break;
        case RELAY_SINGLE_HOST_NAME:
            if (relay->dnsNameSize > 0) pairs += UI_PAIRS_POOL_RELAY_DNS;
            if (!relay->port.isNull)    pairs += UI_PAIRS_POOL_RELAY_PORT;
            break;
        case RELAY_MULTIPLE_HOST_NAME:
            if (relay->dnsNameSize > 0) pairs += UI_PAIRS_POOL_RELAY_DNS;
            break;
        default:
            LEDGER_ASSERT(false, "Unknown relay format type");
    }
    return pairs;
}

void plan_or_render_pool_relay(const parse_tx_mode_t *mode,
                               uint16_t relay_index,
                               const pool_relay_t *relay) {
    LEDGER_ASSERT(relay != NULL, "NULL relay");
    if (mode->run_ui_planning) {
        G_context.tx_info.planned_ui_pairs += count_pool_relay_ui_pairs(relay);
    } else if (mode->run_ui_rendering) {
        START_COUNT();
        uint16_t expected_pairs = count_pool_relay_ui_pairs(relay);
        UI_ADD_FORMAT1(UI_STATIC_LABEL("Relay"),
                       MAX_RELAY_INDEX_STRING_LENGTH,
                       format_index_with_prefix,
                       relay_index + 1);
        switch (relay->format) {
            case RELAY_SINGLE_HOST_IP:
                if (!relay->ipv4.isNull) {
                    UI_ADD_FORMAT1(UI_STATIC_LABEL("IPv4"),
                                   MAX_IPV4_TEXT_LENGTH,
                                   format_ipv4,
                                   &relay->ipv4);
                }
                if (!relay->ipv6.isNull) {
                    UI_ADD_FORMAT1(UI_STATIC_LABEL("IPv6"),
                                   MAX_IPV6_TEXT_LENGTH,
                                   format_ipv6,
                                   &relay->ipv6);
                }
                if (!relay->port.isNull) {
                    UI_ADD_FORMAT1(UI_STATIC_LABEL("Port"),
                                   MAX_UINT64_STRING_LENGTH,
                                   format_uint16,
                                   relay->port.number);
                }
                break;
            case RELAY_SINGLE_HOST_NAME:
                if (relay->dnsNameSize > 0) {
                    UI_ADD_FORMAT2(UI_STATIC_LABEL("DNS name"),
                                   MAX_DNS_NAME_LENGTH,
                                   format_dns_name,
                                   relay->dnsName,
                                   relay->dnsNameSize);
                }
                if (!relay->port.isNull) {
                    UI_ADD_FORMAT1(UI_STATIC_LABEL("Port"),
                                   MAX_UINT64_STRING_LENGTH,
                                   format_uint16,
                                   relay->port.number);
                }
                break;
            case RELAY_MULTIPLE_HOST_NAME:
                if (relay->dnsNameSize > 0) {
                    UI_ADD_FORMAT2(UI_STATIC_LABEL("SRV DNS"),
                                   MAX_DNS_NAME_LENGTH,
                                   format_dns_name,
                                   relay->dnsName,
                                   relay->dnsNameSize);
                }
                break;
            default:
                LEDGER_ASSERT(false, "Unknown relay format type");
        }
        CHECK_COUNT(expected_pairs);
    }
}

void plan_or_render_pool_no_relays(const parse_tx_mode_t *mode) {
    if (mode->run_ui_planning) {
        G_context.tx_info.planned_ui_pairs += UI_PAIRS_POOL_NO_RELAYS;
    } else if (mode->run_ui_rendering) {
        START_COUNT();
        UI_ADD_STATIC(UI_STATIC_LABEL("Pool relays"), UI_STATIC_LABEL("(none)"));
        CHECK_COUNT(UI_PAIRS_POOL_NO_RELAYS);
    }
}

void plan_or_render_pool_metadata(const parse_tx_mode_t *mode,
                                  const pool_metadata_t *pool_metadata) {
    LEDGER_ASSERT(pool_metadata != NULL, "NULL pool_metadata");
    if (mode->run_ui_planning) {
        G_context.tx_info.planned_ui_pairs += UI_PAIRS_POOL_METADATA;
    } else if (mode->run_ui_rendering) {
        START_COUNT();
        if (pool_metadata->urlSize == 0) {
            UI_ADD_STATIC(UI_LABEL_BY_SCREEN("Pool metadata url", "Metadata url"),
                          UI_STATIC_LABEL("(empty)"));
        } else {
            UI_ADD_FORMAT2(UI_LABEL_BY_SCREEN("Pool metadata url", "Metadata url"),
                           MAX_POOL_METADATA_URL_LENGTH,
                           format_url,
                           pool_metadata->url,
                           pool_metadata->urlSize);
        }
        UI_ADD_FORMAT2(UI_LABEL_BY_SCREEN("Pool metadata hash", "Metadata hash"),
                       MAX_POOL_METADATA_HASH_STRING_LENGTH,
                       format_hex_bytes,
                       pool_metadata->hash,
                       POOL_METADATA_HASH_LENGTH);
        CHECK_COUNT(UI_PAIRS_POOL_METADATA);
    }
}

void plan_or_render_pool_no_metadata(const parse_tx_mode_t *mode) {
    if (mode->run_ui_planning) {
        G_context.tx_info.planned_ui_pairs += UI_PAIRS_POOL_NO_METADATA;
    } else if (mode->run_ui_rendering) {
        START_COUNT();
        UI_ADD_STATIC(UI_STATIC_LABEL("Metadata"), UI_STATIC_LABEL("(none)"));
        CHECK_COUNT(UI_PAIRS_POOL_NO_METADATA);
    }
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

void tx_ui_plan_or_render_certificate(const parse_tx_mode_t *mode,
                                      const certificate_data_t *certificate_data) {
    LEDGER_ASSERT(mode != NULL, "NULL mode");
    LEDGER_ASSERT(certificate_data != NULL, "NULL certificate_data");

    switch (certificate_data->type) {
        case CERTIFICATE_STAKE_REGISTRATION:
            plan_or_render_certificate_stake_registration(mode, certificate_data);
            break;

        case CERTIFICATE_STAKE_DEREGISTRATION:
            plan_or_render_certificate_stake_deregistration(mode, certificate_data);
            break;

        case CERTIFICATE_STAKE_REGISTRATION_CONWAY:
            plan_or_render_certificate_stake_registration_conway(mode, certificate_data);
            break;

        case CERTIFICATE_STAKE_DEREGISTRATION_CONWAY:
            plan_or_render_certificate_stake_deregistration_conway(mode, certificate_data);
            break;

        case CERTIFICATE_STAKE_DELEGATION:
            plan_or_render_certificate_stake_delegation(mode, certificate_data);
            break;

        case CERTIFICATE_VOTE_DELEGATION:
            plan_or_render_certificate_vote_delegation(mode, certificate_data);
            break;

        case CERTIFICATE_STAKE_POOL_AND_DREP_DELEGATION:
            plan_or_render_certificate_stake_pool_and_drep_delegation(mode, certificate_data);
            break;

        case CERTIFICATE_ACCOUNT_REGISTRATION_DELEGATION_TO_STAKE_POOL:
            plan_or_render_certificate_account_registration_delegation_to_stake_pool(mode, certificate_data);
            break;

        case CERTIFICATE_ACCOUNT_REGISTRATION_DELEGATION_TO_DREP:
            plan_or_render_certificate_account_registration_delegation_to_drep(mode, certificate_data);
            break;

        case CERTIFICATE_ACCOUNT_REGISTRATION_DELEGATION_TO_STAKE_POOL_AND_DREP:
            plan_or_render_certificate_account_registration_delegation_to_stake_pool_and_drep(mode, certificate_data);
            break;

        case CERTIFICATE_AUTHORIZE_COMMITTEE_HOT:
            plan_or_render_certificate_authorize_committee_hot(mode, certificate_data);
            break;

        case CERTIFICATE_RESIGN_COMMITTEE_COLD:
            plan_or_render_certificate_resign_committee_cold(mode, certificate_data);
            if (certificate_data->anchor.isIncluded) {
                plan_or_render_anchor(mode, &certificate_data->anchor);
            }
            break;

        case CERTIFICATE_DREP_REGISTRATION:
            plan_or_render_certificate_drep_registration(mode, certificate_data);
            if (certificate_data->anchor.isIncluded) {
                plan_or_render_anchor(mode, &certificate_data->anchor);
            }
            break;

        case CERTIFICATE_DREP_DEREGISTRATION:
            plan_or_render_certificate_drep_deregistration(mode, certificate_data);
            break;

        case CERTIFICATE_DREP_UPDATE:
            plan_or_render_certificate_drep_update(mode, certificate_data);
            if (certificate_data->anchor.isIncluded) {
                plan_or_render_anchor(mode, &certificate_data->anchor);
            }
            break;

        case CERTIFICATE_STAKE_POOL_RETIREMENT:
            plan_or_render_certificate_pool_retirement(mode, certificate_data);
            break;

        case CERTIFICATE_STAKE_POOL_REGISTRATION:
            LEDGER_ASSERT(false, "CERTIFICATE_STAKE_POOL_REGISTRATION handled separately");
            break;

        default:
            LEDGER_ASSERT(false, "Unknown certificate type");
            break;
    }
}
