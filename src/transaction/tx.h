/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "cardano_constants.h"
#include "lists.h"
#include "bip44.h"
#include "tx_credential_types.h"

typedef enum {
    AUX_DATA_TYPE_ARBITRARY_HASH = 0,
    AUX_DATA_TYPE_CVOTE_REGISTRATION = 1,
} aux_data_type_t;
#include "tx_certificate_types.h"
#include "tx_output_types.h"
#include "tx_voting_procedure_types.h"

// Mint token limits
// Note: No artificial limits on asset groups or tokens per mint.
// The wire format uses uint16_t for counts, so the natural limit is UINT16_MAX.
// Memory allocation is dynamic, so we can handle any count up to that limit.
#define MAX_MINT_ASSET_NAME_LENGTH 32

typedef struct {
    const uint8_t* txHash;
    uint32_t index;
} tx_input_t;

typedef struct {
    const uint8_t* assetName;
    uint8_t assetNameLen;
    int64_t amount;
} mint_token_t;

typedef struct {
    flist_node_t flist_node;
    mint_token_t token;
} mint_token_node_t;

typedef struct {
    const uint8_t* policyId;
    uint16_t numTokens;
    flist_node_t* tokens;
} mint_asset_group_t;

typedef struct {
    flist_node_t flist_node;
    mint_asset_group_t asset_group;
} mint_asset_group_node_t;

typedef enum {
    SIGN_TX_SIGNINGMODE_ORDINARY_TX = 3,
    SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OWNER = 4,
    SIGN_TX_SIGNINGMODE_POOL_REGISTRATION_OPERATOR = 5,
    SIGN_TX_SIGNINGMODE_MULTISIG_TX = 6,
    SIGN_TX_SIGNINGMODE_PLUTUS_TX = 7,
} sign_tx_signingmode_t;

// Transaction parameters parsed from SIGN_TX INIT APDU.
// These are known before tx body parsing starts.
typedef struct {
    sign_tx_signingmode_t txSigningMode;
    uint8_t networkId;
    uint32_t protocolMagic;
    bool tagCborSets;
    uint16_t num_inputs;
    uint16_t num_outputs;
    bool includeTtl;
    uint16_t num_certificates;
    uint16_t num_withdrawals;
    bool includeAuxDataHash;
    aux_data_type_t auxDataType;
    uint8_t auxDataHash[AUX_DATA_HASH_LENGTH];
    bool includeValidityIntervalStart;
    uint16_t num_mint_asset_groups;
    bool includeScriptDataHash;
    uint16_t num_collateral_inputs;
    uint16_t num_required_signers;
    bool includeNetworkId;
    bool includeCollateralOutput;
    bool includeTotalCollateral;
    uint16_t num_reference_inputs;
    uint16_t num_voters;
    bool includeTreasury;
    bool includeDonation;
} tx_params_t;

typedef enum {
    TX_OPTIONS_TAG_CBOR_SETS = 1,  // Whether to tag CBOR sets in transaction hash
} tx_options_e;

typedef struct {
    flist_node_t flist_node;
    tx_input_t input;
} tx_input_node_t;

typedef struct {
    ext_credential_t stakeCredential;
    uint64_t amount;
} withdrawal_t;

typedef enum {
    REQUIRED_SIGNER_WITH_PATH = 0,
    REQUIRED_SIGNER_WITH_HASH = 1,
} required_signer_type_t;

typedef struct {
    required_signer_type_t type;
    union {
        bip44_path_t keyPath;
        const uint8_t* keyHash;
    };
} required_signer_t;

typedef struct {
    flist_node_t flist_node;
    withdrawal_t withdrawal;
} tx_withdrawal_node_t;

typedef struct {
    flist_node_t flist_node;
    required_signer_t required_signer;
} tx_required_signer_node_t;

// Collateral inputs use the same structure as regular inputs
typedef tx_input_node_t tx_collateral_input_node_t;

// Certificate data structure supporting multiple certificate types.
// Fields are used selectively depending on certificate type:
// - STAKE_REGISTRATION/DEREGISTRATION: stakeCredential
// - STAKE_REGISTRATION_CONWAY/DEREGISTRATION_CONWAY: stakeCredential, deposit
// - STAKE_DELEGATION: stakeCredential, poolKeyHash
// - STAKE_POOL_RETIREMENT: poolCredential, retirementEpoch
// - STAKE_POOL_REGISTRATION: poolId, poolRegistration
// - VOTE_DELEGATION: stakeCredential, drep
// - AUTHORIZE_COMMITTEE_HOT: coldCredential, hotCredential
// - RESIGN_COMMITTEE_COLD: coldCredential, anchor
// - DREP_REGISTRATION/UPDATE: dRepCredential, deposit (reg only), anchor
// - DREP_DEREGISTRATION: dRepCredential, deposit
// - (Future) STAKE_POOL_AND_DREP_DELEGATION: stakeCredential, drep, combinedDelegPoolKeyHash
typedef struct {
    certificate_type_t type;
    ext_credential_t stakeCredential;
    ext_credential_t coldCredential;
    ext_credential_t dRepCredential;
    ext_credential_t poolCredential;
    pool_id_t poolId;
    ext_credential_t hotCredential;
    const uint8_t* poolKeyHash;
    const uint8_t* combinedDelegPoolKeyHash;
    ext_drep_t drep;
    uint64_t deposit;
    uint64_t retirementEpoch;
    anchor_t anchor;  // For committee resign, DRep registration/update
    pool_registration_data_t* poolRegistration;  // NULL if not STAKE_POOL_REGISTRATION; heap-allocated if present
} certificate_data_t;

typedef struct {
    flist_node_t flist_node;
    certificate_data_t certificate;
} tx_certificate_node_t;

typedef struct {
    // Note: We use linked lists (via flist) for parsed transaction items because
    // the memory allocated to list nodes may be gradually reused/reallocated for UI
    // string formatting during processing. Arrays would prevent this reallocation.
    // CBOR key order (matches transaction_body CDDL)
    flist_node_t* inputs;                    // key 0
    flist_node_t* outputs;                   // key 1
    uint64_t fee;                            // key 2
    uint64_t ttl;                            // key 3
    flist_node_t* certificates;              // key 4
    flist_node_t* withdrawals;               // key 5
    uint64_t validityIntervalStart;          // key 8
    flist_node_t* mint_asset_groups;         // key 9
    const uint8_t* scriptDataHash;           // key 11
    flist_node_t* collateral_inputs;         // key 13
    flist_node_t* required_signers;          // key 14
    parsed_tx_output_t collateral_output; // key 16
    // Note: For DESTINATION_DEVICE_OWNED, collateral_output.destination.params points to
    // dynamically allocated memory that must be freed when the collateral output is freed.
    uint64_t totalCollateral;                 // key 17
    flist_node_t* reference_inputs;           // key 18
    flist_node_t* voting_procedures;          // key 19
    uint64_t treasury;                        // key 21
    uint64_t donation;                        // key 22
} tx_parsed_body_t;
