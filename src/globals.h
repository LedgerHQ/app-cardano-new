#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "os.h"
#include "ux.h"
#include "cardano_constants.h"
#include "bip32.h"
#include "securityWarnings.h"
#include "cvote_types.h"
#include "cvote_parser.h"
#include "tx.h"
#include "opcert_types.h"
#include "deriveNativeScriptHash_types.h"
#include "dispatcher.h"
#include "derive_native_script_hash.h"
#include "keyDerivation.h"
#include "addressUtilsShelley.h"
#include "cvote/vote_cast_hash_builder.h"
/**
 * State machine for transaction processing.
 * Tracks the progression through receiving, parsing, hashing, UI preparation, and approval.
 */
typedef enum {
    TX_STATE_NONE,         /// idle
    TX_STATE_AUX_DATA,     /// receiving CVote aux data
    TX_STATE_CHUNKS,       /// receiving transaction chunks
    TX_STATE_RECEIVED,     /// all chunks received, waiting to parse
    TX_STATE_PARSED,       /// transaction parsed, ready for hashing
    TX_STATE_HASHED,       /// hash computed, UI plan ready
    TX_STATE_UI_PREPARED,  /// UI strings prepared
    TX_STATE_APPROVED      /// user approved, waiting for witnesses
} tx_state_e;

/**
 * State machine for operational certificate signing.
 * Tracks the progression through parsing, validation, and approval phases.
 */
typedef enum {
    OPCERT_STATE_NONE,        /// idle
    OPCERT_STATE_PARSED,      /// parsed from bytes, waiting for policy validation
    OPCERT_STATE_VALIDATED,   /// parsed and security policy validated, waiting for approval
    OPCERT_STATE_APPROVED     /// user approved, waiting for signature
} opcert_state_e;

/**
 * State machine for address derivation operation.
 * Tracks the progression through parsing, validation, derivation, and approval phases.
 */
typedef enum {
    DERIVE_ADDRESS_STATE_NONE,        /// idle
    DERIVE_ADDRESS_STATE_PARSED,      /// parameters parsed, waiting for policy validation
    DERIVE_ADDRESS_STATE_VALIDATED,   /// parameters parsed, security policy validated
    DERIVE_ADDRESS_STATE_PREPARED,    /// address derived and ready
    DERIVE_ADDRESS_STATE_APPROVED     /// user approved or auto-approved
} derive_address_state_e;

/**
 * State machine for CVote votecast operation.
 * Tracks the progression through initialization, reception, and confirmation phases.
 */
typedef enum {
    VOTECAST_STAGE_NONE = 0,
    VOTECAST_STAGE_INIT,
    VOTECAST_STAGE_CHUNK,
    VOTECAST_STAGE_CONFIRM,
} cvote_stage_e;

/**
 * Tracks stored account metadata for the single-account security model.
 */
typedef struct {
    bool isStored;
    bool isByron;
    uint32_t accountNumber;
} single_account_data_t;

/**
 * Transaction context (covers raw tx buffer + witness bookkeeping).
 */
typedef struct {
    uint8_t *raw_tx;
    size_t raw_tx_len;
    transaction_t transaction;
    uint8_t tx_hash[TX_HASH_LENGTH];

    uint16_t num_witnesses;
    uint16_t current_witness;
    bip44_path_t witness_path;
    uint8_t witness_signature[ED25519_SIGNATURE_LENGTH];

    // CVote auxiliary data buffers and parsed data
    // (state moved to cvote_aux_data_t.state)
    uint8_t *raw_cvote_init_data;        /// Raw APDU buffer for CVote init (like raw_tx)
    size_t raw_cvote_init_data_len;
    cvote_aux_data_t cvote_aux_data;     /// Parsed CVote data with pointers into raw buffer and state

    bool pool_owner_path_present;
    bip44_path_t pool_owner_path;

    single_account_data_t single_account_data;

    warning_bits_t warning_bits;          /// Transaction warnings only
    warning_bits_t cvote_warning_bits;    /// CVote auxiliary data warnings only
    uint32_t planned_ui_pairs;
} transaction_ctx_t;

/**
 * Operational certificate context.
 */
#define MAX_OPCERT_LENGTH (KES_PUBLIC_KEY_LENGTH + OPCERT_KES_PERIOD_SIZE + OPCERT_ISSUE_COUNTER_SIZE + BIP44_MAX_PATH_SIZE)

typedef struct {
    uint8_t raw_opcert[MAX_OPCERT_LENGTH];
    size_t raw_opcert_len;
    parsed_opcert_t opcert;
    uint8_t signature[ED25519_SIGNATURE_LENGTH];
} sign_opcert_ctx_t;

/*
    Derive native script hash context.
*/
typedef struct {
    uint8_t level;
    // stores information about a complex script at the index level
    complex_native_script_t complexScripts[MAX_SCRIPT_DEPTH];

    uint8_t scriptHashBuffer[SCRIPT_HASH_LENGTH];
    native_script_hash_builder_t hashBuilder;

    native_script_content_t scriptContent;

    // ui native script state
    ui_native_script_type ui_scriptType;
} derive_native_script_hash_ctx_t;

/**
 * Exposed context for public-key exports.
 */
typedef struct {
    bip44_path_t path;
    extendedPublicKey_t extPubKey;
    bool silentExport;
} pubkey_ctx_t;

/**
 * Structure for derive address information context.
 */
typedef struct {
    addressParams_t addressParams;
    struct {
        uint8_t buffer[MAX_ADDRESS_LENGTH];
        size_t size;
    } address;
} derive_address_ctx_t;

#define MAX_VOTECAST_CHUNK_SIZE 240
#define VOTE_PLAN_ID_SIZE       32
#define VOTECAST_HASH_LENGTH 32

/**
 * Context for signing a CVote votecast.
 */
typedef struct {
    uint32_t remaining_votecast_bytes;
    votecast_hash_builder_t votecast_hash_builder;
    uint8_t vote_plan_id[VOTE_PLAN_ID_SIZE];
    uint8_t proposal_index;
    uint8_t payload_type_tag;
    bip44_path_t witness_path;
    uint8_t witness_signature[ED25519_SIGNATURE_LENGTH];
} cvote_cxt_t;

/**
 * Global context for user requests.
 */
typedef struct {
    union {
        tx_state_e tx_state;
        opcert_state_e opcert_state;
        derive_address_state_e derive_address_state;
        cvote_stage_e cvote_state;
    } state;

    union {
        pubkey_ctx_t pk_info;
        transaction_ctx_t tx_info;
        sign_opcert_ctx_t opcert_info;
        derive_address_ctx_t derive_address_info;
        derive_native_script_hash_ctx_t derive_native_script_hash_info;
        cvote_cxt_t cvote_info;
    };

    request_type_e req_type;
    uint32_t bip32_path[MAX_BIP32_PATH];
    uint8_t bip32_path_len;
} global_ctx_t;

extern global_ctx_t G_context;

/**
 * Global structure for NVM data storage.
 */
typedef struct internal_storage_t {
    uint8_t expert_mode_enabled;
    uint8_t silent_pubkey_export_enabled;
    uint8_t initialized;
} internal_storage_t;

extern const internal_storage_t N_storage_real;
#define N_storage (*(volatile internal_storage_t *) PIC(&N_storage_real))
