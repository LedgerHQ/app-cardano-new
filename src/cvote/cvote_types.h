#pragma once

#include <stdint.h>
#include <stdbool.h>

#include "addressUtilsShelley.h"
#include "tx_output_types.h"

// CVote auxiliary data state machine
typedef enum {
    CVOTE_AUX_DATA_STATE_NONE,                  /// No CVote aux data expected
    CVOTE_AUX_DATA_STATE_EXPECTING_INIT,        /// Waiting for P2_AUX_DATA_INIT APDU
    CVOTE_AUX_DATA_STATE_RECEIVING_DELEGATIONS, /// Receiving P2_AUX_DATA_DELEGATION APDUs
    CVOTE_AUX_DATA_STATE_ALL_DATA_RECEIVED,     /// All delegations received, ready to finalize hash
    CVOTE_AUX_DATA_STATE_FINALIZED,             /// Hash computed, ready for UI
    CVOTE_AUX_DATA_STATE_APPROVED               /// User approved, hash ready to send
} cvote_aux_data_state_e;

// CVote registration format (CIP-15 or CIP-36)
typedef enum {
    CIP15 = 1,
    CIP36 = 2
} cvote_registration_format_t;

// CVote-specific credential type
// Per CIP-36 CBOR spec, only 32-byte public keys and BIP44 paths are supported
// Script hashes are NOT allowed for CVote credentials
typedef enum {
    CVOTE_CREDENTIAL_KEY = 0,           // Wire: 0, Data: 32-byte public key
    CVOTE_CREDENTIAL_KEY_PATH = 2,      // Wire: 2, Data: BIP44 path
} cvote_credential_type_t;

typedef struct {
    cvote_credential_type_t type;
    union {
        bip44_path_t keyPath;
        // 32 bytes for CVOTE_CREDENTIAL_KEY type
        // WARNING: For delegations, this pointer is transient (points to APDU buffer) and must be consumed immediately.
        // For INIT, it points to the persistent raw_cvote_init_data buffer.
        const uint8_t* publicKey;
    };
} cvote_credential_t;

// CVote destination - uses shared types from TX outputs
typedef struct {
    tx_output_destination_type_t type;  // 1 = DESTINATION_THIRD_PARTY, 2 = DESTINATION_DEVICE_OWNED
    union {
        third_party_address_t address;  // Shared third-party address type
        addressParams_t params;
    };
} cvote_destination_t;
