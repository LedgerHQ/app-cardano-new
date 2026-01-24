#pragma once

#include <stddef.h>  // size_t
#include <stdbool.h>
#include <stdint.h>  // uint*_t
#include "cardano_constants.h"
#include "addressUtilsShelley.h"
#include "bip44.h"      // for bip44_path_t

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

/**
 * State machine for address derivation operation.
 * Tracks the progression through parsing, validation, derivation, and approval phases.
 */
typedef enum {
    DERIVE_ADDRESS_STATE_NONE,        /// idle
    DERIVE_ADDRESS_STATE_VALIDATED,   /// parameters parsed, security policy validated
    DERIVE_ADDRESS_STATE_PREPARED,    /// address derived and ready
    DERIVE_ADDRESS_STATE_APPROVED     /// user approved or auto-approved
} derive_address_state_e;
