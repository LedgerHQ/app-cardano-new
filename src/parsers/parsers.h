#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "buffer.h"
#include "transaction/tx_credential_types.h"

// =============================================================================
// Item Inclusion Parsing
// =============================================================================

/**
 * Inclusion flag values for optional transaction fields.
 *
 * These values indicate whether an optional field is present in the
 * transaction wire format.
 */
typedef enum {
    ITEM_INCLUDED_NO = 1,   // Field is not included
    ITEM_INCLUDED_YES = 2,  // Field is included
} item_included_e;

/**
 * Parse item inclusion flag for optional transaction fields.
 *
 * @param[in] value The inclusion flag byte (ITEM_INCLUDED_YES or ITEM_INCLUDED_NO)
 * @param[out] result Pointer to store the result (true if included, false otherwise)
 * @return true if parsing succeeded, false if value is invalid
 */
static inline bool parseIncluded(uint8_t value, bool* result) {
    switch (value) {
        case ITEM_INCLUDED_YES:
            *result = true;
            return true;
        case ITEM_INCLUDED_NO:
            *result = false;
            return true;
        default:
            return false;
    }
}

// =============================================================================
// Credential Parsing
// =============================================================================

/**
 * Parse an extended credential (key hash, script hash, or key path).
 *
 * Extended credentials support both CBOR credential types (key hash, script hash)
 * and an additional key path type for device-owned keys.
 *
 * Wire format:
 *   - 1 byte: credential type (0=KEY_HASH, 1=SCRIPT_HASH, 2=KEY_PATH)
 *   - Variable: credential data based on type
 *
 * @param[in] buf Buffer to read from
 * @param[out] credential Parsed credential structure
 * @return true on success, false on failure
 */
bool parse_ext_credential(buffer_t *buf, ext_credential_t *credential);

/**
 * Parse a native script pubkey credential.
 *
 * Similar to parse_ext_credential but only allows KEY_HASH and KEY_PATH types.
 * Script hashes are not valid for native script pubkey constraints.
 *
 * @param[in] buf Buffer to read from
 * @param[out] credential Parsed credential structure (type will be KEY_HASH or KEY_PATH)
 * @return true on success, false on failure
 */
bool parse_native_script_pubkey_credential(buffer_t *buf, ext_credential_t *credential);
