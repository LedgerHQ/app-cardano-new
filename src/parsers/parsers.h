#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "buffer.h"
#include "transaction/tx_credential_types.h"

// =============================================================================
// Optional Item Flags
// =============================================================================

/**
 * Inclusion flag values for optional transaction fields.
 *
 * These values are used on the wire to indicate whether an optional
 * transaction field is present (FLAG_INCLUDED_YES) or omitted
 * (FLAG_INCLUDED_NO).
 */
typedef enum {
    FLAG_INCLUDED_NO = 1,   // Field is not included
    FLAG_INCLUDED_YES = 2,  // Field is included
} flag_included_e;

/**
 * Read and interpret a flag byte as a boolean inclusion indicator.
 *
 * @param[in] buf Buffer to read from
 * @param[out] result true if the field is included, false otherwise
 * @return true if a valid flag was read, false otherwise
 */
bool buffer_read_flag_included(buffer_t *buf, bool* result);

// =============================================================================
// Credential Parsing
// =============================================================================

/**
 * Read an extended credential (key hash, script hash, or key path).
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
bool buffer_read_credential(buffer_t *buf, ext_credential_t *credential);
