/*****************************************************************************
 *   Ledger App Cardano.
 *   (c) 2025 Vacuumlabs
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *****************************************************************************/

#include "parsers.h"
#include "buffer.h"
#include "buffer_utils.h"
#include "cardano_constants.h"
#include "utils/utils.h"
#include "utils/assert.h"

bool buffer_read_flag_included(buffer_t *buf, bool* result) {
    LEDGER_ASSERT(buf != NULL, "NULL buf");
    LEDGER_ASSERT(result != NULL, "NULL result");

    uint8_t value;
    if (!buffer_read_u8(buf, &value)) {
        return false;
    }

    switch (value) {
        case FLAG_INCLUDED_YES:
            *result = true;
            return true;
        case FLAG_INCLUDED_NO:
            *result = false;
            return true;
        default:
            return false;
    }
}

// =============================================================================
// Credential Parsing Implementation
// =============================================================================

/**
 * Parse credential type byte from wire format.
 *
 * Wire format values:
 *   0 = EXT_CREDENTIAL_KEY_HASH
 *   1 = EXT_CREDENTIAL_SCRIPT_HASH
 *   2 = EXT_CREDENTIAL_KEY_PATH
 *
 * @param[in] buf Buffer to read from
 * @param[out] cred_type Parsed credential type
 * @return true on success, false on failure
 */
static bool _parse_credential_type(buffer_t *buf, ext_credential_type_t *cred_type) {
    uint8_t cred_type_wire;
    if (!buffer_read_u8(buf, &cred_type_wire)) {
        TRACE("Failed to read credential type byte");
        return false;
    }

    TRACE("Parsing credential type wire=0x%02x", cred_type_wire);

    switch (cred_type_wire) {
        case EXT_CREDENTIAL_KEY_HASH:
            *cred_type = EXT_CREDENTIAL_KEY_HASH;
            TRACE("Credential type: KEY_HASH");
            break;
        case EXT_CREDENTIAL_SCRIPT_HASH:
            *cred_type = EXT_CREDENTIAL_SCRIPT_HASH;
            TRACE("Credential type: SCRIPT_HASH");
            break;
        case EXT_CREDENTIAL_KEY_PATH:
            *cred_type = EXT_CREDENTIAL_KEY_PATH;
            TRACE("Credential type: KEY_PATH");
            break;
        default:
            TRACE("Invalid credential type wire value: 0x%02x", cred_type_wire);
            return false;
    }
    return true;
}

/**
 * Parse credential data based on its type.
 *
 * @param[in] buf Buffer to read from
 * @param[in] cred_type Credential type to parse
 * @param[out] credential Credential structure to populate
 * @return true on success, false on failure
 */
static bool _parse_credential_data(buffer_t *buf,
                                   ext_credential_type_t cred_type,
                                   ext_credential_t *credential) {
    TRACE("Parsing credential data for type=%u", cred_type);
    switch (cred_type) {
        case EXT_CREDENTIAL_KEY_PATH:
            if (!buffer_read_bip44_path(buf, &credential->keyPath)) {
                TRACE("Failed to read BIP44 path");
                return false;
            }
            TRACE("Successfully parsed KEY_PATH credential");
            break;
        case EXT_CREDENTIAL_KEY_HASH: {
            if (!buffer_read_bytes_ptr(buf, &credential->keyHash, ADDRESS_KEY_HASH_LENGTH)) {
                TRACE("Failed to read key hash");
                return false;
            }
            ASSERT(credential->keyHash != NULL);
            TRACE("Successfully parsed KEY_HASH credential");
            break;
        }
        case EXT_CREDENTIAL_SCRIPT_HASH: {
            if (!buffer_read_bytes_ptr(buf, &credential->scriptHash, SCRIPT_HASH_LENGTH)) {
                TRACE("Failed to read script hash");
                return false;
            }
            ASSERT(credential->scriptHash != NULL);
            TRACE("Successfully parsed SCRIPT_HASH credential");
            break;
        }
        default:
            TRACE("Invalid credential type: %u", cred_type);
            return false;
    }
    return true;
}

bool parse_ext_credential(buffer_t *buf, ext_credential_t *credential) {
    TRACE("Parsing extended credential");
    ext_credential_type_t cred_type = {0};
    if (!_parse_credential_type(buf, &cred_type)) {
        TRACE("Failed to parse credential type");
        return false;
    }
    credential->type = cred_type;

    if (!_parse_credential_data(buf, cred_type, credential)) {
        TRACE("Failed to parse credential data");
        return false;
    }
    TRACE("Successfully parsed extended credential");
    return true;
}

bool parse_native_script_pubkey_credential(buffer_t *buf, ext_credential_t *credential) {
    TRACE("Parsing native script pubkey credential");

    if (!parse_ext_credential(buf, credential)) {
        TRACE("Failed to parse credential");
        return false;
    }

    // Native script pubkey constraints only allow KEY_HASH and KEY_PATH
    // Script hashes are not valid
    if (credential->type == EXT_CREDENTIAL_SCRIPT_HASH) {
        TRACE("Script hash not allowed for native script pubkey");
        return false;
    }

    TRACE("Successfully parsed native script pubkey credential, type=%u", credential->type);
    return true;
}
