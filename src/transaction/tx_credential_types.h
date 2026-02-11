/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include "cardano_constants.h"
#include "bip44.h"
#include "keyDerivation.h"

typedef enum {
    EXT_CREDENTIAL_KEY_HASH = 0,      // Wire: 0, CBOR: 0
    EXT_CREDENTIAL_SCRIPT_HASH = 1,   // Wire: 1, CBOR: 1
    EXT_CREDENTIAL_KEY_PATH = 2,      // Wire: 2, not in CBOR (converted to KEY_HASH via keyPathToKeyHash)
} ext_credential_type_t;

// Extended credential structure
typedef struct {
    ext_credential_type_t type;
    union {
        bip44_path_t keyPath;
        const uint8_t* keyHash;
        const uint8_t* scriptHash;
    };
} ext_credential_t;

// DReps are extended to allow key derivation paths
typedef enum {
    DREP_KEY_HASH = 0,
    DREP_SCRIPT_HASH = 1,
    DREP_ABSTAIN = 2,
    DREP_NO_CONFIDENCE = 3,
} drep_type_t;

typedef enum {
    CREDENTIAL_KEY_HASH = 0,
    CREDENTIAL_SCRIPT_HASH = 1,
} credential_type_t;

typedef struct {
    credential_type_t type;
    union {
        uint8_t keyHash[ADDRESS_KEY_HASH_LENGTH];
        uint8_t scriptHash[SCRIPT_HASH_LENGTH];
    };
} credential_t;

typedef struct {
    drep_type_t type;
    union {
        uint8_t keyHash[ADDRESS_KEY_HASH_LENGTH];
        uint8_t scriptHash[SCRIPT_HASH_LENGTH];
    };
} drep_t;

typedef enum {
    EXT_DREP_KEY_HASH = DREP_KEY_HASH,
    EXT_DREP_KEY_PATH = DREP_KEY_HASH + 100,
    EXT_DREP_SCRIPT_HASH = DREP_SCRIPT_HASH,
    EXT_DREP_ABSTAIN = DREP_ABSTAIN,
    EXT_DREP_NO_CONFIDENCE = DREP_NO_CONFIDENCE,
} ext_drep_type_t;

// Extended DREP structure (includes CBOR hashes + optional key paths)
typedef struct {
    ext_drep_type_t type;
    union {
        bip44_path_t keyPath;
        const uint8_t* keyHash;
        const uint8_t* scriptHash;
    };
} ext_drep_t;
