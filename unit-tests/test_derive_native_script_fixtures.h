// Auto-generated native script hash derivation test fixtures
// Generated from ragger standalone test cases
//
//
// Tree Structure:
//   - Each test case is a root of a native script tree
//   - Leaf nodes (SIMPLE scripts): PUBKEY_DEVICE_OWNED, PUBKEY_THIRD_PARTY,
//                                   INVALID_BEFORE, INVALID_HEREAFTER
//   - Internal nodes (COMPLEX scripts): ALL, ANY, N_OF_K
//   - Internal nodes contain children (can be leaf or internal nodes)
//
#pragma once

#include <stdint.h>
#include <stddef.h>
#include "cardano_swo.h"

#define SCRIPT_HASH_LENGTH 28  // Blake2b-224
#define KEY_HASH_LENGTH 28     // Blake2b-224

// Forward declaration for tree structure
typedef struct native_script_s native_script_t;

// Native script types (matching CBOR encoding)
typedef enum {
    NATIVE_SCRIPT_TYPE_PUBKEY_DEVICE_OWNED = 0x00,
    NATIVE_SCRIPT_TYPE_PUBKEY_THIRD_PARTY = 0xF0,
    NATIVE_SCRIPT_TYPE_ALL = 0x01,
    NATIVE_SCRIPT_TYPE_ANY = 0x02,
    NATIVE_SCRIPT_TYPE_N_OF_K = 0x03,
    NATIVE_SCRIPT_TYPE_INVALID_BEFORE = 0x04,
    NATIVE_SCRIPT_TYPE_INVALID_HEREAFTER = 0x05,
} native_script_type_e;

// SIMPLE script structure (leaf node)
typedef struct {
   const uint8_t* apdu_payload;         // Raw APDU data from command_builder.derive_script_add_complex:
   size_t apdu_payload_length;          // Length of APDU payload
} native_script_simple_t;

// COMPLEX script structure (internal node with children)
typedef struct {
    union {
        struct {
            const native_script_t** scripts;
            size_t scripts_count;
        } all;
        struct {
            const native_script_t** scripts;
            size_t scripts_count;
        } any;
        struct {
            uint32_t required_count;
            const native_script_t** scripts;
            size_t scripts_count;
        } n_of_k;
    } params;
} native_script_complex_t;

// Generic native script (can be simple or complex)
struct native_script_s {
    native_script_type_e type;
    union {
        native_script_simple_t simple;
        native_script_complex_t complex;
    } impl;
};

// Test case structure
typedef struct {
    const char* name;
    const native_script_t* root_script;  // Root of script tree
    const uint8_t* expected_hash;
    bool nano_skip;
    const uint8_t* finish_apdu_payload;     // Raw APDU data from command_builder.derive_script_finish
    size_t finish_apdu_payload_length;      // Length of finish APDU payload
} native_script_test_case_t;

// ======================================================================
// Native Script Tree Fixtures
// ======================================================================

// ======================================================================
// Test Case [0]: PUBKEY_device_owned
// ======================================================================

static const uint8_t EXPECTED_HASH_TC0_PUBKEY_DEVICE_OWNED[SCRIPT_HASH_LENGTH] = {
    0xe0, 0x23, 0x16, 0xef, 0xa0, 0x63, 0x2d, 0x53,
    0xc2, 0x8c, 0x52, 0x1f, 0xc7, 0xbc, 0xad, 0xe6,
    0xe9, 0x29, 0x84, 0x9f, 0xf8, 0xb4, 0x4e, 0xfb,
    0x5a, 0x2c, 0xff, 0xc0,
};

// APDU payload for P1_NATIVE_SCRIPT_ADD_SIMPLE
// Script type: PUBKEY_DEVICE_OWNED
static const uint8_t APDU_PAYLOAD_TC0_PUBKEY_DEVICE_OWNED_C0[23] = {
    0x00, 0x02, 0x05, 0x80, 0x00, 0x07, 0x3c, 0x80,
    0x00, 0x07, 0x17, 0x80, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const native_script_t SCRIPT_TC0_PUBKEY_DEVICE_OWNED_C0 = {
    .type = NATIVE_SCRIPT_TYPE_PUBKEY_DEVICE_OWNED,
    .impl = {
        .simple = {
            .apdu_payload = APDU_PAYLOAD_TC0_PUBKEY_DEVICE_OWNED_C0,
            .apdu_payload_length = sizeof(APDU_PAYLOAD_TC0_PUBKEY_DEVICE_OWNED_C0),
        }
    }
};


// APDU payload for P1_NATIVE_SCRIPT_FINISH
// Display format: BECH32 (0x01)
static const uint8_t FINISH_APDU_PAYLOAD_TC0_PUBKEY_DEVICE_OWNED[1] = {
    0x01
};

// ======================================================================
// Test Case [1]: PUBKEY_third_party
// ======================================================================

static const uint8_t EXPECTED_HASH_TC1_PUBKEY_THIRD_PARTY[SCRIPT_HASH_LENGTH] = {
    0x85, 0x52, 0x28, 0xf5, 0xec, 0xec, 0xec, 0xf9,
    0xc8, 0x56, 0x18, 0x00, 0x7c, 0xc3, 0xc2, 0xe5,
    0xbd, 0xf5, 0xe6, 0xd4, 0x1e, 0xf8, 0xd6, 0xfa,
    0x79, 0x3f, 0xe0, 0xeb,
};

// APDU payload for P1_NATIVE_SCRIPT_ADD_SIMPLE
// Script type: PUBKEY_THIRD_PARTY
static const uint8_t APDU_PAYLOAD_TC1_PUBKEY_THIRD_PARTY_C0[30] = {
    0x00, 0x00, 0x3a, 0x55, 0xd9, 0xf6, 0x82, 0x55,
    0xdf, 0xbe, 0xfa, 0x1e, 0xfd, 0x71, 0x1f, 0x82,
    0xd0, 0x05, 0xfa, 0xe1, 0xbe, 0x2e, 0x14, 0x5d,
    0x61, 0x6c, 0x90, 0xcf, 0x0f, 0xa9
};

static const native_script_t SCRIPT_TC1_PUBKEY_THIRD_PARTY_C0 = {
    .type = NATIVE_SCRIPT_TYPE_PUBKEY_THIRD_PARTY,
    .impl = {
        .simple = {
            .apdu_payload = APDU_PAYLOAD_TC1_PUBKEY_THIRD_PARTY_C0,
            .apdu_payload_length = sizeof(APDU_PAYLOAD_TC1_PUBKEY_THIRD_PARTY_C0),
        }
    }
};


// APDU payload for P1_NATIVE_SCRIPT_FINISH
// Display format: BECH32 (0x01)
static const uint8_t FINISH_APDU_PAYLOAD_TC1_PUBKEY_THIRD_PARTY[1] = {
    0x01
};

// ======================================================================
// Test Case [2]: PUBKEY_third_party_script_hash_displayed_as_policy_id
// ======================================================================

static const uint8_t EXPECTED_HASH_TC2_PUBKEY_THIRD_PARTY_SCRIPT_HASH_DISPLAYED_AS_POLICY_ID[SCRIPT_HASH_LENGTH] = {
    0x85, 0x52, 0x28, 0xf5, 0xec, 0xec, 0xec, 0xf9,
    0xc8, 0x56, 0x18, 0x00, 0x7c, 0xc3, 0xc2, 0xe5,
    0xbd, 0xf5, 0xe6, 0xd4, 0x1e, 0xf8, 0xd6, 0xfa,
    0x79, 0x3f, 0xe0, 0xeb,
};

// APDU payload for P1_NATIVE_SCRIPT_ADD_SIMPLE
// Script type: PUBKEY_THIRD_PARTY
static const uint8_t APDU_PAYLOAD_TC2_PUBKEY_THIRD_PARTY_SCRIPT_HASH_DISPLAYED_AS_POLICY_ID_C0[30] = {
    0x00, 0x00, 0x3a, 0x55, 0xd9, 0xf6, 0x82, 0x55,
    0xdf, 0xbe, 0xfa, 0x1e, 0xfd, 0x71, 0x1f, 0x82,
    0xd0, 0x05, 0xfa, 0xe1, 0xbe, 0x2e, 0x14, 0x5d,
    0x61, 0x6c, 0x90, 0xcf, 0x0f, 0xa9
};

static const native_script_t SCRIPT_TC2_PUBKEY_THIRD_PARTY_SCRIPT_HASH_DISPLAYED_AS_POLICY_ID_C0 = {
    .type = NATIVE_SCRIPT_TYPE_PUBKEY_THIRD_PARTY,
    .impl = {
        .simple = {
            .apdu_payload = APDU_PAYLOAD_TC2_PUBKEY_THIRD_PARTY_SCRIPT_HASH_DISPLAYED_AS_POLICY_ID_C0,
            .apdu_payload_length = sizeof(APDU_PAYLOAD_TC2_PUBKEY_THIRD_PARTY_SCRIPT_HASH_DISPLAYED_AS_POLICY_ID_C0),
        }
    }
};


// APDU payload for P1_NATIVE_SCRIPT_FINISH
// Display format: POLICY_ID (0x02)
static const uint8_t FINISH_APDU_PAYLOAD_TC2_PUBKEY_THIRD_PARTY_SCRIPT_HASH_DISPLAYED_AS_POLICY_ID[1] = {
    0x02
};

// ======================================================================
// Test Case [3]: ALL_script
// ======================================================================

static const uint8_t EXPECTED_HASH_TC3_ALL_SCRIPT[SCRIPT_HASH_LENGTH] = {
    0xaf, 0x5c, 0x2c, 0xe4, 0x76, 0xa6, 0xed, 0xe1,
    0xc8, 0x79, 0xf7, 0xb1, 0x90, 0x9d, 0x6a, 0x0b,
    0x96, 0xcb, 0x20, 0x81, 0x39, 0x17, 0x12, 0xd4,
    0xa3, 0x55, 0xce, 0xf6,
};

// ALL (internal node): 2 children
// APDU payload for P1_NATIVE_SCRIPT_ADD_SIMPLE
// Script type: PUBKEY_THIRD_PARTY
static const uint8_t APDU_PAYLOAD_TC3_ALL_SCRIPT_C0_C0[30] = {
    0x00, 0x00, 0xc4, 0xb9, 0x26, 0x56, 0x45, 0xfd,
    0xe9, 0x53, 0x6c, 0x07, 0x95, 0xad, 0xbc, 0xc5,
    0x29, 0x17, 0x67, 0xa0, 0xc6, 0x1f, 0xd6, 0x24,
    0x48, 0x34, 0x1d, 0x7e, 0x03, 0x86
};

static const native_script_t SCRIPT_TC3_ALL_SCRIPT_C0_C0 = {
    .type = NATIVE_SCRIPT_TYPE_PUBKEY_THIRD_PARTY,
    .impl = {
        .simple = {
            .apdu_payload = APDU_PAYLOAD_TC3_ALL_SCRIPT_C0_C0,
            .apdu_payload_length = sizeof(APDU_PAYLOAD_TC3_ALL_SCRIPT_C0_C0),
        }
    }
};


// APDU payload for P1_NATIVE_SCRIPT_ADD_SIMPLE
// Script type: PUBKEY_THIRD_PARTY
static const uint8_t APDU_PAYLOAD_TC3_ALL_SCRIPT_C0_C1[30] = {
    0x00, 0x00, 0x02, 0x41, 0xf2, 0xd1, 0x96, 0xf5,
    0x2a, 0x92, 0xfb, 0xd2, 0x18, 0x3d, 0x03, 0xb3,
    0x70, 0xc3, 0x0b, 0x69, 0x60, 0xcf, 0xde, 0xae,
    0x36, 0x4f, 0xfa, 0xba, 0xc8, 0x89
};

static const native_script_t SCRIPT_TC3_ALL_SCRIPT_C0_C1 = {
    .type = NATIVE_SCRIPT_TYPE_PUBKEY_THIRD_PARTY,
    .impl = {
        .simple = {
            .apdu_payload = APDU_PAYLOAD_TC3_ALL_SCRIPT_C0_C1,
            .apdu_payload_length = sizeof(APDU_PAYLOAD_TC3_ALL_SCRIPT_C0_C1),
        }
    }
};


static const native_script_t* CHILDREN_TC3_ALL_SCRIPT_C0[] = {
    (const native_script_t*)&SCRIPT_TC3_ALL_SCRIPT_C0_C0,
    (const native_script_t*)&SCRIPT_TC3_ALL_SCRIPT_C0_C1,
};

static const native_script_t SCRIPT_TC3_ALL_SCRIPT_C0 = {
    .type = NATIVE_SCRIPT_TYPE_ALL,
    .impl = {
        .complex = {
             .params = {
                 .all = {
                     .scripts = CHILDREN_TC3_ALL_SCRIPT_C0,
                     .scripts_count = 2,
                 }
             }
         }
     }
};

// APDU payload for P1_NATIVE_SCRIPT_FINISH
// Display format: BECH32 (0x01)
static const uint8_t FINISH_APDU_PAYLOAD_TC3_ALL_SCRIPT[1] = {
    0x01
};

// ======================================================================
// Test Case [4]: ALL_script_no_subscripts
// ======================================================================

static const uint8_t EXPECTED_HASH_TC4_ALL_SCRIPT_NO_SUBSCRIPTS[SCRIPT_HASH_LENGTH] = {
    0xd4, 0x41, 0x22, 0x75, 0x53, 0xa0, 0xf1, 0xa9,
    0x65, 0xfe, 0xe7, 0xd6, 0x0a, 0x0f, 0x72, 0x4b,
    0x36, 0x8d, 0xd1, 0xbd, 0xdb, 0xc2, 0x08, 0x73,
    0x0f, 0xcc, 0xeb, 0xcf,
};

// ALL (internal node): 0 children
static const native_script_t* CHILDREN_TC4_ALL_SCRIPT_NO_SUBSCRIPTS_C0[] = {
    NULL
};

static const native_script_t SCRIPT_TC4_ALL_SCRIPT_NO_SUBSCRIPTS_C0 = {
    .type = NATIVE_SCRIPT_TYPE_ALL,
    .impl = {
        .complex = {
             .params = {
                 .all = {
                     .scripts = CHILDREN_TC4_ALL_SCRIPT_NO_SUBSCRIPTS_C0,
                     .scripts_count = 0,
                 }
             }
         }
     }
};

// APDU payload for P1_NATIVE_SCRIPT_FINISH
// Display format: BECH32 (0x01)
static const uint8_t FINISH_APDU_PAYLOAD_TC4_ALL_SCRIPT_NO_SUBSCRIPTS[1] = {
    0x01
};

// ======================================================================
// Test Case [5]: ANY_script
// ======================================================================

static const uint8_t EXPECTED_HASH_TC5_ANY_SCRIPT[SCRIPT_HASH_LENGTH] = {
    0xd6, 0x42, 0x8e, 0xc3, 0x67, 0x19, 0x14, 0x6b,
    0x7b, 0x5f, 0xb3, 0xa2, 0xd5, 0x32, 0x2c, 0xe7,
    0x02, 0xd3, 0x27, 0x62, 0xb8, 0xc7, 0xee, 0xeb,
    0x79, 0x7a, 0x20, 0xdb,
};

// ANY (internal node): 2 children
// APDU payload for P1_NATIVE_SCRIPT_ADD_SIMPLE
// Script type: PUBKEY_THIRD_PARTY
static const uint8_t APDU_PAYLOAD_TC5_ANY_SCRIPT_C0_C0[30] = {
    0x00, 0x00, 0xc4, 0xb9, 0x26, 0x56, 0x45, 0xfd,
    0xe9, 0x53, 0x6c, 0x07, 0x95, 0xad, 0xbc, 0xc5,
    0x29, 0x17, 0x67, 0xa0, 0xc6, 0x1f, 0xd6, 0x24,
    0x48, 0x34, 0x1d, 0x7e, 0x03, 0x86
};

static const native_script_t SCRIPT_TC5_ANY_SCRIPT_C0_C0 = {
    .type = NATIVE_SCRIPT_TYPE_PUBKEY_THIRD_PARTY,
    .impl = {
        .simple = {
            .apdu_payload = APDU_PAYLOAD_TC5_ANY_SCRIPT_C0_C0,
            .apdu_payload_length = sizeof(APDU_PAYLOAD_TC5_ANY_SCRIPT_C0_C0),
        }
    }
};


// APDU payload for P1_NATIVE_SCRIPT_ADD_SIMPLE
// Script type: PUBKEY_THIRD_PARTY
static const uint8_t APDU_PAYLOAD_TC5_ANY_SCRIPT_C0_C1[30] = {
    0x00, 0x00, 0x02, 0x41, 0xf2, 0xd1, 0x96, 0xf5,
    0x2a, 0x92, 0xfb, 0xd2, 0x18, 0x3d, 0x03, 0xb3,
    0x70, 0xc3, 0x0b, 0x69, 0x60, 0xcf, 0xde, 0xae,
    0x36, 0x4f, 0xfa, 0xba, 0xc8, 0x89
};

static const native_script_t SCRIPT_TC5_ANY_SCRIPT_C0_C1 = {
    .type = NATIVE_SCRIPT_TYPE_PUBKEY_THIRD_PARTY,
    .impl = {
        .simple = {
            .apdu_payload = APDU_PAYLOAD_TC5_ANY_SCRIPT_C0_C1,
            .apdu_payload_length = sizeof(APDU_PAYLOAD_TC5_ANY_SCRIPT_C0_C1),
        }
    }
};


static const native_script_t* CHILDREN_TC5_ANY_SCRIPT_C0[] = {
    (const native_script_t*)&SCRIPT_TC5_ANY_SCRIPT_C0_C0,
    (const native_script_t*)&SCRIPT_TC5_ANY_SCRIPT_C0_C1,
};

static const native_script_t SCRIPT_TC5_ANY_SCRIPT_C0 = {
    .type = NATIVE_SCRIPT_TYPE_ANY,
    .impl = {
        .complex = {
             .params = {
                 .any = {
                     .scripts = CHILDREN_TC5_ANY_SCRIPT_C0,
                     .scripts_count = 2,
                 }
             }
         }
     }
};

// APDU payload for P1_NATIVE_SCRIPT_FINISH
// Display format: BECH32 (0x01)
static const uint8_t FINISH_APDU_PAYLOAD_TC5_ANY_SCRIPT[1] = {
    0x01
};

// ======================================================================
// Test Case [6]: ANY_script_no_subscripts
// ======================================================================

static const uint8_t EXPECTED_HASH_TC6_ANY_SCRIPT_NO_SUBSCRIPTS[SCRIPT_HASH_LENGTH] = {
    0x52, 0xdc, 0x3d, 0x43, 0xb6, 0xd2, 0x46, 0x5e,
    0x96, 0x10, 0x9c, 0xe7, 0x5a, 0xb6, 0x1a, 0xbe,
    0x5e, 0x9c, 0x1d, 0x8a, 0x3c, 0x9c, 0xe6, 0xff,
    0x8a, 0x3a, 0xf5, 0x28,
};

// ANY (internal node): 0 children
static const native_script_t* CHILDREN_TC6_ANY_SCRIPT_NO_SUBSCRIPTS_C0[] = {
    NULL
};

static const native_script_t SCRIPT_TC6_ANY_SCRIPT_NO_SUBSCRIPTS_C0 = {
    .type = NATIVE_SCRIPT_TYPE_ANY,
    .impl = {
        .complex = {
             .params = {
                 .any = {
                     .scripts = CHILDREN_TC6_ANY_SCRIPT_NO_SUBSCRIPTS_C0,
                     .scripts_count = 0,
                 }
             }
         }
     }
};

// APDU payload for P1_NATIVE_SCRIPT_FINISH
// Display format: BECH32 (0x01)
static const uint8_t FINISH_APDU_PAYLOAD_TC6_ANY_SCRIPT_NO_SUBSCRIPTS[1] = {
    0x01
};

// ======================================================================
// Test Case [7]: N_OF_K_script
// ======================================================================

static const uint8_t EXPECTED_HASH_TC7_N_OF_K_SCRIPT[SCRIPT_HASH_LENGTH] = {
    0x78, 0x96, 0x3f, 0x8b, 0xaf, 0x8e, 0x6c, 0x99,
    0xed, 0x03, 0xe5, 0x97, 0x63, 0xb2, 0x4c, 0xf5,
    0x60, 0xbf, 0x12, 0x93, 0x4e, 0xc3, 0x79, 0x3e,
    0xba, 0x83, 0x37, 0x7b,
};

// N_OF_K (internal node): 2 of 2 children required
// APDU payload for P1_NATIVE_SCRIPT_ADD_SIMPLE
// Script type: PUBKEY_THIRD_PARTY
static const uint8_t APDU_PAYLOAD_TC7_N_OF_K_SCRIPT_C0_C0[30] = {
    0x00, 0x00, 0xc4, 0xb9, 0x26, 0x56, 0x45, 0xfd,
    0xe9, 0x53, 0x6c, 0x07, 0x95, 0xad, 0xbc, 0xc5,
    0x29, 0x17, 0x67, 0xa0, 0xc6, 0x1f, 0xd6, 0x24,
    0x48, 0x34, 0x1d, 0x7e, 0x03, 0x86
};

static const native_script_t SCRIPT_TC7_N_OF_K_SCRIPT_C0_C0 = {
    .type = NATIVE_SCRIPT_TYPE_PUBKEY_THIRD_PARTY,
    .impl = {
        .simple = {
            .apdu_payload = APDU_PAYLOAD_TC7_N_OF_K_SCRIPT_C0_C0,
            .apdu_payload_length = sizeof(APDU_PAYLOAD_TC7_N_OF_K_SCRIPT_C0_C0),
        }
    }
};


// APDU payload for P1_NATIVE_SCRIPT_ADD_SIMPLE
// Script type: PUBKEY_THIRD_PARTY
static const uint8_t APDU_PAYLOAD_TC7_N_OF_K_SCRIPT_C0_C1[30] = {
    0x00, 0x00, 0x02, 0x41, 0xf2, 0xd1, 0x96, 0xf5,
    0x2a, 0x92, 0xfb, 0xd2, 0x18, 0x3d, 0x03, 0xb3,
    0x70, 0xc3, 0x0b, 0x69, 0x60, 0xcf, 0xde, 0xae,
    0x36, 0x4f, 0xfa, 0xba, 0xc8, 0x89
};

static const native_script_t SCRIPT_TC7_N_OF_K_SCRIPT_C0_C1 = {
    .type = NATIVE_SCRIPT_TYPE_PUBKEY_THIRD_PARTY,
    .impl = {
        .simple = {
            .apdu_payload = APDU_PAYLOAD_TC7_N_OF_K_SCRIPT_C0_C1,
            .apdu_payload_length = sizeof(APDU_PAYLOAD_TC7_N_OF_K_SCRIPT_C0_C1),
        }
    }
};


static const native_script_t* CHILDREN_TC7_N_OF_K_SCRIPT_C0[] = {
    (const native_script_t*)&SCRIPT_TC7_N_OF_K_SCRIPT_C0_C0,
    (const native_script_t*)&SCRIPT_TC7_N_OF_K_SCRIPT_C0_C1,
};

static const native_script_t SCRIPT_TC7_N_OF_K_SCRIPT_C0 = {
    .type = NATIVE_SCRIPT_TYPE_N_OF_K,
    .impl = {
        .complex = {
            .params = {
                 .n_of_k = {
                     .required_count = 2,
                     .scripts = CHILDREN_TC7_N_OF_K_SCRIPT_C0,
                     .scripts_count = 2,
                 }
            }
        }
    }
};

// APDU payload for P1_NATIVE_SCRIPT_FINISH
// Display format: BECH32 (0x01)
static const uint8_t FINISH_APDU_PAYLOAD_TC7_N_OF_K_SCRIPT[1] = {
    0x01
};

// ======================================================================
// Test Case [8]: N_OF_K_script_no_subscripts
// ======================================================================

static const uint8_t EXPECTED_HASH_TC8_N_OF_K_SCRIPT_NO_SUBSCRIPTS[SCRIPT_HASH_LENGTH] = {
    0x35, 0x30, 0xcc, 0x9a, 0xe7, 0xf2, 0x89, 0x51,
    0x11, 0xa9, 0x9b, 0x7a, 0x02, 0x18, 0x4d, 0xd7,
    0xc0, 0xce, 0xa7, 0x42, 0x4f, 0x16, 0x32, 0xd7,
    0x39, 0x51, 0xb1, 0xd7,
};

// N_OF_K (internal node): 0 of 0 children required
static const native_script_t* CHILDREN_TC8_N_OF_K_SCRIPT_NO_SUBSCRIPTS_C0[] = {
    NULL
};

static const native_script_t SCRIPT_TC8_N_OF_K_SCRIPT_NO_SUBSCRIPTS_C0 = {
    .type = NATIVE_SCRIPT_TYPE_N_OF_K,
    .impl = {
        .complex = {
            .params = {
                 .n_of_k = {
                     .required_count = 0,
                     .scripts = CHILDREN_TC8_N_OF_K_SCRIPT_NO_SUBSCRIPTS_C0,
                     .scripts_count = 0,
                 }
            }
        }
    }
};

// APDU payload for P1_NATIVE_SCRIPT_FINISH
// Display format: BECH32 (0x01)
static const uint8_t FINISH_APDU_PAYLOAD_TC8_N_OF_K_SCRIPT_NO_SUBSCRIPTS[1] = {
    0x01
};

// ======================================================================
// Test Case [9]: INVALID_BEFORE_script
// ======================================================================

static const uint8_t EXPECTED_HASH_TC9_INVALID_BEFORE_SCRIPT[SCRIPT_HASH_LENGTH] = {
    0x2a, 0x25, 0xe6, 0x08, 0xa6, 0x83, 0x05, 0x7e,
    0x32, 0xea, 0x38, 0xb5, 0x0c, 0xe8, 0x87, 0x5d,
    0x5b, 0x34, 0x49, 0x6b, 0x39, 0x3d, 0xa8, 0xd2,
    0x5d, 0x31, 0x4c, 0x4e,
};

// APDU payload for P1_NATIVE_SCRIPT_ADD_SIMPLE
// Script type: INVALID_BEFORE
static const uint8_t APDU_PAYLOAD_TC9_INVALID_BEFORE_SCRIPT_C0[9] = {
    0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x2a
};

static const native_script_t SCRIPT_TC9_INVALID_BEFORE_SCRIPT_C0 = {
    .type = NATIVE_SCRIPT_TYPE_INVALID_BEFORE,
    .impl = {
        .simple = {
            .apdu_payload = APDU_PAYLOAD_TC9_INVALID_BEFORE_SCRIPT_C0,
            .apdu_payload_length = sizeof(APDU_PAYLOAD_TC9_INVALID_BEFORE_SCRIPT_C0),
        }
    }
};


// APDU payload for P1_NATIVE_SCRIPT_FINISH
// Display format: BECH32 (0x01)
static const uint8_t FINISH_APDU_PAYLOAD_TC9_INVALID_BEFORE_SCRIPT[1] = {
    0x01
};

// ======================================================================
// Test Case [10]: INVALID_BEFORE_script_slot_is_a_big_number
// ======================================================================

static const uint8_t EXPECTED_HASH_TC10_INVALID_BEFORE_SCRIPT_SLOT_IS_A_BIG_NUMBER[SCRIPT_HASH_LENGTH] = {
    0xd2, 0x46, 0x9a, 0xda, 0xc4, 0x94, 0x84, 0x9d,
    0xd2, 0x7d, 0x1b, 0x34, 0x4b, 0x74, 0xcc, 0x6c,
    0xd5, 0xbf, 0x31, 0xfb, 0xd0, 0x1c, 0x87, 0x9e,
    0xae, 0x84, 0xc0, 0x4b,
};

// APDU payload for P1_NATIVE_SCRIPT_ADD_SIMPLE
// Script type: INVALID_BEFORE
static const uint8_t APDU_PAYLOAD_TC10_INVALID_BEFORE_SCRIPT_SLOT_IS_A_BIG_NUMBER_C0[9] = {
    0x04, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff
};

static const native_script_t SCRIPT_TC10_INVALID_BEFORE_SCRIPT_SLOT_IS_A_BIG_NUMBER_C0 = {
    .type = NATIVE_SCRIPT_TYPE_INVALID_BEFORE,
    .impl = {
        .simple = {
            .apdu_payload = APDU_PAYLOAD_TC10_INVALID_BEFORE_SCRIPT_SLOT_IS_A_BIG_NUMBER_C0,
            .apdu_payload_length = sizeof(APDU_PAYLOAD_TC10_INVALID_BEFORE_SCRIPT_SLOT_IS_A_BIG_NUMBER_C0),
        }
    }
};


// APDU payload for P1_NATIVE_SCRIPT_FINISH
// Display format: BECH32 (0x01)
static const uint8_t FINISH_APDU_PAYLOAD_TC10_INVALID_BEFORE_SCRIPT_SLOT_IS_A_BIG_NUMBER[1] = {
    0x01
};

// ======================================================================
// Test Case [11]: INVALID_HEREAFTER_script
// ======================================================================

static const uint8_t EXPECTED_HASH_TC11_INVALID_HEREAFTER_SCRIPT[SCRIPT_HASH_LENGTH] = {
    0x16, 0x20, 0xdc, 0x65, 0x99, 0x32, 0x96, 0x33,
    0x51, 0x83, 0xf2, 0x3f, 0xf2, 0xf7, 0x74, 0x72,
    0x68, 0x16, 0x8f, 0xab, 0xbe, 0xec, 0xbf, 0x24,
    0xc8, 0xa2, 0x01, 0x94,
};

// APDU payload for P1_NATIVE_SCRIPT_ADD_SIMPLE
// Script type: INVALID_HEREAFTER
static const uint8_t APDU_PAYLOAD_TC11_INVALID_HEREAFTER_SCRIPT_C0[9] = {
    0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x2a
};

static const native_script_t SCRIPT_TC11_INVALID_HEREAFTER_SCRIPT_C0 = {
    .type = NATIVE_SCRIPT_TYPE_INVALID_HEREAFTER,
    .impl = {
        .simple = {
            .apdu_payload = APDU_PAYLOAD_TC11_INVALID_HEREAFTER_SCRIPT_C0,
            .apdu_payload_length = sizeof(APDU_PAYLOAD_TC11_INVALID_HEREAFTER_SCRIPT_C0),
        }
    }
};


// APDU payload for P1_NATIVE_SCRIPT_FINISH
// Display format: BECH32 (0x01)
static const uint8_t FINISH_APDU_PAYLOAD_TC11_INVALID_HEREAFTER_SCRIPT[1] = {
    0x01
};

// ======================================================================
// Test Case [12]: INVALID_HEREAFTER_script_slot_is_a_big_number
// ======================================================================

static const uint8_t EXPECTED_HASH_TC12_INVALID_HEREAFTER_SCRIPT_SLOT_IS_A_BIG_NUMBER[SCRIPT_HASH_LENGTH] = {
    0xda, 0x60, 0xfa, 0x40, 0x29, 0x0f, 0x93, 0xb8,
    0x89, 0xa8, 0x87, 0x50, 0xeb, 0x14, 0x1f, 0xd2,
    0x27, 0x5e, 0x67, 0xa1, 0x25, 0x5e, 0xfb, 0x9b,
    0xac, 0x25, 0x10, 0x05,
};

// APDU payload for P1_NATIVE_SCRIPT_ADD_SIMPLE
// Script type: INVALID_HEREAFTER
static const uint8_t APDU_PAYLOAD_TC12_INVALID_HEREAFTER_SCRIPT_SLOT_IS_A_BIG_NUMBER_C0[9] = {
    0x05, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff
};

static const native_script_t SCRIPT_TC12_INVALID_HEREAFTER_SCRIPT_SLOT_IS_A_BIG_NUMBER_C0 = {
    .type = NATIVE_SCRIPT_TYPE_INVALID_HEREAFTER,
    .impl = {
        .simple = {
            .apdu_payload = APDU_PAYLOAD_TC12_INVALID_HEREAFTER_SCRIPT_SLOT_IS_A_BIG_NUMBER_C0,
            .apdu_payload_length = sizeof(APDU_PAYLOAD_TC12_INVALID_HEREAFTER_SCRIPT_SLOT_IS_A_BIG_NUMBER_C0),
        }
    }
};


// APDU payload for P1_NATIVE_SCRIPT_FINISH
// Display format: BECH32 (0x01)
static const uint8_t FINISH_APDU_PAYLOAD_TC12_INVALID_HEREAFTER_SCRIPT_SLOT_IS_A_BIG_NUMBER[1] = {
    0x01
};

// ======================================================================
// Test Case [13]: Nested_native_scripts
// ======================================================================

static const uint8_t EXPECTED_HASH_TC13_NESTED_NATIVE_SCRIPTS[SCRIPT_HASH_LENGTH] = {
    0x0d, 0x63, 0xe8, 0xd2, 0xc5, 0xa0, 0x0c, 0xbc,
    0xff, 0xbd, 0xf9, 0x11, 0x24, 0x87, 0xc4, 0x43,
    0x46, 0x6e, 0x1e, 0xa7, 0xd8, 0xc8, 0x34, 0xdf,
    0x5a, 0xc5, 0xc4, 0x25,
};

// ALL (internal node): 5 children
// APDU payload for P1_NATIVE_SCRIPT_ADD_SIMPLE
// Script type: PUBKEY_THIRD_PARTY
static const uint8_t APDU_PAYLOAD_TC13_NESTED_NATIVE_SCRIPTS_C0_C0[30] = {
    0x00, 0x00, 0xc4, 0xb9, 0x26, 0x56, 0x45, 0xfd,
    0xe9, 0x53, 0x6c, 0x07, 0x95, 0xad, 0xbc, 0xc5,
    0x29, 0x17, 0x67, 0xa0, 0xc6, 0x1f, 0xd6, 0x24,
    0x48, 0x34, 0x1d, 0x7e, 0x03, 0x86
};

static const native_script_t SCRIPT_TC13_NESTED_NATIVE_SCRIPTS_C0_C0 = {
    .type = NATIVE_SCRIPT_TYPE_PUBKEY_THIRD_PARTY,
    .impl = {
        .simple = {
            .apdu_payload = APDU_PAYLOAD_TC13_NESTED_NATIVE_SCRIPTS_C0_C0,
            .apdu_payload_length = sizeof(APDU_PAYLOAD_TC13_NESTED_NATIVE_SCRIPTS_C0_C0),
        }
    }
};


// ANY (internal node): 2 children
// APDU payload for P1_NATIVE_SCRIPT_ADD_SIMPLE
// Script type: PUBKEY_THIRD_PARTY
static const uint8_t APDU_PAYLOAD_TC13_NESTED_NATIVE_SCRIPTS_C0_C1_C0[30] = {
    0x00, 0x00, 0xc4, 0xb9, 0x26, 0x56, 0x45, 0xfd,
    0xe9, 0x53, 0x6c, 0x07, 0x95, 0xad, 0xbc, 0xc5,
    0x29, 0x17, 0x67, 0xa0, 0xc6, 0x1f, 0xd6, 0x24,
    0x48, 0x34, 0x1d, 0x7e, 0x03, 0x86
};

static const native_script_t SCRIPT_TC13_NESTED_NATIVE_SCRIPTS_C0_C1_C0 = {
    .type = NATIVE_SCRIPT_TYPE_PUBKEY_THIRD_PARTY,
    .impl = {
        .simple = {
            .apdu_payload = APDU_PAYLOAD_TC13_NESTED_NATIVE_SCRIPTS_C0_C1_C0,
            .apdu_payload_length = sizeof(APDU_PAYLOAD_TC13_NESTED_NATIVE_SCRIPTS_C0_C1_C0),
        }
    }
};


// APDU payload for P1_NATIVE_SCRIPT_ADD_SIMPLE
// Script type: PUBKEY_THIRD_PARTY
static const uint8_t APDU_PAYLOAD_TC13_NESTED_NATIVE_SCRIPTS_C0_C1_C1[30] = {
    0x00, 0x00, 0x02, 0x41, 0xf2, 0xd1, 0x96, 0xf5,
    0x2a, 0x92, 0xfb, 0xd2, 0x18, 0x3d, 0x03, 0xb3,
    0x70, 0xc3, 0x0b, 0x69, 0x60, 0xcf, 0xde, 0xae,
    0x36, 0x4f, 0xfa, 0xba, 0xc8, 0x89
};

static const native_script_t SCRIPT_TC13_NESTED_NATIVE_SCRIPTS_C0_C1_C1 = {
    .type = NATIVE_SCRIPT_TYPE_PUBKEY_THIRD_PARTY,
    .impl = {
        .simple = {
            .apdu_payload = APDU_PAYLOAD_TC13_NESTED_NATIVE_SCRIPTS_C0_C1_C1,
            .apdu_payload_length = sizeof(APDU_PAYLOAD_TC13_NESTED_NATIVE_SCRIPTS_C0_C1_C1),
        }
    }
};


static const native_script_t* CHILDREN_TC13_NESTED_NATIVE_SCRIPTS_C0_C1[] = {
    (const native_script_t*)&SCRIPT_TC13_NESTED_NATIVE_SCRIPTS_C0_C1_C0,
    (const native_script_t*)&SCRIPT_TC13_NESTED_NATIVE_SCRIPTS_C0_C1_C1,
};

static const native_script_t SCRIPT_TC13_NESTED_NATIVE_SCRIPTS_C0_C1 = {
    .type = NATIVE_SCRIPT_TYPE_ANY,
    .impl = {
        .complex = {
             .params = {
                 .any = {
                     .scripts = CHILDREN_TC13_NESTED_NATIVE_SCRIPTS_C0_C1,
                     .scripts_count = 2,
                 }
             }
         }
     }
};

// N_OF_K (internal node): 2 of 3 children required
// APDU payload for P1_NATIVE_SCRIPT_ADD_SIMPLE
// Script type: PUBKEY_THIRD_PARTY
static const uint8_t APDU_PAYLOAD_TC13_NESTED_NATIVE_SCRIPTS_C0_C2_C0[30] = {
    0x00, 0x00, 0xc4, 0xb9, 0x26, 0x56, 0x45, 0xfd,
    0xe9, 0x53, 0x6c, 0x07, 0x95, 0xad, 0xbc, 0xc5,
    0x29, 0x17, 0x67, 0xa0, 0xc6, 0x1f, 0xd6, 0x24,
    0x48, 0x34, 0x1d, 0x7e, 0x03, 0x86
};

static const native_script_t SCRIPT_TC13_NESTED_NATIVE_SCRIPTS_C0_C2_C0 = {
    .type = NATIVE_SCRIPT_TYPE_PUBKEY_THIRD_PARTY,
    .impl = {
        .simple = {
            .apdu_payload = APDU_PAYLOAD_TC13_NESTED_NATIVE_SCRIPTS_C0_C2_C0,
            .apdu_payload_length = sizeof(APDU_PAYLOAD_TC13_NESTED_NATIVE_SCRIPTS_C0_C2_C0),
        }
    }
};


// APDU payload for P1_NATIVE_SCRIPT_ADD_SIMPLE
// Script type: PUBKEY_THIRD_PARTY
static const uint8_t APDU_PAYLOAD_TC13_NESTED_NATIVE_SCRIPTS_C0_C2_C1[30] = {
    0x00, 0x00, 0x02, 0x41, 0xf2, 0xd1, 0x96, 0xf5,
    0x2a, 0x92, 0xfb, 0xd2, 0x18, 0x3d, 0x03, 0xb3,
    0x70, 0xc3, 0x0b, 0x69, 0x60, 0xcf, 0xde, 0xae,
    0x36, 0x4f, 0xfa, 0xba, 0xc8, 0x89
};

static const native_script_t SCRIPT_TC13_NESTED_NATIVE_SCRIPTS_C0_C2_C1 = {
    .type = NATIVE_SCRIPT_TYPE_PUBKEY_THIRD_PARTY,
    .impl = {
        .simple = {
            .apdu_payload = APDU_PAYLOAD_TC13_NESTED_NATIVE_SCRIPTS_C0_C2_C1,
            .apdu_payload_length = sizeof(APDU_PAYLOAD_TC13_NESTED_NATIVE_SCRIPTS_C0_C2_C1),
        }
    }
};


// APDU payload for P1_NATIVE_SCRIPT_ADD_SIMPLE
// Script type: PUBKEY_THIRD_PARTY
static const uint8_t APDU_PAYLOAD_TC13_NESTED_NATIVE_SCRIPTS_C0_C2_C2[30] = {
    0x00, 0x00, 0xce, 0xcb, 0x1d, 0x42, 0x7c, 0x4a,
    0xe4, 0x36, 0xd2, 0x8c, 0xc0, 0xf8, 0xae, 0x9b,
    0xb3, 0x75, 0x01, 0xa5, 0xb7, 0x7b, 0xcc, 0x64,
    0xcd, 0x16, 0x93, 0xe9, 0xae, 0x20
};

static const native_script_t SCRIPT_TC13_NESTED_NATIVE_SCRIPTS_C0_C2_C2 = {
    .type = NATIVE_SCRIPT_TYPE_PUBKEY_THIRD_PARTY,
    .impl = {
        .simple = {
            .apdu_payload = APDU_PAYLOAD_TC13_NESTED_NATIVE_SCRIPTS_C0_C2_C2,
            .apdu_payload_length = sizeof(APDU_PAYLOAD_TC13_NESTED_NATIVE_SCRIPTS_C0_C2_C2),
        }
    }
};


static const native_script_t* CHILDREN_TC13_NESTED_NATIVE_SCRIPTS_C0_C2[] = {
    (const native_script_t*)&SCRIPT_TC13_NESTED_NATIVE_SCRIPTS_C0_C2_C0,
    (const native_script_t*)&SCRIPT_TC13_NESTED_NATIVE_SCRIPTS_C0_C2_C1,
    (const native_script_t*)&SCRIPT_TC13_NESTED_NATIVE_SCRIPTS_C0_C2_C2,
};

static const native_script_t SCRIPT_TC13_NESTED_NATIVE_SCRIPTS_C0_C2 = {
    .type = NATIVE_SCRIPT_TYPE_N_OF_K,
    .impl = {
        .complex = {
            .params = {
                 .n_of_k = {
                     .required_count = 2,
                     .scripts = CHILDREN_TC13_NESTED_NATIVE_SCRIPTS_C0_C2,
                     .scripts_count = 3,
                 }
            }
        }
    }
};

// APDU payload for P1_NATIVE_SCRIPT_ADD_SIMPLE
// Script type: INVALID_BEFORE
static const uint8_t APDU_PAYLOAD_TC13_NESTED_NATIVE_SCRIPTS_C0_C3[9] = {
    0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x64
};

static const native_script_t SCRIPT_TC13_NESTED_NATIVE_SCRIPTS_C0_C3 = {
    .type = NATIVE_SCRIPT_TYPE_INVALID_BEFORE,
    .impl = {
        .simple = {
            .apdu_payload = APDU_PAYLOAD_TC13_NESTED_NATIVE_SCRIPTS_C0_C3,
            .apdu_payload_length = sizeof(APDU_PAYLOAD_TC13_NESTED_NATIVE_SCRIPTS_C0_C3),
        }
    }
};


// APDU payload for P1_NATIVE_SCRIPT_ADD_SIMPLE
// Script type: INVALID_HEREAFTER
static const uint8_t APDU_PAYLOAD_TC13_NESTED_NATIVE_SCRIPTS_C0_C4[9] = {
    0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xc8
};

static const native_script_t SCRIPT_TC13_NESTED_NATIVE_SCRIPTS_C0_C4 = {
    .type = NATIVE_SCRIPT_TYPE_INVALID_HEREAFTER,
    .impl = {
        .simple = {
            .apdu_payload = APDU_PAYLOAD_TC13_NESTED_NATIVE_SCRIPTS_C0_C4,
            .apdu_payload_length = sizeof(APDU_PAYLOAD_TC13_NESTED_NATIVE_SCRIPTS_C0_C4),
        }
    }
};


static const native_script_t* CHILDREN_TC13_NESTED_NATIVE_SCRIPTS_C0[] = {
    (const native_script_t*)&SCRIPT_TC13_NESTED_NATIVE_SCRIPTS_C0_C0,
    (const native_script_t*)&SCRIPT_TC13_NESTED_NATIVE_SCRIPTS_C0_C1,
    (const native_script_t*)&SCRIPT_TC13_NESTED_NATIVE_SCRIPTS_C0_C2,
    (const native_script_t*)&SCRIPT_TC13_NESTED_NATIVE_SCRIPTS_C0_C3,
    (const native_script_t*)&SCRIPT_TC13_NESTED_NATIVE_SCRIPTS_C0_C4,
};

static const native_script_t SCRIPT_TC13_NESTED_NATIVE_SCRIPTS_C0 = {
    .type = NATIVE_SCRIPT_TYPE_ALL,
    .impl = {
        .complex = {
             .params = {
                 .all = {
                     .scripts = CHILDREN_TC13_NESTED_NATIVE_SCRIPTS_C0,
                     .scripts_count = 5,
                 }
             }
         }
     }
};

// APDU payload for P1_NATIVE_SCRIPT_FINISH
// Display format: BECH32 (0x01)
static const uint8_t FINISH_APDU_PAYLOAD_TC13_NESTED_NATIVE_SCRIPTS[1] = {
    0x01
};

// ======================================================================
// Test Case [14]: Nested native scripts #2
// ======================================================================

static const uint8_t EXPECTED_HASH_TC14_NESTED_NATIVE_SCRIPTS_NUM2[SCRIPT_HASH_LENGTH] = {
    0x90, 0x3e, 0x52, 0xef, 0x24, 0x21, 0xab, 0xb1,
    0x15, 0x62, 0x32, 0x91, 0x30, 0x33, 0x07, 0x63,
    0x58, 0x3b, 0xb8, 0x7c, 0xd9, 0x80, 0x06, 0xb7,
    0x0e, 0xcb, 0x1b, 0x1c,
};

// ALL (internal node): 1 children
// ANY (internal node): 2 children
// APDU payload for P1_NATIVE_SCRIPT_ADD_SIMPLE
// Script type: PUBKEY_THIRD_PARTY
static const uint8_t APDU_PAYLOAD_TC14_NESTED_NATIVE_SCRIPTS_NUM2_C0_C0_C0[30] = {
    0x00, 0x00, 0xc4, 0xb9, 0x26, 0x56, 0x45, 0xfd,
    0xe9, 0x53, 0x6c, 0x07, 0x95, 0xad, 0xbc, 0xc5,
    0x29, 0x17, 0x67, 0xa0, 0xc6, 0x1f, 0xd6, 0x24,
    0x48, 0x34, 0x1d, 0x7e, 0x03, 0x86
};

static const native_script_t SCRIPT_TC14_NESTED_NATIVE_SCRIPTS_NUM2_C0_C0_C0 = {
    .type = NATIVE_SCRIPT_TYPE_PUBKEY_THIRD_PARTY,
    .impl = {
        .simple = {
            .apdu_payload = APDU_PAYLOAD_TC14_NESTED_NATIVE_SCRIPTS_NUM2_C0_C0_C0,
            .apdu_payload_length = sizeof(APDU_PAYLOAD_TC14_NESTED_NATIVE_SCRIPTS_NUM2_C0_C0_C0),
        }
    }
};


// APDU payload for P1_NATIVE_SCRIPT_ADD_SIMPLE
// Script type: PUBKEY_THIRD_PARTY
static const uint8_t APDU_PAYLOAD_TC14_NESTED_NATIVE_SCRIPTS_NUM2_C0_C0_C1[30] = {
    0x00, 0x00, 0x02, 0x41, 0xf2, 0xd1, 0x96, 0xf5,
    0x2a, 0x92, 0xfb, 0xd2, 0x18, 0x3d, 0x03, 0xb3,
    0x70, 0xc3, 0x0b, 0x69, 0x60, 0xcf, 0xde, 0xae,
    0x36, 0x4f, 0xfa, 0xba, 0xc8, 0x89
};

static const native_script_t SCRIPT_TC14_NESTED_NATIVE_SCRIPTS_NUM2_C0_C0_C1 = {
    .type = NATIVE_SCRIPT_TYPE_PUBKEY_THIRD_PARTY,
    .impl = {
        .simple = {
            .apdu_payload = APDU_PAYLOAD_TC14_NESTED_NATIVE_SCRIPTS_NUM2_C0_C0_C1,
            .apdu_payload_length = sizeof(APDU_PAYLOAD_TC14_NESTED_NATIVE_SCRIPTS_NUM2_C0_C0_C1),
        }
    }
};


static const native_script_t* CHILDREN_TC14_NESTED_NATIVE_SCRIPTS_NUM2_C0_C0[] = {
    (const native_script_t*)&SCRIPT_TC14_NESTED_NATIVE_SCRIPTS_NUM2_C0_C0_C0,
    (const native_script_t*)&SCRIPT_TC14_NESTED_NATIVE_SCRIPTS_NUM2_C0_C0_C1,
};

static const native_script_t SCRIPT_TC14_NESTED_NATIVE_SCRIPTS_NUM2_C0_C0 = {
    .type = NATIVE_SCRIPT_TYPE_ANY,
    .impl = {
        .complex = {
             .params = {
                 .any = {
                     .scripts = CHILDREN_TC14_NESTED_NATIVE_SCRIPTS_NUM2_C0_C0,
                     .scripts_count = 2,
                 }
             }
         }
     }
};

static const native_script_t* CHILDREN_TC14_NESTED_NATIVE_SCRIPTS_NUM2_C0[] = {
    (const native_script_t*)&SCRIPT_TC14_NESTED_NATIVE_SCRIPTS_NUM2_C0_C0,
};

static const native_script_t SCRIPT_TC14_NESTED_NATIVE_SCRIPTS_NUM2_C0 = {
    .type = NATIVE_SCRIPT_TYPE_ALL,
    .impl = {
        .complex = {
             .params = {
                 .all = {
                     .scripts = CHILDREN_TC14_NESTED_NATIVE_SCRIPTS_NUM2_C0,
                     .scripts_count = 1,
                 }
             }
         }
     }
};

// APDU payload for P1_NATIVE_SCRIPT_FINISH
// Display format: BECH32 (0x01)
static const uint8_t FINISH_APDU_PAYLOAD_TC14_NESTED_NATIVE_SCRIPTS_NUM2[1] = {
    0x01
};

// ======================================================================
// Test Case [15]: Nested native scripts #3
// ======================================================================

static const uint8_t EXPECTED_HASH_TC15_NESTED_NATIVE_SCRIPTS_NUM3[SCRIPT_HASH_LENGTH] = {
    0xed, 0x1d, 0xd7, 0xef, 0x95, 0xca, 0xf3, 0x89,
    0x66, 0x9c, 0x62, 0x61, 0x8e, 0xb7, 0xf7, 0xaa,
    0x7e, 0xad, 0xd0, 0x8f, 0xeb, 0x76, 0x61, 0x8d,
    0xb2, 0xae, 0x0c, 0xfc,
};

// N_OF_K (internal node): 0 of 1 children required
// ALL (internal node): 1 children
// ANY (internal node): 1 children
// N_OF_K (internal node): 0 of 0 children required
static const native_script_t* CHILDREN_TC15_NESTED_NATIVE_SCRIPTS_NUM3_C0_C0_C0_C0[] = {
    NULL
};

static const native_script_t SCRIPT_TC15_NESTED_NATIVE_SCRIPTS_NUM3_C0_C0_C0_C0 = {
    .type = NATIVE_SCRIPT_TYPE_N_OF_K,
    .impl = {
        .complex = {
            .params = {
                 .n_of_k = {
                     .required_count = 0,
                     .scripts = CHILDREN_TC15_NESTED_NATIVE_SCRIPTS_NUM3_C0_C0_C0_C0,
                     .scripts_count = 0,
                 }
            }
        }
    }
};

static const native_script_t* CHILDREN_TC15_NESTED_NATIVE_SCRIPTS_NUM3_C0_C0_C0[] = {
    (const native_script_t*)&SCRIPT_TC15_NESTED_NATIVE_SCRIPTS_NUM3_C0_C0_C0_C0,
};

static const native_script_t SCRIPT_TC15_NESTED_NATIVE_SCRIPTS_NUM3_C0_C0_C0 = {
    .type = NATIVE_SCRIPT_TYPE_ANY,
    .impl = {
        .complex = {
             .params = {
                 .any = {
                     .scripts = CHILDREN_TC15_NESTED_NATIVE_SCRIPTS_NUM3_C0_C0_C0,
                     .scripts_count = 1,
                 }
             }
         }
     }
};

static const native_script_t* CHILDREN_TC15_NESTED_NATIVE_SCRIPTS_NUM3_C0_C0[] = {
    (const native_script_t*)&SCRIPT_TC15_NESTED_NATIVE_SCRIPTS_NUM3_C0_C0_C0,
};

static const native_script_t SCRIPT_TC15_NESTED_NATIVE_SCRIPTS_NUM3_C0_C0 = {
    .type = NATIVE_SCRIPT_TYPE_ALL,
    .impl = {
        .complex = {
             .params = {
                 .all = {
                     .scripts = CHILDREN_TC15_NESTED_NATIVE_SCRIPTS_NUM3_C0_C0,
                     .scripts_count = 1,
                 }
             }
         }
     }
};

static const native_script_t* CHILDREN_TC15_NESTED_NATIVE_SCRIPTS_NUM3_C0[] = {
    (const native_script_t*)&SCRIPT_TC15_NESTED_NATIVE_SCRIPTS_NUM3_C0_C0,
};

static const native_script_t SCRIPT_TC15_NESTED_NATIVE_SCRIPTS_NUM3_C0 = {
    .type = NATIVE_SCRIPT_TYPE_N_OF_K,
    .impl = {
        .complex = {
            .params = {
                 .n_of_k = {
                     .required_count = 0,
                     .scripts = CHILDREN_TC15_NESTED_NATIVE_SCRIPTS_NUM3_C0,
                     .scripts_count = 1,
                 }
            }
        }
    }
};

// APDU payload for P1_NATIVE_SCRIPT_FINISH
// Display format: BECH32 (0x01)
static const uint8_t FINISH_APDU_PAYLOAD_TC15_NESTED_NATIVE_SCRIPTS_NUM3[1] = {
    0x01
};

// ======================================================================
// Test Case Array
// ======================================================================

static const native_script_test_case_t NATIVE_SCRIPT_FIXTURES[] = {
    {
        .name = "PUBKEY_device_owned",
        .root_script = (const native_script_t*)&SCRIPT_TC0_PUBKEY_DEVICE_OWNED_C0,
        .expected_hash = EXPECTED_HASH_TC0_PUBKEY_DEVICE_OWNED,
        .nano_skip = false,
        .finish_apdu_payload = FINISH_APDU_PAYLOAD_TC0_PUBKEY_DEVICE_OWNED,
        .finish_apdu_payload_length = sizeof(FINISH_APDU_PAYLOAD_TC0_PUBKEY_DEVICE_OWNED),
    },
    {
        .name = "PUBKEY_third_party",
        .root_script = (const native_script_t*)&SCRIPT_TC1_PUBKEY_THIRD_PARTY_C0,
        .expected_hash = EXPECTED_HASH_TC1_PUBKEY_THIRD_PARTY,
        .nano_skip = false,
        .finish_apdu_payload = FINISH_APDU_PAYLOAD_TC1_PUBKEY_THIRD_PARTY,
        .finish_apdu_payload_length = sizeof(FINISH_APDU_PAYLOAD_TC1_PUBKEY_THIRD_PARTY),
    },
    {
        .name = "PUBKEY_third_party_script_hash_displayed_as_policy_id",
        .root_script = (const native_script_t*)&SCRIPT_TC2_PUBKEY_THIRD_PARTY_SCRIPT_HASH_DISPLAYED_AS_POLICY_ID_C0,
        .expected_hash = EXPECTED_HASH_TC2_PUBKEY_THIRD_PARTY_SCRIPT_HASH_DISPLAYED_AS_POLICY_ID,
        .nano_skip = false,
        .finish_apdu_payload = FINISH_APDU_PAYLOAD_TC2_PUBKEY_THIRD_PARTY_SCRIPT_HASH_DISPLAYED_AS_POLICY_ID,
        .finish_apdu_payload_length = sizeof(FINISH_APDU_PAYLOAD_TC2_PUBKEY_THIRD_PARTY_SCRIPT_HASH_DISPLAYED_AS_POLICY_ID),
    },
    {
        .name = "ALL_script",
        .root_script = (const native_script_t*)&SCRIPT_TC3_ALL_SCRIPT_C0,
        .expected_hash = EXPECTED_HASH_TC3_ALL_SCRIPT,
        .nano_skip = false,
        .finish_apdu_payload = FINISH_APDU_PAYLOAD_TC3_ALL_SCRIPT,
        .finish_apdu_payload_length = sizeof(FINISH_APDU_PAYLOAD_TC3_ALL_SCRIPT),
    },
    {
        .name = "ALL_script_no_subscripts",
        .root_script = (const native_script_t*)&SCRIPT_TC4_ALL_SCRIPT_NO_SUBSCRIPTS_C0,
        .expected_hash = EXPECTED_HASH_TC4_ALL_SCRIPT_NO_SUBSCRIPTS,
        .nano_skip = false,
        .finish_apdu_payload = FINISH_APDU_PAYLOAD_TC4_ALL_SCRIPT_NO_SUBSCRIPTS,
        .finish_apdu_payload_length = sizeof(FINISH_APDU_PAYLOAD_TC4_ALL_SCRIPT_NO_SUBSCRIPTS),
    },
    {
        .name = "ANY_script",
        .root_script = (const native_script_t*)&SCRIPT_TC5_ANY_SCRIPT_C0,
        .expected_hash = EXPECTED_HASH_TC5_ANY_SCRIPT,
        .nano_skip = false,
        .finish_apdu_payload = FINISH_APDU_PAYLOAD_TC5_ANY_SCRIPT,
        .finish_apdu_payload_length = sizeof(FINISH_APDU_PAYLOAD_TC5_ANY_SCRIPT),
    },
    {
        .name = "ANY_script_no_subscripts",
        .root_script = (const native_script_t*)&SCRIPT_TC6_ANY_SCRIPT_NO_SUBSCRIPTS_C0,
        .expected_hash = EXPECTED_HASH_TC6_ANY_SCRIPT_NO_SUBSCRIPTS,
        .nano_skip = false,
        .finish_apdu_payload = FINISH_APDU_PAYLOAD_TC6_ANY_SCRIPT_NO_SUBSCRIPTS,
        .finish_apdu_payload_length = sizeof(FINISH_APDU_PAYLOAD_TC6_ANY_SCRIPT_NO_SUBSCRIPTS),
    },
    {
        .name = "N_OF_K_script",
        .root_script = (const native_script_t*)&SCRIPT_TC7_N_OF_K_SCRIPT_C0,
        .expected_hash = EXPECTED_HASH_TC7_N_OF_K_SCRIPT,
        .nano_skip = false,
        .finish_apdu_payload = FINISH_APDU_PAYLOAD_TC7_N_OF_K_SCRIPT,
        .finish_apdu_payload_length = sizeof(FINISH_APDU_PAYLOAD_TC7_N_OF_K_SCRIPT),
    },
    {
        .name = "N_OF_K_script_no_subscripts",
        .root_script = (const native_script_t*)&SCRIPT_TC8_N_OF_K_SCRIPT_NO_SUBSCRIPTS_C0,
        .expected_hash = EXPECTED_HASH_TC8_N_OF_K_SCRIPT_NO_SUBSCRIPTS,
        .nano_skip = false,
        .finish_apdu_payload = FINISH_APDU_PAYLOAD_TC8_N_OF_K_SCRIPT_NO_SUBSCRIPTS,
        .finish_apdu_payload_length = sizeof(FINISH_APDU_PAYLOAD_TC8_N_OF_K_SCRIPT_NO_SUBSCRIPTS),
    },
    {
        .name = "INVALID_BEFORE_script",
        .root_script = (const native_script_t*)&SCRIPT_TC9_INVALID_BEFORE_SCRIPT_C0,
        .expected_hash = EXPECTED_HASH_TC9_INVALID_BEFORE_SCRIPT,
        .nano_skip = false,
        .finish_apdu_payload = FINISH_APDU_PAYLOAD_TC9_INVALID_BEFORE_SCRIPT,
        .finish_apdu_payload_length = sizeof(FINISH_APDU_PAYLOAD_TC9_INVALID_BEFORE_SCRIPT),
    },
    {
        .name = "INVALID_BEFORE_script_slot_is_a_big_number",
        .root_script = (const native_script_t*)&SCRIPT_TC10_INVALID_BEFORE_SCRIPT_SLOT_IS_A_BIG_NUMBER_C0,
        .expected_hash = EXPECTED_HASH_TC10_INVALID_BEFORE_SCRIPT_SLOT_IS_A_BIG_NUMBER,
        .nano_skip = false,
        .finish_apdu_payload = FINISH_APDU_PAYLOAD_TC10_INVALID_BEFORE_SCRIPT_SLOT_IS_A_BIG_NUMBER,
        .finish_apdu_payload_length = sizeof(FINISH_APDU_PAYLOAD_TC10_INVALID_BEFORE_SCRIPT_SLOT_IS_A_BIG_NUMBER),
    },
    {
        .name = "INVALID_HEREAFTER_script",
        .root_script = (const native_script_t*)&SCRIPT_TC11_INVALID_HEREAFTER_SCRIPT_C0,
        .expected_hash = EXPECTED_HASH_TC11_INVALID_HEREAFTER_SCRIPT,
        .nano_skip = false,
        .finish_apdu_payload = FINISH_APDU_PAYLOAD_TC11_INVALID_HEREAFTER_SCRIPT,
        .finish_apdu_payload_length = sizeof(FINISH_APDU_PAYLOAD_TC11_INVALID_HEREAFTER_SCRIPT),
    },
    {
        .name = "INVALID_HEREAFTER_script_slot_is_a_big_number",
        .root_script = (const native_script_t*)&SCRIPT_TC12_INVALID_HEREAFTER_SCRIPT_SLOT_IS_A_BIG_NUMBER_C0,
        .expected_hash = EXPECTED_HASH_TC12_INVALID_HEREAFTER_SCRIPT_SLOT_IS_A_BIG_NUMBER,
        .nano_skip = false,
        .finish_apdu_payload = FINISH_APDU_PAYLOAD_TC12_INVALID_HEREAFTER_SCRIPT_SLOT_IS_A_BIG_NUMBER,
        .finish_apdu_payload_length = sizeof(FINISH_APDU_PAYLOAD_TC12_INVALID_HEREAFTER_SCRIPT_SLOT_IS_A_BIG_NUMBER),
    },
    {
        .name = "Nested_native_scripts",
        .root_script = (const native_script_t*)&SCRIPT_TC13_NESTED_NATIVE_SCRIPTS_C0,
        .expected_hash = EXPECTED_HASH_TC13_NESTED_NATIVE_SCRIPTS,
        .nano_skip = true,
        .finish_apdu_payload = FINISH_APDU_PAYLOAD_TC13_NESTED_NATIVE_SCRIPTS,
        .finish_apdu_payload_length = sizeof(FINISH_APDU_PAYLOAD_TC13_NESTED_NATIVE_SCRIPTS),
    },
    {
        .name = "Nested native scripts #2",
        .root_script = (const native_script_t*)&SCRIPT_TC14_NESTED_NATIVE_SCRIPTS_NUM2_C0,
        .expected_hash = EXPECTED_HASH_TC14_NESTED_NATIVE_SCRIPTS_NUM2,
        .nano_skip = true,
        .finish_apdu_payload = FINISH_APDU_PAYLOAD_TC14_NESTED_NATIVE_SCRIPTS_NUM2,
        .finish_apdu_payload_length = sizeof(FINISH_APDU_PAYLOAD_TC14_NESTED_NATIVE_SCRIPTS_NUM2),
    },
    {
        .name = "Nested native scripts #3",
        .root_script = (const native_script_t*)&SCRIPT_TC15_NESTED_NATIVE_SCRIPTS_NUM3_C0,
        .expected_hash = EXPECTED_HASH_TC15_NESTED_NATIVE_SCRIPTS_NUM3,
        .nano_skip = true,
        .finish_apdu_payload = FINISH_APDU_PAYLOAD_TC15_NESTED_NATIVE_SCRIPTS_NUM3,
        .finish_apdu_payload_length = sizeof(FINISH_APDU_PAYLOAD_TC15_NESTED_NATIVE_SCRIPTS_NUM3),
    },
};

#define NATIVE_SCRIPT_FIXTURES_COUNT 16
