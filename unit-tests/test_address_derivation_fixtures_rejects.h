// Auto-generated address derivation rejection test fixtures
// Generated from ragger standalone test cases
//
// These tests verify that the device properly rejects invalid address
// derivation requests according to the security policy defined in
// src/securityPolicy.c
//
// Total rejection tests: 11

#pragma once

#include <stdint.h>
#include <stddef.h>
#include "test_fixture_types.h"
#include "cardano_swo.h"

#define P1_ADDRESS_RETURN  0x20
// ======================================================================
// Address Derivation Rejection Test Fixtures
// ======================================================================


// ----------------------------------------------------------------------
// Reject Test 1: path too short
// Expected rejection: SWO_SECURITY_CONDITION_NOT_SATISFIED
// Address Type: BYRON
// Spending: m/44'/1815'/1'
// ----------------------------------------------------------------------

static const uint8_t DERIVE_ADDRESS_REJECT_001_PATH_TOO_SHORT_APDU[] = {
    0x08, 0x2D, 0x96, 0x4A, 0x09, 0x03, 0x80, 0x00, 0x00, 0x2C, 0x80, 0x00, 0x07, 0x17, 0x80, 0x00,
    0x00, 0x01, 0x11,
};

// ----------------------------------------------------------------------
// Reject Test 2: invalid path
// Expected rejection: SWO_SECURITY_CONDITION_NOT_SATISFIED
// Address Type: BYRON
// Spending: m/44'/1815'/1'/5/10'
// ----------------------------------------------------------------------

static const uint8_t DERIVE_ADDRESS_REJECT_002_INVALID_PATH_APDU[] = {
    0x08, 0x2D, 0x96, 0x4A, 0x09, 0x05, 0x80, 0x00, 0x00, 0x2C, 0x80, 0x00, 0x07, 0x17, 0x80, 0x00,
    0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x80, 0x00, 0x00, 0x0A, 0x11,
};

// ----------------------------------------------------------------------
// Reject Test 3: Byron with Shelley path
// Expected rejection: SWO_SECURITY_CONDITION_NOT_SATISFIED
// Address Type: BYRON
// Spending: m/1852'/1815'/1'/0/10
// ----------------------------------------------------------------------

static const uint8_t DERIVE_ADDRESS_REJECT_003_BYRON_WITH_SHELLEY_PATH_APDU[] = {
    0x08, 0x2D, 0x96, 0x4A, 0x09, 0x05, 0x80, 0x00, 0x07, 0x3C, 0x80, 0x00, 0x07, 0x17, 0x80, 0x00,
    0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A, 0x11,
};

// ----------------------------------------------------------------------
// Reject Test 4: base key/key with Byron spending path
// Expected rejection: SWO_SECURITY_CONDITION_NOT_SATISFIED
// Address Type: BASE_PAYMENT_KEY_STAKE_KEY
// Spending: m/44'/1815'/1'/0/1
// Staking: m/1852'/1815'/1'/2/0
// ----------------------------------------------------------------------

static const uint8_t DERIVE_ADDRESS_REJECT_004_BASE_KEY_KEY_WITH_BYRON_SPENDING_PATH_APDU[] = {
    0x00, 0x01, 0x05, 0x80, 0x00, 0x00, 0x2C, 0x80, 0x00, 0x07, 0x17, 0x80, 0x00, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x22, 0x05, 0x80, 0x00, 0x07, 0x3C, 0x80, 0x00, 0x07,
    0x17, 0x80, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
};

// ----------------------------------------------------------------------
// Reject Test 5: base key/key with wrong spending path
// Expected rejection: SWO_SECURITY_CONDITION_NOT_SATISFIED
// Address Type: BASE_PAYMENT_KEY_STAKE_KEY
// Spending: m/1852'/1815'/1'/2/0
// Staking: m/1852'/1815'/1'/2/0
// ----------------------------------------------------------------------

static const uint8_t DERIVE_ADDRESS_REJECT_005_BASE_KEY_KEY_WITH_WRONG_SPENDING_PATH_APDU[] = {
    0x00, 0x01, 0x05, 0x80, 0x00, 0x07, 0x3C, 0x80, 0x00, 0x07, 0x17, 0x80, 0x00, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x22, 0x05, 0x80, 0x00, 0x07, 0x3C, 0x80, 0x00, 0x07,
    0x17, 0x80, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
};

// ----------------------------------------------------------------------
// Reject Test 6: base key/key with wrong staking path 1
// Expected rejection: SWO_SECURITY_CONDITION_NOT_SATISFIED
// Address Type: BASE_PAYMENT_KEY_STAKE_KEY
// Spending: m/1852'/1815'/1'/0/0
// Staking: m/1852'/1815'/1'/0/1
// ----------------------------------------------------------------------

static const uint8_t DERIVE_ADDRESS_REJECT_006_BASE_KEY_KEY_WITH_WRONG_STAKING_PATH_1_APDU[] = {
    0x00, 0x01, 0x05, 0x80, 0x00, 0x07, 0x3C, 0x80, 0x00, 0x07, 0x17, 0x80, 0x00, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0x05, 0x80, 0x00, 0x07, 0x3C, 0x80, 0x00, 0x07,
    0x17, 0x80, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
};

// ----------------------------------------------------------------------
// Reject Test 7: base key/script with Byron spending path
// Expected rejection: SWO_SECURITY_CONDITION_NOT_SATISFIED
// Address Type: BASE_PAYMENT_KEY_STAKE_SCRIPT
// Spending: m/44'/1815'/1'/0/1
// Staking: 222a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277
// ----------------------------------------------------------------------

static const uint8_t DERIVE_ADDRESS_REJECT_007_BASE_KEY_SCRIPT_WITH_BYRON_SPENDING_PATH_APDU[] = {
    0x02, 0x01, 0x05, 0x80, 0x00, 0x00, 0x2C, 0x80, 0x00, 0x07, 0x17, 0x80, 0x00, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x55, 0x22, 0x2A, 0x94, 0x6B, 0x9A, 0xD3, 0xD2, 0xDD,
    0xF0, 0x29, 0xD3, 0xA8, 0x28, 0xF0, 0x46, 0x8A, 0xEC, 0xE7, 0x68, 0x95, 0xF1, 0x5C, 0x9E, 0xFB,
    0xD6, 0x9B, 0x42, 0x77,
};

// ----------------------------------------------------------------------
// Reject Test 8: pointer with Byron spending path
// Expected rejection: SWO_SECURITY_CONDITION_NOT_SATISFIED
// Address Type: POINTER_KEY
// Spending: m/44'/1815'/1'/0/0
// Staking: 000000010000000200000003
// ----------------------------------------------------------------------

static const uint8_t DERIVE_ADDRESS_REJECT_008_POINTER_WITH_BYRON_SPENDING_PATH_APDU[] = {
    0x04, 0x01, 0x05, 0x80, 0x00, 0x00, 0x2C, 0x80, 0x00, 0x07, 0x17, 0x80, 0x00, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x44, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02,
    0x00, 0x00, 0x00, 0x03,
};

// ----------------------------------------------------------------------
// Reject Test 9: pointer with wrong spending path
// Expected rejection: SWO_SECURITY_CONDITION_NOT_SATISFIED
// Address Type: POINTER_KEY
// Spending: m/1852'/1815'/1'/2/0
// Staking: 000000010000000200000003
// ----------------------------------------------------------------------

static const uint8_t DERIVE_ADDRESS_REJECT_009_POINTER_WITH_WRONG_SPENDING_PATH_APDU[] = {
    0x04, 0x01, 0x05, 0x80, 0x00, 0x07, 0x3C, 0x80, 0x00, 0x07, 0x17, 0x80, 0x00, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x44, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02,
    0x00, 0x00, 0x00, 0x03,
};

// ----------------------------------------------------------------------
// Reject Test 10: enterprise with Byron spending path
// Expected rejection: SWO_SECURITY_CONDITION_NOT_SATISFIED
// Address Type: ENTERPRISE_KEY
// Spending: m/44'/1815'/1'/0/0
// ----------------------------------------------------------------------

static const uint8_t DERIVE_ADDRESS_REJECT_010_ENTERPRISE_WITH_BYRON_SPENDING_PATH_APDU[] = {
    0x06, 0x01, 0x05, 0x80, 0x00, 0x00, 0x2C, 0x80, 0x00, 0x07, 0x17, 0x80, 0x00, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11,
};

// ----------------------------------------------------------------------
// Reject Test 11: enterprise with wrong spending path
// Expected rejection: SWO_SECURITY_CONDITION_NOT_SATISFIED
// Address Type: ENTERPRISE_KEY
// Spending: m/1852'/1815'/1'/2/0
// ----------------------------------------------------------------------

static const uint8_t DERIVE_ADDRESS_REJECT_011_ENTERPRISE_WITH_WRONG_SPENDING_PATH_APDU[] = {
    0x06, 0x01, 0x05, 0x80, 0x00, 0x07, 0x3C, 0x80, 0x00, 0x07, 0x17, 0x80, 0x00, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x11,
};

static const derive_address_fixture_t DERIVE_ADDRESS_REJECT_FIXTURES[] = {
{
    .name = "path too short",
    .p1 = P1_ADDRESS_RETURN,
    .data = DERIVE_ADDRESS_REJECT_001_PATH_TOO_SHORT_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_REJECT_001_PATH_TOO_SHORT_APDU),
    .check_expected = SWO_SECURITY_CONDITION_NOT_SATISFIED,
},
{
    .name = "invalid path",
    .p1 = P1_ADDRESS_RETURN,
    .data = DERIVE_ADDRESS_REJECT_002_INVALID_PATH_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_REJECT_002_INVALID_PATH_APDU),
    .check_expected = SWO_SECURITY_CONDITION_NOT_SATISFIED,
},
{
    .name = "Byron with Shelley path",
    .p1 = P1_ADDRESS_RETURN,
    .data = DERIVE_ADDRESS_REJECT_003_BYRON_WITH_SHELLEY_PATH_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_REJECT_003_BYRON_WITH_SHELLEY_PATH_APDU),
    .check_expected = SWO_SECURITY_CONDITION_NOT_SATISFIED,
},
{
    .name = "base key/key with Byron spending path",
    .p1 = P1_ADDRESS_RETURN,
    .data = DERIVE_ADDRESS_REJECT_004_BASE_KEY_KEY_WITH_BYRON_SPENDING_PATH_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_REJECT_004_BASE_KEY_KEY_WITH_BYRON_SPENDING_PATH_APDU),
    .check_expected = SWO_SECURITY_CONDITION_NOT_SATISFIED,
},
{
    .name = "base key/key with wrong spending path",
    .p1 = P1_ADDRESS_RETURN,
    .data = DERIVE_ADDRESS_REJECT_005_BASE_KEY_KEY_WITH_WRONG_SPENDING_PATH_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_REJECT_005_BASE_KEY_KEY_WITH_WRONG_SPENDING_PATH_APDU),
    .check_expected = SWO_SECURITY_CONDITION_NOT_SATISFIED,
},
{
    .name = "base key/key with wrong staking path 1",
    .p1 = P1_ADDRESS_RETURN,
    .data = DERIVE_ADDRESS_REJECT_006_BASE_KEY_KEY_WITH_WRONG_STAKING_PATH_1_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_REJECT_006_BASE_KEY_KEY_WITH_WRONG_STAKING_PATH_1_APDU),
    .check_expected = SWO_SECURITY_CONDITION_NOT_SATISFIED,
},
{
    .name = "base key/script with Byron spending path",
    .p1 = P1_ADDRESS_RETURN,
    .data = DERIVE_ADDRESS_REJECT_007_BASE_KEY_SCRIPT_WITH_BYRON_SPENDING_PATH_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_REJECT_007_BASE_KEY_SCRIPT_WITH_BYRON_SPENDING_PATH_APDU),
    .check_expected = SWO_SECURITY_CONDITION_NOT_SATISFIED,
},
{
    .name = "pointer with Byron spending path",
    .p1 = P1_ADDRESS_RETURN,
    .data = DERIVE_ADDRESS_REJECT_008_POINTER_WITH_BYRON_SPENDING_PATH_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_REJECT_008_POINTER_WITH_BYRON_SPENDING_PATH_APDU),
    .check_expected = SWO_SECURITY_CONDITION_NOT_SATISFIED,
},
{
    .name = "pointer with wrong spending path",
    .p1 = P1_ADDRESS_RETURN,
    .data = DERIVE_ADDRESS_REJECT_009_POINTER_WITH_WRONG_SPENDING_PATH_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_REJECT_009_POINTER_WITH_WRONG_SPENDING_PATH_APDU),
    .check_expected = SWO_SECURITY_CONDITION_NOT_SATISFIED,
},
{
    .name = "enterprise with Byron spending path",
    .p1 = P1_ADDRESS_RETURN,
    .data = DERIVE_ADDRESS_REJECT_010_ENTERPRISE_WITH_BYRON_SPENDING_PATH_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_REJECT_010_ENTERPRISE_WITH_BYRON_SPENDING_PATH_APDU),
    .check_expected = SWO_SECURITY_CONDITION_NOT_SATISFIED,
},
{
    .name = "enterprise with wrong spending path",
    .p1 = P1_ADDRESS_RETURN,
    .data = DERIVE_ADDRESS_REJECT_011_ENTERPRISE_WITH_WRONG_SPENDING_PATH_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_REJECT_011_ENTERPRISE_WITH_WRONG_SPENDING_PATH_APDU),
    .check_expected = SWO_SECURITY_CONDITION_NOT_SATISFIED,
},
};

#define DERIVE_ADDRESS_REJECT_FIXTURE_COUNT 11