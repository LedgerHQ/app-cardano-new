// Auto-generated address derivation rejection test fixtures
// Generated from ragger standalone test cases
//
// These tests verify that the device properly rejects invalid address
// derivation requests according to the security policy defined in
// src/securityPolicy/securityPolicy.c
//
// Total rejection tests: 12

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
// Reject Test 1: Derive_address_path_too_short
// Expected rejection: SWO_SECURITY_CONDITION_NOT_SATISFIED
// Address Type: BYRON
// Source: tests/standalone/input_files/derive_address.py > reject tests > Derive_address_path_too_short
// Spending: m/44'/1815'/1'
// ----------------------------------------------------------------------

static const uint8_t DERIVE_ADDRESS_REJECT_001_DERIVE_ADDRESS_PATH_TOO_SHORT_APDU[] = {
    0x08, 0x2D, 0x96, 0x4A, 0x09, 0x03, 0x80, 0x00, 0x00, 0x2C, 0x80, 0x00, 0x07, 0x17, 0x80, 0x00,
    0x00, 0x01, 0x11,
};
// 082D964A09038000002C800007178000000111

// ----------------------------------------------------------------------
// Reject Test 2: Derive_address_invalid_path
// Expected rejection: SWO_SECURITY_CONDITION_NOT_SATISFIED
// Address Type: BYRON
// Source: tests/standalone/input_files/derive_address.py > reject tests > Derive_address_invalid_path
// Spending: m/44'/1815'/1'/5/10'
// ----------------------------------------------------------------------

static const uint8_t DERIVE_ADDRESS_REJECT_002_DERIVE_ADDRESS_INVALID_PATH_APDU[] = {
    0x08, 0x2D, 0x96, 0x4A, 0x09, 0x05, 0x80, 0x00, 0x00, 0x2C, 0x80, 0x00, 0x07, 0x17, 0x80, 0x00,
    0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x80, 0x00, 0x00, 0x0A, 0x11,
};
// 082D964A09058000002C8000071780000001000000058000000A11

// ----------------------------------------------------------------------
// Reject Test 3: Derive_address_Byron_with_Shelley_path
// Expected rejection: SWO_SECURITY_CONDITION_NOT_SATISFIED
// Address Type: BYRON
// Source: tests/standalone/input_files/derive_address.py > reject tests > Derive_address_Byron_with_Shelley_path
// Spending: m/1852'/1815'/1'/0/10
// ----------------------------------------------------------------------

static const uint8_t DERIVE_ADDRESS_REJECT_003_DERIVE_ADDRESS_BYRON_WITH_SHELLEY_PATH_APDU[] = {
    0x08, 0x2D, 0x96, 0x4A, 0x09, 0x05, 0x80, 0x00, 0x07, 0x3C, 0x80, 0x00, 0x07, 0x17, 0x80, 0x00,
    0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A, 0x11,
};
// 082D964A09058000073C8000071780000001000000000000000A11

// ----------------------------------------------------------------------
// Reject Test 4: Derive_address_base_key_key_with_Byron_spending_path
// Expected rejection: SWO_SECURITY_CONDITION_NOT_SATISFIED
// Address Type: BASE_PAYMENT_KEY_STAKE_KEY
// Source: tests/standalone/input_files/derive_address.py > reject tests > Derive_address_base_key_key_with_Byron_spending_path
// Spending: m/44'/1815'/1'/0/1
// Staking: m/1852'/1815'/1'/2/0
// ----------------------------------------------------------------------

static const uint8_t DERIVE_ADDRESS_REJECT_004_DERIVE_ADDRESS_BASE_KEY_KEY_WITH_BYRON_SPENDING_PATH_APDU[] = {
    0x00, 0x01, 0x05, 0x80, 0x00, 0x00, 0x2C, 0x80, 0x00, 0x07, 0x17, 0x80, 0x00, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x22, 0x05, 0x80, 0x00, 0x07, 0x3C, 0x80, 0x00, 0x07,
    0x17, 0x80, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
};
// 0001058000002C8000071780000001000000000000000122058000073C80000717800000010000000200000000

// ----------------------------------------------------------------------
// Reject Test 5: Derive_address_base_key_key_with_wrong_spending_path
// Expected rejection: SWO_SECURITY_CONDITION_NOT_SATISFIED
// Address Type: BASE_PAYMENT_KEY_STAKE_KEY
// Source: tests/standalone/input_files/derive_address.py > reject tests > Derive_address_base_key_key_with_wrong_spending_path
// Spending: m/1852'/1815'/1'/2/0
// Staking: m/1852'/1815'/1'/2/0
// ----------------------------------------------------------------------

static const uint8_t DERIVE_ADDRESS_REJECT_005_DERIVE_ADDRESS_BASE_KEY_KEY_WITH_WRONG_SPENDING_PATH_APDU[] = {
    0x00, 0x01, 0x05, 0x80, 0x00, 0x07, 0x3C, 0x80, 0x00, 0x07, 0x17, 0x80, 0x00, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x22, 0x05, 0x80, 0x00, 0x07, 0x3C, 0x80, 0x00, 0x07,
    0x17, 0x80, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
};
// 0001058000073C8000071780000001000000020000000022058000073C80000717800000010000000200000000

// ----------------------------------------------------------------------
// Reject Test 6: Derive_address_base_key_key_with_wrong_staking_path_1
// Expected rejection: SWO_SECURITY_CONDITION_NOT_SATISFIED
// Address Type: BASE_PAYMENT_KEY_STAKE_KEY
// Source: tests/standalone/input_files/derive_address.py > reject tests > Derive_address_base_key_key_with_wrong_staking_path_1
// Spending: m/1852'/1815'/1'/0/0
// Staking: m/1852'/1815'/1'/0/1
// ----------------------------------------------------------------------

static const uint8_t DERIVE_ADDRESS_REJECT_006_DERIVE_ADDRESS_BASE_KEY_KEY_WITH_WRONG_STAKING_PATH_1_APDU[] = {
    0x00, 0x01, 0x05, 0x80, 0x00, 0x07, 0x3C, 0x80, 0x00, 0x07, 0x17, 0x80, 0x00, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0x05, 0x80, 0x00, 0x07, 0x3C, 0x80, 0x00, 0x07,
    0x17, 0x80, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
};
// 0001058000073C8000071780000001000000000000000022058000073C80000717800000010000000000000001

// ----------------------------------------------------------------------
// Reject Test 7: Derive_address_base_key_script_with_Byron_spending_path
// Expected rejection: SWO_SECURITY_CONDITION_NOT_SATISFIED
// Address Type: BASE_PAYMENT_KEY_STAKE_SCRIPT
// Source: tests/standalone/input_files/derive_address.py > reject tests > Derive_address_base_key_script_with_Byron_spending_path
// Spending: m/44'/1815'/1'/0/1
// Staking: 222a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277
// ----------------------------------------------------------------------

static const uint8_t DERIVE_ADDRESS_REJECT_007_DERIVE_ADDRESS_BASE_KEY_SCRIPT_WITH_BYRON_SPENDING_PATH_APDU[] = {
    0x02, 0x01, 0x05, 0x80, 0x00, 0x00, 0x2C, 0x80, 0x00, 0x07, 0x17, 0x80, 0x00, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x55, 0x22, 0x2A, 0x94, 0x6B, 0x9A, 0xD3, 0xD2, 0xDD,
    0xF0, 0x29, 0xD3, 0xA8, 0x28, 0xF0, 0x46, 0x8A, 0xEC, 0xE7, 0x68, 0x95, 0xF1, 0x5C, 0x9E, 0xFB,
    0xD6, 0x9B, 0x42, 0x77,
};
// 0201058000002C8000071780000001000000000000000155222A946B9AD3D2DDF029D3A828F0468AECE76895F15C9EFBD69B4277

// ----------------------------------------------------------------------
// Reject Test 8: Derive_address_base_address_scripthash_keyhash_not_allowed
// Expected rejection: SWO_SECURITY_CONDITION_NOT_SATISFIED
// Address Type: BASE_PAYMENT_SCRIPT_STAKE_KEY
// Source: tests/standalone/input_files/derive_address.py > reject tests > Derive_address_base_address_scripthash_keyhash_not_allowed
// Spending: 122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277
// Staking: 222a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277
// ----------------------------------------------------------------------

static const uint8_t DERIVE_ADDRESS_REJECT_008_DERIVE_ADDRESS_BASE_ADDRESS_SCRIPTHASH_KEYHASH_NOT_ALLOWED_APDU[] = {
    0x01, 0x01, 0x12, 0x2A, 0x94, 0x6B, 0x9A, 0xD3, 0xD2, 0xDD, 0xF0, 0x29, 0xD3, 0xA8, 0x28, 0xF0,
    0x46, 0x8A, 0xEC, 0xE7, 0x68, 0x95, 0xF1, 0x5C, 0x9E, 0xFB, 0xD6, 0x9B, 0x42, 0x77, 0x33, 0x22,
    0x2A, 0x94, 0x6B, 0x9A, 0xD3, 0xD2, 0xDD, 0xF0, 0x29, 0xD3, 0xA8, 0x28, 0xF0, 0x46, 0x8A, 0xEC,
    0xE7, 0x68, 0x95, 0xF1, 0x5C, 0x9E, 0xFB, 0xD6, 0x9B, 0x42, 0x77,
};
// 0101122A946B9AD3D2DDF029D3A828F0468AECE76895F15C9EFBD69B427733222A946B9AD3D2DDF029D3A828F0468AECE76895F15C9EFBD69B4277

// ----------------------------------------------------------------------
// Reject Test 9: Derive_address_pointer_with_Byron_spending_path
// Expected rejection: SWO_SECURITY_CONDITION_NOT_SATISFIED
// Address Type: POINTER_KEY
// Source: tests/standalone/input_files/derive_address.py > reject tests > Derive_address_pointer_with_Byron_spending_path
// Spending: m/44'/1815'/1'/0/0
// Staking: 000000010000000200000003
// ----------------------------------------------------------------------

static const uint8_t DERIVE_ADDRESS_REJECT_009_DERIVE_ADDRESS_POINTER_WITH_BYRON_SPENDING_PATH_APDU[] = {
    0x04, 0x01, 0x05, 0x80, 0x00, 0x00, 0x2C, 0x80, 0x00, 0x07, 0x17, 0x80, 0x00, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x44, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02,
    0x00, 0x00, 0x00, 0x03,
};
// 0401058000002C8000071780000001000000000000000044000000010000000200000003

// ----------------------------------------------------------------------
// Reject Test 10: Derive_address_pointer_with_wrong_spending_path
// Expected rejection: SWO_SECURITY_CONDITION_NOT_SATISFIED
// Address Type: POINTER_KEY
// Source: tests/standalone/input_files/derive_address.py > reject tests > Derive_address_pointer_with_wrong_spending_path
// Spending: m/1852'/1815'/1'/2/0
// Staking: 000000010000000200000003
// ----------------------------------------------------------------------

static const uint8_t DERIVE_ADDRESS_REJECT_010_DERIVE_ADDRESS_POINTER_WITH_WRONG_SPENDING_PATH_APDU[] = {
    0x04, 0x01, 0x05, 0x80, 0x00, 0x07, 0x3C, 0x80, 0x00, 0x07, 0x17, 0x80, 0x00, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x44, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02,
    0x00, 0x00, 0x00, 0x03,
};
// 0401058000073C8000071780000001000000020000000044000000010000000200000003

// ----------------------------------------------------------------------
// Reject Test 11: Derive_address_enterprise_with_Byron_spending_path
// Expected rejection: SWO_SECURITY_CONDITION_NOT_SATISFIED
// Address Type: ENTERPRISE_KEY
// Source: tests/standalone/input_files/derive_address.py > reject tests > Derive_address_enterprise_with_Byron_spending_path
// Spending: m/44'/1815'/1'/0/0
// ----------------------------------------------------------------------

static const uint8_t DERIVE_ADDRESS_REJECT_011_DERIVE_ADDRESS_ENTERPRISE_WITH_BYRON_SPENDING_PATH_APDU[] = {
    0x06, 0x01, 0x05, 0x80, 0x00, 0x00, 0x2C, 0x80, 0x00, 0x07, 0x17, 0x80, 0x00, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11,
};
// 0601058000002C8000071780000001000000000000000011

// ----------------------------------------------------------------------
// Reject Test 12: Derive_address_enterprise_with_wrong_spending_path
// Expected rejection: SWO_SECURITY_CONDITION_NOT_SATISFIED
// Address Type: ENTERPRISE_KEY
// Source: tests/standalone/input_files/derive_address.py > reject tests > Derive_address_enterprise_with_wrong_spending_path
// Spending: m/1852'/1815'/1'/2/0
// ----------------------------------------------------------------------

static const uint8_t DERIVE_ADDRESS_REJECT_012_DERIVE_ADDRESS_ENTERPRISE_WITH_WRONG_SPENDING_PATH_APDU[] = {
    0x06, 0x01, 0x05, 0x80, 0x00, 0x07, 0x3C, 0x80, 0x00, 0x07, 0x17, 0x80, 0x00, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x11,
};
// 0601058000073C8000071780000001000000020000000011

static const derive_address_fixture_t DERIVE_ADDRESS_REJECT_FIXTURES[] = {
// Source: tests/standalone/input_files/derive_address.py > reject tests > Derive_address_path_too_short
{
    .name = "Derive_address_path_too_short",
    .p1 = P1_ADDRESS_RETURN,
    .data = DERIVE_ADDRESS_REJECT_001_DERIVE_ADDRESS_PATH_TOO_SHORT_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_REJECT_001_DERIVE_ADDRESS_PATH_TOO_SHORT_APDU),
    .check_expected = SWO_SECURITY_CONDITION_NOT_SATISFIED,
},
// Source: tests/standalone/input_files/derive_address.py > reject tests > Derive_address_invalid_path
{
    .name = "Derive_address_invalid_path",
    .p1 = P1_ADDRESS_RETURN,
    .data = DERIVE_ADDRESS_REJECT_002_DERIVE_ADDRESS_INVALID_PATH_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_REJECT_002_DERIVE_ADDRESS_INVALID_PATH_APDU),
    .check_expected = SWO_SECURITY_CONDITION_NOT_SATISFIED,
},
// Source: tests/standalone/input_files/derive_address.py > reject tests > Derive_address_Byron_with_Shelley_path
{
    .name = "Derive_address_Byron_with_Shelley_path",
    .p1 = P1_ADDRESS_RETURN,
    .data = DERIVE_ADDRESS_REJECT_003_DERIVE_ADDRESS_BYRON_WITH_SHELLEY_PATH_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_REJECT_003_DERIVE_ADDRESS_BYRON_WITH_SHELLEY_PATH_APDU),
    .check_expected = SWO_SECURITY_CONDITION_NOT_SATISFIED,
},
// Source: tests/standalone/input_files/derive_address.py > reject tests > Derive_address_base_key_key_with_Byron_spending_path
{
    .name = "Derive_address_base_key_key_with_Byron_spending_path",
    .p1 = P1_ADDRESS_RETURN,
    .data = DERIVE_ADDRESS_REJECT_004_DERIVE_ADDRESS_BASE_KEY_KEY_WITH_BYRON_SPENDING_PATH_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_REJECT_004_DERIVE_ADDRESS_BASE_KEY_KEY_WITH_BYRON_SPENDING_PATH_APDU),
    .check_expected = SWO_SECURITY_CONDITION_NOT_SATISFIED,
},
// Source: tests/standalone/input_files/derive_address.py > reject tests > Derive_address_base_key_key_with_wrong_spending_path
{
    .name = "Derive_address_base_key_key_with_wrong_spending_path",
    .p1 = P1_ADDRESS_RETURN,
    .data = DERIVE_ADDRESS_REJECT_005_DERIVE_ADDRESS_BASE_KEY_KEY_WITH_WRONG_SPENDING_PATH_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_REJECT_005_DERIVE_ADDRESS_BASE_KEY_KEY_WITH_WRONG_SPENDING_PATH_APDU),
    .check_expected = SWO_SECURITY_CONDITION_NOT_SATISFIED,
},
// Source: tests/standalone/input_files/derive_address.py > reject tests > Derive_address_base_key_key_with_wrong_staking_path_1
{
    .name = "Derive_address_base_key_key_with_wrong_staking_path_1",
    .p1 = P1_ADDRESS_RETURN,
    .data = DERIVE_ADDRESS_REJECT_006_DERIVE_ADDRESS_BASE_KEY_KEY_WITH_WRONG_STAKING_PATH_1_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_REJECT_006_DERIVE_ADDRESS_BASE_KEY_KEY_WITH_WRONG_STAKING_PATH_1_APDU),
    .check_expected = SWO_SECURITY_CONDITION_NOT_SATISFIED,
},
// Source: tests/standalone/input_files/derive_address.py > reject tests > Derive_address_base_key_script_with_Byron_spending_path
{
    .name = "Derive_address_base_key_script_with_Byron_spending_path",
    .p1 = P1_ADDRESS_RETURN,
    .data = DERIVE_ADDRESS_REJECT_007_DERIVE_ADDRESS_BASE_KEY_SCRIPT_WITH_BYRON_SPENDING_PATH_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_REJECT_007_DERIVE_ADDRESS_BASE_KEY_SCRIPT_WITH_BYRON_SPENDING_PATH_APDU),
    .check_expected = SWO_SECURITY_CONDITION_NOT_SATISFIED,
},
// Source: tests/standalone/input_files/derive_address.py > reject tests > Derive_address_base_address_scripthash_keyhash_not_allowed
{
    .name = "Derive_address_base_address_scripthash_keyhash_not_allowed",
    .p1 = P1_ADDRESS_RETURN,
    .data = DERIVE_ADDRESS_REJECT_008_DERIVE_ADDRESS_BASE_ADDRESS_SCRIPTHASH_KEYHASH_NOT_ALLOWED_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_REJECT_008_DERIVE_ADDRESS_BASE_ADDRESS_SCRIPTHASH_KEYHASH_NOT_ALLOWED_APDU),
    .check_expected = SWO_SECURITY_CONDITION_NOT_SATISFIED,
},
// Source: tests/standalone/input_files/derive_address.py > reject tests > Derive_address_pointer_with_Byron_spending_path
{
    .name = "Derive_address_pointer_with_Byron_spending_path",
    .p1 = P1_ADDRESS_RETURN,
    .data = DERIVE_ADDRESS_REJECT_009_DERIVE_ADDRESS_POINTER_WITH_BYRON_SPENDING_PATH_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_REJECT_009_DERIVE_ADDRESS_POINTER_WITH_BYRON_SPENDING_PATH_APDU),
    .check_expected = SWO_SECURITY_CONDITION_NOT_SATISFIED,
},
// Source: tests/standalone/input_files/derive_address.py > reject tests > Derive_address_pointer_with_wrong_spending_path
{
    .name = "Derive_address_pointer_with_wrong_spending_path",
    .p1 = P1_ADDRESS_RETURN,
    .data = DERIVE_ADDRESS_REJECT_010_DERIVE_ADDRESS_POINTER_WITH_WRONG_SPENDING_PATH_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_REJECT_010_DERIVE_ADDRESS_POINTER_WITH_WRONG_SPENDING_PATH_APDU),
    .check_expected = SWO_SECURITY_CONDITION_NOT_SATISFIED,
},
// Source: tests/standalone/input_files/derive_address.py > reject tests > Derive_address_enterprise_with_Byron_spending_path
{
    .name = "Derive_address_enterprise_with_Byron_spending_path",
    .p1 = P1_ADDRESS_RETURN,
    .data = DERIVE_ADDRESS_REJECT_011_DERIVE_ADDRESS_ENTERPRISE_WITH_BYRON_SPENDING_PATH_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_REJECT_011_DERIVE_ADDRESS_ENTERPRISE_WITH_BYRON_SPENDING_PATH_APDU),
    .check_expected = SWO_SECURITY_CONDITION_NOT_SATISFIED,
},
// Source: tests/standalone/input_files/derive_address.py > reject tests > Derive_address_enterprise_with_wrong_spending_path
{
    .name = "Derive_address_enterprise_with_wrong_spending_path",
    .p1 = P1_ADDRESS_RETURN,
    .data = DERIVE_ADDRESS_REJECT_012_DERIVE_ADDRESS_ENTERPRISE_WITH_WRONG_SPENDING_PATH_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_REJECT_012_DERIVE_ADDRESS_ENTERPRISE_WITH_WRONG_SPENDING_PATH_APDU),
    .check_expected = SWO_SECURITY_CONDITION_NOT_SATISFIED,
},
};

#define DERIVE_ADDRESS_REJECT_FIXTURE_COUNT 12