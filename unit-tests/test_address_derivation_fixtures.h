// Auto-generated address derivation test fixtures
// Generated from ragger standalone test cases
//
//
// Total categories of tests: 6

#pragma once

#include <stdint.h>
#include <stddef.h>
#include "test_fixture_types.h"
#include "cardano_swo.h"
#include "test_derive_address_common.h"

// ======================================================================
// Address Derivation Test Fixtures
// ======================================================================


// ----------------------------------------------------------------------
// Test type: byronTestCases
// Test 0: Derive_address_byron_mainnet_1
// Address Type: BYRON
// Spending: m/44'/1815'/1'/0/55'
// ----------------------------------------------------------------------

static const uint8_t DERIVE_ADDRESS_byronTestCases_000_DERIVE_ADDRESS_BYRON_MAINNET_1_APDU[] = {
    0x08, 0x2D, 0x96, 0x4A, 0x09, 0x05, 0x80, 0x00, 0x00, 0x2C, 0x80, 0x00, 0x07, 0x17, 0x80, 0x00,
    0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x37, 0x11,
};

// ----------------------------------------------------------------------
// Test type: byronTestCases
// Test 1: Derive_address_byron_mainnet_2
// Address Type: BYRON
// Spending: m/44'/1815'/1'/0/12'
// ----------------------------------------------------------------------

static const uint8_t DERIVE_ADDRESS_byronTestCases_001_DERIVE_ADDRESS_BYRON_MAINNET_2_APDU[] = {
    0x08, 0x2D, 0x96, 0x4A, 0x09, 0x05, 0x80, 0x00, 0x00, 0x2C, 0x80, 0x00, 0x07, 0x17, 0x80, 0x00,
    0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x0C, 0x11,
};

// ----------------------------------------------------------------------
// Test type: byronTestCases
// Test 2: Derive_address_byron_mainnet_3
// Address Type: BYRON
// Spending: m/44'/1815'/101'/0/12'
// ----------------------------------------------------------------------

static const uint8_t DERIVE_ADDRESS_byronTestCases_002_DERIVE_ADDRESS_BYRON_MAINNET_3_APDU[] = {
    0x08, 0x2D, 0x96, 0x4A, 0x09, 0x05, 0x80, 0x00, 0x00, 0x2C, 0x80, 0x00, 0x07, 0x17, 0x80, 0x00,
    0x00, 0x65, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x0C, 0x11,
};

// ----------------------------------------------------------------------
// Test type: byronTestCases
// Test 3: Derive_address_byron_mainnet_4
// Address Type: BYRON
// Spending: m/44'/1815'/0'/0/1000001'
// ----------------------------------------------------------------------

static const uint8_t DERIVE_ADDRESS_byronTestCases_003_DERIVE_ADDRESS_BYRON_MAINNET_4_APDU[] = {
    0x08, 0x2D, 0x96, 0x4A, 0x09, 0x05, 0x80, 0x00, 0x00, 0x2C, 0x80, 0x00, 0x07, 0x17, 0x80, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x0F, 0x42, 0x41, 0x11,
};

// ----------------------------------------------------------------------
// Test type: byronTestCases
// Test 4: Derive_address_byron_testnet_1
// Address Type: BYRON
// Spending: m/44'/1815'/1'/0/12'
// ----------------------------------------------------------------------

static const uint8_t DERIVE_ADDRESS_byronTestCases_004_DERIVE_ADDRESS_BYRON_TESTNET_1_APDU[] = {
    0x08, 0x00, 0x00, 0x00, 0x2A, 0x05, 0x80, 0x00, 0x00, 0x2C, 0x80, 0x00, 0x07, 0x17, 0x80, 0x00,
    0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x0C, 0x11,
};

// ----------------------------------------------------------------------
// Test type: shelleyTestCasesNoConfirm
// Test 0: Derive_address_shelley_fakenet_base_path_path_1
// Address Type: BASE_PAYMENT_KEY_STAKE_KEY
// Spending: m/1852'/1815'/0'/0/1
// Staking: m/1852'/1815'/0'/2/0
// ----------------------------------------------------------------------

static const uint8_t DERIVE_ADDRESS_shelleyTestCasesNoConfirm_000_DERIVE_ADDRESS_SHELLEY_FAKENET_BASE_PATH_PATH_1_APDU[] = {
    0x00, 0x03, 0x05, 0x80, 0x00, 0x07, 0x3C, 0x80, 0x00, 0x07, 0x17, 0x80, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x22, 0x05, 0x80, 0x00, 0x07, 0x3C, 0x80, 0x00, 0x07,
    0x17, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
};

// ----------------------------------------------------------------------
// Test type: shelleyTestCasesNoConfirm
// Test 1: Derive_address_shelley_testnet_base_path_path_2
// Address Type: BASE_PAYMENT_KEY_STAKE_KEY
// Spending: m/1852'/1815'/0'/0/1
// Staking: m/1852'/1815'/0'/2/0
// ----------------------------------------------------------------------

static const uint8_t DERIVE_ADDRESS_shelleyTestCasesNoConfirm_001_DERIVE_ADDRESS_SHELLEY_TESTNET_BASE_PATH_PATH_2_APDU[] = {
    0x00, 0x00, 0x05, 0x80, 0x00, 0x07, 0x3C, 0x80, 0x00, 0x07, 0x17, 0x80, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x22, 0x05, 0x80, 0x00, 0x07, 0x3C, 0x80, 0x00, 0x07,
    0x17, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
};

// ----------------------------------------------------------------------
// Test type: shelleyTestCasesNoConfirm
// Test 2: Derive_address_shelley_testnet_base_path_path_multidelegation
// Address Type: BASE_PAYMENT_KEY_STAKE_KEY
// Spending: m/1852'/1815'/0'/0/1
// Staking: m/1852'/1815'/0'/2/60
// ----------------------------------------------------------------------

static const uint8_t DERIVE_ADDRESS_shelleyTestCasesNoConfirm_002_DERIVE_ADDRESS_SHELLEY_TESTNET_BASE_PATH_PATH_MULTIDELEGATION_APDU[] = {
    0x00, 0x00, 0x05, 0x80, 0x00, 0x07, 0x3C, 0x80, 0x00, 0x07, 0x17, 0x80, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x22, 0x05, 0x80, 0x00, 0x07, 0x3C, 0x80, 0x00, 0x07,
    0x17, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x3C,
};

// ----------------------------------------------------------------------
// Test type: shelleyTestCasesNoConfirm
// Test 3: Derive_address_shelley_testnet_base_path_keyhash_1
// Address Type: BASE_PAYMENT_KEY_STAKE_KEY
// Spending: m/1852'/1815'/0'/0/1
// Staking: 1d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c
// ----------------------------------------------------------------------

static const uint8_t DERIVE_ADDRESS_shelleyTestCasesNoConfirm_003_DERIVE_ADDRESS_SHELLEY_TESTNET_BASE_PATH_KEYHASH_1_APDU[] = {
    0x00, 0x00, 0x05, 0x80, 0x00, 0x07, 0x3C, 0x80, 0x00, 0x07, 0x17, 0x80, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x33, 0x1D, 0x22, 0x7A, 0xEF, 0xA4, 0xB7, 0x73, 0x14,
    0x91, 0x70, 0x88, 0x5A, 0xAD, 0xBA, 0x30, 0xAA, 0xB3, 0x12, 0x7C, 0xC6, 0x11, 0xDD, 0xBC, 0x49,
    0x99, 0xDE, 0xF6, 0x1C,
};

// ----------------------------------------------------------------------
// Test type: shelleyTestCasesNoConfirm
// Test 4: Derive_address_shelley_fakenet_base_path_keyhash_2
// Address Type: BASE_PAYMENT_KEY_STAKE_KEY
// Spending: m/1852'/1815'/0'/0/1
// Staking: 122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277
// ----------------------------------------------------------------------

static const uint8_t DERIVE_ADDRESS_shelleyTestCasesNoConfirm_004_DERIVE_ADDRESS_SHELLEY_FAKENET_BASE_PATH_KEYHASH_2_APDU[] = {
    0x00, 0x03, 0x05, 0x80, 0x00, 0x07, 0x3C, 0x80, 0x00, 0x07, 0x17, 0x80, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x33, 0x12, 0x2A, 0x94, 0x6B, 0x9A, 0xD3, 0xD2, 0xDD,
    0xF0, 0x29, 0xD3, 0xA8, 0x28, 0xF0, 0x46, 0x8A, 0xEC, 0xE7, 0x68, 0x95, 0xF1, 0x5C, 0x9E, 0xFB,
    0xD6, 0x9B, 0x42, 0x77,
};

// ----------------------------------------------------------------------
// Test type: shelleyTestCasesNoConfirm
// Test 5: Derive_address_shelley_fakenet_base_scripthash_path
// Address Type: BASE_PAYMENT_SCRIPT_STAKE_KEY
// Spending: 122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277
// Staking: m/1852'/1815'/0'/2/0
// ----------------------------------------------------------------------

static const uint8_t DERIVE_ADDRESS_shelleyTestCasesNoConfirm_005_DERIVE_ADDRESS_SHELLEY_FAKENET_BASE_SCRIPTHASH_PATH_APDU[] = {
    0x01, 0x03, 0x12, 0x2A, 0x94, 0x6B, 0x9A, 0xD3, 0xD2, 0xDD, 0xF0, 0x29, 0xD3, 0xA8, 0x28, 0xF0,
    0x46, 0x8A, 0xEC, 0xE7, 0x68, 0x95, 0xF1, 0x5C, 0x9E, 0xFB, 0xD6, 0x9B, 0x42, 0x77, 0x22, 0x05,
    0x80, 0x00, 0x07, 0x3C, 0x80, 0x00, 0x07, 0x17, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
    0x00, 0x00, 0x00, 0x00,
};

// ----------------------------------------------------------------------
// Test type: shelleyTestCasesNoConfirm
// Test 6: Derive_address_shelley_fakenet_base_scripthash_path_multidelegation
// Address Type: BASE_PAYMENT_SCRIPT_STAKE_KEY
// Spending: 122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277
// Staking: m/1852'/1815'/0'/2/3
// ----------------------------------------------------------------------

static const uint8_t DERIVE_ADDRESS_shelleyTestCasesNoConfirm_006_DERIVE_ADDRESS_SHELLEY_FAKENET_BASE_SCRIPTHASH_PATH_MULTIDELEGATION_APDU[] = {
    0x01, 0x03, 0x12, 0x2A, 0x94, 0x6B, 0x9A, 0xD3, 0xD2, 0xDD, 0xF0, 0x29, 0xD3, 0xA8, 0x28, 0xF0,
    0x46, 0x8A, 0xEC, 0xE7, 0x68, 0x95, 0xF1, 0x5C, 0x9E, 0xFB, 0xD6, 0x9B, 0x42, 0x77, 0x22, 0x05,
    0x80, 0x00, 0x07, 0x3C, 0x80, 0x00, 0x07, 0x17, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
    0x00, 0x00, 0x00, 0x03,
};

// ----------------------------------------------------------------------
// Test type: shelleyTestCasesNoConfirm
// Test 7: Derive_address_shelley_fakenet_base_path_scripthash
// Address Type: BASE_PAYMENT_KEY_STAKE_SCRIPT
// Spending: m/1852'/1815'/0'/0/1
// Staking: 122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277
// ----------------------------------------------------------------------

static const uint8_t DERIVE_ADDRESS_shelleyTestCasesNoConfirm_007_DERIVE_ADDRESS_SHELLEY_FAKENET_BASE_PATH_SCRIPTHASH_APDU[] = {
    0x02, 0x03, 0x05, 0x80, 0x00, 0x07, 0x3C, 0x80, 0x00, 0x07, 0x17, 0x80, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x55, 0x12, 0x2A, 0x94, 0x6B, 0x9A, 0xD3, 0xD2, 0xDD,
    0xF0, 0x29, 0xD3, 0xA8, 0x28, 0xF0, 0x46, 0x8A, 0xEC, 0xE7, 0x68, 0x95, 0xF1, 0x5C, 0x9E, 0xFB,
    0xD6, 0x9B, 0x42, 0x77,
};

// ----------------------------------------------------------------------
// Test type: shelleyTestCasesNoConfirm
// Test 8: Derive_address_shelley_fakenet_base_scripthash_scripthash
// Address Type: BASE_PAYMENT_SCRIPT_STAKE_SCRIPT
// Spending: 122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277
// Staking: 122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277
// ----------------------------------------------------------------------

static const uint8_t DERIVE_ADDRESS_shelleyTestCasesNoConfirm_008_DERIVE_ADDRESS_SHELLEY_FAKENET_BASE_SCRIPTHASH_SCRIPTHASH_APDU[] = {
    0x03, 0x03, 0x12, 0x2A, 0x94, 0x6B, 0x9A, 0xD3, 0xD2, 0xDD, 0xF0, 0x29, 0xD3, 0xA8, 0x28, 0xF0,
    0x46, 0x8A, 0xEC, 0xE7, 0x68, 0x95, 0xF1, 0x5C, 0x9E, 0xFB, 0xD6, 0x9B, 0x42, 0x77, 0x55, 0x12,
    0x2A, 0x94, 0x6B, 0x9A, 0xD3, 0xD2, 0xDD, 0xF0, 0x29, 0xD3, 0xA8, 0x28, 0xF0, 0x46, 0x8A, 0xEC,
    0xE7, 0x68, 0x95, 0xF1, 0x5C, 0x9E, 0xFB, 0xD6, 0x9B, 0x42, 0x77,
};

// ----------------------------------------------------------------------
// Test type: shelleyTestCasesNoConfirm
// Test 9: Derive_address_shelley_testnet_enterprise_path_1
// Address Type: ENTERPRISE_KEY
// Spending: m/1852'/1815'/0'/0/1
// ----------------------------------------------------------------------

static const uint8_t DERIVE_ADDRESS_shelleyTestCasesNoConfirm_009_DERIVE_ADDRESS_SHELLEY_TESTNET_ENTERPRISE_PATH_1_APDU[] = {
    0x06, 0x00, 0x05, 0x80, 0x00, 0x07, 0x3C, 0x80, 0x00, 0x07, 0x17, 0x80, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x11,
};

// ----------------------------------------------------------------------
// Test type: shelleyTestCasesNoConfirm
// Test 10: Derive_address_shelley_fakenet_enterprise_path_2
// Address Type: ENTERPRISE_KEY
// Spending: m/1852'/1815'/0'/0/1
// ----------------------------------------------------------------------

static const uint8_t DERIVE_ADDRESS_shelleyTestCasesNoConfirm_010_DERIVE_ADDRESS_SHELLEY_FAKENET_ENTERPRISE_PATH_2_APDU[] = {
    0x06, 0x03, 0x05, 0x80, 0x00, 0x07, 0x3C, 0x80, 0x00, 0x07, 0x17, 0x80, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x11,
};

// ----------------------------------------------------------------------
// Test type: shelleyTestCasesNoConfirm
// Test 11: Derive_address_shelley_testnet_enterprise_script_1
// Address Type: ENTERPRISE_SCRIPT
// Spending: 122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277
// ----------------------------------------------------------------------

static const uint8_t DERIVE_ADDRESS_shelleyTestCasesNoConfirm_011_DERIVE_ADDRESS_SHELLEY_TESTNET_ENTERPRISE_SCRIPT_1_APDU[] = {
    0x07, 0x00, 0x12, 0x2A, 0x94, 0x6B, 0x9A, 0xD3, 0xD2, 0xDD, 0xF0, 0x29, 0xD3, 0xA8, 0x28, 0xF0,
    0x46, 0x8A, 0xEC, 0xE7, 0x68, 0x95, 0xF1, 0x5C, 0x9E, 0xFB, 0xD6, 0x9B, 0x42, 0x77, 0x11,
};

// ----------------------------------------------------------------------
// Test type: shelleyTestCasesNoConfirm
// Test 12: Derive_address_shelley_fakenet_enterprise_script_2
// Address Type: ENTERPRISE_SCRIPT
// Spending: 122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277
// ----------------------------------------------------------------------

static const uint8_t DERIVE_ADDRESS_shelleyTestCasesNoConfirm_012_DERIVE_ADDRESS_SHELLEY_FAKENET_ENTERPRISE_SCRIPT_2_APDU[] = {
    0x07, 0x03, 0x12, 0x2A, 0x94, 0x6B, 0x9A, 0xD3, 0xD2, 0xDD, 0xF0, 0x29, 0xD3, 0xA8, 0x28, 0xF0,
    0x46, 0x8A, 0xEC, 0xE7, 0x68, 0x95, 0xF1, 0x5C, 0x9E, 0xFB, 0xD6, 0x9B, 0x42, 0x77, 0x11,
};

// ----------------------------------------------------------------------
// Test type: shelleyTestCasesNoConfirm
// Test 13: Derive_address_shelley_testnet_pointer_path_1
// Address Type: POINTER_KEY
// Spending: m/1852'/1815'/0'/0/1
// Staking: 000000010000000200000003
// ----------------------------------------------------------------------

static const uint8_t DERIVE_ADDRESS_shelleyTestCasesNoConfirm_013_DERIVE_ADDRESS_SHELLEY_TESTNET_POINTER_PATH_1_APDU[] = {
    0x04, 0x00, 0x05, 0x80, 0x00, 0x07, 0x3C, 0x80, 0x00, 0x07, 0x17, 0x80, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02,
    0x00, 0x00, 0x00, 0x03,
};

// ----------------------------------------------------------------------
// Test type: shelleyTestCasesNoConfirm
// Test 14: Derive_address_shelley_fakenet_pointer_path_2
// Address Type: POINTER_KEY
// Spending: m/1852'/1815'/0'/0/1
// Staking: 00005e5d000000b10000002a
// ----------------------------------------------------------------------

static const uint8_t DERIVE_ADDRESS_shelleyTestCasesNoConfirm_014_DERIVE_ADDRESS_SHELLEY_FAKENET_POINTER_PATH_2_APDU[] = {
    0x04, 0x03, 0x05, 0x80, 0x00, 0x07, 0x3C, 0x80, 0x00, 0x07, 0x17, 0x80, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00, 0x5E, 0x5D, 0x00, 0x00, 0x00, 0xB1,
    0x00, 0x00, 0x00, 0x2A,
};

// ----------------------------------------------------------------------
// Test type: shelleyTestCasesNoConfirm
// Test 15: Derive_address_shelley_fakenet_pointer_path_3
// Address Type: POINTER_KEY
// Spending: m/1852'/1815'/0'/0/1
// Staking: 000000000000000000000000
// ----------------------------------------------------------------------

static const uint8_t DERIVE_ADDRESS_shelleyTestCasesNoConfirm_015_DERIVE_ADDRESS_SHELLEY_FAKENET_POINTER_PATH_3_APDU[] = {
    0x04, 0x03, 0x05, 0x80, 0x00, 0x07, 0x3C, 0x80, 0x00, 0x07, 0x17, 0x80, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
};

// ----------------------------------------------------------------------
// Test type: shelleyTestCasesNoConfirm
// Test 16: Derive_address_shelley_testnet_pointer_script_1
// Address Type: POINTER_SCRIPT
// Spending: 122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277
// Staking: 000000010000000200000003
// ----------------------------------------------------------------------

static const uint8_t DERIVE_ADDRESS_shelleyTestCasesNoConfirm_016_DERIVE_ADDRESS_SHELLEY_TESTNET_POINTER_SCRIPT_1_APDU[] = {
    0x05, 0x00, 0x12, 0x2A, 0x94, 0x6B, 0x9A, 0xD3, 0xD2, 0xDD, 0xF0, 0x29, 0xD3, 0xA8, 0x28, 0xF0,
    0x46, 0x8A, 0xEC, 0xE7, 0x68, 0x95, 0xF1, 0x5C, 0x9E, 0xFB, 0xD6, 0x9B, 0x42, 0x77, 0x44, 0x00,
    0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03,
};

// ----------------------------------------------------------------------
// Test type: shelleyTestCasesNoConfirm
// Test 17: Derive_address_shelley_fakenet_pointer_script_2
// Address Type: POINTER_SCRIPT
// Spending: 122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277
// Staking: 00005e5d000000b10000002a
// ----------------------------------------------------------------------

static const uint8_t DERIVE_ADDRESS_shelleyTestCasesNoConfirm_017_DERIVE_ADDRESS_SHELLEY_FAKENET_POINTER_SCRIPT_2_APDU[] = {
    0x05, 0x03, 0x12, 0x2A, 0x94, 0x6B, 0x9A, 0xD3, 0xD2, 0xDD, 0xF0, 0x29, 0xD3, 0xA8, 0x28, 0xF0,
    0x46, 0x8A, 0xEC, 0xE7, 0x68, 0x95, 0xF1, 0x5C, 0x9E, 0xFB, 0xD6, 0x9B, 0x42, 0x77, 0x44, 0x00,
    0x00, 0x5E, 0x5D, 0x00, 0x00, 0x00, 0xB1, 0x00, 0x00, 0x00, 0x2A,
};

// ----------------------------------------------------------------------
// Test type: shelleyTestCasesNoConfirm
// Test 18: Derive_address_shelley_fakenet_pointer_script_3
// Address Type: POINTER_SCRIPT
// Spending: 122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277
// Staking: 000000000000000000000000
// ----------------------------------------------------------------------

static const uint8_t DERIVE_ADDRESS_shelleyTestCasesNoConfirm_018_DERIVE_ADDRESS_SHELLEY_FAKENET_POINTER_SCRIPT_3_APDU[] = {
    0x05, 0x03, 0x12, 0x2A, 0x94, 0x6B, 0x9A, 0xD3, 0xD2, 0xDD, 0xF0, 0x29, 0xD3, 0xA8, 0x28, 0xF0,
    0x46, 0x8A, 0xEC, 0xE7, 0x68, 0x95, 0xF1, 0x5C, 0x9E, 0xFB, 0xD6, 0x9B, 0x42, 0x77, 0x44, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

// ----------------------------------------------------------------------
// Test type: shelleyTestCasesNoConfirm
// Test 19: Derive_address_shelley_testnet_reward_path_1
// Address Type: REWARD_KEY
// Spending: 
// Staking: m/1852'/1815'/0'/2/0
// ----------------------------------------------------------------------

static const uint8_t DERIVE_ADDRESS_shelleyTestCasesNoConfirm_019_DERIVE_ADDRESS_SHELLEY_TESTNET_REWARD_PATH_1_APDU[] = {
    0x0E, 0x00, 0x22, 0x05, 0x80, 0x00, 0x07, 0x3C, 0x80, 0x00, 0x07, 0x17, 0x80, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
};

// ----------------------------------------------------------------------
// Test type: shelleyTestCasesNoConfirm
// Test 20: Derive_address_shelley_fakenet_reward_path_2
// Address Type: REWARD_KEY
// Spending: 
// Staking: m/1852'/1815'/0'/2/0
// ----------------------------------------------------------------------

static const uint8_t DERIVE_ADDRESS_shelleyTestCasesNoConfirm_020_DERIVE_ADDRESS_SHELLEY_FAKENET_REWARD_PATH_2_APDU[] = {
    0x0E, 0x03, 0x22, 0x05, 0x80, 0x00, 0x07, 0x3C, 0x80, 0x00, 0x07, 0x17, 0x80, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
};

// ----------------------------------------------------------------------
// Test type: shelleyTestCasesNoConfirm
// Test 21: Derive_address_shelley_testnet_reward_multidelegation
// Address Type: REWARD_KEY
// Spending: 
// Staking: m/1852'/1815'/0'/2/1
// ----------------------------------------------------------------------

static const uint8_t DERIVE_ADDRESS_shelleyTestCasesNoConfirm_021_DERIVE_ADDRESS_SHELLEY_TESTNET_REWARD_MULTIDELEGATION_APDU[] = {
    0x0E, 0x00, 0x22, 0x05, 0x80, 0x00, 0x07, 0x3C, 0x80, 0x00, 0x07, 0x17, 0x80, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01,
};

// ----------------------------------------------------------------------
// Test type: shelleyTestCasesNoConfirm
// Test 22: Derive_address_shelley_testnet_reward_script_1
// Address Type: REWARD_SCRIPT
// Spending: 
// Staking: 122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277
// ----------------------------------------------------------------------

static const uint8_t DERIVE_ADDRESS_shelleyTestCasesNoConfirm_022_DERIVE_ADDRESS_SHELLEY_TESTNET_REWARD_SCRIPT_1_APDU[] = {
    0x0F, 0x00, 0x55, 0x12, 0x2A, 0x94, 0x6B, 0x9A, 0xD3, 0xD2, 0xDD, 0xF0, 0x29, 0xD3, 0xA8, 0x28,
    0xF0, 0x46, 0x8A, 0xEC, 0xE7, 0x68, 0x95, 0xF1, 0x5C, 0x9E, 0xFB, 0xD6, 0x9B, 0x42, 0x77,
};

// ----------------------------------------------------------------------
// Test type: shelleyTestCasesNoConfirm
// Test 23: Derive_address_shelley_fakenet_reward_script_2
// Address Type: REWARD_SCRIPT
// Spending: 
// Staking: 122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277
// ----------------------------------------------------------------------

static const uint8_t DERIVE_ADDRESS_shelleyTestCasesNoConfirm_023_DERIVE_ADDRESS_SHELLEY_FAKENET_REWARD_SCRIPT_2_APDU[] = {
    0x0F, 0x03, 0x55, 0x12, 0x2A, 0x94, 0x6B, 0x9A, 0xD3, 0xD2, 0xDD, 0xF0, 0x29, 0xD3, 0xA8, 0x28,
    0xF0, 0x46, 0x8A, 0xEC, 0xE7, 0x68, 0x95, 0xF1, 0x5C, 0x9E, 0xFB, 0xD6, 0x9B, 0x42, 0x77,
};

// ----------------------------------------------------------------------
// Test type: shelleyTestCasesWithConfirm
// Test 0: Derive_address_shelley_fakenet_base_path_path_unusual_spending_account
// Address Type: BASE_PAYMENT_KEY_STAKE_KEY
// Spending: m/1852'/1815'/101'/0/1
// Staking: m/1852'/1815'/0'/2/0
// ----------------------------------------------------------------------

static const uint8_t DERIVE_ADDRESS_shelleyTestCasesWithConfirm_000_DERIVE_ADDRESS_SHELLEY_FAKENET_BASE_PATH_PATH_UNUSUAL_SPENDING_ACCOUNT_APDU[] = {
    0x00, 0x03, 0x05, 0x80, 0x00, 0x07, 0x3C, 0x80, 0x00, 0x07, 0x17, 0x80, 0x00, 0x00, 0x65, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x22, 0x05, 0x80, 0x00, 0x07, 0x3C, 0x80, 0x00, 0x07,
    0x17, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
};

// ----------------------------------------------------------------------
// Test type: shelleyTestCasesWithConfirm
// Test 1: Derive_address_shelley_fakenet_base_path_path_unusual_spending_index
// Address Type: BASE_PAYMENT_KEY_STAKE_KEY
// Spending: m/1852'/1815'/1'/0/1000001
// Staking: m/1852'/1815'/0'/2/0
// ----------------------------------------------------------------------

static const uint8_t DERIVE_ADDRESS_shelleyTestCasesWithConfirm_001_DERIVE_ADDRESS_SHELLEY_FAKENET_BASE_PATH_PATH_UNUSUAL_SPENDING_INDEX_APDU[] = {
    0x00, 0x03, 0x05, 0x80, 0x00, 0x07, 0x3C, 0x80, 0x00, 0x07, 0x17, 0x80, 0x00, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x0F, 0x42, 0x41, 0x22, 0x05, 0x80, 0x00, 0x07, 0x3C, 0x80, 0x00, 0x07,
    0x17, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
};

// ----------------------------------------------------------------------
// Test type: shelleyTestCasesWithConfirm
// Test 2: Derive_address_shelley_fakenet_base_path_path_unusual_staking_account
// Address Type: BASE_PAYMENT_KEY_STAKE_KEY
// Spending: m/1852'/1815'/10'/0/4
// Staking: m/1852'/1815'/101'/2/0
// ----------------------------------------------------------------------

static const uint8_t DERIVE_ADDRESS_shelleyTestCasesWithConfirm_002_DERIVE_ADDRESS_SHELLEY_FAKENET_BASE_PATH_PATH_UNUSUAL_STAKING_ACCOUNT_APDU[] = {
    0x00, 0x03, 0x05, 0x80, 0x00, 0x07, 0x3C, 0x80, 0x00, 0x07, 0x17, 0x80, 0x00, 0x00, 0x0A, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x22, 0x05, 0x80, 0x00, 0x07, 0x3C, 0x80, 0x00, 0x07,
    0x17, 0x80, 0x00, 0x00, 0x65, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
};

// ----------------------------------------------------------------------
// Test type: shelleyTestCasesWithConfirm
// Test 3: Derive_address_shelley_fakenet_base_path_path_multidelegation_unusual_account
// Address Type: BASE_PAYMENT_KEY_STAKE_KEY
// Spending: m/1852'/1815'/0'/0/1
// Staking: m/1852'/1815'/101'/2/60
// ----------------------------------------------------------------------

static const uint8_t DERIVE_ADDRESS_shelleyTestCasesWithConfirm_003_DERIVE_ADDRESS_SHELLEY_FAKENET_BASE_PATH_PATH_MULTIDELEGATION_UNUSUAL_ACCOUNT_APDU[] = {
    0x00, 0x03, 0x05, 0x80, 0x00, 0x07, 0x3C, 0x80, 0x00, 0x07, 0x17, 0x80, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x22, 0x05, 0x80, 0x00, 0x07, 0x3C, 0x80, 0x00, 0x07,
    0x17, 0x80, 0x00, 0x00, 0x65, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x3C,
};

// ----------------------------------------------------------------------
// Test type: shelleyTestCasesWithConfirm
// Test 4: Derive_address_shelley_fakenet_base_path_path_multidelegation_unusual_index
// Address Type: BASE_PAYMENT_KEY_STAKE_KEY
// Spending: m/1852'/1815'/0'/0/1
// Staking: m/1852'/1815'/0'/2/1000001
// ----------------------------------------------------------------------

static const uint8_t DERIVE_ADDRESS_shelleyTestCasesWithConfirm_004_DERIVE_ADDRESS_SHELLEY_FAKENET_BASE_PATH_PATH_MULTIDELEGATION_UNUSUAL_INDEX_APDU[] = {
    0x00, 0x03, 0x05, 0x80, 0x00, 0x07, 0x3C, 0x80, 0x00, 0x07, 0x17, 0x80, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x22, 0x05, 0x80, 0x00, 0x07, 0x3C, 0x80, 0x00, 0x07,
    0x17, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x0F, 0x42, 0x41,
};

// ----------------------------------------------------------------------
// Test type: shelleyTestCasesWithConfirm
// Test 5: Derive_address_shelley_testnet_base_path_keyhash_unusual_account
// Address Type: BASE_PAYMENT_KEY_STAKE_KEY
// Spending: m/1852'/1815'/101'/0/1
// Staking: 1d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c
// ----------------------------------------------------------------------

static const uint8_t DERIVE_ADDRESS_shelleyTestCasesWithConfirm_005_DERIVE_ADDRESS_SHELLEY_TESTNET_BASE_PATH_KEYHASH_UNUSUAL_ACCOUNT_APDU[] = {
    0x00, 0x00, 0x05, 0x80, 0x00, 0x07, 0x3C, 0x80, 0x00, 0x07, 0x17, 0x80, 0x00, 0x00, 0x65, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x33, 0x1D, 0x22, 0x7A, 0xEF, 0xA4, 0xB7, 0x73, 0x14,
    0x91, 0x70, 0x88, 0x5A, 0xAD, 0xBA, 0x30, 0xAA, 0xB3, 0x12, 0x7C, 0xC6, 0x11, 0xDD, 0xBC, 0x49,
    0x99, 0xDE, 0xF6, 0x1C,
};

// ----------------------------------------------------------------------
// Test type: shelleyTestCasesWithConfirm
// Test 6: Derive_address_shelley_testnet_base_path_keyhash_unusual_index
// Address Type: BASE_PAYMENT_KEY_STAKE_KEY
// Spending: m/1852'/1815'/0'/0/1'
// Staking: 1d227aefa4b773149170885aadba30aab3127cc611ddbc4999def61c
// ----------------------------------------------------------------------

static const uint8_t DERIVE_ADDRESS_shelleyTestCasesWithConfirm_006_DERIVE_ADDRESS_SHELLEY_TESTNET_BASE_PATH_KEYHASH_UNUSUAL_INDEX_APDU[] = {
    0x00, 0x00, 0x05, 0x80, 0x00, 0x07, 0x3C, 0x80, 0x00, 0x07, 0x17, 0x80, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x01, 0x33, 0x1D, 0x22, 0x7A, 0xEF, 0xA4, 0xB7, 0x73, 0x14,
    0x91, 0x70, 0x88, 0x5A, 0xAD, 0xBA, 0x30, 0xAA, 0xB3, 0x12, 0x7C, 0xC6, 0x11, 0xDD, 0xBC, 0x49,
    0x99, 0xDE, 0xF6, 0x1C,
};

// ----------------------------------------------------------------------
// Test type: shelleyTestCasesWithConfirm
// Test 7: Derive_address_shelley_testnet_base_scripthash_path_unusual_account
// Address Type: BASE_PAYMENT_SCRIPT_STAKE_KEY
// Spending: 122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277
// Staking: m/1852'/1815'/200'/2/0
// ----------------------------------------------------------------------

static const uint8_t DERIVE_ADDRESS_shelleyTestCasesWithConfirm_007_DERIVE_ADDRESS_SHELLEY_TESTNET_BASE_SCRIPTHASH_PATH_UNUSUAL_ACCOUNT_APDU[] = {
    0x01, 0x00, 0x12, 0x2A, 0x94, 0x6B, 0x9A, 0xD3, 0xD2, 0xDD, 0xF0, 0x29, 0xD3, 0xA8, 0x28, 0xF0,
    0x46, 0x8A, 0xEC, 0xE7, 0x68, 0x95, 0xF1, 0x5C, 0x9E, 0xFB, 0xD6, 0x9B, 0x42, 0x77, 0x22, 0x05,
    0x80, 0x00, 0x07, 0x3C, 0x80, 0x00, 0x07, 0x17, 0x80, 0x00, 0x00, 0xC8, 0x00, 0x00, 0x00, 0x02,
    0x00, 0x00, 0x00, 0x00,
};

// ----------------------------------------------------------------------
// Test type: shelleyTestCasesWithConfirm
// Test 8: Derive_address_shelley_testnet_base_path_scripthash_unusual_account
// Address Type: BASE_PAYMENT_KEY_STAKE_SCRIPT
// Spending: m/1852'/1815'/101'/0/1
// Staking: 122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277
// ----------------------------------------------------------------------

static const uint8_t DERIVE_ADDRESS_shelleyTestCasesWithConfirm_008_DERIVE_ADDRESS_SHELLEY_TESTNET_BASE_PATH_SCRIPTHASH_UNUSUAL_ACCOUNT_APDU[] = {
    0x02, 0x00, 0x05, 0x80, 0x00, 0x07, 0x3C, 0x80, 0x00, 0x07, 0x17, 0x80, 0x00, 0x00, 0x65, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x55, 0x12, 0x2A, 0x94, 0x6B, 0x9A, 0xD3, 0xD2, 0xDD,
    0xF0, 0x29, 0xD3, 0xA8, 0x28, 0xF0, 0x46, 0x8A, 0xEC, 0xE7, 0x68, 0x95, 0xF1, 0x5C, 0x9E, 0xFB,
    0xD6, 0x9B, 0x42, 0x77,
};

// ----------------------------------------------------------------------
// Test type: shelleyTestCasesWithConfirm
// Test 9: Derive_address_shelley_testnet_base_path_scripthash_unusual_index
// Address Type: BASE_PAYMENT_KEY_STAKE_SCRIPT
// Spending: m/1852'/1815'/0'/0/1'
// Staking: 122a946b9ad3d2ddf029d3a828f0468aece76895f15c9efbd69b4277
// ----------------------------------------------------------------------

static const uint8_t DERIVE_ADDRESS_shelleyTestCasesWithConfirm_009_DERIVE_ADDRESS_SHELLEY_TESTNET_BASE_PATH_SCRIPTHASH_UNUSUAL_INDEX_APDU[] = {
    0x02, 0x00, 0x05, 0x80, 0x00, 0x07, 0x3C, 0x80, 0x00, 0x07, 0x17, 0x80, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x01, 0x55, 0x12, 0x2A, 0x94, 0x6B, 0x9A, 0xD3, 0xD2, 0xDD,
    0xF0, 0x29, 0xD3, 0xA8, 0x28, 0xF0, 0x46, 0x8A, 0xEC, 0xE7, 0x68, 0x95, 0xF1, 0x5C, 0x9E, 0xFB,
    0xD6, 0x9B, 0x42, 0x77,
};

// ----------------------------------------------------------------------
// Test type: shelleyTestCasesWithConfirm
// Test 10: Derive_address_shelley_testnet_pointer_unusual_account
// Address Type: POINTER_KEY
// Spending: m/1852'/1815'/1000'/0/1
// Staking: 000000010000000000000000
// ----------------------------------------------------------------------

static const uint8_t DERIVE_ADDRESS_shelleyTestCasesWithConfirm_010_DERIVE_ADDRESS_SHELLEY_TESTNET_POINTER_UNUSUAL_ACCOUNT_APDU[] = {
    0x04, 0x00, 0x05, 0x80, 0x00, 0x07, 0x3C, 0x80, 0x00, 0x07, 0x17, 0x80, 0x00, 0x03, 0xE8, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
};

// ----------------------------------------------------------------------
// Test type: shelleyTestCasesWithConfirm
// Test 11: Derive_address_shelley_testnet_pointer_unusual_index
// Address Type: POINTER_KEY
// Spending: m/1852'/1815'/0'/0/1'
// Staking: 000000000000000700000000
// ----------------------------------------------------------------------

static const uint8_t DERIVE_ADDRESS_shelleyTestCasesWithConfirm_011_DERIVE_ADDRESS_SHELLEY_TESTNET_POINTER_UNUSUAL_INDEX_APDU[] = {
    0x04, 0x00, 0x05, 0x80, 0x00, 0x07, 0x3C, 0x80, 0x00, 0x07, 0x17, 0x80, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07,
    0x00, 0x00, 0x00, 0x00,
};

// ----------------------------------------------------------------------
// Test type: shelleyTestCasesWithConfirm
// Test 12: Derive_address_shelley_testnet_reward_multidelegation_unusual_account
// Address Type: REWARD_KEY
// Spending: 
// Staking: m/1852'/1815'/101'/2/1
// ----------------------------------------------------------------------

static const uint8_t DERIVE_ADDRESS_shelleyTestCasesWithConfirm_012_DERIVE_ADDRESS_SHELLEY_TESTNET_REWARD_MULTIDELEGATION_UNUSUAL_ACCOUNT_APDU[] = {
    0x0E, 0x00, 0x22, 0x05, 0x80, 0x00, 0x07, 0x3C, 0x80, 0x00, 0x07, 0x17, 0x80, 0x00, 0x00, 0x65,
    0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01,
};

// ----------------------------------------------------------------------
// Test type: shelleyTestCasesWithConfirm
// Test 13: Derive_address_shelley_testnet_reward_multidelegation_unusual_index
// Address Type: REWARD_KEY
// Spending: 
// Staking: m/1852'/1815'/0'/2/20000000
// ----------------------------------------------------------------------

static const uint8_t DERIVE_ADDRESS_shelleyTestCasesWithConfirm_013_DERIVE_ADDRESS_SHELLEY_TESTNET_REWARD_MULTIDELEGATION_UNUSUAL_INDEX_APDU[] = {
    0x0E, 0x00, 0x22, 0x05, 0x80, 0x00, 0x07, 0x3C, 0x80, 0x00, 0x07, 0x17, 0x80, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x02, 0x01, 0x31, 0x2D, 0x00,
};

// ----------------------------------------------------------------------
// Test type: shelleyTestCasesWithConfirm
// Test 14: Derive_address_shelley_fakenet_reward_unusual_account
// Address Type: REWARD_KEY
// Spending: 
// Staking: m/1852'/1815'/300'/2/0
// ----------------------------------------------------------------------

static const uint8_t DERIVE_ADDRESS_shelleyTestCasesWithConfirm_014_DERIVE_ADDRESS_SHELLEY_FAKENET_REWARD_UNUSUAL_ACCOUNT_APDU[] = {
    0x0E, 0x03, 0x22, 0x05, 0x80, 0x00, 0x07, 0x3C, 0x80, 0x00, 0x07, 0x17, 0x80, 0x00, 0x01, 0x2C,
    0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
};

static const derive_address_fixture_t DERIVE_ADDRESS_FIXTURES_TEST_DERIVE_ADDRESS_BYRON[] = {
{
    .name = "Derive_address_byron_mainnet_1",
    .p1 = P1_ADDRESS_RETURN,
    .data = DERIVE_ADDRESS_byronTestCases_000_DERIVE_ADDRESS_BYRON_MAINNET_1_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_byronTestCases_000_DERIVE_ADDRESS_BYRON_MAINNET_1_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_byron_mainnet_2",
    .p1 = P1_ADDRESS_RETURN,
    .data = DERIVE_ADDRESS_byronTestCases_001_DERIVE_ADDRESS_BYRON_MAINNET_2_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_byronTestCases_001_DERIVE_ADDRESS_BYRON_MAINNET_2_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_byron_mainnet_3",
    .p1 = P1_ADDRESS_RETURN,
    .data = DERIVE_ADDRESS_byronTestCases_002_DERIVE_ADDRESS_BYRON_MAINNET_3_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_byronTestCases_002_DERIVE_ADDRESS_BYRON_MAINNET_3_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_byron_mainnet_4",
    .p1 = P1_ADDRESS_RETURN,
    .data = DERIVE_ADDRESS_byronTestCases_003_DERIVE_ADDRESS_BYRON_MAINNET_4_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_byronTestCases_003_DERIVE_ADDRESS_BYRON_MAINNET_4_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_byron_testnet_1",
    .p1 = P1_ADDRESS_RETURN,
    .data = DERIVE_ADDRESS_byronTestCases_004_DERIVE_ADDRESS_BYRON_TESTNET_1_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_byronTestCases_004_DERIVE_ADDRESS_BYRON_TESTNET_1_APDU),
    .check_expected = SWO_SUCCESS,
},
};

static const derive_address_fixture_t DERIVE_ADDRESS_FIXTURES_TEST_DERIVE_ADDRESS_BYRON_SHOW[] = {
{
    .name = "Derive_address_byron_mainnet_1",
    .p1 = P1_ADDRESS_DISPLAY,
    .data = DERIVE_ADDRESS_byronTestCases_000_DERIVE_ADDRESS_BYRON_MAINNET_1_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_byronTestCases_000_DERIVE_ADDRESS_BYRON_MAINNET_1_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_byron_mainnet_2",
    .p1 = P1_ADDRESS_DISPLAY,
    .data = DERIVE_ADDRESS_byronTestCases_001_DERIVE_ADDRESS_BYRON_MAINNET_2_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_byronTestCases_001_DERIVE_ADDRESS_BYRON_MAINNET_2_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_byron_mainnet_3",
    .p1 = P1_ADDRESS_DISPLAY,
    .data = DERIVE_ADDRESS_byronTestCases_002_DERIVE_ADDRESS_BYRON_MAINNET_3_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_byronTestCases_002_DERIVE_ADDRESS_BYRON_MAINNET_3_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_byron_mainnet_4",
    .p1 = P1_ADDRESS_DISPLAY,
    .data = DERIVE_ADDRESS_byronTestCases_003_DERIVE_ADDRESS_BYRON_MAINNET_4_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_byronTestCases_003_DERIVE_ADDRESS_BYRON_MAINNET_4_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_byron_testnet_1",
    .p1 = P1_ADDRESS_DISPLAY,
    .data = DERIVE_ADDRESS_byronTestCases_004_DERIVE_ADDRESS_BYRON_TESTNET_1_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_byronTestCases_004_DERIVE_ADDRESS_BYRON_TESTNET_1_APDU),
    .check_expected = SWO_SUCCESS,
},
};

static const derive_address_fixture_t DERIVE_ADDRESS_FIXTURES_TEST_DERIVE_ADDRESS_SHELLEY[] = {
{
    .name = "Derive_address_shelley_fakenet_base_path_path_1",
    .p1 = P1_ADDRESS_RETURN,
    .data = DERIVE_ADDRESS_shelleyTestCasesNoConfirm_000_DERIVE_ADDRESS_SHELLEY_FAKENET_BASE_PATH_PATH_1_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesNoConfirm_000_DERIVE_ADDRESS_SHELLEY_FAKENET_BASE_PATH_PATH_1_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_testnet_base_path_path_2",
    .p1 = P1_ADDRESS_RETURN,
    .data = DERIVE_ADDRESS_shelleyTestCasesNoConfirm_001_DERIVE_ADDRESS_SHELLEY_TESTNET_BASE_PATH_PATH_2_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesNoConfirm_001_DERIVE_ADDRESS_SHELLEY_TESTNET_BASE_PATH_PATH_2_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_testnet_base_path_path_multidelegation",
    .p1 = P1_ADDRESS_RETURN,
    .data = DERIVE_ADDRESS_shelleyTestCasesNoConfirm_002_DERIVE_ADDRESS_SHELLEY_TESTNET_BASE_PATH_PATH_MULTIDELEGATION_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesNoConfirm_002_DERIVE_ADDRESS_SHELLEY_TESTNET_BASE_PATH_PATH_MULTIDELEGATION_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_testnet_base_path_keyhash_1",
    .p1 = P1_ADDRESS_RETURN,
    .data = DERIVE_ADDRESS_shelleyTestCasesNoConfirm_003_DERIVE_ADDRESS_SHELLEY_TESTNET_BASE_PATH_KEYHASH_1_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesNoConfirm_003_DERIVE_ADDRESS_SHELLEY_TESTNET_BASE_PATH_KEYHASH_1_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_fakenet_base_path_keyhash_2",
    .p1 = P1_ADDRESS_RETURN,
    .data = DERIVE_ADDRESS_shelleyTestCasesNoConfirm_004_DERIVE_ADDRESS_SHELLEY_FAKENET_BASE_PATH_KEYHASH_2_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesNoConfirm_004_DERIVE_ADDRESS_SHELLEY_FAKENET_BASE_PATH_KEYHASH_2_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_fakenet_base_scripthash_path",
    .p1 = P1_ADDRESS_RETURN,
    .data = DERIVE_ADDRESS_shelleyTestCasesNoConfirm_005_DERIVE_ADDRESS_SHELLEY_FAKENET_BASE_SCRIPTHASH_PATH_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesNoConfirm_005_DERIVE_ADDRESS_SHELLEY_FAKENET_BASE_SCRIPTHASH_PATH_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_fakenet_base_scripthash_path_multidelegation",
    .p1 = P1_ADDRESS_RETURN,
    .data = DERIVE_ADDRESS_shelleyTestCasesNoConfirm_006_DERIVE_ADDRESS_SHELLEY_FAKENET_BASE_SCRIPTHASH_PATH_MULTIDELEGATION_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesNoConfirm_006_DERIVE_ADDRESS_SHELLEY_FAKENET_BASE_SCRIPTHASH_PATH_MULTIDELEGATION_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_fakenet_base_path_scripthash",
    .p1 = P1_ADDRESS_RETURN,
    .data = DERIVE_ADDRESS_shelleyTestCasesNoConfirm_007_DERIVE_ADDRESS_SHELLEY_FAKENET_BASE_PATH_SCRIPTHASH_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesNoConfirm_007_DERIVE_ADDRESS_SHELLEY_FAKENET_BASE_PATH_SCRIPTHASH_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_fakenet_base_scripthash_scripthash",
    .p1 = P1_ADDRESS_RETURN,
    .data = DERIVE_ADDRESS_shelleyTestCasesNoConfirm_008_DERIVE_ADDRESS_SHELLEY_FAKENET_BASE_SCRIPTHASH_SCRIPTHASH_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesNoConfirm_008_DERIVE_ADDRESS_SHELLEY_FAKENET_BASE_SCRIPTHASH_SCRIPTHASH_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_testnet_enterprise_path_1",
    .p1 = P1_ADDRESS_RETURN,
    .data = DERIVE_ADDRESS_shelleyTestCasesNoConfirm_009_DERIVE_ADDRESS_SHELLEY_TESTNET_ENTERPRISE_PATH_1_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesNoConfirm_009_DERIVE_ADDRESS_SHELLEY_TESTNET_ENTERPRISE_PATH_1_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_fakenet_enterprise_path_2",
    .p1 = P1_ADDRESS_RETURN,
    .data = DERIVE_ADDRESS_shelleyTestCasesNoConfirm_010_DERIVE_ADDRESS_SHELLEY_FAKENET_ENTERPRISE_PATH_2_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesNoConfirm_010_DERIVE_ADDRESS_SHELLEY_FAKENET_ENTERPRISE_PATH_2_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_testnet_enterprise_script_1",
    .p1 = P1_ADDRESS_RETURN,
    .data = DERIVE_ADDRESS_shelleyTestCasesNoConfirm_011_DERIVE_ADDRESS_SHELLEY_TESTNET_ENTERPRISE_SCRIPT_1_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesNoConfirm_011_DERIVE_ADDRESS_SHELLEY_TESTNET_ENTERPRISE_SCRIPT_1_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_fakenet_enterprise_script_2",
    .p1 = P1_ADDRESS_RETURN,
    .data = DERIVE_ADDRESS_shelleyTestCasesNoConfirm_012_DERIVE_ADDRESS_SHELLEY_FAKENET_ENTERPRISE_SCRIPT_2_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesNoConfirm_012_DERIVE_ADDRESS_SHELLEY_FAKENET_ENTERPRISE_SCRIPT_2_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_testnet_pointer_path_1",
    .p1 = P1_ADDRESS_RETURN,
    .data = DERIVE_ADDRESS_shelleyTestCasesNoConfirm_013_DERIVE_ADDRESS_SHELLEY_TESTNET_POINTER_PATH_1_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesNoConfirm_013_DERIVE_ADDRESS_SHELLEY_TESTNET_POINTER_PATH_1_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_fakenet_pointer_path_2",
    .p1 = P1_ADDRESS_RETURN,
    .data = DERIVE_ADDRESS_shelleyTestCasesNoConfirm_014_DERIVE_ADDRESS_SHELLEY_FAKENET_POINTER_PATH_2_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesNoConfirm_014_DERIVE_ADDRESS_SHELLEY_FAKENET_POINTER_PATH_2_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_fakenet_pointer_path_3",
    .p1 = P1_ADDRESS_RETURN,
    .data = DERIVE_ADDRESS_shelleyTestCasesNoConfirm_015_DERIVE_ADDRESS_SHELLEY_FAKENET_POINTER_PATH_3_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesNoConfirm_015_DERIVE_ADDRESS_SHELLEY_FAKENET_POINTER_PATH_3_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_testnet_pointer_script_1",
    .p1 = P1_ADDRESS_RETURN,
    .data = DERIVE_ADDRESS_shelleyTestCasesNoConfirm_016_DERIVE_ADDRESS_SHELLEY_TESTNET_POINTER_SCRIPT_1_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesNoConfirm_016_DERIVE_ADDRESS_SHELLEY_TESTNET_POINTER_SCRIPT_1_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_fakenet_pointer_script_2",
    .p1 = P1_ADDRESS_RETURN,
    .data = DERIVE_ADDRESS_shelleyTestCasesNoConfirm_017_DERIVE_ADDRESS_SHELLEY_FAKENET_POINTER_SCRIPT_2_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesNoConfirm_017_DERIVE_ADDRESS_SHELLEY_FAKENET_POINTER_SCRIPT_2_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_fakenet_pointer_script_3",
    .p1 = P1_ADDRESS_RETURN,
    .data = DERIVE_ADDRESS_shelleyTestCasesNoConfirm_018_DERIVE_ADDRESS_SHELLEY_FAKENET_POINTER_SCRIPT_3_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesNoConfirm_018_DERIVE_ADDRESS_SHELLEY_FAKENET_POINTER_SCRIPT_3_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_testnet_reward_path_1",
    .p1 = P1_ADDRESS_RETURN,
    .data = DERIVE_ADDRESS_shelleyTestCasesNoConfirm_019_DERIVE_ADDRESS_SHELLEY_TESTNET_REWARD_PATH_1_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesNoConfirm_019_DERIVE_ADDRESS_SHELLEY_TESTNET_REWARD_PATH_1_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_fakenet_reward_path_2",
    .p1 = P1_ADDRESS_RETURN,
    .data = DERIVE_ADDRESS_shelleyTestCasesNoConfirm_020_DERIVE_ADDRESS_SHELLEY_FAKENET_REWARD_PATH_2_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesNoConfirm_020_DERIVE_ADDRESS_SHELLEY_FAKENET_REWARD_PATH_2_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_testnet_reward_multidelegation",
    .p1 = P1_ADDRESS_RETURN,
    .data = DERIVE_ADDRESS_shelleyTestCasesNoConfirm_021_DERIVE_ADDRESS_SHELLEY_TESTNET_REWARD_MULTIDELEGATION_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesNoConfirm_021_DERIVE_ADDRESS_SHELLEY_TESTNET_REWARD_MULTIDELEGATION_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_testnet_reward_script_1",
    .p1 = P1_ADDRESS_RETURN,
    .data = DERIVE_ADDRESS_shelleyTestCasesNoConfirm_022_DERIVE_ADDRESS_SHELLEY_TESTNET_REWARD_SCRIPT_1_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesNoConfirm_022_DERIVE_ADDRESS_SHELLEY_TESTNET_REWARD_SCRIPT_1_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_fakenet_reward_script_2",
    .p1 = P1_ADDRESS_RETURN,
    .data = DERIVE_ADDRESS_shelleyTestCasesNoConfirm_023_DERIVE_ADDRESS_SHELLEY_FAKENET_REWARD_SCRIPT_2_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesNoConfirm_023_DERIVE_ADDRESS_SHELLEY_FAKENET_REWARD_SCRIPT_2_APDU),
    .check_expected = SWO_SUCCESS,
},
};

static const derive_address_fixture_t DERIVE_ADDRESS_FIXTURES_TEST_DERIVE_ADDRESS_SHELLEY_CONFIRM[] = {
{
    .name = "Derive_address_shelley_fakenet_base_path_path_unusual_spending_account",
    .p1 = P1_ADDRESS_RETURN,
    .data = DERIVE_ADDRESS_shelleyTestCasesWithConfirm_000_DERIVE_ADDRESS_SHELLEY_FAKENET_BASE_PATH_PATH_UNUSUAL_SPENDING_ACCOUNT_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesWithConfirm_000_DERIVE_ADDRESS_SHELLEY_FAKENET_BASE_PATH_PATH_UNUSUAL_SPENDING_ACCOUNT_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_fakenet_base_path_path_unusual_spending_index",
    .p1 = P1_ADDRESS_RETURN,
    .data = DERIVE_ADDRESS_shelleyTestCasesWithConfirm_001_DERIVE_ADDRESS_SHELLEY_FAKENET_BASE_PATH_PATH_UNUSUAL_SPENDING_INDEX_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesWithConfirm_001_DERIVE_ADDRESS_SHELLEY_FAKENET_BASE_PATH_PATH_UNUSUAL_SPENDING_INDEX_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_fakenet_base_path_path_unusual_staking_account",
    .p1 = P1_ADDRESS_RETURN,
    .data = DERIVE_ADDRESS_shelleyTestCasesWithConfirm_002_DERIVE_ADDRESS_SHELLEY_FAKENET_BASE_PATH_PATH_UNUSUAL_STAKING_ACCOUNT_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesWithConfirm_002_DERIVE_ADDRESS_SHELLEY_FAKENET_BASE_PATH_PATH_UNUSUAL_STAKING_ACCOUNT_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_fakenet_base_path_path_multidelegation_unusual_account",
    .p1 = P1_ADDRESS_RETURN,
    .data = DERIVE_ADDRESS_shelleyTestCasesWithConfirm_003_DERIVE_ADDRESS_SHELLEY_FAKENET_BASE_PATH_PATH_MULTIDELEGATION_UNUSUAL_ACCOUNT_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesWithConfirm_003_DERIVE_ADDRESS_SHELLEY_FAKENET_BASE_PATH_PATH_MULTIDELEGATION_UNUSUAL_ACCOUNT_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_fakenet_base_path_path_multidelegation_unusual_index",
    .p1 = P1_ADDRESS_RETURN,
    .data = DERIVE_ADDRESS_shelleyTestCasesWithConfirm_004_DERIVE_ADDRESS_SHELLEY_FAKENET_BASE_PATH_PATH_MULTIDELEGATION_UNUSUAL_INDEX_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesWithConfirm_004_DERIVE_ADDRESS_SHELLEY_FAKENET_BASE_PATH_PATH_MULTIDELEGATION_UNUSUAL_INDEX_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_testnet_base_path_keyhash_unusual_account",
    .p1 = P1_ADDRESS_RETURN,
    .data = DERIVE_ADDRESS_shelleyTestCasesWithConfirm_005_DERIVE_ADDRESS_SHELLEY_TESTNET_BASE_PATH_KEYHASH_UNUSUAL_ACCOUNT_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesWithConfirm_005_DERIVE_ADDRESS_SHELLEY_TESTNET_BASE_PATH_KEYHASH_UNUSUAL_ACCOUNT_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_testnet_base_path_keyhash_unusual_index",
    .p1 = P1_ADDRESS_RETURN,
    .data = DERIVE_ADDRESS_shelleyTestCasesWithConfirm_006_DERIVE_ADDRESS_SHELLEY_TESTNET_BASE_PATH_KEYHASH_UNUSUAL_INDEX_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesWithConfirm_006_DERIVE_ADDRESS_SHELLEY_TESTNET_BASE_PATH_KEYHASH_UNUSUAL_INDEX_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_testnet_base_scripthash_path_unusual_account",
    .p1 = P1_ADDRESS_RETURN,
    .data = DERIVE_ADDRESS_shelleyTestCasesWithConfirm_007_DERIVE_ADDRESS_SHELLEY_TESTNET_BASE_SCRIPTHASH_PATH_UNUSUAL_ACCOUNT_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesWithConfirm_007_DERIVE_ADDRESS_SHELLEY_TESTNET_BASE_SCRIPTHASH_PATH_UNUSUAL_ACCOUNT_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_testnet_base_path_scripthash_unusual_account",
    .p1 = P1_ADDRESS_RETURN,
    .data = DERIVE_ADDRESS_shelleyTestCasesWithConfirm_008_DERIVE_ADDRESS_SHELLEY_TESTNET_BASE_PATH_SCRIPTHASH_UNUSUAL_ACCOUNT_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesWithConfirm_008_DERIVE_ADDRESS_SHELLEY_TESTNET_BASE_PATH_SCRIPTHASH_UNUSUAL_ACCOUNT_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_testnet_base_path_scripthash_unusual_index",
    .p1 = P1_ADDRESS_RETURN,
    .data = DERIVE_ADDRESS_shelleyTestCasesWithConfirm_009_DERIVE_ADDRESS_SHELLEY_TESTNET_BASE_PATH_SCRIPTHASH_UNUSUAL_INDEX_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesWithConfirm_009_DERIVE_ADDRESS_SHELLEY_TESTNET_BASE_PATH_SCRIPTHASH_UNUSUAL_INDEX_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_testnet_pointer_unusual_account",
    .p1 = P1_ADDRESS_RETURN,
    .data = DERIVE_ADDRESS_shelleyTestCasesWithConfirm_010_DERIVE_ADDRESS_SHELLEY_TESTNET_POINTER_UNUSUAL_ACCOUNT_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesWithConfirm_010_DERIVE_ADDRESS_SHELLEY_TESTNET_POINTER_UNUSUAL_ACCOUNT_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_testnet_pointer_unusual_index",
    .p1 = P1_ADDRESS_RETURN,
    .data = DERIVE_ADDRESS_shelleyTestCasesWithConfirm_011_DERIVE_ADDRESS_SHELLEY_TESTNET_POINTER_UNUSUAL_INDEX_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesWithConfirm_011_DERIVE_ADDRESS_SHELLEY_TESTNET_POINTER_UNUSUAL_INDEX_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_testnet_reward_multidelegation_unusual_account",
    .p1 = P1_ADDRESS_RETURN,
    .data = DERIVE_ADDRESS_shelleyTestCasesWithConfirm_012_DERIVE_ADDRESS_SHELLEY_TESTNET_REWARD_MULTIDELEGATION_UNUSUAL_ACCOUNT_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesWithConfirm_012_DERIVE_ADDRESS_SHELLEY_TESTNET_REWARD_MULTIDELEGATION_UNUSUAL_ACCOUNT_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_testnet_reward_multidelegation_unusual_index",
    .p1 = P1_ADDRESS_RETURN,
    .data = DERIVE_ADDRESS_shelleyTestCasesWithConfirm_013_DERIVE_ADDRESS_SHELLEY_TESTNET_REWARD_MULTIDELEGATION_UNUSUAL_INDEX_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesWithConfirm_013_DERIVE_ADDRESS_SHELLEY_TESTNET_REWARD_MULTIDELEGATION_UNUSUAL_INDEX_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_fakenet_reward_unusual_account",
    .p1 = P1_ADDRESS_RETURN,
    .data = DERIVE_ADDRESS_shelleyTestCasesWithConfirm_014_DERIVE_ADDRESS_SHELLEY_FAKENET_REWARD_UNUSUAL_ACCOUNT_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesWithConfirm_014_DERIVE_ADDRESS_SHELLEY_FAKENET_REWARD_UNUSUAL_ACCOUNT_APDU),
    .check_expected = SWO_SUCCESS,
},
};

static const derive_address_fixture_t DERIVE_ADDRESS_FIXTURES_TEST_DERIVE_ADDRESS_SHELLEY_SHOW_NO_CONFIRM[] = {
{
    .name = "Derive_address_shelley_fakenet_base_path_path_1",
    .p1 = P1_ADDRESS_DISPLAY,
    .data = DERIVE_ADDRESS_shelleyTestCasesNoConfirm_000_DERIVE_ADDRESS_SHELLEY_FAKENET_BASE_PATH_PATH_1_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesNoConfirm_000_DERIVE_ADDRESS_SHELLEY_FAKENET_BASE_PATH_PATH_1_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_testnet_base_path_path_2",
    .p1 = P1_ADDRESS_DISPLAY,
    .data = DERIVE_ADDRESS_shelleyTestCasesNoConfirm_001_DERIVE_ADDRESS_SHELLEY_TESTNET_BASE_PATH_PATH_2_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesNoConfirm_001_DERIVE_ADDRESS_SHELLEY_TESTNET_BASE_PATH_PATH_2_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_testnet_base_path_path_multidelegation",
    .p1 = P1_ADDRESS_DISPLAY,
    .data = DERIVE_ADDRESS_shelleyTestCasesNoConfirm_002_DERIVE_ADDRESS_SHELLEY_TESTNET_BASE_PATH_PATH_MULTIDELEGATION_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesNoConfirm_002_DERIVE_ADDRESS_SHELLEY_TESTNET_BASE_PATH_PATH_MULTIDELEGATION_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_testnet_base_path_keyhash_1",
    .p1 = P1_ADDRESS_DISPLAY,
    .data = DERIVE_ADDRESS_shelleyTestCasesNoConfirm_003_DERIVE_ADDRESS_SHELLEY_TESTNET_BASE_PATH_KEYHASH_1_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesNoConfirm_003_DERIVE_ADDRESS_SHELLEY_TESTNET_BASE_PATH_KEYHASH_1_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_fakenet_base_path_keyhash_2",
    .p1 = P1_ADDRESS_DISPLAY,
    .data = DERIVE_ADDRESS_shelleyTestCasesNoConfirm_004_DERIVE_ADDRESS_SHELLEY_FAKENET_BASE_PATH_KEYHASH_2_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesNoConfirm_004_DERIVE_ADDRESS_SHELLEY_FAKENET_BASE_PATH_KEYHASH_2_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_fakenet_base_scripthash_path",
    .p1 = P1_ADDRESS_DISPLAY,
    .data = DERIVE_ADDRESS_shelleyTestCasesNoConfirm_005_DERIVE_ADDRESS_SHELLEY_FAKENET_BASE_SCRIPTHASH_PATH_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesNoConfirm_005_DERIVE_ADDRESS_SHELLEY_FAKENET_BASE_SCRIPTHASH_PATH_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_fakenet_base_scripthash_path_multidelegation",
    .p1 = P1_ADDRESS_DISPLAY,
    .data = DERIVE_ADDRESS_shelleyTestCasesNoConfirm_006_DERIVE_ADDRESS_SHELLEY_FAKENET_BASE_SCRIPTHASH_PATH_MULTIDELEGATION_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesNoConfirm_006_DERIVE_ADDRESS_SHELLEY_FAKENET_BASE_SCRIPTHASH_PATH_MULTIDELEGATION_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_fakenet_base_path_scripthash",
    .p1 = P1_ADDRESS_DISPLAY,
    .data = DERIVE_ADDRESS_shelleyTestCasesNoConfirm_007_DERIVE_ADDRESS_SHELLEY_FAKENET_BASE_PATH_SCRIPTHASH_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesNoConfirm_007_DERIVE_ADDRESS_SHELLEY_FAKENET_BASE_PATH_SCRIPTHASH_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_fakenet_base_scripthash_scripthash",
    .p1 = P1_ADDRESS_DISPLAY,
    .data = DERIVE_ADDRESS_shelleyTestCasesNoConfirm_008_DERIVE_ADDRESS_SHELLEY_FAKENET_BASE_SCRIPTHASH_SCRIPTHASH_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesNoConfirm_008_DERIVE_ADDRESS_SHELLEY_FAKENET_BASE_SCRIPTHASH_SCRIPTHASH_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_testnet_enterprise_path_1",
    .p1 = P1_ADDRESS_DISPLAY,
    .data = DERIVE_ADDRESS_shelleyTestCasesNoConfirm_009_DERIVE_ADDRESS_SHELLEY_TESTNET_ENTERPRISE_PATH_1_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesNoConfirm_009_DERIVE_ADDRESS_SHELLEY_TESTNET_ENTERPRISE_PATH_1_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_fakenet_enterprise_path_2",
    .p1 = P1_ADDRESS_DISPLAY,
    .data = DERIVE_ADDRESS_shelleyTestCasesNoConfirm_010_DERIVE_ADDRESS_SHELLEY_FAKENET_ENTERPRISE_PATH_2_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesNoConfirm_010_DERIVE_ADDRESS_SHELLEY_FAKENET_ENTERPRISE_PATH_2_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_testnet_enterprise_script_1",
    .p1 = P1_ADDRESS_DISPLAY,
    .data = DERIVE_ADDRESS_shelleyTestCasesNoConfirm_011_DERIVE_ADDRESS_SHELLEY_TESTNET_ENTERPRISE_SCRIPT_1_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesNoConfirm_011_DERIVE_ADDRESS_SHELLEY_TESTNET_ENTERPRISE_SCRIPT_1_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_fakenet_enterprise_script_2",
    .p1 = P1_ADDRESS_DISPLAY,
    .data = DERIVE_ADDRESS_shelleyTestCasesNoConfirm_012_DERIVE_ADDRESS_SHELLEY_FAKENET_ENTERPRISE_SCRIPT_2_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesNoConfirm_012_DERIVE_ADDRESS_SHELLEY_FAKENET_ENTERPRISE_SCRIPT_2_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_testnet_pointer_path_1",
    .p1 = P1_ADDRESS_DISPLAY,
    .data = DERIVE_ADDRESS_shelleyTestCasesNoConfirm_013_DERIVE_ADDRESS_SHELLEY_TESTNET_POINTER_PATH_1_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesNoConfirm_013_DERIVE_ADDRESS_SHELLEY_TESTNET_POINTER_PATH_1_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_fakenet_pointer_path_2",
    .p1 = P1_ADDRESS_DISPLAY,
    .data = DERIVE_ADDRESS_shelleyTestCasesNoConfirm_014_DERIVE_ADDRESS_SHELLEY_FAKENET_POINTER_PATH_2_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesNoConfirm_014_DERIVE_ADDRESS_SHELLEY_FAKENET_POINTER_PATH_2_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_fakenet_pointer_path_3",
    .p1 = P1_ADDRESS_DISPLAY,
    .data = DERIVE_ADDRESS_shelleyTestCasesNoConfirm_015_DERIVE_ADDRESS_SHELLEY_FAKENET_POINTER_PATH_3_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesNoConfirm_015_DERIVE_ADDRESS_SHELLEY_FAKENET_POINTER_PATH_3_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_testnet_pointer_script_1",
    .p1 = P1_ADDRESS_DISPLAY,
    .data = DERIVE_ADDRESS_shelleyTestCasesNoConfirm_016_DERIVE_ADDRESS_SHELLEY_TESTNET_POINTER_SCRIPT_1_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesNoConfirm_016_DERIVE_ADDRESS_SHELLEY_TESTNET_POINTER_SCRIPT_1_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_fakenet_pointer_script_2",
    .p1 = P1_ADDRESS_DISPLAY,
    .data = DERIVE_ADDRESS_shelleyTestCasesNoConfirm_017_DERIVE_ADDRESS_SHELLEY_FAKENET_POINTER_SCRIPT_2_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesNoConfirm_017_DERIVE_ADDRESS_SHELLEY_FAKENET_POINTER_SCRIPT_2_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_fakenet_pointer_script_3",
    .p1 = P1_ADDRESS_DISPLAY,
    .data = DERIVE_ADDRESS_shelleyTestCasesNoConfirm_018_DERIVE_ADDRESS_SHELLEY_FAKENET_POINTER_SCRIPT_3_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesNoConfirm_018_DERIVE_ADDRESS_SHELLEY_FAKENET_POINTER_SCRIPT_3_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_testnet_reward_path_1",
    .p1 = P1_ADDRESS_DISPLAY,
    .data = DERIVE_ADDRESS_shelleyTestCasesNoConfirm_019_DERIVE_ADDRESS_SHELLEY_TESTNET_REWARD_PATH_1_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesNoConfirm_019_DERIVE_ADDRESS_SHELLEY_TESTNET_REWARD_PATH_1_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_fakenet_reward_path_2",
    .p1 = P1_ADDRESS_DISPLAY,
    .data = DERIVE_ADDRESS_shelleyTestCasesNoConfirm_020_DERIVE_ADDRESS_SHELLEY_FAKENET_REWARD_PATH_2_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesNoConfirm_020_DERIVE_ADDRESS_SHELLEY_FAKENET_REWARD_PATH_2_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_testnet_reward_multidelegation",
    .p1 = P1_ADDRESS_DISPLAY,
    .data = DERIVE_ADDRESS_shelleyTestCasesNoConfirm_021_DERIVE_ADDRESS_SHELLEY_TESTNET_REWARD_MULTIDELEGATION_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesNoConfirm_021_DERIVE_ADDRESS_SHELLEY_TESTNET_REWARD_MULTIDELEGATION_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_testnet_reward_script_1",
    .p1 = P1_ADDRESS_DISPLAY,
    .data = DERIVE_ADDRESS_shelleyTestCasesNoConfirm_022_DERIVE_ADDRESS_SHELLEY_TESTNET_REWARD_SCRIPT_1_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesNoConfirm_022_DERIVE_ADDRESS_SHELLEY_TESTNET_REWARD_SCRIPT_1_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_fakenet_reward_script_2",
    .p1 = P1_ADDRESS_DISPLAY,
    .data = DERIVE_ADDRESS_shelleyTestCasesNoConfirm_023_DERIVE_ADDRESS_SHELLEY_FAKENET_REWARD_SCRIPT_2_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesNoConfirm_023_DERIVE_ADDRESS_SHELLEY_FAKENET_REWARD_SCRIPT_2_APDU),
    .check_expected = SWO_SUCCESS,
},
};

static const derive_address_fixture_t DERIVE_ADDRESS_FIXTURES_TEST_DERIVE_ADDRESS_SHELLEY_SHOW_WITH_CONFIRM[] = {
{
    .name = "Derive_address_shelley_fakenet_base_path_path_unusual_spending_account",
    .p1 = P1_ADDRESS_DISPLAY,
    .data = DERIVE_ADDRESS_shelleyTestCasesWithConfirm_000_DERIVE_ADDRESS_SHELLEY_FAKENET_BASE_PATH_PATH_UNUSUAL_SPENDING_ACCOUNT_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesWithConfirm_000_DERIVE_ADDRESS_SHELLEY_FAKENET_BASE_PATH_PATH_UNUSUAL_SPENDING_ACCOUNT_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_fakenet_base_path_path_unusual_spending_index",
    .p1 = P1_ADDRESS_DISPLAY,
    .data = DERIVE_ADDRESS_shelleyTestCasesWithConfirm_001_DERIVE_ADDRESS_SHELLEY_FAKENET_BASE_PATH_PATH_UNUSUAL_SPENDING_INDEX_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesWithConfirm_001_DERIVE_ADDRESS_SHELLEY_FAKENET_BASE_PATH_PATH_UNUSUAL_SPENDING_INDEX_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_fakenet_base_path_path_unusual_staking_account",
    .p1 = P1_ADDRESS_DISPLAY,
    .data = DERIVE_ADDRESS_shelleyTestCasesWithConfirm_002_DERIVE_ADDRESS_SHELLEY_FAKENET_BASE_PATH_PATH_UNUSUAL_STAKING_ACCOUNT_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesWithConfirm_002_DERIVE_ADDRESS_SHELLEY_FAKENET_BASE_PATH_PATH_UNUSUAL_STAKING_ACCOUNT_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_fakenet_base_path_path_multidelegation_unusual_account",
    .p1 = P1_ADDRESS_DISPLAY,
    .data = DERIVE_ADDRESS_shelleyTestCasesWithConfirm_003_DERIVE_ADDRESS_SHELLEY_FAKENET_BASE_PATH_PATH_MULTIDELEGATION_UNUSUAL_ACCOUNT_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesWithConfirm_003_DERIVE_ADDRESS_SHELLEY_FAKENET_BASE_PATH_PATH_MULTIDELEGATION_UNUSUAL_ACCOUNT_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_fakenet_base_path_path_multidelegation_unusual_index",
    .p1 = P1_ADDRESS_DISPLAY,
    .data = DERIVE_ADDRESS_shelleyTestCasesWithConfirm_004_DERIVE_ADDRESS_SHELLEY_FAKENET_BASE_PATH_PATH_MULTIDELEGATION_UNUSUAL_INDEX_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesWithConfirm_004_DERIVE_ADDRESS_SHELLEY_FAKENET_BASE_PATH_PATH_MULTIDELEGATION_UNUSUAL_INDEX_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_testnet_base_path_keyhash_unusual_account",
    .p1 = P1_ADDRESS_DISPLAY,
    .data = DERIVE_ADDRESS_shelleyTestCasesWithConfirm_005_DERIVE_ADDRESS_SHELLEY_TESTNET_BASE_PATH_KEYHASH_UNUSUAL_ACCOUNT_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesWithConfirm_005_DERIVE_ADDRESS_SHELLEY_TESTNET_BASE_PATH_KEYHASH_UNUSUAL_ACCOUNT_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_testnet_base_path_keyhash_unusual_index",
    .p1 = P1_ADDRESS_DISPLAY,
    .data = DERIVE_ADDRESS_shelleyTestCasesWithConfirm_006_DERIVE_ADDRESS_SHELLEY_TESTNET_BASE_PATH_KEYHASH_UNUSUAL_INDEX_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesWithConfirm_006_DERIVE_ADDRESS_SHELLEY_TESTNET_BASE_PATH_KEYHASH_UNUSUAL_INDEX_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_testnet_base_scripthash_path_unusual_account",
    .p1 = P1_ADDRESS_DISPLAY,
    .data = DERIVE_ADDRESS_shelleyTestCasesWithConfirm_007_DERIVE_ADDRESS_SHELLEY_TESTNET_BASE_SCRIPTHASH_PATH_UNUSUAL_ACCOUNT_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesWithConfirm_007_DERIVE_ADDRESS_SHELLEY_TESTNET_BASE_SCRIPTHASH_PATH_UNUSUAL_ACCOUNT_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_testnet_base_path_scripthash_unusual_account",
    .p1 = P1_ADDRESS_DISPLAY,
    .data = DERIVE_ADDRESS_shelleyTestCasesWithConfirm_008_DERIVE_ADDRESS_SHELLEY_TESTNET_BASE_PATH_SCRIPTHASH_UNUSUAL_ACCOUNT_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesWithConfirm_008_DERIVE_ADDRESS_SHELLEY_TESTNET_BASE_PATH_SCRIPTHASH_UNUSUAL_ACCOUNT_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_testnet_base_path_scripthash_unusual_index",
    .p1 = P1_ADDRESS_DISPLAY,
    .data = DERIVE_ADDRESS_shelleyTestCasesWithConfirm_009_DERIVE_ADDRESS_SHELLEY_TESTNET_BASE_PATH_SCRIPTHASH_UNUSUAL_INDEX_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesWithConfirm_009_DERIVE_ADDRESS_SHELLEY_TESTNET_BASE_PATH_SCRIPTHASH_UNUSUAL_INDEX_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_testnet_pointer_unusual_account",
    .p1 = P1_ADDRESS_DISPLAY,
    .data = DERIVE_ADDRESS_shelleyTestCasesWithConfirm_010_DERIVE_ADDRESS_SHELLEY_TESTNET_POINTER_UNUSUAL_ACCOUNT_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesWithConfirm_010_DERIVE_ADDRESS_SHELLEY_TESTNET_POINTER_UNUSUAL_ACCOUNT_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_testnet_pointer_unusual_index",
    .p1 = P1_ADDRESS_DISPLAY,
    .data = DERIVE_ADDRESS_shelleyTestCasesWithConfirm_011_DERIVE_ADDRESS_SHELLEY_TESTNET_POINTER_UNUSUAL_INDEX_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesWithConfirm_011_DERIVE_ADDRESS_SHELLEY_TESTNET_POINTER_UNUSUAL_INDEX_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_testnet_reward_multidelegation_unusual_account",
    .p1 = P1_ADDRESS_DISPLAY,
    .data = DERIVE_ADDRESS_shelleyTestCasesWithConfirm_012_DERIVE_ADDRESS_SHELLEY_TESTNET_REWARD_MULTIDELEGATION_UNUSUAL_ACCOUNT_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesWithConfirm_012_DERIVE_ADDRESS_SHELLEY_TESTNET_REWARD_MULTIDELEGATION_UNUSUAL_ACCOUNT_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_testnet_reward_multidelegation_unusual_index",
    .p1 = P1_ADDRESS_DISPLAY,
    .data = DERIVE_ADDRESS_shelleyTestCasesWithConfirm_013_DERIVE_ADDRESS_SHELLEY_TESTNET_REWARD_MULTIDELEGATION_UNUSUAL_INDEX_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesWithConfirm_013_DERIVE_ADDRESS_SHELLEY_TESTNET_REWARD_MULTIDELEGATION_UNUSUAL_INDEX_APDU),
    .check_expected = SWO_SUCCESS,
},
{
    .name = "Derive_address_shelley_fakenet_reward_unusual_account",
    .p1 = P1_ADDRESS_DISPLAY,
    .data = DERIVE_ADDRESS_shelleyTestCasesWithConfirm_014_DERIVE_ADDRESS_SHELLEY_FAKENET_REWARD_UNUSUAL_ACCOUNT_APDU,
    .data_len = sizeof(DERIVE_ADDRESS_shelleyTestCasesWithConfirm_014_DERIVE_ADDRESS_SHELLEY_FAKENET_REWARD_UNUSUAL_ACCOUNT_APDU),
    .check_expected = SWO_SUCCESS,
},
};
