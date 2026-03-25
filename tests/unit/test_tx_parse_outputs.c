/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "tx_parse_outputs.h"
#include "cardano_constants.h"
#include "cardano_swo.h"

// ---------------------------------------------------------------------------
// parse_output_destination
// ---------------------------------------------------------------------------

static void test_parse_output_destination_truncated_type(void **state) {
    (void) state;
    uint8_t buf_data[1] = {0};
    buffer_t buf = {.ptr = buf_data, .size = 0, .offset = 0};
    tx_output_destination_t dest;
    assert_int_not_equal(parse_output_destination(&buf, &dest), SWO_OK);
}

static void test_parse_output_destination_truncated_address_size(void **state) {
    (void) state;
    // Type = DESTINATION_THIRD_PARTY=1, but no address-size u16 follows.
    uint8_t buf_data[1] = {DESTINATION_THIRD_PARTY};
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    tx_output_destination_t dest;
    assert_int_not_equal(parse_output_destination(&buf, &dest), SWO_OK);
}

static void test_parse_output_destination_zero_address_size(void **state) {
    (void) state;
    // address_size = 0 must be rejected.
    uint8_t buf_data[3] = {DESTINATION_THIRD_PARTY, 0x00, 0x00};
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    tx_output_destination_t dest;
    assert_int_not_equal(parse_output_destination(&buf, &dest), SWO_OK);
}

static void test_parse_output_destination_address_size_too_large(void **state) {
    (void) state;
    // address_size = MAX_ADDRESS_LENGTH + 1.
    uint16_t bad_size = MAX_ADDRESS_LENGTH + 1;
    uint8_t buf_data[3] = {
        DESTINATION_THIRD_PARTY,
        (uint8_t)(bad_size >> 8),
        (uint8_t)(bad_size & 0xFF),
    };
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    tx_output_destination_t dest;
    assert_int_not_equal(parse_output_destination(&buf, &dest), SWO_OK);
}

static void test_parse_output_destination_truncated_address_bytes(void **state) {
    (void) state;
    // address_size = 5, but only 2 bytes follow.
    uint8_t buf_data[5] = {DESTINATION_THIRD_PARTY, 0x00, 0x05, 0xAA, 0xBB};
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    tx_output_destination_t dest;
    assert_int_not_equal(parse_output_destination(&buf, &dest), SWO_OK);
}

static void test_parse_output_destination_unknown_type(void **state) {
    (void) state;
    uint8_t buf_data[1] = {0xFF};
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    tx_output_destination_t dest;
    assert_int_not_equal(parse_output_destination(&buf, &dest), SWO_OK);
}

// ---------------------------------------------------------------------------
// parse_output_format
// ---------------------------------------------------------------------------

static void test_parse_output_format_truncated(void **state) {
    (void) state;
    uint8_t buf_data[1] = {0};
    buffer_t buf = {.ptr = buf_data, .size = 0, .offset = 0};
    tx_output_serialization_format_t fmt;
    assert_int_not_equal(
        parse_output_format(&buf, &fmt, SWO_TX_PARSING_FAIL_OUTPUTS), SWO_OK);
}

static void test_parse_output_format_unknown(void **state) {
    (void) state;
    uint8_t buf_data[1] = {0xFF};
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    tx_output_serialization_format_t fmt;
    assert_int_not_equal(
        parse_output_format(&buf, &fmt, SWO_TX_PARSING_FAIL_OUTPUTS), SWO_OK);
}

// ---------------------------------------------------------------------------
// parse_output_top_level
// ---------------------------------------------------------------------------

static void test_parse_output_top_level_truncated_amount(void **state) {
    (void) state;
    // Minimal valid third-party destination (29-byte enterprise address header + keyhash).
    // Destination type=1, address_size=29, 29 address bytes, then amount truncated.
    uint8_t address_bytes[29] = {0};
    address_bytes[0] = 0x61;  // enterprise mainnet header byte

    uint8_t buf_data[1 + 2 + 29 + 4] = {0};  // 4 amount bytes instead of 8
    size_t off = 0;
    buf_data[off++] = DESTINATION_THIRD_PARTY;
    buf_data[off++] = 0x00;
    buf_data[off++] = 29;
    memcpy(&buf_data[off], address_bytes, 29);
    off += 29;
    // only 4 amount bytes (need 8)
    buffer_t buf = {.ptr = buf_data, .size = off + 4, .offset = 0};
    tx_output_description_t desc;
    assert_int_not_equal(
        parse_output_top_level(&buf, &desc, SWO_TX_PARSING_FAIL_OUTPUTS), SWO_OK);
}

static void test_parse_output_top_level_amount_too_large(void **state) {
    (void) state;
    // amount = LOVELACE_MAX_SUPPLY = 0x00A0AEA1C0C40000
    uint8_t address_bytes[29] = {0};
    address_bytes[0] = 0x61;

    uint8_t buf_data[1 + 2 + 29 + 8] = {0};
    size_t off = 0;
    buf_data[off++] = DESTINATION_THIRD_PARTY;
    buf_data[off++] = 0x00;
    buf_data[off++] = 29;
    memcpy(&buf_data[off], address_bytes, 29);
    off += 29;
    // LOVELACE_MAX_SUPPLY big-endian
    buf_data[off++] = 0x00;
    buf_data[off++] = 0xA0;
    buf_data[off++] = 0xAE;
    buf_data[off++] = 0xA1;
    buf_data[off++] = 0xC0;
    buf_data[off++] = 0xC4;
    buf_data[off++] = 0x00;
    buf_data[off++] = 0x00;
    buffer_t buf = {.ptr = buf_data, .size = off, .offset = 0};
    tx_output_description_t desc;
    assert_int_not_equal(
        parse_output_top_level(&buf, &desc, SWO_TX_PARSING_FAIL_OUTPUTS), SWO_OK);
}

// Build a minimal valid output header up through the format byte and return offset.
// Writes into buf_data starting at offset 0, returns bytes written.
static size_t _write_valid_output_header_with_format(uint8_t *buf_data,
                                                     size_t buf_cap,
                                                     uint8_t format_byte) {
    (void) buf_cap;
    size_t off = 0;
    buf_data[off++] = DESTINATION_THIRD_PARTY;
    buf_data[off++] = 0x00;
    buf_data[off++] = 29;
    buf_data[off] = 0x61;  // enterprise mainnet header
    off += 29;
    // amount = 1_500_000 = 0x0000000000_16E360
    buf_data[off++] = 0x00;
    buf_data[off++] = 0x00;
    buf_data[off++] = 0x00;
    buf_data[off++] = 0x00;
    buf_data[off++] = 0x00;
    buf_data[off++] = 0x16;
    buf_data[off++] = 0xE3;
    buf_data[off++] = 0x60;
    buf_data[off++] = format_byte;
    return off;
}

static void test_parse_output_top_level_truncated_datum_flag(void **state) {
    (void) state;
    uint8_t buf_data[1 + 2 + 29 + 8 + 1] = {0};
    size_t off = _write_valid_output_header_with_format(buf_data, sizeof(buf_data), ARRAY_LEGACY);
    // No datum flag byte follows.
    buffer_t buf = {.ptr = buf_data, .size = off, .offset = 0};
    tx_output_description_t desc;
    assert_int_not_equal(
        parse_output_top_level(&buf, &desc, SWO_TX_PARSING_FAIL_OUTPUTS), SWO_OK);
}

static void test_parse_output_top_level_truncated_ref_script_flag(void **state) {
    (void) state;
    uint8_t buf_data[1 + 2 + 29 + 8 + 1 + 1] = {0};
    size_t off = _write_valid_output_header_with_format(buf_data, sizeof(buf_data), ARRAY_LEGACY);
    buf_data[off++] = 1;  // datum absent (FLAG_INCLUDED_NO=1)
    // No ref script flag byte follows.
    buffer_t buf = {.ptr = buf_data, .size = off, .offset = 0};
    tx_output_description_t desc;
    assert_int_not_equal(
        parse_output_top_level(&buf, &desc, SWO_TX_PARSING_FAIL_OUTPUTS), SWO_OK);
}

static void test_parse_output_top_level_truncated_num_asset_groups(void **state) {
    (void) state;
    uint8_t buf_data[1 + 2 + 29 + 8 + 1 + 1 + 1] = {0};
    size_t off = _write_valid_output_header_with_format(buf_data, sizeof(buf_data), ARRAY_LEGACY);
    buf_data[off++] = 1;  // datum absent
    buf_data[off++] = 1;  // ref script absent
    // No numAssetGroups u16 follows.
    buffer_t buf = {.ptr = buf_data, .size = off, .offset = 0};
    tx_output_description_t desc;
    assert_int_not_equal(
        parse_output_top_level(&buf, &desc, SWO_TX_PARSING_FAIL_OUTPUTS), SWO_OK);
}

static void test_parse_output_top_level_ref_script_in_array_legacy(void **state) {
    (void) state;
    // ref_script_present=true but format=ARRAY_LEGACY — must be rejected.
    uint8_t buf_data[1 + 2 + 29 + 8 + 1 + 1 + 1 + 2] = {0};
    size_t off = _write_valid_output_header_with_format(buf_data, sizeof(buf_data), ARRAY_LEGACY);
    buf_data[off++] = 1;  // datum absent
    buf_data[off++] = 2;  // ref script present (FLAG_INCLUDED_YES=2)
    buf_data[off++] = 0x00;  // numAssetGroups high
    buf_data[off++] = 0x00;  // numAssetGroups low
    buffer_t buf = {.ptr = buf_data, .size = off, .offset = 0};
    tx_output_description_t desc;
    assert_int_not_equal(
        parse_output_top_level(&buf, &desc, SWO_TX_PARSING_FAIL_OUTPUTS), SWO_OK);
}

// ---------------------------------------------------------------------------
// parse_output_asset_group
// ---------------------------------------------------------------------------

static void test_parse_output_asset_group_truncated_policy_id(void **state) {
    (void) state;
    // Buffer shorter than MINTING_POLICY_ID_LENGTH=28.
    uint8_t buf_data[10] = {0};
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    output_asset_group_t group;
    assert_false(parse_output_asset_group(&buf, &group));
}

static void test_parse_output_asset_group_truncated_num_tokens(void **state) {
    (void) state;
    // Policy ID present but num_tokens u16 missing.
    uint8_t buf_data[MINTING_POLICY_ID_LENGTH] = {0};
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    output_asset_group_t group;
    assert_false(parse_output_asset_group(&buf, &group));
}

static void test_parse_output_asset_group_zero_tokens(void **state) {
    (void) state;
    uint8_t buf_data[MINTING_POLICY_ID_LENGTH + 2] = {0};
    // numTokens = 0
    buf_data[MINTING_POLICY_ID_LENGTH + 0] = 0x00;
    buf_data[MINTING_POLICY_ID_LENGTH + 1] = 0x00;
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    output_asset_group_t group;
    assert_false(parse_output_asset_group(&buf, &group));
}

// ---------------------------------------------------------------------------
// parse_output_token
// ---------------------------------------------------------------------------

static void test_parse_output_token_name_too_long(void **state) {
    (void) state;
    uint8_t buf_data[1] = {MAX_ASSET_NAME_LENGTH + 1};
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    output_token_t token;
    assert_false(parse_output_token(&buf, &token));
}

static void test_parse_output_token_name_truncated(void **state) {
    (void) state;
    // assetNameLen=5 but only 3 name bytes present.
    uint8_t buf_data[4] = {5, 0xAA, 0xBB, 0xCC};
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    output_token_t token;
    assert_false(parse_output_token(&buf, &token));
}

static void test_parse_output_token_amount_truncated(void **state) {
    (void) state;
    // assetNameLen=1, name present, amount bytes missing.
    uint8_t buf_data[2] = {1, 0xAA};
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    output_token_t token;
    assert_false(parse_output_token(&buf, &token));
}

static void test_parse_output_token_zero_amount(void **state) {
    (void) state;
    uint8_t buf_data[1 + 1 + 8] = {0};
    buf_data[0] = 1;    // assetNameLen
    buf_data[1] = 0xAA; // name byte
    // amount = 0 (all zero)
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    output_token_t token;
    assert_false(parse_output_token(&buf, &token));
}

// ---------------------------------------------------------------------------
// parse_output_datum
// ---------------------------------------------------------------------------

static void test_parse_output_datum_truncated_type(void **state) {
    (void) state;
    uint8_t buf_data[1] = {0};
    buffer_t buf = {.ptr = buf_data, .size = 0, .offset = 0};
    output_datum_t datum;
    assert_false(parse_output_datum(&buf, &datum));
}

static void test_parse_output_datum_hash_truncated(void **state) {
    (void) state;
    // type = DATUM_HASH=0, but no hash bytes.
    uint8_t buf_data[1] = {DATUM_HASH};
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    output_datum_t datum;
    assert_false(parse_output_datum(&buf, &datum));
}

static void test_parse_output_datum_inline_truncated_size(void **state) {
    (void) state;
    // type = DATUM_INLINE=1, but no size u16.
    uint8_t buf_data[1] = {DATUM_INLINE};
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    output_datum_t datum;
    assert_false(parse_output_datum(&buf, &datum));
}

static void test_parse_output_datum_inline_zero_size(void **state) {
    (void) state;
    // type = DATUM_INLINE, size = 0 must be rejected.
    uint8_t buf_data[3] = {DATUM_INLINE, 0x00, 0x00};
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    output_datum_t datum;
    assert_false(parse_output_datum(&buf, &datum));
}

static void test_parse_output_datum_inline_truncated_data(void **state) {
    (void) state;
    // type = DATUM_INLINE, size = 5, but only 2 data bytes.
    uint8_t buf_data[5] = {DATUM_INLINE, 0x00, 0x05, 0xAA, 0xBB};
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    output_datum_t datum;
    assert_false(parse_output_datum(&buf, &datum));
}

static void test_parse_output_datum_unknown_type(void **state) {
    (void) state;
    uint8_t buf_data[1] = {0xFF};
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    output_datum_t datum;
    assert_false(parse_output_datum(&buf, &datum));
}

// ---------------------------------------------------------------------------
// parse_output_ref_script
// ---------------------------------------------------------------------------

static void test_parse_output_ref_script_truncated_size(void **state) {
    (void) state;
    uint8_t buf_data[1] = {0x00};  // only 1 byte, need 2 for u16
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    ref_script_t ref_script;
    assert_false(parse_output_ref_script(&buf, &ref_script));
}

static void test_parse_output_ref_script_zero_size(void **state) {
    (void) state;
    uint8_t buf_data[2] = {0x00, 0x00};
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    ref_script_t ref_script;
    assert_false(parse_output_ref_script(&buf, &ref_script));
}

static void test_parse_output_ref_script_truncated_data(void **state) {
    (void) state;
    // size = 5, but only 2 data bytes follow.
    uint8_t buf_data[4] = {0x00, 0x05, 0xAA, 0xBB};
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    ref_script_t ref_script;
    assert_false(parse_output_ref_script(&buf, &ref_script));
}

// parse_output_top_level: destination parse failure propagation (line 114)
static void test_parse_output_top_level_bad_destination(void **state) {
    (void) state;
    // First byte is an unknown destination type, so parse_output_destination fails
    // and parse_output_top_level must propagate the failure (line 113-114).
    uint8_t buf_data[1] = {0xFF};
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    tx_output_description_t desc;
    assert_int_not_equal(
        parse_output_top_level(&buf, &desc, SWO_TX_PARSING_FAIL_OUTPUTS), SWO_OK);
}

// parse_output_top_level: format parse failure propagation (line 129)
static void test_parse_output_top_level_bad_format(void **state) {
    (void) state;
    // Valid destination, valid amount, then invalid format byte — parse_output_format
    // returns failure and parse_output_top_level propagates it (line 128-129).
    uint8_t buf_data[1 + 2 + 29 + 8 + 1] = {0};
    size_t off = 0;
    buf_data[off++] = DESTINATION_THIRD_PARTY;
    buf_data[off++] = 0x00;
    buf_data[off++] = 29;
    buf_data[off] = 0x61;  // enterprise mainnet header
    off += 29;
    // amount = 1_500_000
    buf_data[off++] = 0x00; buf_data[off++] = 0x00; buf_data[off++] = 0x00;
    buf_data[off++] = 0x00; buf_data[off++] = 0x00; buf_data[off++] = 0x16;
    buf_data[off++] = 0xE3; buf_data[off++] = 0x60;
    buf_data[off++] = 0xFF;  // unknown format byte
    buffer_t buf = {.ptr = buf_data, .size = off, .offset = 0};
    tx_output_description_t desc;
    assert_int_not_equal(
        parse_output_top_level(&buf, &desc, SWO_TX_PARSING_FAIL_OUTPUTS), SWO_OK);
}

// parse_output_destination DEVICE_OWNED: buffer_read_address_params failure (lines 62-63)
// We pass a DESTINATION_DEVICE_OWNED type byte followed by a truncated/empty params buffer.
static void test_parse_output_destination_device_owned_truncated_params(void **state) {
    (void) state;
    // type = DESTINATION_DEVICE_OWNED=2, then no params bytes — buffer_read_address_params fails.
    uint8_t buf_data[1] = {DESTINATION_DEVICE_OWNED};
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    tx_output_destination_t dest;
    assert_int_not_equal(parse_output_destination(&buf, &dest), SWO_OK);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        // parse_output_destination
        cmocka_unit_test(test_parse_output_destination_truncated_type),
        cmocka_unit_test(test_parse_output_destination_truncated_address_size),
        cmocka_unit_test(test_parse_output_destination_zero_address_size),
        cmocka_unit_test(test_parse_output_destination_address_size_too_large),
        cmocka_unit_test(test_parse_output_destination_truncated_address_bytes),
        cmocka_unit_test(test_parse_output_destination_unknown_type),
        cmocka_unit_test(test_parse_output_destination_device_owned_truncated_params),
        // parse_output_format
        cmocka_unit_test(test_parse_output_format_truncated),
        cmocka_unit_test(test_parse_output_format_unknown),
        // parse_output_top_level
        cmocka_unit_test(test_parse_output_top_level_bad_destination),
        cmocka_unit_test(test_parse_output_top_level_bad_format),
        cmocka_unit_test(test_parse_output_top_level_truncated_amount),
        cmocka_unit_test(test_parse_output_top_level_amount_too_large),
        cmocka_unit_test(test_parse_output_top_level_truncated_datum_flag),
        cmocka_unit_test(test_parse_output_top_level_truncated_ref_script_flag),
        cmocka_unit_test(test_parse_output_top_level_truncated_num_asset_groups),
        cmocka_unit_test(test_parse_output_top_level_ref_script_in_array_legacy),
        // parse_output_asset_group
        cmocka_unit_test(test_parse_output_asset_group_truncated_policy_id),
        cmocka_unit_test(test_parse_output_asset_group_truncated_num_tokens),
        cmocka_unit_test(test_parse_output_asset_group_zero_tokens),
        // parse_output_token
        cmocka_unit_test(test_parse_output_token_name_too_long),
        cmocka_unit_test(test_parse_output_token_name_truncated),
        cmocka_unit_test(test_parse_output_token_amount_truncated),
        cmocka_unit_test(test_parse_output_token_zero_amount),
        // parse_output_datum
        cmocka_unit_test(test_parse_output_datum_truncated_type),
        cmocka_unit_test(test_parse_output_datum_hash_truncated),
        cmocka_unit_test(test_parse_output_datum_inline_truncated_size),
        cmocka_unit_test(test_parse_output_datum_inline_zero_size),
        cmocka_unit_test(test_parse_output_datum_inline_truncated_data),
        cmocka_unit_test(test_parse_output_datum_unknown_type),
        // parse_output_ref_script
        cmocka_unit_test(test_parse_output_ref_script_truncated_size),
        cmocka_unit_test(test_parse_output_ref_script_zero_size),
        cmocka_unit_test(test_parse_output_ref_script_truncated_data),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
