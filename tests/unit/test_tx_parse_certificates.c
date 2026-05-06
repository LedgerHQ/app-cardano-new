/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "tx_parse_certificates.h"
#include "cardano_constants.h"
#include "cardano_swo.h"

// ---------------------------------------------------------------------------
// Helpers: build minimal valid credential wire bytes (KEY_HASH type)
// ---------------------------------------------------------------------------

// Write EXT_CREDENTIAL_KEY_HASH + 28 zero bytes into dst; return bytes written.
static size_t _write_key_hash_credential(uint8_t *dst) {
    dst[0] = EXT_CREDENTIAL_KEY_HASH;
    memset(dst + 1, 0, ADDRESS_KEY_HASH_LENGTH);
    return 1 + ADDRESS_KEY_HASH_LENGTH;
}

// Write a 64-bit big-endian value into dst; return bytes written.
static size_t _write_u64_be(uint8_t *dst, uint64_t value) {
    for (int i = 7; i >= 0; i--) {
        dst[i] = (uint8_t) (value & 0xFF);
        value >>= 8;
    }
    return 8;
}

static void _write_payload_length(uint8_t *dst, size_t payload_length) {
    dst[0] = (uint8_t) (payload_length >> 8);
    dst[1] = (uint8_t) (payload_length & 0xFF);
}

// ---------------------------------------------------------------------------
// parse_certificate_stake_registration_deregistration
// ---------------------------------------------------------------------------

static void test_cert_stake_reg_truncated_credential(void **state) {
    (void) state;
    // Empty buffer — credential type byte missing.
    uint8_t buf_data[1] = {0};
    buffer_t buf = {.ptr = buf_data, .size = 0, .offset = 0};
    certificate_data_t cert;
    assert_false(parse_certificate_stake_registration_deregistration(&buf,
                                                                     CERTIFICATE_STAKE_REGISTRATION,
                                                                     &cert));
}

// ---------------------------------------------------------------------------
// parse_certificate_stake_delegation
// ---------------------------------------------------------------------------

static void test_cert_stake_delegation_truncated_credential(void **state) {
    (void) state;
    uint8_t buf_data[1] = {0};
    buffer_t buf = {.ptr = buf_data, .size = 0, .offset = 0};
    certificate_data_t cert;
    assert_false(parse_certificate_stake_delegation(&buf, &cert));
}

static void test_cert_stake_delegation_truncated_pool_hash(void **state) {
    (void) state;
    // Valid credential, pool hash missing.
    uint8_t buf_data[1 + ADDRESS_KEY_HASH_LENGTH] = {0};
    _write_key_hash_credential(buf_data);
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    certificate_data_t cert;
    assert_false(parse_certificate_stake_delegation(&buf, &cert));
}

// ---------------------------------------------------------------------------
// parse_certificate_stake_registration_deregistration_conway
// ---------------------------------------------------------------------------

static void test_cert_conway_reg_truncated_credential(void **state) {
    (void) state;
    uint8_t buf_data[1] = {0};
    buffer_t buf = {.ptr = buf_data, .size = 0, .offset = 0};
    certificate_data_t cert;
    assert_false(parse_certificate_stake_registration_deregistration_conway(
        &buf,
        CERTIFICATE_STAKE_REGISTRATION_CONWAY,
        &cert));
}

static void test_cert_conway_reg_truncated_deposit(void **state) {
    (void) state;
    uint8_t buf_data[1 + ADDRESS_KEY_HASH_LENGTH + 4] = {0};  // 4 bytes instead of 8
    _write_key_hash_credential(buf_data);
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    certificate_data_t cert;
    assert_false(parse_certificate_stake_registration_deregistration_conway(
        &buf,
        CERTIFICATE_STAKE_REGISTRATION_CONWAY,
        &cert));
}

static void test_cert_conway_reg_deposit_too_large(void **state) {
    (void) state;
    uint8_t buf_data[1 + ADDRESS_KEY_HASH_LENGTH + 8] = {0};
    size_t off = _write_key_hash_credential(buf_data);
    _write_u64_be(buf_data + off, LOVELACE_MAX_SUPPLY);
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    certificate_data_t cert;
    assert_false(parse_certificate_stake_registration_deregistration_conway(
        &buf,
        CERTIFICATE_STAKE_REGISTRATION_CONWAY,
        &cert));
}

static void test_cert_conway_dereg_deposit_too_large(void **state) {
    (void) state;
    uint8_t buf_data[1 + ADDRESS_KEY_HASH_LENGTH + 8] = {0};
    size_t off = _write_key_hash_credential(buf_data);
    _write_u64_be(buf_data + off, LOVELACE_MAX_SUPPLY);
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    certificate_data_t cert;
    assert_false(parse_certificate_stake_registration_deregistration_conway(
        &buf,
        CERTIFICATE_STAKE_DEREGISTRATION_CONWAY,
        &cert));
}

// ---------------------------------------------------------------------------
// parse_certificate_stake_pool_retirement
// ---------------------------------------------------------------------------

static void test_cert_pool_retirement_truncated_credential(void **state) {
    (void) state;
    uint8_t buf_data[1] = {0};
    buffer_t buf = {.ptr = buf_data, .size = 0, .offset = 0};
    certificate_data_t cert;
    assert_false(parse_certificate_stake_pool_retirement(&buf, &cert));
}

static void test_cert_pool_retirement_truncated_epoch(void **state) {
    (void) state;
    uint8_t buf_data[1 + ADDRESS_KEY_HASH_LENGTH + 4] = {0};  // 4 bytes instead of 8
    _write_key_hash_credential(buf_data);
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    certificate_data_t cert;
    assert_false(parse_certificate_stake_pool_retirement(&buf, &cert));
}

// ---------------------------------------------------------------------------
// parse_certificate_vote_delegation
// ---------------------------------------------------------------------------

static void test_cert_vote_delegation_truncated_credential(void **state) {
    (void) state;
    uint8_t buf_data[1] = {0};
    buffer_t buf = {.ptr = buf_data, .size = 0, .offset = 0};
    certificate_data_t cert;
    assert_false(parse_certificate_vote_delegation(&buf, &cert));
}

static void test_cert_vote_delegation_truncated_drep(void **state) {
    (void) state;
    uint8_t buf_data[1 + ADDRESS_KEY_HASH_LENGTH] = {0};
    _write_key_hash_credential(buf_data);
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    certificate_data_t cert;
    assert_false(parse_certificate_vote_delegation(&buf, &cert));
}

// ---------------------------------------------------------------------------
// parse_certificate_stake_pool_and_drep_delegation
// ---------------------------------------------------------------------------

static void test_cert_pool_and_drep_delegation_truncated_credential(void **state) {
    (void) state;
    uint8_t buf_data[1] = {0};
    buffer_t buf = {.ptr = buf_data, .size = 0, .offset = 0};
    certificate_data_t cert;
    assert_false(parse_certificate_stake_pool_and_drep_delegation(&buf, &cert));
}

static void test_cert_pool_and_drep_delegation_truncated_pool_hash(void **state) {
    (void) state;
    uint8_t buf_data[1 + ADDRESS_KEY_HASH_LENGTH] = {0};
    _write_key_hash_credential(buf_data);
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    certificate_data_t cert;
    assert_false(parse_certificate_stake_pool_and_drep_delegation(&buf, &cert));
}

static void test_cert_pool_and_drep_delegation_truncated_drep(void **state) {
    (void) state;
    uint8_t buf_data[1 + ADDRESS_KEY_HASH_LENGTH + POOL_KEY_HASH_LENGTH] = {0};
    _write_key_hash_credential(buf_data);
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    certificate_data_t cert;
    assert_false(parse_certificate_stake_pool_and_drep_delegation(&buf, &cert));
}

// ---------------------------------------------------------------------------
// parse_certificate_account_registration_delegation_to_stake_pool
// ---------------------------------------------------------------------------

static void test_cert_acct_reg_to_pool_truncated_credential(void **state) {
    (void) state;
    uint8_t buf_data[1] = {0};
    buffer_t buf = {.ptr = buf_data, .size = 0, .offset = 0};
    certificate_data_t cert;
    assert_false(parse_certificate_account_registration_delegation_to_stake_pool(&buf, &cert));
}

static void test_cert_acct_reg_to_pool_truncated_pool_hash(void **state) {
    (void) state;
    uint8_t buf_data[1 + ADDRESS_KEY_HASH_LENGTH] = {0};
    _write_key_hash_credential(buf_data);
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    certificate_data_t cert;
    assert_false(parse_certificate_account_registration_delegation_to_stake_pool(&buf, &cert));
}

static void test_cert_acct_reg_to_pool_truncated_deposit(void **state) {
    (void) state;
    uint8_t buf_data[1 + ADDRESS_KEY_HASH_LENGTH + POOL_KEY_HASH_LENGTH + 4] = {0};
    _write_key_hash_credential(buf_data);
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    certificate_data_t cert;
    assert_false(parse_certificate_account_registration_delegation_to_stake_pool(&buf, &cert));
}

static void test_cert_acct_reg_to_pool_deposit_too_large(void **state) {
    (void) state;
    uint8_t buf_data[1 + ADDRESS_KEY_HASH_LENGTH + POOL_KEY_HASH_LENGTH + 8] = {0};
    size_t off = _write_key_hash_credential(buf_data);
    off += POOL_KEY_HASH_LENGTH;  // pool hash (zeros)
    _write_u64_be(buf_data + off, LOVELACE_MAX_SUPPLY);
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    certificate_data_t cert;
    assert_false(parse_certificate_account_registration_delegation_to_stake_pool(&buf, &cert));
}

// ---------------------------------------------------------------------------
// parse_certificate_account_registration_delegation_to_drep
// ---------------------------------------------------------------------------

static void test_cert_acct_reg_to_drep_truncated_credential(void **state) {
    (void) state;
    uint8_t buf_data[1] = {0};
    buffer_t buf = {.ptr = buf_data, .size = 0, .offset = 0};
    certificate_data_t cert;
    assert_false(parse_certificate_account_registration_delegation_to_drep(&buf, &cert));
}

static void test_cert_acct_reg_to_drep_truncated_drep(void **state) {
    (void) state;
    uint8_t buf_data[1 + ADDRESS_KEY_HASH_LENGTH] = {0};
    _write_key_hash_credential(buf_data);
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    certificate_data_t cert;
    assert_false(parse_certificate_account_registration_delegation_to_drep(&buf, &cert));
}

static void test_cert_acct_reg_to_drep_deposit_too_large(void **state) {
    (void) state;
    // credential + drep (DREP_ABSTAIN=2, no extra bytes) + deposit = LOVELACE_MAX_SUPPLY
    uint8_t buf_data[1 + ADDRESS_KEY_HASH_LENGTH + 1 + 8] = {0};
    size_t off = _write_key_hash_credential(buf_data);
    buf_data[off++] = (uint8_t) EXT_DREP_ABSTAIN;  // drep type, no hash follows
    _write_u64_be(buf_data + off, LOVELACE_MAX_SUPPLY);
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    certificate_data_t cert;
    assert_false(parse_certificate_account_registration_delegation_to_drep(&buf, &cert));
}

// ---------------------------------------------------------------------------
// parse_certificate_account_registration_delegation_to_stake_pool_and_drep
// ---------------------------------------------------------------------------

static void test_cert_acct_reg_to_pool_and_drep_truncated_credential(void **state) {
    (void) state;
    uint8_t buf_data[1] = {0};
    buffer_t buf = {.ptr = buf_data, .size = 0, .offset = 0};
    certificate_data_t cert;
    assert_false(
        parse_certificate_account_registration_delegation_to_stake_pool_and_drep(&buf, &cert));
}

static void test_cert_acct_reg_to_pool_and_drep_deposit_too_large(void **state) {
    (void) state;
    // credential + pool_hash + drep(ABSTAIN) + deposit=MAX
    uint8_t buf_data[1 + ADDRESS_KEY_HASH_LENGTH + POOL_KEY_HASH_LENGTH + 1 + 8] = {0};
    size_t off = _write_key_hash_credential(buf_data);
    off += POOL_KEY_HASH_LENGTH;  // pool hash zeros
    buf_data[off++] = (uint8_t) EXT_DREP_ABSTAIN;
    _write_u64_be(buf_data + off, LOVELACE_MAX_SUPPLY);
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    certificate_data_t cert;
    assert_false(
        parse_certificate_account_registration_delegation_to_stake_pool_and_drep(&buf, &cert));
}

// ---------------------------------------------------------------------------
// parse_certificate_authorize_committee_hot
// ---------------------------------------------------------------------------

static void test_cert_authorize_committee_hot_truncated_cold_credential(void **state) {
    (void) state;
    uint8_t buf_data[1] = {0};
    buffer_t buf = {.ptr = buf_data, .size = 0, .offset = 0};
    certificate_data_t cert;
    assert_false(parse_certificate_authorize_committee_hot(&buf, &cert));
}

static void test_cert_authorize_committee_hot_truncated_hot_credential(void **state) {
    (void) state;
    uint8_t buf_data[1 + ADDRESS_KEY_HASH_LENGTH] = {0};
    _write_key_hash_credential(buf_data);
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    certificate_data_t cert;
    assert_false(parse_certificate_authorize_committee_hot(&buf, &cert));
}

// ---------------------------------------------------------------------------
// parse_certificate_resign_committee_cold
// ---------------------------------------------------------------------------

static void test_cert_resign_committee_cold_truncated_credential(void **state) {
    (void) state;
    uint8_t buf_data[1] = {0};
    buffer_t buf = {.ptr = buf_data, .size = 0, .offset = 0};
    certificate_data_t cert;
    assert_false(parse_certificate_resign_committee_cold(&buf, &cert));
}

static void test_cert_resign_committee_cold_truncated_anchor(void **state) {
    (void) state;
    uint8_t buf_data[1 + ADDRESS_KEY_HASH_LENGTH] = {0};
    _write_key_hash_credential(buf_data);
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    certificate_data_t cert;
    assert_false(parse_certificate_resign_committee_cold(&buf, &cert));
}

// ---------------------------------------------------------------------------
// parse_certificate_drep_registration
// ---------------------------------------------------------------------------

static void test_cert_drep_registration_truncated_credential(void **state) {
    (void) state;
    uint8_t buf_data[1] = {0};
    buffer_t buf = {.ptr = buf_data, .size = 0, .offset = 0};
    certificate_data_t cert;
    assert_false(parse_certificate_drep_registration(&buf, &cert));
}

static void test_cert_drep_registration_deposit_too_large(void **state) {
    (void) state;
    uint8_t buf_data[1 + ADDRESS_KEY_HASH_LENGTH + 8] = {0};
    size_t off = _write_key_hash_credential(buf_data);
    _write_u64_be(buf_data + off, LOVELACE_MAX_SUPPLY);
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    certificate_data_t cert;
    assert_false(parse_certificate_drep_registration(&buf, &cert));
}

static void test_cert_drep_registration_truncated_deposit(void **state) {
    (void) state;
    uint8_t buf_data[1 + ADDRESS_KEY_HASH_LENGTH + 4] = {0};
    _write_key_hash_credential(buf_data);
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    certificate_data_t cert;
    assert_false(parse_certificate_drep_registration(&buf, &cert));
}

static void test_cert_drep_registration_truncated_anchor(void **state) {
    (void) state;
    // Valid credential + valid deposit, but no anchor bytes.
    uint8_t buf_data[1 + ADDRESS_KEY_HASH_LENGTH + 8] = {0};
    size_t off = _write_key_hash_credential(buf_data);
    _write_u64_be(buf_data + off, 2000000);  // valid deposit
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    certificate_data_t cert;
    assert_false(parse_certificate_drep_registration(&buf, &cert));
}

// ---------------------------------------------------------------------------
// parse_certificate_drep_deregistration
// ---------------------------------------------------------------------------

static void test_cert_drep_deregistration_truncated_credential(void **state) {
    (void) state;
    uint8_t buf_data[1] = {0};
    buffer_t buf = {.ptr = buf_data, .size = 0, .offset = 0};
    certificate_data_t cert;
    assert_false(parse_certificate_drep_deregistration(&buf, &cert));
}

static void test_cert_drep_deregistration_deposit_too_large(void **state) {
    (void) state;
    uint8_t buf_data[1 + ADDRESS_KEY_HASH_LENGTH + 8] = {0};
    size_t off = _write_key_hash_credential(buf_data);
    _write_u64_be(buf_data + off, LOVELACE_MAX_SUPPLY);
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    certificate_data_t cert;
    assert_false(parse_certificate_drep_deregistration(&buf, &cert));
}

static void test_cert_drep_deregistration_truncated_deposit(void **state) {
    (void) state;
    uint8_t buf_data[1 + ADDRESS_KEY_HASH_LENGTH + 4] = {0};
    _write_key_hash_credential(buf_data);
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    certificate_data_t cert;
    assert_false(parse_certificate_drep_deregistration(&buf, &cert));
}

// ---------------------------------------------------------------------------
// parse_certificate_drep_update
// ---------------------------------------------------------------------------

static void test_cert_drep_update_truncated_credential(void **state) {
    (void) state;
    uint8_t buf_data[1] = {0};
    buffer_t buf = {.ptr = buf_data, .size = 0, .offset = 0};
    certificate_data_t cert;
    assert_false(parse_certificate_drep_update(&buf, &cert));
}

static void test_cert_drep_update_truncated_anchor(void **state) {
    (void) state;
    uint8_t buf_data[1 + ADDRESS_KEY_HASH_LENGTH] = {0};
    _write_key_hash_credential(buf_data);
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    certificate_data_t cert;
    assert_false(parse_certificate_drep_update(&buf, &cert));
}

// ---------------------------------------------------------------------------
// parse_certificate (dispatcher) — unknown type
// ---------------------------------------------------------------------------

static void test_cert_parse_unknown_type(void **state) {
    (void) state;
    // Certificate type byte 0xFF is not a valid certificate_type_t.
    uint8_t buf_data[1] = {0xFF};
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    certificate_data_t cert;
    assert_false(parse_certificate(&buf, &cert));
}

static void test_cert_parse_truncated_type(void **state) {
    (void) state;
    uint8_t buf_data[1] = {0};
    buffer_t buf = {.ptr = buf_data, .size = 0, .offset = 0};
    certificate_data_t cert;
    assert_false(parse_certificate(&buf, &cert));
}

// ---------------------------------------------------------------------------
// parse_pool_relay error paths
// ---------------------------------------------------------------------------

static void test_parse_pool_relay_truncated_type(void **state) {
    (void) state;
    uint8_t buf_data[1] = {0};
    buffer_t buf = {.ptr = buf_data, .size = 0, .offset = 0};
    pool_relay_t relay;
    assert_false(parse_pool_relay(&buf, &relay));
}

static void test_parse_pool_relay_single_host_ip_missing_port(void **state) {
    (void) state;
    // RELAY_SINGLE_HOST_IP=0, port absent (FLAG_INCLUDED_NO=1) — must be rejected.
    uint8_t buf_data[2] = {
        RELAY_SINGLE_HOST_IP,
        1,  // FLAG_INCLUDED_NO -> port.isNull=true -> rejected
    };
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    pool_relay_t relay;
    assert_false(parse_pool_relay(&buf, &relay));
}

static void test_parse_pool_relay_single_host_ip_no_ip(void **state) {
    (void) state;
    // RELAY_SINGLE_HOST_IP, port present, both IPv4 and IPv6 absent — rejected.
    uint8_t buf_data[] = {
        RELAY_SINGLE_HOST_IP,
        2,  // FLAG_INCLUDED_YES -> port present
        0x00,
        0x50,  // port = 80
        1,     // IPv4 absent
        1,     // IPv6 absent
    };
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    pool_relay_t relay;
    assert_false(parse_pool_relay(&buf, &relay));
}

static void test_parse_pool_relay_single_host_name_missing_port(void **state) {
    (void) state;
    // RELAY_SINGLE_HOST_NAME=1, port absent — must be rejected.
    uint8_t buf_data[2] = {
        RELAY_SINGLE_HOST_NAME,
        1,  // FLAG_INCLUDED_NO -> port absent -> rejected
    };
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    pool_relay_t relay;
    assert_false(parse_pool_relay(&buf, &relay));
}

static void test_relay_multiple_host_name_success(void **state) {
    (void) state;
    uint8_t buf_data[] = {RELAY_MULTIPLE_HOST_NAME,
                          2,  // FLAG_INCLUDED_YES
                          3,  // length
                          'a',
                          'b',
                          'c'};
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    pool_relay_t relay;
    assert_true(parse_pool_relay(&buf, &relay));
    assert_int_equal(relay.format, RELAY_MULTIPLE_HOST_NAME);
    assert_int_equal(relay.dnsNameSize, 3);
    assert_memory_equal(relay.dnsName, "abc", 3);
}

static void test_relay_multiple_host_name_truncated_dns(void **state) {
    (void) state;
    uint8_t buf_data[] = {
        RELAY_MULTIPLE_HOST_NAME,
        2,  // FLAG_INCLUDED_YES
        3,  // length
        'a',
        'b'  // truncated
    };
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    pool_relay_t relay;
    assert_false(parse_pool_relay(&buf, &relay));
}

static void test_parse_pool_relay_unknown_type(void **state) {
    (void) state;
    uint8_t buf_data[1] = {0xFF};
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    pool_relay_t relay;
    assert_false(parse_pool_relay(&buf, &relay));
}

// ---------------------------------------------------------------------------
// parse_certificate_stake_pool_registration — margin and reward account errors
// ---------------------------------------------------------------------------

static void test_cert_pool_reg_invalid_margin(void **state) {
    (void) state;
    // Build a pool registration payload where marginNumerator > marginDenominator.
    // Layout (after the outer 2-byte payload-length prefix parsed by the caller):
    //   pool_id (EXT_CREDENTIAL_KEY_HASH + 28 bytes)
    //   vrf_key_hash (32 bytes)
    //   pledge (8 bytes)
    //   cost (8 bytes)
    //   margin_numerator (8 bytes)
    //   margin_denominator (8 bytes)
    //   reward_account_type (1 byte) + data
    //   num_owners (2 bytes)
    //   num_relays (2 bytes)
    //   metadata flag (1 byte)
    // parse_certificate_stake_pool_registration reads a 2-byte payloadLength first,
    // then creates a sub-buffer of that size.  We put all payload bytes after the 2-byte
    // length prefix.
    const size_t POOL_ID_SIZE = 1 + POOL_KEY_HASH_LENGTH;  // type + 28 bytes
    const size_t VRF_SIZE = VRF_KEY_HASH_LENGTH;           // 32 bytes
    const size_t U64_SIZE = 8;
    const size_t REWARD_ACCOUNT_SIZE = 1 + REWARD_ACCOUNT_LENGTH;   // type + 29 bytes
    const size_t TAIL_SIZE = 2 + 2 + 1;                             // owners, relays, metadata flag
    const size_t PAYLOAD_SIZE = POOL_ID_SIZE + VRF_SIZE + U64_SIZE  // pledge
                                + U64_SIZE                          // cost
                                + U64_SIZE                          // marginNumerator
                                + U64_SIZE                          // marginDenominator
                                + REWARD_ACCOUNT_SIZE + TAIL_SIZE;

    uint8_t buf_data[2 + PAYLOAD_SIZE];
    memset(buf_data, 0, sizeof(buf_data));
    buf_data[0] = (uint8_t) (PAYLOAD_SIZE >> 8);
    buf_data[1] = (uint8_t) (PAYLOAD_SIZE & 0xFF);

    size_t off = 2;
    // pool_id: EXT_CREDENTIAL_KEY_HASH + 28 zero bytes
    buf_data[off++] = EXT_CREDENTIAL_KEY_HASH;
    off += POOL_KEY_HASH_LENGTH;
    // vrf_key_hash: 32 zero bytes
    off += VRF_SIZE;
    // pledge = 1
    _write_u64_be(buf_data + off, 1);
    off += 8;
    // cost = 1
    _write_u64_be(buf_data + off, 1);
    off += 8;
    // marginNumerator = 5
    _write_u64_be(buf_data + off, 5);
    off += 8;
    // marginDenominator = 3  (5 > 3 -> invalid)
    _write_u64_be(buf_data + off, 3);
    off += 8;
    // reward account: EXT_CREDENTIAL_KEY_HASH + 29 zero bytes
    buf_data[off++] = EXT_CREDENTIAL_KEY_HASH;
    off += REWARD_ACCOUNT_LENGTH;
    // num_owners = 0, num_relays = 0, metadata absent
    buf_data[off++] = 0x00;
    buf_data[off++] = 0x00;  // num_owners
    buf_data[off++] = 0x00;
    buf_data[off++] = 0x00;  // num_relays
    buf_data[off++] = 1;     // FLAG_INCLUDED_NO (no metadata)

    buffer_t buf = {.ptr = buf_data, .size = off, .offset = 0};
    certificate_data_t cert;
    assert_false(parse_certificate_stake_pool_registration(&buf, &cert));
}

static void test_cert_pool_reg_unknown_reward_account_type(void **state) {
    (void) state;
    const size_t POOL_ID_SIZE = 1 + POOL_KEY_HASH_LENGTH;
    const size_t VRF_SIZE = VRF_KEY_HASH_LENGTH;
    const size_t U64_SIZE = 8;
    const size_t PAYLOAD_SIZE = POOL_ID_SIZE + VRF_SIZE + U64_SIZE  // pledge
                                + U64_SIZE                          // cost
                                + U64_SIZE                          // marginNumerator
                                + U64_SIZE                          // marginDenominator
                                + 1;  // unknown reward account type byte (then truncated)

    uint8_t buf_data[2 + PAYLOAD_SIZE];
    memset(buf_data, 0, sizeof(buf_data));
    buf_data[0] = (uint8_t) (PAYLOAD_SIZE >> 8);
    buf_data[1] = (uint8_t) (PAYLOAD_SIZE & 0xFF);

    size_t off = 2;
    buf_data[off++] = EXT_CREDENTIAL_KEY_HASH;
    off += POOL_KEY_HASH_LENGTH;
    off += VRF_SIZE;
    _write_u64_be(buf_data + off, 1);
    off += 8;  // pledge
    _write_u64_be(buf_data + off, 1);
    off += 8;  // cost
    _write_u64_be(buf_data + off, 1);
    off += 8;  // numerator
    _write_u64_be(buf_data + off, 2);
    off += 8;                // denominator (valid: 1/2)
    buf_data[off++] = 0xFF;  // unknown reward account type

    buffer_t buf = {.ptr = buf_data, .size = off, .offset = 0};
    certificate_data_t cert;
    assert_false(parse_certificate_stake_pool_registration(&buf, &cert));
}

static void test_cert_pool_reg_payload_length_exceeds_buffer(void **state) {
    (void) state;
    uint8_t buf_data[2] = {0x00, 0x01};
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    certificate_data_t cert;
    assert_false(parse_certificate_stake_pool_registration(&buf, &cert));
}

// ---------------------------------------------------------------------------
// _parse_pool_id error paths (called via parse_certificate_stake_pool_registration)
// We test it by building minimal pool reg payloads that fail at pool id parsing.
// ---------------------------------------------------------------------------

static void test_pool_id_truncated_type(void **state) {
    (void) state;
    // payloadLength = 0 -> sub-buffer empty -> pool id type byte read fails.
    uint8_t buf_data[2] = {0x00, 0x00};
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    certificate_data_t cert;
    assert_false(parse_certificate_stake_pool_registration(&buf, &cert));
}

static void test_pool_id_unknown_type(void **state) {
    (void) state;
    // payload = [0xFF] -> unknown pool id type byte.
    uint8_t buf_data[3] = {0x00, 0x01, 0xFF};
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    certificate_data_t cert;
    assert_false(parse_certificate_stake_pool_registration(&buf, &cert));
}

static void test_pool_id_hash_truncated(void **state) {
    (void) state;
    // pool id type = EXT_CREDENTIAL_KEY_HASH, but only 5 hash bytes follow.
    uint8_t buf_data[2 + 1 + 5];
    memset(buf_data, 0, sizeof(buf_data));
    buf_data[0] = 0x00;
    buf_data[1] = 1 + 5;  // payloadLength = 6
    buf_data[2] = EXT_CREDENTIAL_KEY_HASH;
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    certificate_data_t cert;
    assert_false(parse_certificate_stake_pool_registration(&buf, &cert));
}

static void test_pool_id_path_truncated(void **state) {
    (void) state;
    uint8_t buf_data[2 + 2] = {0};
    _write_payload_length(buf_data, 2);
    buf_data[2] = EXT_CREDENTIAL_KEY_PATH;
    buf_data[3] = 5;  // path length byte, no path words follow
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    certificate_data_t cert;
    assert_false(parse_certificate_stake_pool_registration(&buf, &cert));
}

// Helper: write a valid pool registration payload into buf_data starting at off=2
// (after 2-byte payloadLength), up through the end of the reward account (KEY_HASH).
// Returns offset after last written byte (does NOT write numOwners/numRelays/metadata).
// pool_payload_size must be set to the total payload size written by the caller.
static size_t _write_pool_reg_header_up_to_reward_account(uint8_t *buf_data) {
    size_t off = 2;  // skip payloadLength placeholder
    buf_data[off++] = EXT_CREDENTIAL_KEY_HASH;
    off += POOL_KEY_HASH_LENGTH;  // vrf id hash zeros
    off += VRF_KEY_HASH_LENGTH;   // vrf key hash zeros
    _write_u64_be(buf_data + off, 1);
    off += 8;  // pledge = 1
    _write_u64_be(buf_data + off, 1);
    off += 8;  // cost = 1
    _write_u64_be(buf_data + off, 1);
    off += 8;  // numerator = 1
    _write_u64_be(buf_data + off, 2);
    off += 8;  // denominator = 2 (valid)
    buf_data[off++] = EXT_CREDENTIAL_KEY_HASH;
    off += REWARD_ACCOUNT_LENGTH;  // reward account hash zeros
    return off;
}

static void test_pool_reg_truncated_vrf_hash(void **state) {
    (void) state;
    // payload = pool_id(valid) + only 5 vrf bytes
    uint8_t buf_data[2 + 1 + POOL_KEY_HASH_LENGTH + 5];
    memset(buf_data, 0, sizeof(buf_data));
    size_t payload_size = 1 + POOL_KEY_HASH_LENGTH + 5;
    buf_data[0] = (uint8_t) (payload_size >> 8);
    buf_data[1] = (uint8_t) (payload_size & 0xFF);
    buf_data[2] = EXT_CREDENTIAL_KEY_HASH;
    // rest zeros
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    certificate_data_t cert;
    assert_false(parse_certificate_stake_pool_registration(&buf, &cert));
}

static void test_pool_reg_pledge_too_large(void **state) {
    (void) state;
    const size_t PAYLOAD_SIZE = 1 + POOL_KEY_HASH_LENGTH + VRF_KEY_HASH_LENGTH + 8;
    uint8_t buf_data[2 + PAYLOAD_SIZE];
    memset(buf_data, 0, sizeof(buf_data));
    buf_data[0] = (uint8_t) (PAYLOAD_SIZE >> 8);
    buf_data[1] = (uint8_t) (PAYLOAD_SIZE & 0xFF);
    size_t off = 2;
    buf_data[off++] = EXT_CREDENTIAL_KEY_HASH;
    off += POOL_KEY_HASH_LENGTH;
    off += VRF_KEY_HASH_LENGTH;
    _write_u64_be(buf_data + off, LOVELACE_MAX_SUPPLY);  // pledge = max (invalid)
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    certificate_data_t cert;
    assert_false(parse_certificate_stake_pool_registration(&buf, &cert));
}

static void test_pool_reg_truncated_pledge(void **state) {
    (void) state;
    const size_t PAYLOAD_SIZE = 1 + POOL_KEY_HASH_LENGTH + VRF_KEY_HASH_LENGTH + 4;
    uint8_t buf_data[2 + PAYLOAD_SIZE];
    memset(buf_data, 0, sizeof(buf_data));
    _write_payload_length(buf_data, PAYLOAD_SIZE);
    size_t off = 2;
    buf_data[off++] = EXT_CREDENTIAL_KEY_HASH;
    off += POOL_KEY_HASH_LENGTH;
    off += VRF_KEY_HASH_LENGTH;
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    certificate_data_t cert;
    assert_false(parse_certificate_stake_pool_registration(&buf, &cert));
}

static void test_pool_reg_cost_too_large(void **state) {
    (void) state;
    const size_t PAYLOAD_SIZE = 1 + POOL_KEY_HASH_LENGTH + VRF_KEY_HASH_LENGTH + 8 + 8;
    uint8_t buf_data[2 + PAYLOAD_SIZE];
    memset(buf_data, 0, sizeof(buf_data));
    buf_data[0] = (uint8_t) (PAYLOAD_SIZE >> 8);
    buf_data[1] = (uint8_t) (PAYLOAD_SIZE & 0xFF);
    size_t off = 2;
    buf_data[off++] = EXT_CREDENTIAL_KEY_HASH;
    off += POOL_KEY_HASH_LENGTH;
    off += VRF_KEY_HASH_LENGTH;
    _write_u64_be(buf_data + off, 1);
    off += 8;                                            // pledge valid
    _write_u64_be(buf_data + off, LOVELACE_MAX_SUPPLY);  // cost = max (invalid)
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    certificate_data_t cert;
    assert_false(parse_certificate_stake_pool_registration(&buf, &cert));
}

static void test_pool_reg_truncated_cost(void **state) {
    (void) state;
    const size_t PAYLOAD_SIZE = 1 + POOL_KEY_HASH_LENGTH + VRF_KEY_HASH_LENGTH + 8 + 4;
    uint8_t buf_data[2 + PAYLOAD_SIZE];
    memset(buf_data, 0, sizeof(buf_data));
    _write_payload_length(buf_data, PAYLOAD_SIZE);
    size_t off = 2;
    buf_data[off++] = EXT_CREDENTIAL_KEY_HASH;
    off += POOL_KEY_HASH_LENGTH;
    off += VRF_KEY_HASH_LENGTH;
    _write_u64_be(buf_data + off, 1);
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    certificate_data_t cert;
    assert_false(parse_certificate_stake_pool_registration(&buf, &cert));
}

static void test_pool_reg_truncated_margin_numerator(void **state) {
    (void) state;
    const size_t PAYLOAD_SIZE = 1 + POOL_KEY_HASH_LENGTH + VRF_KEY_HASH_LENGTH + 8 + 8 + 4;
    uint8_t buf_data[2 + PAYLOAD_SIZE];
    memset(buf_data, 0, sizeof(buf_data));
    _write_payload_length(buf_data, PAYLOAD_SIZE);
    size_t off = 2;
    buf_data[off++] = EXT_CREDENTIAL_KEY_HASH;
    off += POOL_KEY_HASH_LENGTH;
    off += VRF_KEY_HASH_LENGTH;
    _write_u64_be(buf_data + off, 1);
    off += 8;
    _write_u64_be(buf_data + off, 1);
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    certificate_data_t cert;
    assert_false(parse_certificate_stake_pool_registration(&buf, &cert));
}

static void test_pool_reg_truncated_margin_denominator(void **state) {
    (void) state;
    const size_t PAYLOAD_SIZE = 1 + POOL_KEY_HASH_LENGTH + VRF_KEY_HASH_LENGTH + 8 + 8 + 8 + 4;
    uint8_t buf_data[2 + PAYLOAD_SIZE];
    memset(buf_data, 0, sizeof(buf_data));
    _write_payload_length(buf_data, PAYLOAD_SIZE);
    size_t off = 2;
    buf_data[off++] = EXT_CREDENTIAL_KEY_HASH;
    off += POOL_KEY_HASH_LENGTH;
    off += VRF_KEY_HASH_LENGTH;
    _write_u64_be(buf_data + off, 1);
    off += 8;
    _write_u64_be(buf_data + off, 1);
    off += 8;
    _write_u64_be(buf_data + off, 1);
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    certificate_data_t cert;
    assert_false(parse_certificate_stake_pool_registration(&buf, &cert));
}

static void test_pool_reg_truncated_reward_account_type(void **state) {
    (void) state;
    const size_t PAYLOAD_SIZE = 1 + POOL_KEY_HASH_LENGTH + VRF_KEY_HASH_LENGTH + 8 + 8 + 8 + 8;
    uint8_t buf_data[2 + PAYLOAD_SIZE];
    memset(buf_data, 0, sizeof(buf_data));
    _write_payload_length(buf_data, PAYLOAD_SIZE);
    size_t off = 2;
    buf_data[off++] = EXT_CREDENTIAL_KEY_HASH;
    off += POOL_KEY_HASH_LENGTH;
    off += VRF_KEY_HASH_LENGTH;
    _write_u64_be(buf_data + off, 1);
    off += 8;
    _write_u64_be(buf_data + off, 1);
    off += 8;
    _write_u64_be(buf_data + off, 1);
    off += 8;
    _write_u64_be(buf_data + off, 2);
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    certificate_data_t cert;
    assert_false(parse_certificate_stake_pool_registration(&buf, &cert));
}

static void test_pool_reg_truncated_reward_account_hash(void **state) {
    (void) state;
    const size_t PAYLOAD_SIZE = 1 + POOL_KEY_HASH_LENGTH + VRF_KEY_HASH_LENGTH + 8 + 8 + 8 + 8 +
                                1 + 5;
    uint8_t buf_data[2 + PAYLOAD_SIZE];
    memset(buf_data, 0, sizeof(buf_data));
    _write_payload_length(buf_data, PAYLOAD_SIZE);
    size_t off = 2;
    buf_data[off++] = EXT_CREDENTIAL_KEY_HASH;
    off += POOL_KEY_HASH_LENGTH;
    off += VRF_KEY_HASH_LENGTH;
    _write_u64_be(buf_data + off, 1);
    off += 8;
    _write_u64_be(buf_data + off, 1);
    off += 8;
    _write_u64_be(buf_data + off, 1);
    off += 8;
    _write_u64_be(buf_data + off, 2);
    off += 8;
    buf_data[off++] = EXT_CREDENTIAL_KEY_HASH;
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    certificate_data_t cert;
    assert_false(parse_certificate_stake_pool_registration(&buf, &cert));
}

static void test_pool_reg_truncated_reward_account_path(void **state) {
    (void) state;
    const size_t PAYLOAD_SIZE = 1 + POOL_KEY_HASH_LENGTH + VRF_KEY_HASH_LENGTH + 8 + 8 + 8 + 8 +
                                1 + 1;
    uint8_t buf_data[2 + PAYLOAD_SIZE];
    memset(buf_data, 0, sizeof(buf_data));
    _write_payload_length(buf_data, PAYLOAD_SIZE);
    size_t off = 2;
    buf_data[off++] = EXT_CREDENTIAL_KEY_HASH;
    off += POOL_KEY_HASH_LENGTH;
    off += VRF_KEY_HASH_LENGTH;
    _write_u64_be(buf_data + off, 1);
    off += 8;
    _write_u64_be(buf_data + off, 1);
    off += 8;
    _write_u64_be(buf_data + off, 1);
    off += 8;
    _write_u64_be(buf_data + off, 2);
    off += 8;
    buf_data[off++] = EXT_CREDENTIAL_KEY_PATH;
    buf_data[off++] = 5;
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    certificate_data_t cert;
    assert_false(parse_certificate_stake_pool_registration(&buf, &cert));
}

static void test_pool_reg_truncated_num_owners(void **state) {
    (void) state;
    // Full header through reward account, then num_owners truncated (only 1 byte).
    const size_t HDR_SIZE = 1 + POOL_KEY_HASH_LENGTH + VRF_KEY_HASH_LENGTH + 8 + 8 + 8 +
                            8                            // pledge, cost, num, denom
                            + 1 + REWARD_ACCOUNT_LENGTH  // reward account
                            + 1;                         // only 1 byte instead of 2 for num_owners
    uint8_t buf_data[2 + HDR_SIZE];
    memset(buf_data, 0, sizeof(buf_data));
    buf_data[0] = (uint8_t) (HDR_SIZE >> 8);
    buf_data[1] = (uint8_t) (HDR_SIZE & 0xFF);
    size_t off = _write_pool_reg_header_up_to_reward_account(buf_data);
    buf_data[off++] = 0x00;  // only 1 byte for num_owners
    buffer_t buf = {.ptr = buf_data, .size = 2 + HDR_SIZE, .offset = 0};
    certificate_data_t cert;
    assert_false(parse_certificate_stake_pool_registration(&buf, &cert));
}

static void test_pool_reg_truncated_num_relays(void **state) {
    (void) state;
    const size_t HDR_SIZE = 1 + POOL_KEY_HASH_LENGTH + VRF_KEY_HASH_LENGTH + 8 + 8 + 8 + 8 + 1 +
                            REWARD_ACCOUNT_LENGTH + 2  // num_owners OK
                            + 1;                       // only 1 byte for num_relays
    uint8_t buf_data[2 + HDR_SIZE];
    memset(buf_data, 0, sizeof(buf_data));
    buf_data[0] = (uint8_t) (HDR_SIZE >> 8);
    buf_data[1] = (uint8_t) (HDR_SIZE & 0xFF);
    size_t off = _write_pool_reg_header_up_to_reward_account(buf_data);
    buf_data[off++] = 0x00;
    buf_data[off++] = 0x00;  // num_owners = 0
    buf_data[off++] = 0x00;  // only 1 byte for num_relays
    buffer_t buf = {.ptr = buf_data, .size = 2 + HDR_SIZE, .offset = 0};
    certificate_data_t cert;
    assert_false(parse_certificate_stake_pool_registration(&buf, &cert));
}

static void test_pool_reg_truncated_metadata_flag(void **state) {
    (void) state;
    const size_t HDR_SIZE = 1 + POOL_KEY_HASH_LENGTH + VRF_KEY_HASH_LENGTH + 8 + 8 + 8 + 8 + 1 +
                            REWARD_ACCOUNT_LENGTH + 2 +
                            2;  // num_owners + num_relays, metadata flag missing
    uint8_t buf_data[2 + HDR_SIZE];
    memset(buf_data, 0, sizeof(buf_data));
    buf_data[0] = (uint8_t) (HDR_SIZE >> 8);
    buf_data[1] = (uint8_t) (HDR_SIZE & 0xFF);
    size_t off = _write_pool_reg_header_up_to_reward_account(buf_data);
    buf_data[off++] = 0x00;
    buf_data[off++] = 0x00;  // num_owners = 0
    buf_data[off++] = 0x00;
    buf_data[off++] = 0x00;  // num_relays = 0
    // no metadata flag
    buffer_t buf = {.ptr = buf_data, .size = 2 + HDR_SIZE, .offset = 0};
    certificate_data_t cert;
    assert_false(parse_certificate_stake_pool_registration(&buf, &cert));
}

// ---------------------------------------------------------------------------
// _parse_required_relay_dns_name error paths (via RELAY_SINGLE_HOST_NAME)
// ---------------------------------------------------------------------------

static void test_relay_dns_truncated_inclusion_flag(void **state) {
    (void) state;
    // RELAY_SINGLE_HOST_NAME + port present + port value, then no dns inclusion flag.
    uint8_t buf_data[] = {
        RELAY_SINGLE_HOST_NAME,
        2,  // FLAG_INCLUDED_YES -> port present
        0x00,
        0x50,  // port = 80
        // no dns inclusion flag byte
    };
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    pool_relay_t relay;
    assert_false(parse_pool_relay(&buf, &relay));
}

static void test_relay_dns_missing(void **state) {
    (void) state;
    // RELAY_SINGLE_HOST_NAME, port present, dns inclusion flag = NO.
    uint8_t buf_data[] = {
        RELAY_SINGLE_HOST_NAME,
        2,  // FLAG_INCLUDED_YES -> port present
        0x00,
        0x50,  // port = 80
        1,     // FLAG_INCLUDED_NO -> dns not included -> rejected
    };
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    pool_relay_t relay;
    assert_false(parse_pool_relay(&buf, &relay));
}

static void test_relay_dns_length_truncated(void **state) {
    (void) state;
    // dns inclusion flag = YES, but no dns length byte follows.
    uint8_t buf_data[] = {
        RELAY_SINGLE_HOST_NAME,
        2,  // port present
        0x00,
        0x50,
        2,  // FLAG_INCLUDED_YES
        // no dns length byte
    };
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    pool_relay_t relay;
    assert_false(parse_pool_relay(&buf, &relay));
}

static void test_relay_dns_length_zero(void **state) {
    (void) state;
    // dns inclusion flag = YES, but dns length = 0 -> rejected.
    uint8_t buf_data[] = {
        RELAY_SINGLE_HOST_NAME,
        2,  // port present
        0x00,
        0x50,
        2,  // FLAG_INCLUDED_YES
        0,  // dns_length = 0 -> rejected
    };
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    pool_relay_t relay;
    assert_false(parse_pool_relay(&buf, &relay));
}

static void test_relay_dns_too_long(void **state) {
    (void) state;
    // dns length = MAX_DNS_NAME_LENGTH + 1 = 129 (now checked before the > 0 guard).
    uint8_t buf_data[] = {
        RELAY_SINGLE_HOST_NAME,
        2,  // port present
        0x00,
        0x50,
        2,                        // FLAG_INCLUDED_YES
        MAX_DNS_NAME_LENGTH + 1,  // dns_length too large
    };
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    pool_relay_t relay;
    assert_false(parse_pool_relay(&buf, &relay));
}

static void test_relay_dns_name_truncated(void **state) {
    (void) state;
    // dns length = 5, but only 2 name bytes follow.
    uint8_t buf_data[] = {
        RELAY_SINGLE_HOST_NAME,
        2,  // port present
        0x00,
        0x50,
        2,  // FLAG_INCLUDED_YES
        5,  // dns_length = 5
        'a',
        'b',  // only 2 bytes
    };
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    pool_relay_t relay;
    assert_false(parse_pool_relay(&buf, &relay));
}

static void test_relay_dns_non_ascii(void **state) {
    (void) state;
    // dns length = 3, name contains a non-ASCII byte (0x80).
    uint8_t buf_data[] = {
        RELAY_SINGLE_HOST_NAME,
        2,  // port present
        0x00,
        0x50,
        2,  // FLAG_INCLUDED_YES
        3,  // dns_length = 3
        'a',
        0x80,
        'b',  // 0x80 is not unambiguous ASCII
    };
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    pool_relay_t relay;
    assert_false(parse_pool_relay(&buf, &relay));
}

// ---------------------------------------------------------------------------
// parse_pool_relay RELAY_SINGLE_HOST_IP remaining truncation paths
// ---------------------------------------------------------------------------

static void test_relay_ip_truncated_port_flag(void **state) {
    (void) state;
    uint8_t buf_data[1] = {RELAY_SINGLE_HOST_IP};
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    pool_relay_t relay;
    assert_false(parse_pool_relay(&buf, &relay));
}

static void test_relay_ip_truncated_port_number(void **state) {
    (void) state;
    // port flag = YES, but only 1 byte of port (need 2).
    uint8_t buf_data[] = {RELAY_SINGLE_HOST_IP, 2, 0x00};
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    pool_relay_t relay;
    assert_false(parse_pool_relay(&buf, &relay));
}

static void test_relay_ip_truncated_ipv4_flag(void **state) {
    (void) state;
    // port present + value, no ipv4 flag.
    uint8_t buf_data[] = {RELAY_SINGLE_HOST_IP, 2, 0x00, 0x50};
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    pool_relay_t relay;
    assert_false(parse_pool_relay(&buf, &relay));
}

static void test_relay_ip_truncated_ipv4_bytes(void **state) {
    (void) state;
    // ipv4 flag = YES, but only 2 ipv4 bytes (need 4).
    uint8_t buf_data[] = {RELAY_SINGLE_HOST_IP, 2, 0x00, 0x50, 2, 0x01, 0x02};
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    pool_relay_t relay;
    assert_false(parse_pool_relay(&buf, &relay));
}

static void test_relay_ip_truncated_ipv6_flag(void **state) {
    (void) state;
    // port + ipv4 present, no ipv6 flag byte.
    uint8_t buf_data[] = {
        RELAY_SINGLE_HOST_IP,
        2,
        0x00,
        0x50,  // port
        2,
        0x01,
        0x02,
        0x03,
        0x04,  // ipv4 present + 4 bytes
        // no ipv6 flag
    };
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    pool_relay_t relay;
    assert_false(parse_pool_relay(&buf, &relay));
}

static void test_relay_ip_truncated_ipv6_bytes(void **state) {
    (void) state;
    // ipv6 flag = YES, but only 5 ipv6 bytes (need 16).
    uint8_t buf_data[] = {
        RELAY_SINGLE_HOST_IP,
        2,
        0x00,
        0x50,
        1,  // ipv4 absent
        2,
        0x20,
        0x01,
        0x0D,
        0xB8,
        0x00,  // ipv6 present + 5 bytes only
    };
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    pool_relay_t relay;
    assert_false(parse_pool_relay(&buf, &relay));
}

// ---------------------------------------------------------------------------
// parse_pool_relay RELAY_SINGLE_HOST_NAME remaining truncation paths
// ---------------------------------------------------------------------------

static void test_relay_hostname_truncated_port_flag(void **state) {
    (void) state;
    uint8_t buf_data[1] = {RELAY_SINGLE_HOST_NAME};
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    pool_relay_t relay;
    assert_false(parse_pool_relay(&buf, &relay));
}

static void test_relay_hostname_truncated_port_number(void **state) {
    (void) state;
    // port flag = YES, only 1 port byte.
    uint8_t buf_data[] = {RELAY_SINGLE_HOST_NAME, 2, 0x00};
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    pool_relay_t relay;
    assert_false(parse_pool_relay(&buf, &relay));
}

// ---------------------------------------------------------------------------
// parse_pool_metadata error paths
// ---------------------------------------------------------------------------

static void test_pool_metadata_truncated_url_length(void **state) {
    (void) state;
    uint8_t buf_data[1] = {0x00};  // only 1 byte, need 2 for u16
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    pool_metadata_t meta;
    assert_false(parse_pool_metadata(&buf, &meta));
}

static void test_pool_metadata_url_too_long(void **state) {
    (void) state;
    // url_length = MAX_POOL_METADATA_URL_LENGTH + 1
    uint16_t bad_len = MAX_POOL_METADATA_URL_LENGTH + 1;
    uint8_t buf_data[2] = {(uint8_t) (bad_len >> 8), (uint8_t) (bad_len & 0xFF)};
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    pool_metadata_t meta;
    assert_false(parse_pool_metadata(&buf, &meta));
}

static void test_pool_metadata_url_truncated(void **state) {
    (void) state;
    // url_length = 10, only 3 url bytes.
    uint8_t buf_data[5] = {0x00, 0x0A, 'h', 't', 't'};
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    pool_metadata_t meta;
    assert_false(parse_pool_metadata(&buf, &meta));
}

static void test_pool_metadata_url_non_printable(void **state) {
    (void) state;
    // url_length = 3, url contains a space (0x20 is printable but spaces are rejected
    // by str_isPrintableAsciiWithoutSpaces).
    uint8_t buf_data[2 + 3] = {0x00, 0x03, 'h', ' ', 'p'};
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    pool_metadata_t meta;
    assert_false(parse_pool_metadata(&buf, &meta));
}

static void test_pool_metadata_hash_truncated(void **state) {
    (void) state;
    // url_length = 0 (skip url), then only 5 hash bytes (need POOL_METADATA_HASH_LENGTH=32).
    uint8_t buf_data[2 + 5] = {0x00, 0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE};
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    pool_metadata_t meta;
    assert_false(parse_pool_metadata(&buf, &meta));
}

// ---------------------------------------------------------------------------
// parse_certificate_account_registration_delegation_to_drep remaining gaps
// ---------------------------------------------------------------------------

static void test_cert_acct_reg_to_drep_truncated_deposit(void **state) {
    (void) state;
    // Valid credential + drep(ABSTAIN) + only 4 deposit bytes (need 8).
    uint8_t buf_data[1 + ADDRESS_KEY_HASH_LENGTH + 1 + 4] = {0};
    size_t off = _write_key_hash_credential(buf_data);
    buf_data[off++] = (uint8_t) EXT_DREP_ABSTAIN;
    // 4 deposit bytes (truncated)
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    certificate_data_t cert;
    assert_false(parse_certificate_account_registration_delegation_to_drep(&buf, &cert));
}

// ---------------------------------------------------------------------------
// parse_certificate_account_registration_delegation_to_stake_pool_and_drep remaining
// ---------------------------------------------------------------------------

static void test_cert_acct_reg_to_pool_and_drep_truncated_pool_hash(void **state) {
    (void) state;
    uint8_t buf_data[1 + ADDRESS_KEY_HASH_LENGTH + 5] = {0};  // only 5 pool hash bytes
    _write_key_hash_credential(buf_data);
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    certificate_data_t cert;
    assert_false(
        parse_certificate_account_registration_delegation_to_stake_pool_and_drep(&buf, &cert));
}

static void test_cert_acct_reg_to_pool_and_drep_truncated_drep(void **state) {
    (void) state;
    uint8_t buf_data[1 + ADDRESS_KEY_HASH_LENGTH + POOL_KEY_HASH_LENGTH] = {0};
    _write_key_hash_credential(buf_data);
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    certificate_data_t cert;
    assert_false(
        parse_certificate_account_registration_delegation_to_stake_pool_and_drep(&buf, &cert));
}

static void test_cert_acct_reg_to_pool_and_drep_truncated_deposit(void **state) {
    (void) state;
    uint8_t buf_data[1 + ADDRESS_KEY_HASH_LENGTH + POOL_KEY_HASH_LENGTH + 1 + 4] = {0};
    size_t off = _write_key_hash_credential(buf_data);
    off += POOL_KEY_HASH_LENGTH;
    buf_data[off] = (uint8_t) EXT_DREP_ABSTAIN;
    // 4 deposit bytes only (truncated)
    buffer_t buf = {.ptr = buf_data, .size = sizeof(buf_data), .offset = 0};
    certificate_data_t cert;
    assert_false(
        parse_certificate_account_registration_delegation_to_stake_pool_and_drep(&buf, &cert));
}

int main(void) {
    const struct CMUnitTest tests[] = {
        // parse_certificate_stake_registration_deregistration
        cmocka_unit_test(test_cert_stake_reg_truncated_credential),
        // parse_certificate_stake_delegation
        cmocka_unit_test(test_cert_stake_delegation_truncated_credential),
        cmocka_unit_test(test_cert_stake_delegation_truncated_pool_hash),
        // parse_certificate_stake_registration_deregistration_conway
        cmocka_unit_test(test_cert_conway_reg_truncated_credential),
        cmocka_unit_test(test_cert_conway_reg_truncated_deposit),
        cmocka_unit_test(test_cert_conway_reg_deposit_too_large),
        cmocka_unit_test(test_cert_conway_dereg_deposit_too_large),
        // parse_certificate_stake_pool_retirement
        cmocka_unit_test(test_cert_pool_retirement_truncated_credential),
        cmocka_unit_test(test_cert_pool_retirement_truncated_epoch),
        // parse_certificate_vote_delegation
        cmocka_unit_test(test_cert_vote_delegation_truncated_credential),
        cmocka_unit_test(test_cert_vote_delegation_truncated_drep),
        // parse_certificate_stake_pool_and_drep_delegation
        cmocka_unit_test(test_cert_pool_and_drep_delegation_truncated_credential),
        cmocka_unit_test(test_cert_pool_and_drep_delegation_truncated_pool_hash),
        cmocka_unit_test(test_cert_pool_and_drep_delegation_truncated_drep),
        // parse_certificate_account_registration_delegation_to_stake_pool
        cmocka_unit_test(test_cert_acct_reg_to_pool_truncated_credential),
        cmocka_unit_test(test_cert_acct_reg_to_pool_truncated_pool_hash),
        cmocka_unit_test(test_cert_acct_reg_to_pool_truncated_deposit),
        cmocka_unit_test(test_cert_acct_reg_to_pool_deposit_too_large),
        // parse_certificate_account_registration_delegation_to_drep
        cmocka_unit_test(test_cert_acct_reg_to_drep_truncated_credential),
        cmocka_unit_test(test_cert_acct_reg_to_drep_truncated_drep),
        cmocka_unit_test(test_cert_acct_reg_to_drep_truncated_deposit),
        cmocka_unit_test(test_cert_acct_reg_to_drep_deposit_too_large),
        // parse_certificate_account_registration_delegation_to_stake_pool_and_drep
        cmocka_unit_test(test_cert_acct_reg_to_pool_and_drep_truncated_credential),
        cmocka_unit_test(test_cert_acct_reg_to_pool_and_drep_truncated_pool_hash),
        cmocka_unit_test(test_cert_acct_reg_to_pool_and_drep_truncated_drep),
        cmocka_unit_test(test_cert_acct_reg_to_pool_and_drep_truncated_deposit),
        cmocka_unit_test(test_cert_acct_reg_to_pool_and_drep_deposit_too_large),
        // parse_certificate_authorize_committee_hot
        cmocka_unit_test(test_cert_authorize_committee_hot_truncated_cold_credential),
        cmocka_unit_test(test_cert_authorize_committee_hot_truncated_hot_credential),
        // parse_certificate_resign_committee_cold
        cmocka_unit_test(test_cert_resign_committee_cold_truncated_credential),
        cmocka_unit_test(test_cert_resign_committee_cold_truncated_anchor),
        // parse_certificate_drep_registration
        cmocka_unit_test(test_cert_drep_registration_truncated_credential),
        cmocka_unit_test(test_cert_drep_registration_truncated_deposit),
        cmocka_unit_test(test_cert_drep_registration_deposit_too_large),
        cmocka_unit_test(test_cert_drep_registration_truncated_anchor),
        // parse_certificate_drep_deregistration
        cmocka_unit_test(test_cert_drep_deregistration_truncated_credential),
        cmocka_unit_test(test_cert_drep_deregistration_truncated_deposit),
        cmocka_unit_test(test_cert_drep_deregistration_deposit_too_large),
        // parse_certificate_drep_update
        cmocka_unit_test(test_cert_drep_update_truncated_credential),
        cmocka_unit_test(test_cert_drep_update_truncated_anchor),
        // parse_certificate dispatcher
        cmocka_unit_test(test_cert_parse_truncated_type),
        cmocka_unit_test(test_cert_parse_unknown_type),
        // parse_pool_relay
        cmocka_unit_test(test_pool_id_truncated_type),
        cmocka_unit_test(test_pool_id_unknown_type),
        cmocka_unit_test(test_pool_id_hash_truncated),
        cmocka_unit_test(test_pool_id_path_truncated),

        cmocka_unit_test(test_pool_reg_truncated_vrf_hash),
        cmocka_unit_test(test_pool_reg_truncated_pledge),
        cmocka_unit_test(test_pool_reg_pledge_too_large),
        cmocka_unit_test(test_pool_reg_truncated_cost),
        cmocka_unit_test(test_pool_reg_cost_too_large),
        cmocka_unit_test(test_pool_reg_truncated_margin_numerator),
        cmocka_unit_test(test_pool_reg_truncated_margin_denominator),
        cmocka_unit_test(test_pool_reg_truncated_reward_account_type),
        cmocka_unit_test(test_pool_reg_truncated_reward_account_hash),
        cmocka_unit_test(test_pool_reg_truncated_reward_account_path),
        cmocka_unit_test(test_pool_reg_truncated_num_owners),
        cmocka_unit_test(test_pool_reg_truncated_num_relays),
        cmocka_unit_test(test_pool_reg_truncated_metadata_flag),

        cmocka_unit_test(test_relay_dns_truncated_inclusion_flag),
        cmocka_unit_test(test_relay_dns_missing),
        cmocka_unit_test(test_relay_dns_length_truncated),
        cmocka_unit_test(test_relay_dns_length_zero),
        cmocka_unit_test(test_relay_dns_too_long),
        cmocka_unit_test(test_relay_dns_name_truncated),
        cmocka_unit_test(test_relay_dns_non_ascii),

        cmocka_unit_test(test_relay_ip_truncated_port_flag),
        cmocka_unit_test(test_relay_ip_truncated_port_number),
        cmocka_unit_test(test_relay_ip_truncated_ipv4_flag),
        cmocka_unit_test(test_relay_ip_truncated_ipv4_bytes),
        cmocka_unit_test(test_relay_ip_truncated_ipv6_flag),
        cmocka_unit_test(test_relay_ip_truncated_ipv6_bytes),

        cmocka_unit_test(test_relay_hostname_truncated_port_flag),
        cmocka_unit_test(test_relay_hostname_truncated_port_number),

        cmocka_unit_test(test_pool_metadata_truncated_url_length),
        cmocka_unit_test(test_pool_metadata_url_too_long),
        cmocka_unit_test(test_pool_metadata_url_truncated),
        cmocka_unit_test(test_pool_metadata_url_non_printable),
        cmocka_unit_test(test_pool_metadata_hash_truncated),

        cmocka_unit_test(test_parse_pool_relay_truncated_type),
        cmocka_unit_test(test_parse_pool_relay_single_host_ip_missing_port),
        cmocka_unit_test(test_parse_pool_relay_single_host_ip_no_ip),
        cmocka_unit_test(test_parse_pool_relay_single_host_name_missing_port),
        cmocka_unit_test(test_relay_multiple_host_name_success),
        cmocka_unit_test(test_relay_multiple_host_name_truncated_dns),
        cmocka_unit_test(test_parse_pool_relay_unknown_type),
        // parse_certificate_stake_pool_registration
        cmocka_unit_test(test_cert_pool_reg_payload_length_exceeds_buffer),
        cmocka_unit_test(test_cert_pool_reg_invalid_margin),
        cmocka_unit_test(test_cert_pool_reg_unknown_reward_account_type),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
