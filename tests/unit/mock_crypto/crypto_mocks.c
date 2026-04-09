/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdbool.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cardano_constants.h"
#include "cx.h"

#include "decorators.h"
#include "crypto.h"
#include "keyDerivation.h"
#include "crypto_mock_data.h"
#include "utils/assert.h"

#define RAW_PUBKEY_SIZE 65

uint8_t g_mock_last_signed_message[MOCK_SIGNED_MESSAGE_BUFFER_SIZE];
size_t g_mock_last_signed_message_len = 0;
const mock_signature_data_t* g_mock_last_signature_entry = NULL;

void reset_mock_signature_state(void) {
    memset(g_mock_last_signed_message, 0, sizeof(g_mock_last_signed_message));
    g_mock_last_signed_message_len = 0;
    g_mock_last_signature_entry = NULL;
}

static bool path_matches(const uint32_t* lhs, size_t lhs_len, const uint32_t* rhs, size_t rhs_len) {
    if (lhs_len != rhs_len) {
        return false;
    }
    for (size_t i = 0; i < lhs_len; i++) {
        if (lhs[i] != rhs[i]) {
            return false;
        }
    }
    return true;
}

static const mock_path_data_t* find_path_entry(const uint32_t* path, size_t path_len) {
    for (size_t i = 0; i < MOCK_PATH_COUNT; i++) {
        if (path_matches(path, path_len, MOCK_PATHS[i].path, MOCK_PATHS[i].path_len)) {
            return &MOCK_PATHS[i];
        }
    }
    return NULL;
}

static const mock_signature_data_t* find_signature_entry(const uint32_t* path,
                                                         size_t path_len,
                                                         const uint8_t* message,
                                                         size_t message_len) {
    for (size_t i = 0; i < MOCK_SIGNATURE_COUNT; i++) {
        const mock_signature_data_t* entry = &MOCK_SIGNATURES[i];
        if (!path_matches(path, path_len, entry->path, entry->path_len)) {
            continue;
        }
        if (entry->message_len != message_len) {
            continue;
        }
        if (memcmp(entry->message, message, message_len) != 0) {
            continue;
        }
        return entry;
    }
    return NULL;
}

static void maybe_log_signature_entry_usage(const mock_signature_data_t* entry) {
    const char* log_path = getenv("CARDANO_MOCK_SIGNATURE_USAGE_LOG");
    if (log_path == NULL || log_path[0] == '\0') {
        return;
    }

    const int log_fd = open(log_path, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (log_fd < 0) {
        return;
    }

    const size_t entry_index = (size_t) (entry - MOCK_SIGNATURES);
    char line_buffer[32];
    size_t line_length = 0;
    size_t remaining_value = entry_index;
    do {
        line_buffer[line_length++] = (char) ('0' + (remaining_value % 10));
        remaining_value /= 10;
    } while (remaining_value > 0);
    line_buffer[line_length++] = '\n';

    for (size_t i = 0; i < line_length / 2; i++) {
        const char tmp = line_buffer[i];
        line_buffer[i] = line_buffer[line_length - 2 - i];
        line_buffer[line_length - 2 - i] = tmp;
    }

    if (write(log_fd, line_buffer, line_length) < 0) {
        // best-effort logging only
    }
    close(log_fd);
}

static void encode_raw_pubkey(const uint8_t public_key[32], uint8_t raw_pubkey[RAW_PUBKEY_SIZE]) {
    memset(raw_pubkey, 0, RAW_PUBKEY_SIZE);
    raw_pubkey[0] = 0x04;

    uint8_t y_le[32];
    memcpy(y_le, public_key, 32);
    uint8_t sign_bit = (uint8_t) (y_le[31] & 0x80u);
    y_le[31] &= 0x7Fu;

    for (size_t i = 0; i < 32; i++) {
        raw_pubkey[RAW_PUBKEY_SIZE - 1 - i] = y_le[i];
    }
    raw_pubkey[32] = (uint8_t) (sign_bit ? 0x01 : 0x00);
}

void crypto_get_pubkey(const uint32_t* path,
                       size_t path_len,
                       uint8_t raw_pubkey[static RAW_PUBKEY_SIZE],
                       uint8_t* chain_code) {
    const mock_path_data_t* entry = find_path_entry(path, path_len);
    if (entry == NULL) {
        fprintf(stderr, "crypto_mock: missing pubkey path len=%zu [", path_len);
        for (size_t i = 0; i < path_len; i++) {
            fprintf(stderr, "%s0x%08x", (i == 0 ? "" : ", "), path[i]);
        }
        fprintf(stderr, "]\n");
        LEDGER_ASSERT(false, "Missing mock public key path");
    }
    encode_raw_pubkey(entry->public_key, raw_pubkey);
    memcpy(chain_code, entry->chain_code, CHAIN_CODE_LENGTH);
}

void crypto_eddsa_sign(const uint32_t* path,
                       size_t path_len,
                       const uint8_t* hash,
                       size_t hash_len,
                       uint8_t* sig,
                       size_t expected_sig_len) {
    LEDGER_ASSERT(path != NULL, "path is NULL");
    LEDGER_ASSERT(path_len > 0, "path_len is zero");
    LEDGER_ASSERT(hash != NULL, "hash is NULL");
    LEDGER_ASSERT(hash_len > 0, "hash_len is zero");
    LEDGER_ASSERT(sig != NULL, "sig is NULL");
    LEDGER_ASSERT(expected_sig_len == ED25519_SIGNATURE_LENGTH,
                  "expected_sig_len must equal ED25519_SIGNATURE_LENGTH");

    if (hash_len > MOCK_SIGNED_MESSAGE_BUFFER_SIZE) {
        LEDGER_ASSERT(false,
                      "Signed message (%zu) exceeds mock buffer (%d)",
                      hash_len,
                      MOCK_SIGNED_MESSAGE_BUFFER_SIZE);
    }
    g_mock_last_signed_message_len = hash_len;
    memcpy(g_mock_last_signed_message, hash, hash_len);

    const mock_signature_data_t* entry = find_signature_entry(path, path_len, hash, hash_len);
    if (entry == NULL) {
        fprintf(stderr, "crypto_mock: missing signature path len=%zu [", path_len);
        for (size_t i = 0; i < path_len; i++) {
            fprintf(stderr, "%s0x%08x", (i == 0 ? "" : ", "), path[i]);
        }
        fprintf(stderr, "] message_len=%zu message_hex=", hash_len);
        for (size_t j = 0; j < hash_len; j++) {
            fprintf(stderr, "%02x", hash[j]);
        }
        fprintf(stderr, "\n");
        LEDGER_ASSERT(false, "Missing mock signature entry");
    }

    g_mock_last_signature_entry = entry;
    maybe_log_signature_entry_usage(entry);
    LEDGER_ASSERT(g_mock_last_signed_message_len == entry->message_len,
                  "Signed message length (%zu) does not match entry (%zu)",
                  g_mock_last_signed_message_len,
                  entry->message_len);

    memcpy(sig, entry->signature, ED25519_SIGNATURE_LENGTH);
}
