/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include "parser.h"

/** Instruction class byte for the Cardano app. */
#define CLA 0xD7

/**
 * Expected INS values for APDU commands.
 *
 * Mirrors `tests/application_client/command_builder.py::InsType` to keep
 * command constants aligned with the Python helpers.
 */
typedef enum {
    INS_GET_SERIAL = 0x01,
    INS_GET_VERSION = 0x03,
    INS_GET_APP_NAME = 0x04,
    INS_GET_PUBLIC_KEY = 0x10,
    INS_DERIVE_ADDRESS = 0x11,
    INS_DERIVE_NATIVE_SCRIPT_HASH = 0x12,
    INS_SIGN_TX = 0x21,
    INS_SIGN_OPCERT = 0x22,
    INS_SIGN_CVOTE = 0x23,
    INS_SIGN_MSG = 0x24,  // CIP-8 message signing
#ifdef DEBUG
    INS_DEBUG_SET_SETTINGS = 0xF0,  // Debug-only command for testing
#endif
} command_e;

/**
 * Request types handled by the dispatcher.
 */
typedef enum {
    REQUEST_NONE = 0,
    REQUEST_EXPORT_PUBKEY,
    REQUEST_SIGN_TRANSACTION,
    REQUEST_SIGN_OPCERT,
    REQUEST_DERIVE_ADDRESS,
    REQUEST_DERIVE_NATIVE_SCRIPT_HASH,
    REQUEST_CVOTE,
    REQUEST_SIGN_MSG,
} request_type_e;

/**
 * Parameter 1 (P1) values for APDU commands.
 * Organized hierarchically: 0x1x for transactions, 0x2x for address, 0x3x for opcert, 0x4x for
 * native scripts.
 *
 * Matches `tests/application_client/command_builder.py::P1Type`.
 */
typedef enum {
    P1_UNUSED = 0x00,

    // Transaction-related P1 values (0x1x range)
    P1_TX_INIT = 0x10,          // Start of transaction data
    P1_TX_CHUNK = 0x11,         // More transaction data chunks follow
    P1_TX_CONFIRM = 0x12,       // Last chunk of transaction data / confirmation
    P1_TX_AUX_DATA = 0x13,      // CVote auxiliary data APDU
    P1_TX_SIGN_WITNESS = 0x1F,  // Transaction witness signing (legacy)

    // Address derivation P1 values (0x2x range)
    P1_ADDRESS_RETURN = 0x20,   // Return address without display
    P1_ADDRESS_DISPLAY = 0x21,  // Display address on screen before returning

    // Operational certificate P1 values (0x3x range)
    // (No multi-step parameters needed for opcert)

    // Native script hash derivation P1 values (0x4x range)
    P1_NATIVE_SCRIPT_INIT = 0x40,           // Initialize: start request and UI streaming
    P1_NATIVE_SCRIPT_START_COMPLEX = 0x41,  // Start a complex script (ALL/ANY/N-of-K)
    P1_NATIVE_SCRIPT_ADD_SIMPLE = 0x42,     // Add a simple script (pubkey/timelock)
    P1_NATIVE_SCRIPT_FINISH = 0x43,         // Finish script tree and compute hash

    // Cvote P1 values (0x5x range)
    P1_CVOTE_INIT = 0x50,     // Initialize votecast signing
    P1_CVOTE_CHUNK = 0x51,    // Votecast data chunk
    P1_CVOTE_CONFIRM = 0x52,  // Confirm votecast details

    // Message signing P1 values (0x6x range, CIP-8)
    P1_SIGN_MSG_INIT = 0x60,     // Initialize message signing
    P1_SIGN_MSG_CHUNK = 0x61,    // Message data chunk
    P1_SIGN_MSG_CONFIRM = 0x62,  // Confirm and sign message
} p1_e;

/**
 * Parameter 2 (P2) values for APDU commands.
 * Organized hierarchically: 0x3x for CVote auxiliary data.
 *
 * Matches `tests/application_client/command_builder.py::P2Type`.
 */
typedef enum {
    P2_UNUSED = 0x00,

    // CVote auxiliary data P2 values (0x3x range)
    P2_AUX_DATA_INIT = 0x36,        // Initialize auxiliary data
    P2_AUX_DATA_DELEGATION = 0x37,  // Delegation record
} p2_e;

/**
 * Dispatch APDU command received to the right handler.
 *
 * @param[in] cmd
 *   Structured APDU command (CLA, INS, P1, P2, Lc, Command data).
 */
void apdu_dispatcher(const command_t *cmd);
