/* SPDX-FileCopyrightText: 2016-2025 Ledger */
/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include "swap.h"
#include "bip44.h"
#include "addressUtilsShelley.h"
#include "cardano_constants.h"
#include "utils.h"

#ifdef HAVE_SWAP

// Set params.result to 0 on error, 1 otherwise
void swap_handle_check_address(check_address_parameters_t *params) {
    uint8_t rawAddressBuffer[MAX_ADDRESS_LENGTH] = {0};
    char derivedAddressHumanReadable[MAX_HUMAN_ADDRESS_LENGTH] = {0};
    address_params_t addressParams = {0};
    bip44_path_t pathSpec = {0};
    size_t derivedAddressLength = 0;

    TRACE("Inside swap_handle_check_address");
    params->result = 0;

    if (params->address_parameters == NULL) {
        TRACE("ERROR: derivation path expected");
        return;
    }

    if (params->address_to_check == NULL) {
        TRACE("ERROR: Address to check expected");
        return;
    }

    // Parse the derivation path from the packed wire format
    // The packed format is: 1 byte length + N * 4 bytes big-endian path components
    buffer_t pathBuffer = {
        .ptr = params->address_parameters,
        .size = params->address_parameters_length,
        .offset = 0,
    };
    if (!buffer_read_bip44_path(&pathBuffer, &pathSpec)) {
        TRACE("ERROR: failed to parse BIP44 path");
        return;
    }
    if (buffer_can_read(&pathBuffer, 1)) {
        TRACE("ERROR: trailing bytes in packed BIP44 path");
        return;
    }

    uint32_t purpose = pathSpec.path[BIP44_I_PURPOSE] & (~HARDENED_BIP32);

    switch (purpose) {
        case PURPOSE_SHELLEY: {
            // Compute default device address from received path:
            // Base address with payment key from the path and staking key
            // derived from the same account (chain=2, index=0)
            addressParams.type = BASE_PAYMENT_KEY_STAKE_KEY;
            addressParams.networkId = MAINNET_NETWORK_ID;
            addressParams.paymentPartType = PAYMENT_PART_KEY_PATH;
            memcpy(&addressParams.paymentKeyPath, &pathSpec, sizeof(bip44_path_t));
            addressParams.stakingPartType = STAKING_PART_KEY_PATH;
            memcpy(&addressParams.stakingKeyPath, &pathSpec, sizeof(bip44_path_t));
            // The default staking key path is the same as the payment key path,
            // except for the chain and address index elements
            addressParams.stakingKeyPath.path[BIP44_I_CHAIN] = 2;
            addressParams.stakingKeyPath.path[BIP44_I_ADDRESS] = 0;

            derivedAddressLength = deriveAddress(&addressParams,
                                                 rawAddressBuffer,
                                                 sizeof(rawAddressBuffer));
            if (!format_address_human_readable(rawAddressBuffer,
                                               derivedAddressLength,
                                               derivedAddressHumanReadable,
                                               sizeof(derivedAddressHumanReadable))) {
                TRACE("Failed to format derived address");
                return;
            }
            if (strcmp(params->address_to_check, derivedAddressHumanReadable) != 0) {
                TRACE("Address %s != %s", params->address_to_check, derivedAddressHumanReadable);
                return;
            }
            break;
        }
        default:
            // Intentionally reject non-Shelley purposes (including PURPOSE_BYRON).
            // Swap flow in this app supports only Shelley refund path/address checks.
            TRACE("ERROR: unsupported purpose %u for swap check address", purpose);
            return;
    }

    TRACE("Addresses match");
    params->result = 1;
    return;
}

#endif  // HAVE_SWAP
