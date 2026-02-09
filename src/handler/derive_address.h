#pragma once

#include <stdbool.h>

#include "buffer.h"

/**
 * Handler for INS_DERIVE_ADDRESS command.
 * Derives a Cardano address from provided address parameters and optionally displays it.
 *
 * Supports two modes via P1 parameter:
 * - P1_ADDRESS_RETURN: Derive address and return without display
 * - P1_ADDRESS_DISPLAY: Derive address, display on screen, then return
 *
 * @param[in] cdata
 *   Buffer containing APDU data with address parameters
 * @param[in] display_type
 *   P1 parameter value indicating operation mode (return or display)
 *
 * @see P1_ADDRESS_RETURN and P1_ADDRESS_DISPLAY in dispatcher.h
 */
void handler_derive_address(buffer_t *cdata, uint8_t display_type);

/**
 * Finalize derive-address flow after review decision.
 * On approval, sends response based on derive-address operation mode.
 */
void finalize_derive_address(bool confirmed);
