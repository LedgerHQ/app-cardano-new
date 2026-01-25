#pragma once

#include <stddef.h>
#include <stdint.h>

#include "buffer.h"

/**
 * Handler for SIGN_TX_AUX_DATA command. Processes auxiliary data (currently CVote registration).
 *
 * @param[in] cdata Buffer containing APDU data payload
 * @param[in] p2    P2 parameter (P2_AUX_DATA_INIT or P2_AUX_DATA_DELEGATION)
 */
void handler_sign_tx_aux_data(buffer_t *cdata, uint8_t p2);
