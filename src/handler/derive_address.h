#pragma once

enum {
    P1_RETURN = 0x01,
    P1_DISPLAY = 0x02,
};

//TODO: comments
/**
 * Handler for INS_DERIVE_ADDRESS command. Send APDU response with ASCII
 * encoded name of the application.
 *
 * @see variable APPNAME in Makefile.
 * @param cdata
 *
 */
void handler_derive_address(buffer_t *cdata, uint8_t display_type);

