#pragma once

#include <stddef.h>   // size_t
#include <stdbool.h>  // bool
#include <stdint.h>   // uint*_t

#include "buffer.h"

/**
 * Handler for INS_GET_PUBLIC_KEY command. If successfully parse BIP32 path,
 * derive public key/chain code and send APDU response.
 */
void handler_get_public_key(buffer_t *cdata);

void finalize_pubkey_export(bool confirmed);
