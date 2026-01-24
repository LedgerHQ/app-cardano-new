#pragma once

#include <stddef.h>  // size_t
#include <stdbool.h>
#include <stdint.h>  // uint*_t
#include "cardano_constants.h"
#include "addressUtilsShelley.h"
#include "bip44.h"      // for bip44_path_t

/**
 * Structure for derive address information context.
 */
typedef struct {
    uint16_t responseReadyMagic;
    addressParams_t addressParams;
    struct {
        uint8_t buffer[MAX_ADDRESS_LENGTH];
        size_t size;
    } address;
} derive_address_ctx_t;
