#pragma once

#include "addressUtils/bip44.h"
#include "cx.h"

#define PUBLIC_KEY_LENGTH    (32)
#define CHAIN_CODE_LENGTH    (32)
#define EXTENDED_PUBKEY_SIZE (CHAIN_CODE_LENGTH + PUBLIC_KEY_LENGTH)

typedef cx_ecfp_256_extended_private_key_t privateKey_t;

typedef struct {
    uint8_t code[CHAIN_CODE_LENGTH];
} chain_code_t;

typedef struct {
    uint8_t pubKey[PUBLIC_KEY_LENGTH];
    uint8_t chainCode[CHAIN_CODE_LENGTH];
} extendedPublicKey_t;

cx_err_t deriveExtendedPublicKey(const bip44_path_t* pathSpec, extendedPublicKey_t* out);
