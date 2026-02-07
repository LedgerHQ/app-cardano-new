#pragma once

#include "bip44.h"

typedef enum {
    CIP8_ADDRESS_FIELD_ADDRESS = 1,
    CIP8_ADDRESS_FIELD_KEYHASH = 2,
} cip8_address_field_type_t;

void signRawMessageWithPath(const bip44_path_t* path,
                            const uint8_t* messageBuffer,
                            size_t messageSize,
                            uint8_t* outBuffer,
                            size_t outSize);

void getWitness(const bip44_path_t* path,
                const uint8_t* txHashBuffer,
                size_t txHashSize,
                uint8_t* outBuffer,
                size_t outSize);

void getCVoteRegistrationSignature(const bip44_path_t* path,
                                   const uint8_t* payloadHashBuffer,
                                   size_t payloadHashSize,
                                   uint8_t* outBuffer,
                                   size_t outSize);
