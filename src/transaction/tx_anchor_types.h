#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

typedef struct {
    bool isIncluded;
    const uint8_t* url;
    uint16_t urlLength;
    const uint8_t* hash;
} anchor_t;
