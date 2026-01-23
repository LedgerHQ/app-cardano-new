#pragma once

#include "utils.h"

// Maximum raw transaction buffer length accepted from the host
#define TX_BUFFER_SIZE (17 * 1024)

// Ensure BUFFER_SIZE_PARANOIA is always greater than TX_BUFFER_SIZE
STATIC_ASSERT(BUFFER_SIZE_PARANOIA > TX_BUFFER_SIZE, "BUFFER_SIZE_PARANOIA must be > TX_BUFFER_SIZE");
