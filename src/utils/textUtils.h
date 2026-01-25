#pragma once

#include <stddef.h>
#include <stdint.h>

#include "utils.h"

bool str_isPrintableAsciiWithoutSpaces(const uint8_t* buffer, size_t bufferSize);
bool str_isPrintableAsciiWithSpaces(const uint8_t* buffer, size_t bufferSize);

bool str_isUnambiguousAscii(const uint8_t* buffer, size_t bufferSize);
