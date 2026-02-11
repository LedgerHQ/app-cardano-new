/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include "assert.h"
#include "utils.h"
#include "textUtils.h"
#include <stddef.h>
#include <stdint.h>

// check if a non-null-terminated buffer contains printable ASCII between 33 and 126 (inclusive)
bool str_isPrintableAsciiWithoutSpaces(const uint8_t* buffer, size_t bufferSize) {
    ASSERT(bufferSize < BUFFER_SIZE_PARANOIA);

    for (size_t i = 0; i < bufferSize; i++) {
        if (buffer[i] > 126) return false;
        if (buffer[i] < 33) return false;
    }

    return true;
}

// check if a non-null-terminated buffer contains printable ASCII between 32 and 126 (inclusive)
bool str_isPrintableAsciiWithSpaces(const uint8_t* buffer, size_t bufferSize) {
    ASSERT(bufferSize < BUFFER_SIZE_PARANOIA);

    for (size_t i = 0; i < bufferSize; i++) {
        if (buffer[i] > 126) return false;
        if (buffer[i] < 32) return false;
    }

    return true;
}

// check if the string can be unambiguously displayed to the user
bool str_isUnambiguousAscii(const uint8_t* buffer, size_t bufferSize) {
    ASSERT(bufferSize < BUFFER_SIZE_PARANOIA);

    // must not be empty
    if (bufferSize == 0) return false;

    // no non-printable characters except spaces
    if (!str_isPrintableAsciiWithSpaces(buffer, bufferSize)) return false;

    // no leading spaces
    ASSERT(bufferSize >= 1);
    if (buffer[0] == ' ') return false;

    // no trailing spaces
    ASSERT(bufferSize >= 1);
    if (buffer[bufferSize - 1] == ' ') return false;

    // only single spaces
    for (size_t i = 0; i + 1 < bufferSize; i++) {
        if ((buffer[i] == ' ') && (buffer[i + 1] == ' ')) return false;
    }

    return true;
}
