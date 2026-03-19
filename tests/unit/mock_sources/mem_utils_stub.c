/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>

#include "app_mem_utils.h"

// Host stub: ignore heap buffer and delegate to libc.
bool mem_utils_init(void *heap_start, size_t heap_size) {
    (void) heap_start;
    (void) heap_size;
    return true;
}

void *mem_utils_alloc(size_t size, bool permanent, const char *file, int line) {
    (void) permanent;
    (void) file;
    (void) line;
    if (size == 0) {
        return NULL;
    }
    void *ptr = malloc(size);
    if (ptr != NULL) {
        memset(ptr, 0, size);
    }
    return ptr;
}

void *mem_utils_realloc(void *ptr, size_t size, const char *file, int line) {
    (void) file;
    (void) line;
    if (size == 0) {
        free(ptr);
        return NULL;
    }
    return realloc(ptr, size);
}

void mem_utils_free(void *ptr, const char *file, int line) {
    (void) file;
    (void) line;
    free(ptr);
}

void mem_utils_free_and_null(void **buffer, const char *file, int line) {
    (void) file;
    (void) line;
    if (buffer != NULL && *buffer != NULL) {
        free(*buffer);
        *buffer = NULL;
    }
}

char *mem_utils_strdup(const char *s, const char *file, int line) {
    (void) file;
    (void) line;
    if (s == NULL) {
        return NULL;
    }
    size_t len = strlen(s) + 1;
    char *dst = malloc(len);
    if (dst != NULL) {
        memcpy(dst, s, len);
    }
    return dst;
}

bool mem_utils_calloc(void **buffer, uint16_t size, bool permanent, const char *file, int line) {
    (void) permanent;
    (void) file;
    (void) line;
    if (buffer == NULL) {
        return false;
    }
    if (*buffer != NULL) {
        free(*buffer);
        *buffer = NULL;
    }
    if (size == 0) {
        return true;
    }
    *buffer = calloc(1, size);
    return *buffer != NULL;
}
