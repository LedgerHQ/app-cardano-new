/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#ifndef LCX_RIPEMD160_H
#define LCX_RIPEMD160_H

/** RIPEMD160 message digest size */
#define CX_RIPEMD160_SIZE 20

/**
 * RIPEMD-160 context
 */
struct cx_ripemd160_s {
    /** See #cx_hash_header_s */
    struct cx_hash_header_s header;
    /** @internal
     * pending partial block length
     */
    unsigned int blen;
    /** @internal
     * pending partial block
     */
    unsigned char block[64];
    /** Current digest state.
     * After finishing the digest, contains the digest if correct parameters are
     * passed.
     */
    unsigned char acc[5 * 4];
};
/** Convenience type. See #cx_ripemd160_s. */
typedef struct cx_ripemd160_s cx_ripemd160_t;

/**
 * Initialize a RIPEMD-160 context.
 *
 * @param [out] hash the context to init.
 *    The context shall be in RAM
 *
 * @return algorithm identifier
 */
CXCALL int cx_ripemd160_init(cx_ripemd160_t *hash PLENGTH(sizeof(cx_ripemd160_t)));

#endif
