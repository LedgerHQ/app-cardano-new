/* SPDX-FileCopyrightText: 2025 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdbool.h>
#include <stdint.h>

#include "assert.h"
#include "app_context.h"
#include "bip44.h"
#include "buffer.h"
#include "cardano_constants.h"
#include "cardano_parsers.h"
#include "cardano_swo.h"
#include "opcert_parse.h"
#include "opcert_types.h"
#include "utils.h"

bool parse_opcert(buffer_t *buf, parsed_opcert_t *opcert)
{
    LEDGER_ASSERT(buf != NULL, "NULL buf");
    LEDGER_ASSERT(opcert != NULL, "NULL opcert");

    // KES public key
    if (!buffer_read_bytes_ptr(buf, &opcert->kesPublicKey, KES_PUBLIC_KEY_LENGTH)) {
        send_swo_and_reset(SWO_OPCERT_PARSING_FAIL_KES_KEY);
        return false;
    }

    // KES period
    ASSERT_TYPE(opcert->kesPeriod, uint64_t);
    if (!buffer_read_u64(buf, &opcert->kesPeriod, BE)) {
        send_swo_and_reset(SWO_OPCERT_PARSING_FAIL_KES_PERIOD);
        return false;
    }

    // issue counter
    ASSERT_TYPE(opcert->issueCounter, uint64_t);
    if (!buffer_read_u64(buf, &opcert->issueCounter, BE)) {
        send_swo_and_reset(SWO_OPCERT_PARSING_FAIL_ISSUE_COUNTER);
        return false;
    }

    // pool cold key path
    if (!buffer_read_bip44_path(buf, &opcert->poolColdKeyPath)) {
        send_swo_and_reset(SWO_OPCERT_PARSING_FAIL_POOL_KEY_PATH);
        return false;
    }

    if (deny_unconsumed_bytes(buf, SWO_INVALID_OPCERT_LENGTH)) {
        return false;
    }

    return true;
}
