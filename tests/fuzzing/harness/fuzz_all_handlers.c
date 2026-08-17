#include <stdint.h>
#include <string.h>

#include "apdu/dispatcher.h"
#include "app_context.h"
#include "dispatcher.h"
#include "fuzz_utils.h"

#define FUZZ_APP_CUSTOM_ENTRY
#include "fuzz_harness.h"

/**
 * Unified fuzzing harness for all APDU commands.
 *
 * Feeds a continuous stream of random APDU commands to the dispatcher,
 * testing command routing, state machine transitions, and handler dispatch.
 * The tail input is interpreted as a sequence of 5-byte APDU headers followed
 * by their payloads; processing continues until the input is exhausted.
 */
int fuzz_entry(const uint8_t *data, size_t size) {
    try_context_set(&fuzz_exit_jump_ctx);
    if (sigsetjmp(fuzz_exit_jump_ctx.jmp_buf, 1)) {
        try_context_set(NULL);
        return 0;
    }

    fuzzing_reset_state();

    static const uint8_t dummy = 0;

    while (size >= 5) {
        command_t cmd = {0};
        cmd.cla = data[0];
        cmd.ins = data[1];
        cmd.p1 = data[2];
        cmd.p2 = data[3];
        cmd.lc = data[4];

        data += 5;
        size -= 5;

        if (size < cmd.lc) {
            break;
        }

        if (cmd.lc > 0) {
            // Use a stack buffer: cmd.lc is uint8_t so at most 255 bytes (short-form APDU).
            // A heap allocation would leak when apdu_dispatcher() triggers os_sched_exit()
            // which longjmps past the free().
            uint8_t cmd_data[UINT8_MAX];
            memcpy(cmd_data, data, cmd.lc);
            cmd.data = cmd_data;
            apdu_dispatcher(&cmd);
            apdu_response_state_force_reset();
        } else {
            cmd.data = (uint8_t *) &dummy;
            apdu_dispatcher(&cmd);
            apdu_response_state_force_reset();
        }

        data += cmd.lc;
        size -= cmd.lc;
    }

    try_context_set(NULL);
    return 0;
}
