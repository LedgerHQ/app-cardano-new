#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>

#include "apdu/dispatcher.h"
#include "dispatcher.h"
#include "fuzz_utils.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (sigsetjmp(fuzz_exit_jump_ctx.jmp_buf, 1)) return 0;
    fuzzing_reset_state();
    static const uint8_t dummy = 0;

    if (size < 5) {
        return 0;
    }

    command_t cmd = {0};
    cmd.cla = CLA;
    cmd.ins = INS_SIGN_TX;
    cmd.p1 = data[2];
    cmd.p2 = data[3];
    cmd.lc = data[4];

    data += 5;
    size -= 5;
    if (size < cmd.lc) {
        return 0;
    }

    if (cmd.lc > 0) {
        uint8_t *cmd_data = malloc(cmd.lc);
        if (cmd_data == NULL) {
            return 0;
        }
        memcpy(cmd_data, data, cmd.lc);
        cmd.data = cmd_data;
        apdu_dispatcher(&cmd);
        free(cmd_data);
    } else {
        cmd.data = (uint8_t *) &dummy;
        apdu_dispatcher(&cmd);
    }

    return 0;
}
