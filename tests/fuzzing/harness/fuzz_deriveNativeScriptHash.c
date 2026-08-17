#include "apdu/dispatcher.h"
#include "dispatcher.h"
#include "fuzz_harness.h"
#include "fuzz_utils.h"

const fuzz_command_spec_t fuzz_commands[] = {
    {CLA, INS_DERIVE_NATIVE_SCRIPT_HASH, 0, 0, FUZZ_CMD_HAS_DATA},
};
FUZZ_COMMAND_COUNT();

void fuzz_app_reset(void) {
    fuzzing_reset_state();
}
void fuzz_app_dispatch(void *cmd) {
    apdu_dispatcher((const command_t *) cmd);
}
