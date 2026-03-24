#include "fuzz_utils.h"

#include <stdlib.h>
#include <string.h>

#include "globals.h"
#include "app_mem_utils.h"
#include "ui_utils.h"

#ifndef explicit_bzero
#define explicit_bzero(addr, size) memset((addr), 0, (size))
#endif

fuzz_exit_jump_ctx_t fuzz_exit_jump_ctx;

void fuzzing_reset_state(void) {
    // Clean up UI allocations left over from the previous iteration
    ui_free_pairs();

    // Reset the dispatcher state to avoid cross-iteration contamination
    explicit_bzero(&G_context, sizeof(G_context));

    // Reinitialize the SDK allocator so dangling pointers cannot trigger frees
    if (!mem_utils_reset_app_heap()) {
        abort();
    }
}
