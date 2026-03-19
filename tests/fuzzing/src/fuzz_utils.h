#pragma once

#include <setjmp.h>

typedef struct {
    sigjmp_buf jmp_buf;
} fuzz_exit_jump_ctx_t;

extern fuzz_exit_jump_ctx_t fuzz_exit_jump_ctx;

void fuzzing_reset_state(void);
