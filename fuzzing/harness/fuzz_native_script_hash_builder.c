#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "cardano_constants.h"
#include "derive_native_script_hash_builder.h"
#include "fuzz_utils.h"

static uint8_t read_u8(const uint8_t *data, size_t size, size_t *offset) {
    if (*offset >= size) {
        return 0;
    }
    return data[(*offset)++];
}

static uint32_t read_u32_be(const uint8_t *data, size_t size, size_t *offset) {
    uint32_t result = 0;
    for (int i = 0; i < 4; i++) {
        result = (result << 8) | read_u8(data, size, offset);
    }
    return result;
}

static uint64_t read_u64_be(const uint8_t *data, size_t size, size_t *offset) {
    uint64_t result = 0;
    for (int i = 0; i < 8; i++) {
        result = (result << 8) | read_u8(data, size, offset);
    }
    return result;
}

static void add_simple_script(native_script_hash_builder_t *builder,
                              const uint8_t *data,
                              size_t size,
                              size_t *offset) {
    const uint8_t simple_type = read_u8(data, size, offset) % 3;
    switch (simple_type) {
        case 0: {
            uint8_t key_hash[ADDRESS_KEY_HASH_LENGTH] = {0};
            for (size_t i = 0; i < sizeof(key_hash); i++) {
                key_hash[i] = read_u8(data, size, offset);
            }
            nativeScriptHashBuilder_addScript_pubkey(builder, key_hash, sizeof(key_hash));
            break;
        }
        case 1:
            nativeScriptHashBuilder_addScript_invalidBefore(builder, read_u64_be(data, size, offset));
            break;
        case 2:
            nativeScriptHashBuilder_addScript_invalidHereafter(builder, read_u64_be(data, size, offset));
            break;
        default:
            break;
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    fuzzing_reset_state();

    if (size == 0) {
        return 0;
    }

    native_script_hash_builder_t builder = {0};
    nativeScriptHashBuilder_init(&builder);

    size_t offset = 0;
    const uint8_t scenario = read_u8(data, size, &offset) % 4;

    switch (scenario) {
        case 0:
            add_simple_script(&builder, data, size, &offset);
            break;
        case 1:
        case 2:
        case 3: {
            const uint32_t remaining_scripts = (read_u8(data, size, &offset) % 5) + 1;
            if (scenario == 1) {
                nativeScriptHashBuilder_startComplexScript_all(&builder, remaining_scripts);
            } else if (scenario == 2) {
                nativeScriptHashBuilder_startComplexScript_any(&builder, remaining_scripts);
            } else {
                const uint32_t required = read_u8(data, size, &offset) % (remaining_scripts + 1);
                nativeScriptHashBuilder_startComplexScript_n_of_k(&builder,
                                                                  required,
                                                                  remaining_scripts);
            }

            for (uint32_t i = 0; i < remaining_scripts; i++) {
                add_simple_script(&builder, data, size, &offset);
            }
            break;
        }
        default:
            break;
    }

    uint8_t script_hash[SCRIPT_HASH_LENGTH] = {0};
    nativeScriptHashBuilder_finalize(&builder, script_hash, sizeof(script_hash));

    // Keep builder output live for sanitizer visibility.
    if (read_u32_be(data, size, &offset) == 0xFFFFFFFFu) {
        memset(script_hash, 0, sizeof(script_hash));
    }

    return 0;
}
