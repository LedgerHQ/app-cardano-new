#include <stdint.h>
#include <stddef.h>

#include "bip44.h"
#include "buffer.h"
#include "fuzz_utils.h"
#include "messageSigning.h"
#include "securityPolicy.h"
#include "securityWarnings.h"

#define FUZZ_APP_CUSTOM_ENTRY
#include "fuzz_harness.h"

int fuzz_entry(const uint8_t *data, size_t size) {
    fuzzing_reset_state();

    buffer_t path_buffer = {
        .ptr = (uint8_t *) data,
        .size = size,
        .offset = 0,
    };

    bip44_path_t primary_path = {0};
    if (!buffer_read_bip44_path(&path_buffer, &primary_path)) {
        return 0;
    }

    // Path classification and formatting.
    // bip44_isPathReasonable asserts the path is not PATH_INVALID, so only
    // call it when classification succeeds.
    bip44_path_type_t path_type = bip44_classifyPath(&primary_path);
    if (path_type != PATH_INVALID) {
        (void) bip44_isPathReasonable(&primary_path);
    }
    (void) bip44_hasByronPrefix(&primary_path);
    (void) bip44_hasShelleyPrefix(&primary_path);
    (void) bip44_hasMultisigWalletKeyPrefix(&primary_path);
    (void) bip44_hasCVoteKeyPrefix(&primary_path);

    char path_string[MAX_BIP44_PATH_STRING_LENGTH + 1] = {0};
    (void) format_bip44_path(&primary_path, path_string, sizeof(path_string));

    // Compare two fuzzed paths when possible.
    bip44_path_t secondary_path = {0};
    if (buffer_read_bip44_path(&path_buffer, &secondary_path)) {
        (void) bip44_pathsEqual(&primary_path, &secondary_path);
    } else {
        (void) bip44_pathsEqual(&primary_path, &primary_path);
    }

    // Security policy entry points tied to path validation.
    // These assert the path is not PATH_INVALID, so only call them when
    // classification succeeds.
    warning_bits_t warnings = 0;
    if (path_type != PATH_INVALID) {
        (void) policyForDerivePrivateKey(&primary_path);
        (void) policyForGetExtendedPublicKey(&primary_path, &warnings);
        (void) policyForSignCVoteWitness(&primary_path, &warnings);
        (void) policyForSignMsg(&primary_path, CIP8_ADDRESS_FIELD_KEYHASH, NULL, &warnings);
    }

    return 0;
}
