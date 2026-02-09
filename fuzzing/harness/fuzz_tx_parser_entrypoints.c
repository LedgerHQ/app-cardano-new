#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "buffer.h"
#include "fuzz_utils.h"
#include "mem.h"
#include "tx.h"
#include "tx_parse.h"
#include "tx_parse_certificates.h"
#include "tx_parse_outputs.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    fuzzing_reset_state();

    if (size == 0) {
        return 0;
    }

    const uint8_t mode = data[0] % 6;
    data++;
    size--;

    buffer_t parse_buffer = {
        .ptr = data,
        .size = size,
        .offset = 0,
    };

    switch (mode) {
        case 0: {
            // Fuzz full transaction parsing with bounded counts.
            transaction_t transaction = {0};
            if (size < 10) {
                return 0;
            }

            transaction.num_inputs = data[0] & 0x07;
            transaction.num_outputs = data[1] & 0x07;
            transaction.num_certificates = data[2] & 0x03;
            transaction.num_withdrawals = data[3] & 0x03;
            transaction.num_mint_asset_groups = data[4] & 0x03;
            transaction.num_collateral_inputs = data[5] & 0x03;
            transaction.num_required_signers = data[6] & 0x03;
            transaction.num_reference_inputs = data[7] & 0x03;
            transaction.num_voters = data[8] & 0x03;

            const uint8_t flags = data[9];
            transaction.includeTtl = (flags & 0x01) != 0;
            transaction.includeValidityIntervalStart = (flags & 0x02) != 0;
            transaction.includeScriptDataHash = (flags & 0x04) != 0;
            transaction.includeCollateralOutput = (flags & 0x08) != 0;
            transaction.includeTotalCollateral = (flags & 0x10) != 0;
            transaction.includeTreasury = (flags & 0x20) != 0;
            transaction.includeDonation = (flags & 0x40) != 0;

            parse_buffer.ptr = data + 10;
            parse_buffer.size = size - 10;
            parse_buffer.offset = 0;

            (void) parse_tx(&parse_buffer, &transaction);
            break;
        }
        case 1: {
            tx_output_destination_t destination = {0};
            (void) parse_output_destination(&parse_buffer, &destination);
            if (destination.type == DESTINATION_DEVICE_OWNED && destination.params != NULL) {
                APP_MEM_FREE(destination.params);
                destination.params = NULL;
            }
            break;
        }
        case 2: {
            tx_output_serialization_format_t format = ARRAY_LEGACY;
            (void) parse_output_format(&parse_buffer, &format, OUTPUTS_PARSING_ERROR);
            break;
        }
        case 3: {
            output_datum_t datum = {0};
            (void) parse_output_datum(&parse_buffer, &datum, OUTPUTS_PARSING_ERROR);
            break;
        }
        case 4: {
            ref_script_t ref_script = {0};
            (void) parse_output_ref_script(&parse_buffer, &ref_script, OUTPUTS_PARSING_ERROR);
            break;
        }
        case 5: {
            ext_credential_t credential = {0};
            (void) parse_stake_credential(&parse_buffer, &credential);
            break;
        }
        default:
            break;
    }

    return 0;
}
