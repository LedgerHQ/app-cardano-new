#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "buffer.h"
#include "cardano_swo.h"
#include "fuzz_utils.h"
#include "globals.h"
#include "mem.h"
#include "tx.h"
#include "tx_parse.h"
#include "tx_parse_certificates.h"
#include "tx_parse_outputs.h"
#include "tx_processing.h"
#include "cardano_parsers.h"
#include "securityPolicy.h"
#include "securityWarnings.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    fuzzing_reset_state();

    if (size == 0) {
        return 0;
    }

    const uint8_t mode = data[0] % 6;
    data++;
    size--;

    buffer_t parse_buffer = {
        .ptr = (uint8_t *) data,
        .size = size,
        .offset = 0,
    };

    switch (mode) {
        case 0: {
            // Fuzz full transaction parsing with bounded counts.
            if (size < 10) {
                return 0;
            }

            tx_params_t *tx_params = &G_context.tx_info.tx_params;
            memset(tx_params, 0, sizeof(*tx_params));

            tx_params->num_inputs = data[0] & 0x07;
            tx_params->num_outputs = data[1] & 0x07;
            tx_params->num_certificates = data[2] & 0x03;
            tx_params->num_withdrawals = data[3] & 0x03;
            tx_params->num_mint_asset_groups = data[4] & 0x03;
            tx_params->num_collateral_inputs = data[5] & 0x03;
            tx_params->num_required_signers = data[6] & 0x03;
            tx_params->num_reference_inputs = data[7] & 0x03;
            tx_params->num_voters = data[8] & 0x03;

            const uint8_t flags = data[9];
            tx_params->includeTtl = (flags & 0x01) != 0;
            tx_params->includeValidityIntervalStart = (flags & 0x02) != 0;
            tx_params->includeScriptDataHash = (flags & 0x04) != 0;
            tx_params->includeCollateralOutput = (flags & 0x08) != 0;
            tx_params->includeTotalCollateral = (flags & 0x10) != 0;
            tx_params->includeTreasury = (flags & 0x20) != 0;
            tx_params->includeDonation = (flags & 0x40) != 0;

            G_context.tx_info.body.raw_tx = (uint8_t *) (data + 10);
            G_context.tx_info.raw_tx_total_length = (uint16_t) (size - 10);

            // tx_body_ctx() asserts TX_STATE_CHUNKS (or later states); set it
            // before calling tx_validate() which accesses tx_body_ctx().
            G_context.state.tx_state = TX_STATE_CHUNKS;
            // policyForSignTxInit asserts txSigningMode is a valid enum value.
            tx_params->txSigningMode = SIGN_TX_SIGNINGMODE_ORDINARY_TX +
                (tx_params->txSigningMode % (SIGN_TX_SIGNINGMODE_PLUTUS_TX -
                                             SIGN_TX_SIGNINGMODE_ORDINARY_TX + 1));
            // tx_validate() asserts policyForSignTxInit != POLICY_DENY, which can
            // happen with arbitrary fuzz params that were never validated by the
            // real init APDU handler. Skip tx_validate() in that case.
            warning_bits_t policy_warnings = 0;
            if (policyForSignTxInit(tx_params, &policy_warnings) != POLICY_DENY) {
                (void) tx_validate();
            }
            break;
        }
        case 1: {
            tx_output_destination_t destination = {0};
            (void) parse_output_destination(&parse_buffer, &destination);
            // destination.params is embedded by value; no cleanup needed.
            break;
        }
        case 2: {
            tx_output_serialization_format_t format = ARRAY_LEGACY;
            (void) parse_output_format(&parse_buffer, &format, SWO_TX_PARSING_FAIL_OUTPUTS);
            break;
        }
        case 3: {
            output_datum_t datum = {0};
            (void) parse_output_datum(&parse_buffer, &datum);
            break;
        }
        case 4: {
            ref_script_t ref_script = {0};
            (void) parse_output_ref_script(&parse_buffer, &ref_script);
            break;
        }
        case 5: {
            ext_credential_t credential = {0};
            (void) buffer_read_credential(&parse_buffer, &credential);
            break;
        }
        default:
            break;
    }

    return 0;
}
