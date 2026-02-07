#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "apdu/dispatcher.h"
#include "buffer.h"
#include "cardano_swo.h"
#include "globals.h"

static uint16_t g_last_sw = 0;
static uint8_t g_last_called_ins = 0;

static void reset_test_context(void) {
    memset(&G_context, 0, sizeof(G_context));
    g_last_sw = 0;
    g_last_called_ins = 0;
}

// -------------------------------------------------------------------------
// App context / IO hooks
// -------------------------------------------------------------------------

void reset_app_context(void) {
    memset(&G_context, 0, sizeof(G_context));
    G_context.req_type = REQUEST_NONE;
}

void send_swo_and_reset(uint16_t swo) {
    reset_app_context();
    g_last_sw = swo;
}

int io_send_sw(uint16_t swo) {
    g_last_sw = swo;
    return 0;
}

int io_send_response_pointer(const uint8_t *buffer, size_t bufferLength, uint16_t swo) {
    (void) buffer;
    (void) bufferLength;
    g_last_sw = swo;
    return 0;
}

// -------------------------------------------------------------------------
// Handler stubs used by dispatcher
// -------------------------------------------------------------------------

void handler_get_serial(buffer_t *cdata) {
    (void) cdata;
    g_last_called_ins = INS_GET_SERIAL;
}

void handler_get_version(buffer_t *cdata) {
    (void) cdata;
    g_last_called_ins = INS_GET_VERSION;
}

void handler_get_app_name(buffer_t *cdata) {
    (void) cdata;
    g_last_called_ins = INS_GET_APP_NAME;
}

void handler_get_public_key(buffer_t *cdata) {
    (void) cdata;
    g_last_called_ins = INS_GET_PUBLIC_KEY;
}

void handler_derive_address(buffer_t *cdata, uint8_t p1) {
    (void) cdata;
    (void) p1;
    g_last_called_ins = INS_DERIVE_ADDRESS;
}

void handler_derive_native_script_hash(buffer_t *cdata, uint8_t script_type) {
    (void) cdata;
    (void) script_type;
    g_last_called_ins = INS_DERIVE_NATIVE_SCRIPT_HASH;
}

void handler_sign_tx(buffer_t *cdata, uint8_t p1) {
    (void) cdata;
    (void) p1;
    g_last_called_ins = INS_SIGN_TX;
}

void handler_sign_tx_witness(buffer_t *cdata) {
    (void) cdata;
    g_last_called_ins = INS_SIGN_TX;
}

void handler_sign_tx_aux_data(buffer_t *cdata, uint8_t p2) {
    (void) cdata;
    (void) p2;
    g_last_called_ins = INS_SIGN_TX;
}

void handler_sign_opcert(buffer_t *cdata) {
    (void) cdata;
    g_last_called_ins = INS_SIGN_OPCERT;
}

void handler_sign_cvote(buffer_t *cdata, uint8_t p1) {
    (void) cdata;
    (void) p1;
    g_last_called_ins = INS_SIGN_CVOTE;
}

void handler_sign_msg(buffer_t *cdata, uint8_t p1) {
    (void) cdata;
    (void) p1;
    g_last_called_ins = INS_SIGN_MSG;
}

#ifdef DEBUG
void handler_debug_set_settings(buffer_t *cdata) {
    (void) cdata;
    g_last_called_ins = INS_DEBUG_SET_SETTINGS;
}
#endif

static command_t make_command(uint8_t ins, uint8_t p1, uint8_t p2) {
    static uint8_t dummy = 0;
    command_t cmd = {
        .cla = CLA,
        .ins = ins,
        .p1 = p1,
        .p2 = p2,
        .lc = 0,
        .data = &dummy,
    };
    return cmd;
}

static void test_interleaving_guard_blocks_other_instructions(void **state) {
    (void) state;

    const struct {
        request_type_e req;
        uint8_t expected_ins;
    } cases[] = {
        {REQUEST_EXPORT_PUBKEY, INS_GET_PUBLIC_KEY},
        {REQUEST_SIGN_TRANSACTION, INS_SIGN_TX},
        {REQUEST_SIGN_OPCERT, INS_SIGN_OPCERT},
        {REQUEST_DERIVE_ADDRESS, INS_DERIVE_ADDRESS},
        {REQUEST_DERIVE_NATIVE_SCRIPT_HASH, INS_DERIVE_NATIVE_SCRIPT_HASH},
        {REQUEST_CVOTE, INS_SIGN_CVOTE},
        {REQUEST_SIGN_MSG, INS_SIGN_MSG},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        reset_test_context();
        G_context.req_type = cases[i].req;

        uint8_t attempted_ins = INS_GET_VERSION;
        if (attempted_ins == cases[i].expected_ins) {
            attempted_ins = INS_GET_APP_NAME;
        }
        command_t cmd = make_command(attempted_ins, P1_UNUSED, P2_UNUSED);
        apdu_dispatcher(&cmd);

        assert_int_equal(g_last_sw, SWO_COMMAND_NOT_ALLOWED);
        assert_int_equal(G_context.req_type, REQUEST_NONE);
    }
}

static void test_interleaving_allows_expected_instruction(void **state) {
    (void) state;

    const struct {
        request_type_e req;
        uint8_t ins;
        uint8_t p1;
        uint8_t p2;
    } cases[] = {
        {REQUEST_EXPORT_PUBKEY, INS_GET_PUBLIC_KEY, P1_UNUSED, P2_UNUSED},
        {REQUEST_SIGN_TRANSACTION, INS_SIGN_TX, P1_TX_INIT, P2_UNUSED},
        {REQUEST_SIGN_OPCERT, INS_SIGN_OPCERT, P1_UNUSED, P2_UNUSED},
        {REQUEST_DERIVE_ADDRESS, INS_DERIVE_ADDRESS, P1_ADDRESS_RETURN, P2_UNUSED},
        {REQUEST_DERIVE_NATIVE_SCRIPT_HASH, INS_DERIVE_NATIVE_SCRIPT_HASH, P1_NATIVE_SCRIPT_FINISH, P2_UNUSED},
        {REQUEST_CVOTE, INS_SIGN_CVOTE, P1_CVOTE_INIT, P2_UNUSED},
        {REQUEST_SIGN_MSG, INS_SIGN_MSG, P1_SIGN_MSG_INIT, P2_UNUSED},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        reset_test_context();
        G_context.req_type = cases[i].req;
        command_t cmd = make_command(cases[i].ins, cases[i].p1, cases[i].p2);
        apdu_dispatcher(&cmd);

        assert_int_equal(g_last_sw, 0);
        assert_int_equal(g_last_called_ins, cases[i].ins);
    }
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_interleaving_guard_blocks_other_instructions),
        cmocka_unit_test(test_interleaving_allows_expected_instruction),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
