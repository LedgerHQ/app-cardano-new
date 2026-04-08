/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "utils/textUtils.h"

// Test ASCII validation functions
static void test_is_printable_ascii(void **state) {
    (void) state;

    // Valid printable ASCII without spaces
    const uint8_t *valid_no_spaces = (const uint8_t *) "HelloWorld123";
    assert_true(
        str_isPrintableAsciiWithoutSpaces(valid_no_spaces, strlen((const char *) valid_no_spaces)));

    // Valid printable ASCII with spaces
    const uint8_t *valid_with_spaces = (const uint8_t *) "Hello World 123";
    assert_true(str_isPrintableAsciiWithSpaces(valid_with_spaces,
                                               strlen((const char *) valid_with_spaces)));

    // Invalid - has space but checking without spaces allowed
    assert_false(str_isPrintableAsciiWithoutSpaces(valid_with_spaces,
                                                   strlen((const char *) valid_with_spaces)));

    // Invalid - non-ASCII character
    const uint8_t invalid_ascii[] = {0x48, 0x65, 0xff, 0x00};  // "He" + invalid byte
    assert_false(str_isPrintableAsciiWithoutSpaces(invalid_ascii, 3));
    assert_false(str_isPrintableAsciiWithSpaces(invalid_ascii, 3));

    // Boundary tests - value 126 (tilde ~) should be valid without spaces
    const uint8_t boundary_126[] = {126};  // '~'
    assert_true(str_isPrintableAsciiWithoutSpaces(boundary_126, 1));
    assert_true(str_isPrintableAsciiWithSpaces(boundary_126, 1));

    // Boundary tests - value 127 should be invalid
    const uint8_t boundary_127[] = {127};  // DEL character
    assert_false(str_isPrintableAsciiWithoutSpaces(boundary_127, 1));
    assert_false(str_isPrintableAsciiWithSpaces(boundary_127, 1));

    // Boundary tests - value 33 should be valid without spaces
    const uint8_t boundary_33[] = {33};  // '!'
    assert_true(str_isPrintableAsciiWithoutSpaces(boundary_33, 1));
    assert_true(str_isPrintableAsciiWithSpaces(boundary_33, 1));

    // Boundary tests - value 32 (space) should be invalid without spaces
    const uint8_t boundary_32[] = {32};  // space
    assert_false(str_isPrintableAsciiWithoutSpaces(boundary_32, 1));
    assert_true(str_isPrintableAsciiWithSpaces(boundary_32, 1));

    // Boundary tests - value 31 should be invalid
    const uint8_t boundary_31[] = {31};  // Unit separator
    assert_false(str_isPrintableAsciiWithoutSpaces(boundary_31, 1));
    assert_false(str_isPrintableAsciiWithSpaces(boundary_31, 1));
}

// Test unambiguous ASCII
static void test_is_unambiguous_ascii(void **state) {
    (void) state;

    // Valid unambiguous ASCII - alphanumeric only
    const uint8_t *valid = (const uint8_t *) "HelloWorld123abc";
    assert_true(str_isUnambiguousAscii(valid, strlen((const char *) valid)));

    // Valid - single spaces in middle allowed
    const uint8_t *with_space = (const uint8_t *) "Hello World";
    assert_true(str_isUnambiguousAscii(with_space, strlen((const char *) with_space)));

    // Valid - printable special characters allowed (hyphen, etc)
    const uint8_t *with_special = (const uint8_t *) "Hello-World";
    assert_true(str_isUnambiguousAscii(with_special, strlen((const char *) with_special)));

    // Invalid - has leading space
    const uint8_t *leading_space = (const uint8_t *) " Hello";
    assert_false(str_isUnambiguousAscii(leading_space, strlen((const char *) leading_space)));

    // Invalid - has trailing space
    const uint8_t *trailing_space = (const uint8_t *) "Hello ";
    assert_false(str_isUnambiguousAscii(trailing_space, strlen((const char *) trailing_space)));

    // Invalid - double space
    const uint8_t *double_space = (const uint8_t *) "Hello  World";
    assert_false(str_isUnambiguousAscii(double_space, strlen((const char *) double_space)));

    // Invalid - has non-ASCII
    const uint8_t non_ascii[] = {0x48, 0x65, 0xff, 0x00};
    assert_false(str_isUnambiguousAscii(non_ascii, 3));

    // Invalid - empty string
    assert_false(str_isUnambiguousAscii((const uint8_t *) "", 0));

    // Invalid - double space at end
    const uint8_t *double_space_end = (const uint8_t *) "Hello  ";
    assert_false(str_isUnambiguousAscii(double_space_end, strlen((const char *) double_space_end)));

    // Invalid - double space at beginning
    const uint8_t *double_space_start = (const uint8_t *) "  World";
    assert_false(
        str_isUnambiguousAscii(double_space_start, strlen((const char *) double_space_start)));
}

// Additional tests for better mutation coverage - specific boundary values
static void test_printable_ascii_boundary_lower_without_spaces(void **state) {
    (void) state;

    // Test value 32 (space) - should fail WithoutSpaces
    const uint8_t space = 32;
    assert_false(str_isPrintableAsciiWithoutSpaces(&space, 1));

    // Test value 33 (!) - should pass WithoutSpaces
    const uint8_t exclaim = 33;
    assert_true(str_isPrintableAsciiWithoutSpaces(&exclaim, 1));

    // Test value 34 (") - should pass WithoutSpaces
    const uint8_t quote = 34;
    assert_true(str_isPrintableAsciiWithoutSpaces(&quote, 1));
}

static void test_printable_ascii_boundary_upper_without_spaces(void **state) {
    (void) state;

    // Test value 125 (}) - should pass WithoutSpaces
    const uint8_t brace = 125;
    assert_true(str_isPrintableAsciiWithoutSpaces(&brace, 1));

    // Test value 126 (~) - should pass WithoutSpaces
    const uint8_t tilde = 126;
    assert_true(str_isPrintableAsciiWithoutSpaces(&tilde, 1));

    // Test value 127 (DEL) - should fail WithoutSpaces
    const uint8_t del = 127;
    assert_false(str_isPrintableAsciiWithoutSpaces(&del, 1));
}

static void test_printable_ascii_invalid_control_chars(void **state) {
    (void) state;

    // Test value 0 (NUL) - should fail
    const uint8_t nul = 0;
    assert_false(str_isPrintableAsciiWithoutSpaces(&nul, 1));
    assert_false(str_isPrintableAsciiWithSpaces(&nul, 1));

    // Test value 31 (Unit Separator) - should fail
    const uint8_t us = 31;
    assert_false(str_isPrintableAsciiWithoutSpaces(&us, 1));
    assert_false(str_isPrintableAsciiWithSpaces(&us, 1));

    // Test value 255 (high byte) - should fail
    const uint8_t high = 255;
    assert_false(str_isPrintableAsciiWithoutSpaces(&high, 1));
    assert_false(str_isPrintableAsciiWithSpaces(&high, 1));
}

static void test_printable_ascii_space_handling(void **state) {
    (void) state;

    // Space (32) should be accepted by WithSpaces but not WithoutSpaces
    const uint8_t space = 32;
    assert_false(str_isPrintableAsciiWithoutSpaces(&space, 1));
    assert_true(str_isPrintableAsciiWithSpaces(&space, 1));

    // Multiple spaces in sequence
    const uint8_t multi_spaces[] = {32, 32, 32};
    assert_false(str_isPrintableAsciiWithoutSpaces(multi_spaces, 3));
    assert_true(str_isPrintableAsciiWithSpaces(multi_spaces, 3));
}

static void test_printable_ascii_empty_buffer_contract(void **state) {
    (void) state;

    const uint8_t dummy = 'X';
    assert_true(str_isPrintableAsciiWithoutSpaces(&dummy, 0));
    assert_true(str_isPrintableAsciiWithSpaces(&dummy, 0));
    assert_false(str_isUnambiguousAscii(&dummy, 0));
}

static void test_unambiguous_single_chars(void **state) {
    (void) state;

    // Single alphanumeric characters should be valid
    for (int i = 48; i <= 57; i++) {  // 0-9
        uint8_t single_char = (uint8_t) i;
        assert_true(str_isUnambiguousAscii(&single_char, 1));
    }

    for (int i = 65; i <= 90; i++) {  // A-Z
        uint8_t single_char = (uint8_t) i;
        assert_true(str_isUnambiguousAscii(&single_char, 1));
    }

    for (int i = 97; i <= 122; i++) {  // a-z
        uint8_t single_char = (uint8_t) i;
        assert_true(str_isUnambiguousAscii(&single_char, 1));
    }
}

static void test_unambiguous_consecutive_spaces(void **state) {
    (void) state;

    // Triple space
    const uint8_t triple[] = {'A', ' ', ' ', ' ', 'B'};
    assert_false(str_isUnambiguousAscii(triple, 5));
}

static void test_unambiguous_special_chars(void **state) {
    (void) state;

    // Hyphen in middle is valid
    const uint8_t hyphen[] = {'A', '-', 'B'};
    assert_true(str_isUnambiguousAscii(hyphen, 3));

    // Underscore in middle is valid
    const uint8_t underscore[] = {'t', 'e', 's', 't', '_', 'v', 'a', 'l'};
    assert_true(str_isUnambiguousAscii(underscore, 8));

    // Dot in middle is valid
    const uint8_t dot[] = {'a', '.', 'b'};
    assert_true(str_isUnambiguousAscii(dot, 3));
}

static void test_unambiguous_edge_case_single_space(void **state) {
    (void) state;

    // Single space as only character should fail
    const uint8_t space_only[] = {' '};
    assert_false(str_isUnambiguousAscii(space_only, 1));

    // Space at exactly position 0 with text after
    const uint8_t leading[] = {' ', 't', 'e', 's', 't'};
    assert_false(str_isUnambiguousAscii(leading, 5));

    // Space at exactly last position
    const uint8_t trailing[] = {'t', 'e', 's', 't', ' '};
    assert_false(str_isUnambiguousAscii(trailing, 5));
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_is_printable_ascii),
        cmocka_unit_test(test_is_unambiguous_ascii),
        cmocka_unit_test(test_printable_ascii_boundary_lower_without_spaces),
        cmocka_unit_test(test_printable_ascii_boundary_upper_without_spaces),
        cmocka_unit_test(test_printable_ascii_invalid_control_chars),
        cmocka_unit_test(test_printable_ascii_space_handling),
        cmocka_unit_test(test_printable_ascii_empty_buffer_contract),
        cmocka_unit_test(test_unambiguous_single_chars),
        cmocka_unit_test(test_unambiguous_consecutive_spaces),
        cmocka_unit_test(test_unambiguous_special_chars),
        cmocka_unit_test(test_unambiguous_edge_case_single_space),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
