cmake_minimum_required(VERSION 3.20)

project(CardanoFuzzers
        VERSION 1.0
        DESCRIPTION "Fuzzing harnesses for Cardano Ledger app"
        LANGUAGES C)

if(NOT DEFINED BOLOS_SDK)
  message(FATAL_ERROR "BOLOS_SDK must be defined")
endif()

# Exports the `secure_sdk` target and ledger_fuzz_add_app_target().
include(${BOLOS_SDK}/fuzzing/cmake/LedgerAppFuzz.cmake)
ledger_fuzz_setup()

set(APP_SOURCE_DIR ${CMAKE_SOURCE_DIR}/../../src)

# Whole app plus the fuzz mocks; app_main.c and non-portable swap helpers are
# replaced by the fuzz entry point or are not used in fuzzing context.
file(GLOB_RECURSE C_SOURCES CONFIGURE_DEPENDS
    ${APP_SOURCE_DIR}/*.c
    ${CMAKE_SOURCE_DIR}/mock/*.c
    ${CMAKE_SOURCE_DIR}/src/fuzz_utils.c)
list(REMOVE_ITEM C_SOURCES
    ${APP_SOURCE_DIR}/app_main.c
    ${APP_SOURCE_DIR}/handler/debug_settings.c
    ${APP_SOURCE_DIR}/swap/swap_check_address.c
    ${APP_SOURCE_DIR}/swap/swap_printable_amount.c)

# Collect all header directories under src/, mock/, and include/ recursively.
ledger_fuzz_collect_include_dirs(APP_INCLUDE_DIRS ${APP_SOURCE_DIR})
list(APPEND APP_INCLUDE_DIRS
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/mock
    ${CMAKE_SOURCE_DIR}/include)

# FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION is the shared app/SDK sentinel for
# fuzz-only relaxations. HAVE_* / APPNAME / ... arrive transitively from
# secure_sdk (make list-defines + macros/add_macros.txt).
# Invariant models are machine-local and regenerated per build (.gitignored).
function(cardano_add_fuzz_target NAME)
  set(INVARIANT "${CMAKE_SOURCE_DIR}/invariants/${NAME}.zon")
  ledger_fuzz_bootstrap_file("${INVARIANT}" ".{}\n")
  ledger_fuzz_add_app_target(
      NAME ${NAME}
      HARNESS ${CMAKE_SOURCE_DIR}/harness/${NAME}.c
      INVARIANT ${INVARIANT}
      SOURCES ${C_SOURCES}
      INCLUDE_DIRECTORIES ${APP_INCLUDE_DIRS}
      COMPILE_DEFINITIONS FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION=1)
  # Absolution's generated fuzzer.c calls assert() without including <assert.h>.
  # src/utils/assert.h (now a proxy to the system header via #include_next) used
  # to shadow <assert.h> in this build, preventing -include from finding the real
  # one. With the proxy in place, -include assert.h now reaches the system header
  # and defines the assert() macro, resolving both the warning and the linker error.
  # Suppress alignment sanitizer: the app uses packed struct accesses
  # that trigger false positives with UBSan alignment checks.
  target_compile_options(${NAME} PRIVATE -include assert.h -fno-sanitize=alignment)
  target_link_options(${NAME} PRIVATE -fno-sanitize=alignment)
endfunction()

# ── Single-APDU targets (standard fuzz_harness.h loop) ──────────────────────
cardano_add_fuzz_target(fuzz_getVersion)
cardano_add_fuzz_target(fuzz_getSerial)
cardano_add_fuzz_target(fuzz_getAppName)
cardano_add_fuzz_target(fuzz_getPublicKeys)
cardano_add_fuzz_target(fuzz_deriveAddress)
cardano_add_fuzz_target(fuzz_deriveNativeScriptHash)
cardano_add_fuzz_target(fuzz_signTx)
cardano_add_fuzz_target(fuzz_signOpCert)

# ── Multi-APDU and parser-level targets (custom fuzz_entry) ─────────────────
cardano_add_fuzz_target(fuzz_all_handlers)
cardano_add_fuzz_target(fuzz_bip44_policy)
cardano_add_fuzz_target(fuzz_cvote_aux_parser)
cardano_add_fuzz_target(fuzz_native_script_hash_builder)
cardano_add_fuzz_target(fuzz_tx_parser_entrypoints)
