cmake_minimum_required(VERSION 3.14)

project(CardanoFuzzers
        VERSION 1.0
        DESCRIPTION "Fuzzing harnesses for Cardano Ledger app"
        LANGUAGES C)

if(NOT DEFINED BOLOS_SDK)
  message(FATAL_ERROR "BOLOS_SDK must be defined, CMake will exit.")
  return()
endif()

if(NOT DEFINED APP_BUILD_PATH)
  set(APP_BUILD_PATH "${CMAKE_SOURCE_DIR}/..")
endif()

# Pull in the SDK fuzzing framework: secure_sdk target, macro extraction,
# sanitizer/coverage flags, mock libraries, etc.
add_subdirectory(${BOLOS_SDK}/fuzzing ${CMAKE_CURRENT_BINARY_DIR}/ledger-secure-sdk EXCLUDE_FROM_ALL)

set(CARDANO_PATH ${CMAKE_SOURCE_DIR}/..)

set(CARDANO_SOURCE
    ${CARDANO_PATH}/src/addressUtils/addressUtilsByron.c
    ${CARDANO_PATH}/src/addressUtils/addressUtilsShelley.c
    ${CARDANO_PATH}/src/bech32/bech32.c
    ${CARDANO_PATH}/src/addressUtils/bip44.c
    ${CARDANO_PATH}/src/apdu/dispatcher.c
    ${CARDANO_PATH}/src/cardano_tokens/cardano_tokens.c
    ${CARDANO_PATH}/src/cvote/aux_data_hash_builder.c
    ${CARDANO_PATH}/src/cvote/cvote_hash.c
    ${CARDANO_PATH}/src/cvote/cvote_parser.c
    ${CARDANO_PATH}/src/cvote/vote_cast_hash_builder.c
    ${CARDANO_PATH}/src/crypto/crypto.c
    ${CARDANO_PATH}/src/deriveNativeScriptHash/derive_native_script_hash_builder.c
    ${CARDANO_PATH}/src/handler/sign_cvote.c
    ${CARDANO_PATH}/src/handler/derive_address.c
    ${CARDANO_PATH}/src/handler/derive_native_script_hash.c
    ${CARDANO_PATH}/src/handler/get_app_name.c
    ${CARDANO_PATH}/src/handler/get_public_key.c
    ${CARDANO_PATH}/src/handler/get_serial.c
    ${CARDANO_PATH}/src/handler/get_version.c
    ${CARDANO_PATH}/src/handler/sign_msg.c
    ${CARDANO_PATH}/src/handler/sign_opcert.c
    ${CARDANO_PATH}/src/handler/sign_tx.c
    ${CARDANO_PATH}/src/handler/sign_tx_aux_data.c
    ${CARDANO_PATH}/src/keyDerivation/keyDerivation.c
    ${CARDANO_PATH}/src/utils/mem.c
    ${CARDANO_PATH}/src/messageSigning/messageSigning.c
    ${CARDANO_PATH}/src/opcert/opcert_parse.c
    ${CARDANO_PATH}/src/parsers/cardano_parsers.c
    ${CARDANO_PATH}/src/securityPolicy/securityPolicy.c
    ${CARDANO_PATH}/src/securityPolicy/securityPolicy_privkey.c
    ${CARDANO_PATH}/src/swap/swap_lib.c
    ${CARDANO_PATH}/src/transaction/tx_parse.c
    ${CARDANO_PATH}/src/transaction/tx_parse_certificates.c
    ${CARDANO_PATH}/src/transaction/tx_parse_outputs.c
    ${CARDANO_PATH}/src/transaction/tx_processing.c
    ${CARDANO_PATH}/src/transaction/tx_processing_certificates.c
    ${CARDANO_PATH}/src/transaction/tx_processing_outputs.c
    ${CARDANO_PATH}/src/transaction/tx_ui_render.c
    ${CARDANO_PATH}/src/transaction/tx_ui_render_certificates.c
    ${CARDANO_PATH}/src/transaction/tx_ui_render_outputs.c
    ${CARDANO_PATH}/src/transaction/tx_utils.c
    ${CARDANO_PATH}/src/transaction/tx_hash_builder.c
    ${CARDANO_PATH}/src/ui/menu.c
    ${CARDANO_PATH}/src/ui/ui_cvote.c
    ${CARDANO_PATH}/src/ui/ui_display_address_derivation.c
    ${CARDANO_PATH}/src/ui/ui_display_cvote_aux_data.c
    ${CARDANO_PATH}/src/ui/ui_display_native_script_hash.c
    ${CARDANO_PATH}/src/ui/ui_display_opcert.c
    ${CARDANO_PATH}/src/ui/ui_display_pubkey.c
    ${CARDANO_PATH}/src/ui/ui_display_tx.c
    ${CARDANO_PATH}/src/ui/ui_display_witness.c
    ${CARDANO_PATH}/src/ui/ui_sign_msg.c
    ${CARDANO_PATH}/src/ui/ui_address_fields.c
    ${CARDANO_PATH}/src/ui/ui_formatters.c
    ${CARDANO_PATH}/src/ui/ui_utils.c
    ${CARDANO_PATH}/src/ui/ui_warnings.c
    ${CARDANO_PATH}/src/utils/cardano_buffer.c
    ${CARDANO_PATH}/src/app_context.c
    ${CARDANO_PATH}/src/utils/cbor.c
    ${CARDANO_PATH}/src/utils/cbor_canonical.c
    ${CARDANO_PATH}/src/utils/ipUtils.c
    ${CARDANO_PATH}/src/utils/textUtils.c
)

set(FUZZING_SOURCE
    ${CMAKE_SOURCE_DIR}/mock/os_mocks.c
    ${CMAKE_SOURCE_DIR}/mock/ui_mocks.c
    ${CMAKE_SOURCE_DIR}/mock/crc32.c
    ${CMAKE_SOURCE_DIR}/src/fuzz_utils.c
)

add_library(code_lib ${CARDANO_SOURCE} ${FUZZING_SOURCE})

target_include_directories(
  code_lib
  PUBLIC ${CMAKE_SOURCE_DIR}/src
         ${CMAKE_SOURCE_DIR}/mock
         ${CMAKE_SOURCE_DIR}/include
         ${CARDANO_PATH}/src
         ${CARDANO_PATH}/src/bech32
         ${CARDANO_PATH}/src/addressUtils
         ${CARDANO_PATH}/src/apdu
         ${CARDANO_PATH}/src/cardano_tokens
         ${CARDANO_PATH}/src/cvote
         ${CARDANO_PATH}/src/crypto
         ${CARDANO_PATH}/src/deriveNativeScriptHash
         ${CARDANO_PATH}/src/handler
         ${CARDANO_PATH}/src/keyDerivation
         ${CARDANO_PATH}/src/memory
         ${CARDANO_PATH}/src/messageSigning
         ${CARDANO_PATH}/src/opcert
         ${CARDANO_PATH}/src/parsers
         ${CARDANO_PATH}/src/securityPolicy
         ${CARDANO_PATH}/src/swap
         ${CARDANO_PATH}/src/transaction
         ${CARDANO_PATH}/src/txHashBuilder
         ${CARDANO_PATH}/src/ui
         ${CARDANO_PATH}/src/utils
)

target_link_libraries(code_lib PUBLIC secure_sdk)

# Suppress alignment sanitizer: the app uses packed struct accesses
# that trigger false positives with UBSan alignment checks.
target_compile_options(code_lib PUBLIC -fno-sanitize=alignment)
target_link_options(code_lib PUBLIC -fno-sanitize=alignment)

# All compile definitions (HAVE_NBGL, crypto flags, etc.) are now
# extracted automatically from the app Makefile by the SDK macro system
# (via 'make list-defines'). App-specific additions go in
# macros/add_macros.txt; exclusions in macros/exclude_macros.txt.

file(GLOB FUZZ_HARNESSES "${CMAKE_SOURCE_DIR}/harness/fuzz_*.c")

foreach(HARNESS_FILE ${FUZZ_HARNESSES})
  get_filename_component(HARNESS_NAME ${HARNESS_FILE} NAME_WE)

  add_executable(${HARNESS_NAME} ${HARNESS_FILE})
  target_link_libraries(${HARNESS_NAME} PUBLIC code_lib)

  message(STATUS "Creating fuzzer target: ${HARNESS_NAME}")
endforeach()
