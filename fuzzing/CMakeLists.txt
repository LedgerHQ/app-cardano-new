cmake_minimum_required(VERSION 3.14)

project(CardanoFuzzers
        VERSION 1.0
        DESCRIPTION "Fuzzing harnesses for Cardano Ledger app"
        LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-sanitize=alignment")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fno-sanitize=alignment")

if(NOT DEFINED BOLOS_SDK)
  message(FATAL_ERROR "BOLOS_SDK must be defined, CMake will exit.")
  return()
endif()

if(NOT DEFINED TARGET)
  set(TARGET stax)
endif()

if(NOT DEFINED APP_BUILD_PATH)
  set(APP_BUILD_PATH "${CMAKE_SOURCE_DIR}/..")
endif()

if(NOT DEFINED ENV{LIB_FUZZING_ENGINE})
  # Force libFuzzer + address sanitizer without relying on lld
  set(ENV{LIB_FUZZING_ENGINE} "-fsanitize=fuzzer,address -fno-sanitize=alignment")
endif()
if(NOT DEFINED ENV{CFLAGS})
  set(ENV{CFLAGS} "-g -fno-omit-frame-pointer -fno-sanitize=alignment")
endif()

if(EXISTS "${BOLOS_SDK}/.target")
  file(STRINGS "${BOLOS_SDK}/.target" SDK_TARGET)
  string(STRIP "${SDK_TARGET}" SDK_TARGET)
  if(NOT "${SDK_TARGET}" STREQUAL "stax")
    message(FATAL_ERROR "Fuzzing requires stax target, BOLOS_SDK/.target is '${SDK_TARGET}'")
  endif()
endif()

add_subdirectory(${BOLOS_SDK}/fuzzing ${CMAKE_CURRENT_BINARY_DIR}/ledger-secure-sdk EXCLUDE_FROM_ALL)

set(CARDANO_PATH ${CMAKE_SOURCE_DIR}/..)

set(CARDANO_SOURCE
    ${CARDANO_PATH}/src/addressUtils/addressUtilsByron.c
    ${CARDANO_PATH}/src/addressUtils/addressUtilsShelley.c
    ${CARDANO_PATH}/src/addressUtils/bech32.c
    ${CARDANO_PATH}/src/addressUtils/bip44.c
    ${CARDANO_PATH}/src/apdu/dispatcher.c
    ${CARDANO_PATH}/src/cardano_tokens/cardano_tokens.c
    ${CARDANO_PATH}/src/cvote/aux_data_hash_builder.c
    ${CARDANO_PATH}/src/cvote/cvote_parser.c
    ${CARDANO_PATH}/src/crypto/crypto.c
    ${CARDANO_PATH}/src/deriveNativeScriptHash/derive_native_script_hash_builder.c
    ${CARDANO_PATH}/src/handler/derive_address.c
    ${CARDANO_PATH}/src/handler/derive_native_script_hash.c
    ${CARDANO_PATH}/src/handler/get_app_name.c
    ${CARDANO_PATH}/src/handler/get_public_key.c
    ${CARDANO_PATH}/src/handler/get_serial.c
    ${CARDANO_PATH}/src/handler/get_version.c
    ${CARDANO_PATH}/src/handler/sign_opcert.c
    ${CARDANO_PATH}/src/handler/sign_tx.c
    ${CARDANO_PATH}/src/keyDerivation/keyDerivation.c
    ${CARDANO_PATH}/src/memory/mem.c
    ${CARDANO_PATH}/src/memory/flist.c
    ${CARDANO_PATH}/src/messageSigning/messageSigning.c
    ${CARDANO_PATH}/src/opcert/opcert_parse.c
    ${CARDANO_PATH}/src/parsers/cardano_parsers.c
    ${CARDANO_PATH}/src/securityPolicy/securityPolicy.c
    ${CARDANO_PATH}/src/securityPolicy/securityPolicy_privkey.c
    ${CARDANO_PATH}/src/transaction/tx_parse.c
    ${CARDANO_PATH}/src/transaction/tx_parse_certificates.c
    ${CARDANO_PATH}/src/transaction/tx_parse_outputs.c
    ${CARDANO_PATH}/src/transaction/tx_utils.c
    ${CARDANO_PATH}/src/transaction/tx_hash_builder.c
    ${CARDANO_PATH}/src/transaction/tx_validate.c
    ${CARDANO_PATH}/src/ui/menu.c
    ${CARDANO_PATH}/src/ui/ui_display_address_derivation.c
    ${CARDANO_PATH}/src/ui/ui_display_native_script_hash.c
    ${CARDANO_PATH}/src/ui/ui_display_opcert.c
    ${CARDANO_PATH}/src/ui/ui_display_pubkey.c
    ${CARDANO_PATH}/src/ui/ui_display_tx.c
    ${CARDANO_PATH}/src/ui/ui_display_witness.c
    ${CARDANO_PATH}/src/ui/tx_ui_format.c
    ${CARDANO_PATH}/src/ui/tx_ui_helpers.c
    ${CARDANO_PATH}/src/ui/ui_formatters.c
    ${CARDANO_PATH}/src/ui/ui_utils.c
    ${CARDANO_PATH}/src/ui/ui_warnings.c
    ${CARDANO_PATH}/src/utils/buffer_write.c
    ${CARDANO_PATH}/src/app_context.c
    ${CARDANO_PATH}/src/utils/cbor.c
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
         ${CARDANO_PATH}/src/transaction
         ${CARDANO_PATH}/src/txHashBuilder
         ${CARDANO_PATH}/src/ui
         ${CARDANO_PATH}/src/utils
)

target_link_libraries(code_lib PUBLIC secure_sdk)
target_compile_options(code_lib PUBLIC -fno-sanitize=alignment)
target_link_options(code_lib PUBLIC -fno-sanitize=alignment)

target_compile_definitions(
  code_lib
  PUBLIC FUZZING
         FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION=1
         HAVE_NBGL
         NBGL_PAGE
         HAVE_PIEZO_SOUND
         TARGET_STAX
         HAVE_SE_TOUCH
         SCREEN_SIZE_WALLET
         IO_HID_EP_LENGTH=64
         IO_SEPROXYHAL_BUFFER_SIZE_B=300
         OS_IO_SEPROXYHAL
         HAVE_ECC
         HAVE_CRC
         HAVE_BLAKE2
         HAVE_ECC_WEIERSTRASS
         HAVE_SECP256K1_CURVE
         HAVE_SECP256R1_CURVE
         HAVE_ECC_TWISTED_EDWARDS
         HAVE_ED25519_CURVE
         HAVE_ECDSA
         HAVE_EDDSA
         HAVE_HASH
         HAVE_SHA224
         HAVE_SHA256
         HAVE_SHA3
         APP_FEATURE_OPCERT
)

file(GLOB FUZZ_HARNESSES "${CMAKE_SOURCE_DIR}/harness/fuzz_*.c")

foreach(HARNESS_FILE ${FUZZ_HARNESSES})
  get_filename_component(HARNESS_NAME ${HARNESS_FILE} NAME_WE)

  add_executable(${HARNESS_NAME} ${HARNESS_FILE})
  target_compile_definitions(${HARNESS_NAME} PUBLIC FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION=1)
  target_link_libraries(${HARNESS_NAME} PUBLIC secure_sdk code_lib)
  target_compile_options(${HARNESS_NAME} PUBLIC -fno-sanitize=alignment)
  target_link_options(${HARNESS_NAME} PUBLIC -fno-sanitize=alignment)
endforeach()
