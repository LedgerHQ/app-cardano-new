#pragma once

/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#ifndef OS_H
#define OS_H

#include <stdint.h>
#include "os_utils.h"

#ifndef WARN_UNUSED_RESULT
#define WARN_UNUSED_RESULT __attribute__((warn_unused_result))
#endif

// Mock arch qualifiers have to be available before crypto headers pull them in.
#ifndef WIDE
#define WIDE  // const // don't !!
#endif
#ifndef WIDE_AS_INT
#define WIDE_AS_INT unsigned long int
#endif
#ifndef REENTRANT
#define REENTRANT(x) x  //
#endif
#ifndef SYSCALL
#define SYSCALL
#endif
#ifndef TASKSWITCH
#define TASKSWITCH
#endif
#ifndef SUDOCALL
#define SUDOCALL
#endif
#ifndef LIBCALL
#define LIBCALL
#endif
#ifndef SHARED
#define SHARED
#endif
#ifndef PERMISSION
#define PERMISSION(...)
#endif
#ifndef PLENGTH
#define PLENGTH(...)
#endif
#ifndef CXPORT
#define CXPORT(...)
#endif
#ifndef TASKLEVEL
#define TASKLEVEL(...)
#endif
#ifndef CXCALL
#define CXCALL SYSCALL
#endif

// Include crypto types needed by this header
#include "lcx_ecfp.h"

#define TARGET_NANOSP
#define USB_SEGMENT_SIZE 64

// #include "os_hal.h"

cx_err_t os_derive_bip32_no_throw(cx_curve_t curve,
                                  const unsigned int *path,
                                  unsigned int path_len,
                                  unsigned char raw_privkey[static 64],
                                  unsigned char *chain_code);

// -----------------------------------------------------------------------
// - BASIC MATHS
// -----------------------------------------------------------------------
#define U2(hi, lo) ((((hi) & 0xFFu) << 8) | ((lo) & 0xFFu))
#define U4(hi3, hi2, lo1, lo0) \
    ((((hi3) & 0xFFu) << 24) | (((hi2) & 0xFFu) << 16) | (((lo1) & 0xFFu) << 8) | ((lo0) & 0xFFu))
#define U2BE(buf, off) ((((buf)[off] & 0xFFu) << 8) | ((buf)[off + 1] & 0xFFu))
#define U2LE(buf, off) ((((buf)[off + 1] & 0xFFu) << 8) | ((buf)[off] & 0xFFu))
#define U4BE(buf, off) ((U2BE(buf, off) << 16) | (U2BE(buf, off + 2) & 0xFFFFu))
#define U4LE(buf, off) ((U2LE(buf, off + 2) << 16) | (U2LE(buf, off) & 0xFFFFu))
#define MIN(x, y)      ((x) < (y) ? (x) : (y))
#define MAX(x, y)      ((x) > (y) ? (x) : (y))
#define IS_POW2(x)     (((x) & ((x) - 1)) == 0)
#define UPPER_ALIGN(adr, align, type)                                                       \
    (type)((type) ((type) (adr) +                                                           \
                   (type) ((type) ((type) MAX((type) (align), (type) 1UL)) - (type) 1UL)) & \
           (type) (~(type) ((type) ((type) MAX(((type) align), (type) 1UL)) - (type) 1UL)))
#define LOWER_ALIGN(adr, align, type) \
    ((type) (adr) & (type) ((type) ~(type) (((type) MAX((type) (align), (type) 1UL)) - (type) 1UL)))
#define U4BE_ENCODE(buf, off, value)               \
    {                                              \
        (buf)[(off) + 0] = ((value) >> 24) & 0xFF; \
        (buf)[(off) + 1] = ((value) >> 16) & 0xFF; \
        (buf)[(off) + 2] = ((value) >> 8) & 0xFF;  \
        (buf)[(off) + 3] = ((value)) & 0xFF;       \
    }
#define U4LE_ENCODE(buf, off, value)               \
    {                                              \
        (buf)[(off) + 3] = ((value) >> 24) & 0xFF; \
        (buf)[(off) + 2] = ((value) >> 16) & 0xFF; \
        (buf)[(off) + 1] = ((value) >> 8) & 0xFF;  \
        (buf)[(off) + 0] = ((value)) & 0xFF;       \
    }
#define U2BE_ENCODE(buf, off, value)              \
    {                                             \
        (buf)[(off) + 0] = ((value) >> 8) & 0xFF; \
        (buf)[(off) + 1] = ((value)) & 0xFF;      \
    }
#define U2LE_ENCODE(buf, off, value)              \
    {                                             \
        (buf)[(off) + 1] = ((value) >> 8) & 0xFF; \
        (buf)[(off) + 0] = ((value)) & 0xFF;      \
    }

/**
 * Helper to perform compilation time assertions
 */
#if !defined(SYSCALL_GENERATE) && \
    (defined(__clang__) || (__GNUC__ > 4 || (__GNUC__ == 4 && (__GNUC_MINOR__ >= 6))))
#define CCASSERT(id, predicate) _Static_assert(predicate, #id)
#else
#define CCASSERT(id, predicate)                  __x_CCASSERT_LINE(predicate, id, __LINE__)
#define __x_CCASSERT_LINE(predicate, file, line) __xx_CCASSERT_LINE(predicate, file, line)
#define __xx_CCASSERT_LINE(predicate, file, line) \
    typedef char CCASSERT_##file##_line_##line[((predicate) ? 1 : -1)]
#endif

#ifdef macro_offsetof
#define offsetof(type, field) ((unsigned int) &(((type *) NULL)->field))
#endif

/**
 * Quality development guidelines:
 * - NO header defined per arch and included in common if needed per arch,
 * define below
 * - exception model
 * - G_ prefix for RAM vars
 * - N_ prefix for NVRAM vars (mandatory for x86 link script to operate
 * correctly)
 * - C_ prefix for ROM   constants (mandatory for x86 link script to operate
 * correctly)
 * - extensive use of * and arch specific C modifier
 */

// error type definition
typedef unsigned short exception_t;

// #define macro_offsetof // already defined in stddef.h
#define OS_LITTLE_ENDIAN
#define NATIVE_64BITS
#define NVM_ERASED_WORD_VALUE 0xFFFFFFFFUL

#include <setjmp.h>
// GCC/LLVM declare way too big jmp context, reduce them to what is used on CM0+
typedef struct try_context_s try_context_t;

struct try_context_s {
    // jmp context to backup (in increasing order address: r4, r5, r6, r7, r8, r9,
    // r10, r11, SP, setjmpcallPC)
    jmp_buf jmp_buf;

    // link to the previous jmp_buf context
    try_context_t *previous;

    // current exception
    exception_t ex;
};

// borrowed from setjmp.h

#ifdef __GNUC__
void longjmp(jmp_buf __jmpb, int __retval) __attribute__((__noreturn__));
#else
void longjmp(jmp_buf __jmpb, int __retval);
#endif
int setjmp(jmp_buf __jmpb);

#include "stddef.h"
#include "stdint.h"
// #include <core_sc000.h>

#define UNUSED(x) (void) x

// #include "os_apilevel.h"

#ifndef NULL
#define NULL ((void *) 0)
#endif

#ifndef WIDE_NULL
#define WIDE_NULL ((void WIDE *) 0)
#endif

// Position-independent code reference
// Function that align the dereferenced value in a rom struct to use it
// depending on the execution address. Can be used even if code is executing at
// the same place where it had been linked.
#ifndef PIC
#define PIC(x) ((const uint8_t *) (x))
#endif

/* ----------------------------------------------------------------------- */
/* -                            APPLICATION PRIVILEGES                   - */
/* ----------------------------------------------------------------------- */

/**
 * No rights concealed to the call
 */
#define APPLICATION_FLAG_NONE 0x0

/**
 * Base flag added to loaded application, to allow them to call all syscalls by
 * default (the one requiring no extra permission)
 */
#define APPLICATION_FLAG_MAIN 0x1

/**
 * Flag which combined with ::APPLICATION_FLAG_ISSUER.
 * The application is given full nvram access after the global seed has been
 * destroyed.
 */
#define APPLICATION_FLAG_BOLOS_UPGRADE 0x2

// this flag is set when a valid signature of the loaded application is
// presented at the end of the bolos application load.
#define APPLICATION_FLAG_SIGNED 0x4

// must be set on one application in the registry which is used
#define APPLICATION_FLAG_BOLOS_UX 0x8

// application is allowed to use the raw master seed, if not set, at least a
// level of derivation is required.
#define APPLICATION_FLAG_DERIVE_MASTER 0x10

#define APPLICATION_FLAG_SHARED_NVRAM 0x20
#define APPLICATION_FLAG_GLOBAL_PIN   0x40

// This flag means the application is meant to be debugged and allows for dump
// or core ARM register in case of a fault detection
#define APPLICATION_FLAG_DEBUG 0x80

/**
 * Mark this application as defaultly booting along with the bootloader (no
 * application menu displayed) Only one application can have this at a time. It
 * is managed by the bootloader interface.
 */
#define APPLICATION_FLAG_AUTOBOOT 0x100

/**
 * Application is allowed to change the settings
 */
#define APPLICATION_FLAG_BOLOS_SETTINGS 0x200

#define APPLICATION_FLAG_CUSTOM_CA 0x400

/**
 * The application main can be called in two ways:
 *  - with first arg (stored in r0) set to 0: The application is called from the
 * dashboard
 *  - with first arg (stored in r0) set to != 0 (ram address likely): The
 * application is used as a library from another app.
 */
#define APPLICATION_FLAG_LIBRARY 0x800

/**
 * The application won't be shown on the dashboard (somewhat reasonable for pure
 * library)
 */
#define APPLICATION_FLAG_NO_RUN 0x1000

/**
 * The application is considered an IO task by the system. It only gives
 * privileges to BOLOS' internal IO task
 */
#define APPLICATION_FLAG_IO 0x2000

/**
 * Application has been loaded using a secure channel opened using the
 * bootloader's issuer public key. This application is ledger legit.
 */
#define APPLICATION_FLAG_ISSUER 0x4000

/**
 * Application is enabled (when not being updated or removed)
 */
#define APPLICATION_FLAG_ENABLED 0x8000

#define APPLICATION_FLAG_NEG_MASK 0xFFFF0000UL

/* ----------------------------------------------------------------------- */
/* -                            SYSCALL CRYPTO EXPORT                    - */
/* ----------------------------------------------------------------------- */

#define CXPORT_ED_DES 0x0001UL
#define CXPORT_ED_AES 0x0002UL
#define CXPORT_ED_RSA 0x0004UL

/* ----------------------------------------------------------------------- */
/* -                            TYPES                                    - */
/* ----------------------------------------------------------------------- */

/* ----------------------------------------------------------------------- */
/* -                            GLOBALS                                  - */
/* ----------------------------------------------------------------------- */

// the global apdu buffer
#ifdef HAVE_IO_U2F
#define IMPL_IO_APDU_BUFFER_SIZE (3 + 32 + 32 + 15 + 255)
#else
#define IMPL_IO_APDU_BUFFER_SIZE (5 + 255)
#endif

#ifdef CUSTOM_IO_APDU_BUFFER_SIZE
#define IO_APDU_BUFFER_SIZE MAX(IMPL_IO_APDU_BUFFER_SIZE, CUSTOM_IO_APDU_BUFFER_SIZE)
#else
#define IO_APDU_BUFFER_SIZE IMPL_IO_APDU_BUFFER_SIZE
#endif
extern unsigned char G_io_apdu_buffer[IO_APDU_BUFFER_SIZE];

#define CUSTOMCA_MAXLEN 64

/* ----------------------------------------------------------------------- */
/* -                            ENTRY POINT                              - */
/* ----------------------------------------------------------------------- */

// os entry point
void app_main(void);

// os initialization function to be called by application entry point
void os_boot();

/* ----------------------------------------------------------------------- */
/* -                            OS FUNCTIONS                             - */
/* ----------------------------------------------------------------------- */
#define os_swap_u16(u16) \
    ((((unsigned short) (u16) << 8) & 0xFF00U) | (((unsigned short) (u16) >> 8) & 0x00FFU))

#define os_swap_u32(u32)                                                                     \
    (((unsigned long int) (u32) >> 24) | (((unsigned long int) (u32) << 8) & 0x00FF0000UL) | \
     (((unsigned long int) (u32) >> 8) & 0x0000FF00UL) | ((unsigned long int) (u32) << 24))

REENTRANT(void os_memmove(void *dst, const void WIDE *src, unsigned int length));
#define os_memcpy os_memmove

void os_memset(void *dst, unsigned char c, unsigned int length);

void os_memset4(void *dst, unsigned int initval, unsigned int nbintval);

char os_memcmp(const void WIDE *buf1, const void WIDE *buf2, unsigned int length);

void os_xor(void *dst, void WIDE *src1, void WIDE *src2, unsigned int length);

// Secure memory comparison
char os_secure_memcmp(void WIDE *src1, void WIDE *src2, unsigned int length);

// patch point, address used to dispatch, no index
REENTRANT(void patch(void));

// check API level
SYSCALL void check_api_level(unsigned int apiLevel);

// halt the chip, waiting for a physical user interaction
SYSCALL REENTRANT(void halt(void));

// deprecated
#define reset halt

// send tx_len bytes (atr or rapdu) and retrieve the length of the next command
// apdu (over the requested channel)
#define CHANNEL_APDU           0
#define CHANNEL_KEYBOARD       1
#define CHANNEL_SPI            2
#define IO_RESET_AFTER_REPLIED 0x80
#define IO_RECEIVE_DATA        0x40
#define IO_RETURN_AFTER_TX     0x20
#define IO_ASYNCH_REPLY        0x10  // avoid apdu state reset if tx_len == 0 when we're expected to reply
#define IO_FINISHED            0x08  // inter task communication value
#define IO_FLAGS               0xF8
unsigned short io_exchange(unsigned char channel_and_flags, unsigned short tx_len);

typedef enum {
    IO_APDU_MEDIA_NONE = 0,  // not correctly in an apdu exchange
    IO_APDU_MEDIA_USB_HID = 1,
    IO_APDU_MEDIA_BLE,
    IO_APDU_MEDIA_NFC,
    IO_APDU_MEDIA_USB_CCID,
    IO_APDU_MEDIA_USB_WEBUSB,
    IO_APDU_MEDIA_RAW,
    IO_APDU_MEDIA_U2F,
} io_apdu_media_t;

#ifndef USB_SEGMENT_SIZE
#ifdef IO_HID_EP_LENGTH
#define USB_SEGMENT_SIZE IO_HID_EP_LENGTH
#else
#error IO_HID_EP_LENGTH and USB_SEGMENT_SIZE not defined
#endif
#endif
#ifndef BLE_SEGMENT_SIZE
#define BLE_SEGMENT_SIZE USB_SEGMENT_SIZE
#endif

// common usb endpoint buffer
extern unsigned char G_io_usb_ep_buffer[MAX(USB_SEGMENT_SIZE, BLE_SEGMENT_SIZE)];

/**
 * Return 1 when the event has been processed, 0 else
 */
// io callback in the application called when an interrupt based channel has
// received data to be processed
unsigned char io_event(unsigned char channel);

/**
 * Function takes 0 for first call. Returns 0 when timeout has occurred. Returned
 * value is passed as argument for next call, acting as a timeout context.
 */
unsigned short io_timeout(unsigned short last_timeout);
// write in persistent memory, to make things easy keep a layout of the memory
// in a structure and update fields upon needs The function throws exception
// when the requesting application buffer being written in its declared data
// segment. The later is declared during the application slot allocation (using
// --dataSize parameter in the python scripts) NOTE: accept copy from far memory
// to another far memory.
// @param src_adr NULL to fill with 00's
SYSCALL void nvm_write(void WIDE *dst_adr PLENGTH(src_len),
                       void WIDE *src_adr PLENGTH(src_len),
                       unsigned int src_len);
// the privileged version of nvm_write, called by bolos itself
void nvm_write_os(void WIDE *dst_adr PLENGTH(src_len),
                  void WIDE *src_adr PLENGTH(src_len),
                  unsigned int src_len);

// program a page with the content of the nvm_page_buffer
// HAL for the high level NVM management functions
SUDOCALL PERMISSION(APPLICATION_FLAG_ISSUER) void nvm_write_page(unsigned char WIDE *page_adr);
void svc_nvm_write_page(unsigned char WIDE *page_adr);

/* ----------------------------------------------------------------------- */
/* -                            EXCEPTIONS                               - */
/* ----------------------------------------------------------------------- */

// workaround to make sure defines are replaced by their value for example
#define CPP_CONCAT(x, y)   CPP_CONCAT_x(x, y)
#define CPP_CONCAT_x(x, y) x##y

SUDOCALL PERMISSION(APPLICATION_FLAG_NONE)
try_context_t *try_context_get(void);
try_context_t *svc_try_context_get(void);
// set the new try context and retrieve the previous one
// SECURITY NOTE: no PLENGTH(sizeof(try_context_t)) set because the value is
// never dereferenced within the SUDOCALL.
//                and is checked before being used in all SYSCALL that would use
//                it.
SUDOCALL PERMISSION(APPLICATION_FLAG_NONE)
try_context_t *try_context_set(try_context_t *context);
try_context_t *svc_try_context_set(try_context_t *tryctx);

// -----------------------------------------------------------------------
// - BEGIN TRY
// -----------------------------------------------------------------------

#define BEGIN_TRY_L(L) \
    {                  \
        try_context_t __try##L;

// -----------------------------------------------------------------------
// - TRY
// -----------------------------------------------------------------------
#define TRY_L(L)                                                              \
    /* previous exception context chain is saved within the setjmp r9 save */ \
    __try                                                                     \
        ##L.ex = setjmp(__try##L.jmp_buf);                                    \
    if (__try##L.ex == 0) {                                                   \
        __try                                                                 \
            ##L.previous = try_context_set(&__try##L);

// -----------------------------------------------------------------------
// - EXCEPTION CATCH
// -----------------------------------------------------------------------
#define CATCH_L(L, x)              \
    goto CPP_CONCAT(__FINALLY, L); \
    }                              \
    else if (__try##L.ex == x) {   \
        __try                      \
            ##L.ex = 0;            \
        CLOSE_TRY_L(L);

// -----------------------------------------------------------------------
// - EXCEPTION CATCH OTHER
// -----------------------------------------------------------------------
#define CATCH_OTHER_L(L, e)        \
    goto CPP_CONCAT(__FINALLY, L); \
    }                              \
    else {                         \
        exception_t e;             \
        e = __try##L.ex;           \
        __try                      \
            ##L.ex = 0;            \
        CLOSE_TRY_L(L);

// -----------------------------------------------------------------------
// - EXCEPTION CATCH ALL
// -----------------------------------------------------------------------
#define CATCH_ALL_L(L)             \
    goto CPP_CONCAT(__FINALLY, L); \
    }                              \
    else {                         \
        __try                      \
            ##L.ex = 0;            \
        CLOSE_TRY_L(L);

// -----------------------------------------------------------------------
// - FINALLY
// -----------------------------------------------------------------------
#define FINALLY_L(L)                                                             \
    goto CPP_CONCAT(__FINALLY, L);                                               \
    }                                                                            \
    CPP_CONCAT(__FINALLY, L)                                                     \
        : /* has TRY clause ended without nested throw ? */                      \
          if (try_context_get() == &__try##L) {                                  \
        /* restore previous context manually (as a throw would have when caught) \
         */                                                                      \
        CLOSE_TRY_L(L);                                                          \
    }
// -----------------------------------------------------------------------
// - CLOSE TRY
// -----------------------------------------------------------------------
/**
 * Forced finally like clause.
 */
#define CLOSE_TRY_L(L) try_context_set(__try##L.previous)

// -----------------------------------------------------------------------
// - END TRY
// -----------------------------------------------------------------------
#define END_TRY_L(L)                                     \
    /* nested throw not consumed ? (by CATCH* clause) */ \
    if (__try##L.ex != 0) {                              \
        /* rethrow */                                    \
        THROW_L(L, __try##L.ex);                         \
    }                                                    \
    }

// -----------------------------------------------------------------------
// - EXCEPTION THROW
// -----------------------------------------------------------------------

/**
 Remember that using break/return/goto/continue keywords that disrupt the
 execution flow may introduce silent errors which can pop afterwards in a
 very sneaky and hard to debug way. Those keywords are malicious ONLY when
 jumping out of the current block (TRY/CATCH/CATCH_OTHER/CATCH_ALL) else
 they are perfectly fine.
 When those keywords use are unavoidable, then remember to CLOSE_TRY your
 opened BEGIN/END block.
 To detect those potential problems, here is a basic sed based script to
 narrow down the search to potentially suspicious cases.
 for i in `find . -name "*.c"`; do echo $i ; sed -n '/BEGIN_TRY/,/END_TRY/{
 /goto/{=;H;g;p} ;/return/{=;H;g;p} ; /continue/{=;H;g;p} ; /break/{=;H;g;p} ; h
 }' $i ; done Run it on your source code if unsure. The rule of thumb to respect
 to decide whether or not to use the CLOSE_TRY statement is the following:
 Jumping out of a TRY/CATCH/CATCH_ALL/CATCH_OTHER clause is not closing the
 BEGIN/TRY block if the FINALLY is not executed wholly (jumping to a label
 at the beginning of the FINALLY is not solving the above stated problem).

 Faulty example:
 ===============
 BEGIN_TRY {
   TRY {
    ...
   }
   CATCH {
     ...
     goto noway;
   }
   FINALLY {

   }
 }
 END_TRY;
 noway:
 return;

 Faulty example 2:
 ===============
 BEGIN_TRY {
   TRY {
    ...
     goto noway;
   }
   CATCH {
     ...
   }
   FINALLY {

   }
 }
 END_TRY;
 noway:
 return;

 Faulty example 3:
 ===============
 BEGIN_TRY {
   TRY {
    ...
   }
   CATCH {
     ...
     goto end;
     ...
   }
   FINALLY {
     end:
   }
 }
 END_TRY;
 noway:
 return;

 Faulty example 4:
 ===============
 for(;;) {
   BEGIN_TRY {
     TRY {
      ...
       continue;
       ...
     }
     CATCH {
       ...
     }
     FINALLY {

     }
   }
   END_TRY;
 }

 Ok example (but very suspicious algorithmly speaking):
 ===============
 BEGIN_TRY {
   TRY {
    ...
    yo:
    ...
   }
   CATCH {
     ...
     goto yo;
   }
   FINALLY {

   }
 }
 END_TRY;
 noway:
 return;

 Ok example 2:
 ===============
 BEGIN_TRY {
   TRY {
    ...
    CLOSE_TRY;
    goto noway;
    ...
   }
   CATCH {
     ...
   }
   FINALLY {

   }
 }
 END_TRY;
 noway:
 return;

 Ok example 3:
 ===============
 BEGIN_TRY {
   TRY {
    ...
    goto baz;
    ...
    baz:
   }
   CATCH {
     ...
   }
   FINALLY {

   }
 }
 END_TRY;

 Faulty example 5:
 ===============
 BEGIN_TRY {
   TRY {
    ...
   }
   CATCH {
     return val;
   }
   FINALLY {
     ...
   }
 }
 END_TRY;

 Faulty example 6:
 ===============
 BEGIN_TRY {
   TRY {
     ...
     return val;
   }
   CATCH {
     ...
   }
   FINALLY {
     ...
   }
 }
 END_TRY;

 Ok example 4:
 ===============
 BEGIN_TRY {
   TRY {
    ...
   }
   CATCH {
     ...
   }
   FINALLY {
     return val;
   }
 }
 END_TRY;
 */

// longjmp is marked as no return to avoid too much generated code
#ifdef __clang_analyzer__
void os_longjmp(unsigned int exception) __attribute__((analyzer_noreturn));
#else
void os_longjmp(unsigned int exception) __attribute__((noreturn));
#endif
#define THROW_L(L, x) \
    _Static_assert(0, "Legacy THROW_L is forbidden; return errors explicitly instead.")

// Default macros when nesting is not used.
#define THROW(x)       _Static_assert(0, "Legacy THROW is forbidden; return errors explicitly instead.")
#define BEGIN_TRY      BEGIN_TRY_L(EX)
#define TRY            TRY_L(EX)
#define CATCH(x)       CATCH_L(EX, x)
#define CATCH_OTHER(e) CATCH_OTHER_L(EX, e)
#define CATCH_ALL      CATCH_ALL_L(EX)
#define FINALLY        FINALLY_L(EX)
#define CLOSE_TRY      CLOSE_TRY_L(EX)
#define END_TRY        END_TRY_L(EX)

#define EXCEPTION             1
#define INVALID_PARAMETER     2
#define EXCEPTION_OVERFLOW    3
#define EXCEPTION_SECURITY    4
#define INVALID_CRC           5
#define INVALID_CHECKSUM      6
#define INVALID_COUNTER       7
#define NOT_SUPPORTED         8
#define INVALID_STATE         9
#define TIMEOUT               10
#define EXCEPTION_PIC         11
#define EXCEPTION_APPEXIT     12
#define EXCEPTION_IO_OVERFLOW 13
#define EXCEPTION_IO_HEADER   14
#define EXCEPTION_IO_STATE    15
#define EXCEPTION_IO_RESET    16
#define EXCEPTION_CXPORT      17
#define EXCEPTION_SYSTEM      18
#define NOT_ENOUGH_SPACE      19

/* ----------------------------------------------------------------------- */
/* -                          CRYPTO FUNCTIONS                           - */
/* ----------------------------------------------------------------------- */
#include "cx.h"

/**
 BOLOS RAM LAYOUT
                msp                          psp                   psp
 | bolos ram <-os stack-| bolos ux ram <-ux_stack-| app ram <-app stack-|

 ux and app are seen as applications.
 os is not an application (it calls ux upon user inputs)
**/

/* BOLOS_UX and application registration removed - not used in unit tests */

typedef char bolos_bool_t;
typedef unsigned char bolos_task_status_t;

// any application can wipe the global pin, global seed, user's keys
// disabled for security reasons // SYSCALL void           os_perso_wipe(void);
// erase seed, settings AND applications
SYSCALL void os_perso_erase_all(void);

/* set_pin can update the pin if the perso is onboarded (tearing leads to perso
 * wipe though) */
SYSCALL PERMISSION(APPLICATION_FLAG_BOLOS_UX) void os_perso_set_pin(unsigned int identity,
                                                                    unsigned char *pin
                                                                        PLENGTH(length),
                                                                    unsigned int length);
// set the currently unlocked identity pin. (change pin feature)
SYSCALL
PERMISSION(APPLICATION_FLAG_BOLOS_UX)
void os_perso_set_current_identity_pin(unsigned char *pin PLENGTH(length), unsigned int length);

#define BOLOS_UX_ONBOARDING_ALGORITHM_BIP39    1
#define BOLOS_UX_ONBOARDING_ALGORITHM_ELECTRUM 2

/**
 * Set the persisted seed if none yet, else override the volatile seed (in RAM)
 */
SYSCALL PERMISSION(APPLICATION_FLAG_BOLOS_UX) void os_perso_set_seed(unsigned int identity,
                                                                     unsigned int algorithm,
                                                                     unsigned char *seed
                                                                         PLENGTH(length),
                                                                     unsigned int length);

SYSCALL PERMISSION(APPLICATION_FLAG_BOLOS_UX) void os_perso_derive_and_set_seed(
    unsigned char identity,
    const char *prefix PLENGTH(prefix_length),
    unsigned int prefix_length,
    const char *passphrase PLENGTH(passphrase_length),
    unsigned int passphrase_length,
    const char *words PLENGTH(words_length),
    unsigned int words_length);

// SYSCALL PERMISSION(APPLICATION_FLAG_BOLOS_UX) void
// os_perso_set_alternate_pin(unsigned char* pin PLENGTH(pinLength), unsigned int
// pinLength); SYSCALL PERMISSION(APPLICATION_FLAG_BOLOS_UX) void
// os_perso_set_alternate_seed(unsigned char* seed PLENGTH(seedLength), unsigned
// int seedLength);
SYSCALL PERMISSION(APPLICATION_FLAG_BOLOS_UX) void os_perso_set_words(const unsigned char *words
                                                                          PLENGTH(length),
                                                                      unsigned int length);
SYSCALL PERMISSION(APPLICATION_FLAG_BOLOS_UX) void os_perso_finalize(void);

// checked in the ux flow to avoid asking the pin for example
// NBA : could also be checked by applications running in insecure mode - thus
// unprivilegied
// @return BOLOS_UX_OK when perso is onboarded.
SYSCALL bolos_bool_t os_perso_isonboarded(void);

// derive the seed for the requested BIP32 path
SYSCALL void os_perso_derive_node_bip32(cx_curve_t curve,
                                        const unsigned int *path PLENGTH(4 * (pathLength &
                                                                              0x0FFFFFFFu)),
                                        unsigned int pathLength,
                                        unsigned char *privateKey PLENGTH(64),
                                        unsigned char *chain PLENGTH(32));

#define HDW_NORMAL         0
#define HDW_ED25519_SLIP10 1
// symmetric key derivation according to SLIP-0021
// this only supports derivation of the master node (level 1)
// the beginning of the authorized path is to be provided in the authorized
// derivation tag of the registry starting with a \x00 Note: for SLIP21, the
// path is a string and the pathLength is the number of chars including the
// starting \0 byte. However, firewall checks are processing a number of
// integers, therefore, take care not to locate the buffer too far in memory to
// pass the firewall check.
#define HDW_SLIP21 2
// derive the seed for the requested BIP32 path, with the custom provided
// seed_key for the sha512 hmac ("Bitcoin Seed", "Nist256p1 Seed", "ed25519
// seed", ...)
SYSCALL void os_perso_derive_node_with_seed_key(unsigned int mode,
                                                cx_curve_t curve,
                                                const unsigned int *path PLENGTH(4 * (pathLength &
                                                                                      0x0FFFFFFFu)),
                                                unsigned int pathLength,
                                                unsigned char *privateKey PLENGTH(64),
                                                unsigned char *chain PLENGTH(32),
                                                unsigned char *seed_key PLENGTH(seed_key_length),
                                                unsigned int seed_key_length);
#define os_perso_derive_node_bip32_seed_key(mode,            \
                                            curve,           \
                                            path,            \
                                            pathLength,      \
                                            privateKey,      \
                                            chain,           \
                                            seed_key,        \
                                            seed_key_length) \
    os_perso_derive_node_with_seed_key(mode,                 \
                                       curve,                \
                                       path,                 \
                                       pathLength,           \
                                       privateKey,           \
                                       chain,                \
                                       seed_key,             \
                                       seed_key_length)

/**
 * Generate a seed based cookie
 * seed => derivation (path 0xda7aba5e/0xc1a551c5) => priv key =SECP256K1=>
 * pubkey => sha512 => cookie
 */
SYSCALL unsigned int os_perso_seed_cookie(unsigned char *seed_cookie PLENGTH(seed_cookie_length),
                                          unsigned int seed_cookie_length);

// endorsement APIs
SYSCALL unsigned int os_endorsement_get_code_hash(unsigned char *buffer PLENGTH(32));
SYSCALL unsigned int os_endorsement_get_public_key(unsigned char index,
                                                   unsigned char *buffer PLENGTH(65));
SYSCALL unsigned int os_endorsement_get_public_key_certificate(
    unsigned char index,
    unsigned char *buffer PLENGTH(1 + 1 + 2 * (1 + 1 + 33)));
SYSCALL unsigned int os_endorsement_key1_get_app_secret(unsigned char *buffer PLENGTH(64));
SYSCALL unsigned int os_endorsement_key1_sign_data(unsigned char *src PLENGTH(srcLength),
                                                   unsigned int srcLength,
                                                   unsigned char *signature
                                                       PLENGTH(1 + 1 + 2 * (1 + 1 + 33)));
SYSCALL unsigned int os_endorsement_key2_derive_sign_data(unsigned char *src PLENGTH(srcLength),
                                                          unsigned int srcLength,
                                                          unsigned char *signature
                                                              PLENGTH(1 + 1 + 2 * (1 + 1 + 33)));

// nvram shared zone access right => MPU opening at application switch, using a
// flags in the registry

/* Global PIN functions removed - device-only */

/* UX registry and UX function declarations removed - not used in unit tests */

/* ----------------------------------------------------------------------- */
/* -                            LIB FUNCTIONS                            - */
/* ----------------------------------------------------------------------- */
/**
 * Library call function.
 * call_parameters[0] = library name string pointer (const)
 * call_parameters[1] = library call identifier (0 = init, ...)
 * call_parameters[2+] = called function parameters
 */
SYSCALL void os_lib_call(unsigned int *call_parameters PLENGTH(3 * sizeof(unsigned int)));
SYSCALL void __attribute__((noreturn)) os_lib_end(void);
SYSCALL void os_lib_throw(unsigned int exception);

/* ----------------------------------------------------------------------- */
/* -                            ID FUNCTIONS                             - */
/* ----------------------------------------------------------------------- */
#define OS_FLAG_RECOVERY        1
#define OS_FLAG_SIGNED_MCU_CODE 2
#define OS_FLAG_ONBOARDED       4
#define OS_FLAG_PIN_VALIDATED   128
// #define OS_FLAG_CUSTOM_UX       4
/* Enable application to retrieve OS current running options */
SYSCALL PERMISSION(APPLICATION_FLAG_NONE)
unsigned int os_flags(void);
SYSCALL unsigned int os_version(unsigned char *version PLENGTH(maxlength), unsigned int maxlength);
/* Grab the SE serial number */
SYSCALL unsigned int os_serial(unsigned char *serial PLENGTH(maxlength), unsigned int maxlength);
#ifdef TARGET_NANOX
/* Grab the SEPROXYHAL's MCU serial number */
SYSCALL unsigned int os_seph_serial(unsigned char *serial PLENGTH(maxlength),
                                    unsigned int maxlength);
#endif  // TARGET_NANOX
/* Grab the SEPROXYHAL's feature set */
SYSCALL unsigned int os_seph_features(void);
/* Grab the SEPROXYHAL's version */
SYSCALL unsigned int os_seph_version(unsigned char *version PLENGTH(maxlength),
                                     unsigned int maxlength);
SYSCALL unsigned int os_bootloader_version(unsigned char *version PLENGTH(maxlength),
                                           unsigned int maxlength);

/*
 * Copy the serial number in the given buffer and return its length
 */
unsigned int os_get_sn(unsigned char *buffer);

/* ----------------------------------------------------------------------- */
/* -                         SETTINGS FUNCTIONS                          - */
/* ----------------------------------------------------------------------- */
typedef enum os_setting_e {
    OS_SETTING_BRIGHTNESS,
    OS_SETTING_INVERT,
    OS_SETTING_ROTATION,
#ifdef HAVE_BOLOS_NOT_SHUFFLED_PIN
    OS_SETTING_NOSHUFFLE_PIN,
#endif  // HAVE_BOLOS_NOT_SHUFFLED_PIN
    OS_SETTING_AUTO_LOCK_DELAY,
    OS_SETTING_POWER_OFF_DELAY,

    OS_SETTING_PLANEMODE,

    // default off
    OS_SETTING_PRIVACY_MODE,

    // before that value, all settings are only making use of the length value
    // with a null buffer to be set, and are returned through the return value
    // with a maxlength = 0 in the get.
    OS_SETTING_LAST_INT,

    // screen saver string to display
    OS_SETTING_SAVER_STRING = OS_SETTING_LAST_INT,
    OS_SETTING_DEVICENAME,
    OS_SETTING_BLEMACADR,

    OS_SETTING_LAST,
} os_setting_t;

/**
 * Retrieve the value of a setting in a user specified buffer, with a max
 * length, and return the effective returned length.
 */
SYSCALL PERMISSION(APPLICATION_FLAG_BOLOS_SETTINGS)
unsigned int os_setting_get(unsigned int setting_id,
                            unsigned char *value PLENGTH(maxlen),
                            unsigned int maxlen);

/**
 * Define a setting's value from a user buffer and its length. In case of error,
 * a throw is executed.
 */
SYSCALL PERMISSION(APPLICATION_FLAG_BOLOS_SETTINGS) void os_setting_set(unsigned int setting_id,
                                                                        unsigned char *value
                                                                            PLENGTH(length),
                                                                        unsigned int length);

/* ----------------------------------------------------------------------- */
/* -                          DEBUG FUNCTIONS                           - */
/* ----------------------------------------------------------------------- */
void screen_printf(const char *format, ...);

// emit a single byte
void screen_printc(unsigned char const c);

// redefined if string.h not included
int snprintf(char *str, size_t str_size, const char *format, ...);

#ifndef PRINTF
#define PRINTF(...)
#endif

// syscall test
// SYSCALL void dummy_1(unsigned int* p PLENGTH(2+len+15+ len + 16 +
// sizeof(io_send_t) + 1 ), unsigned int len);

typedef struct meminfo_s {
    unsigned int free_nvram_size;
    unsigned int appMemory;
    unsigned int systemSize;
    unsigned int slots;
} meminfo_t;

/* Device registry and custom CA functions removed - not used in unit tests */

/* ----------------------------------------------------------------------- */
/* -                         PRECISE WATCHDOG                            - */
/* ----------------------------------------------------------------------- */

#ifndef BOLOS_SECURITY_BOOT_DELAY_H
#ifdef BOLOS_RELEASE
// Boot delay before wiping the fault detection counter
#define BOLOS_SECURITY_BOOT_DELAY_H 5
#else  // BOLOS_RELEASE
#define BOLOS_SECURITY_BOOT_DELAY_H 1 - (60 * 60 * 100) + 15 * 100
#endif  // BOLOS_RELEASE
#endif  // BOLOS_SECURITY_BOOT_DELAY_H
#ifndef BOLOS_SECURITY_ONBOARD_DELAY_S
#ifdef BOLOS_RELEASE
// Minimal time for an onboard
#define BOLOS_SECURITY_ONBOARD_DELAY_S (2 * 60)
#else  // BOLOS_RELEASE
// small overhead in dev
#define BOLOS_SECURITY_ONBOARD_DELAY_S 5
#endif  // BOLOS_RELEASE
#endif  // BOLOS_SECURITY_ONBOARD_DELAY_S

#ifndef BOLOS_SECURITY_ATTESTATION_DELAY_S
// Minimal time interval in between two use of the device's private key (SCP
// opening and endorsement)
#define BOLOS_SECURITY_ATTESTATION_DELAY_S 5
#endif  // BOLOS_SECURITY_ATTESTATION_DELAY_S

void safe_desynch();
#define SAFE_DESYNCH() safe_desynch()

typedef enum {
    /* Watchdog consumption lead to no action being taken, overflowed value is
       accounted and can be retrieved by the application */
    OS_WATCHDOG_NOACTION = 0,
    /* Request a platform reset when the watchdog set value is completely consumed
     */
    OS_WATCHDOG_RESET = 1,
    /* Request a wipe of the user data when the watchdog times out */
    OS_WATCHDOG_WIPE = 2,
} os_watchdog_behavior_t;

/**
 * This function arm a low level watchdog, when the value is consumed, and
 * depending on the requested behavior, an action can be taken.
 * @throw INVALID_PARAMETER when the useconds value overflows the possible
 * value.
 */
void os_watchdog_arm(unsigned int useconds, os_watchdog_behavior_t behavior);

/**
 * This function returns the number of useconds to be still consumed by the
 * watchdog (when > 0), or the overflowed useconds after the watchdog has timed
 * out (when < 0)
 */
int os_watchdog_value(void);

/* Task scheduling functions removed - not used in unit tests */

/* BAGL graphics, coroutines, and I2C peripheral functions removed - not used in unit tests */

#ifndef SYSCALL_GENERATE
// #include "syscalls.h"
#endif  // SYSCALL_GENERATE

#endif  // OS_H
