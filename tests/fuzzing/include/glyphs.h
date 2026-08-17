#pragma once
#include "nbgl_types.h"

// App-specific icons — defined in mock/ui_mocks.c.
extern const nbgl_icon_details_t C_cardano_64;
extern const nbgl_icon_details_t C_icon_ada_stax;
extern const nbgl_icon_details_t C_icon_ada_flex;
extern const nbgl_icon_details_t C_icon_ada_nanox;
extern const nbgl_icon_details_t C_icon_ada_apex;
extern const nbgl_icon_details_t C_icon_warning;

// SDK NBGL icons used by lib_nbgl source files included in the fuzz build.
// Only the symbols actually referenced via nbgl_icons.h macros in
// nbgl_page.c and nbgl_layout.c are listed here; the rest are not compiled.
extern const nbgl_icon_details_t C_Chevron_40px;       // PUSH_ICON
extern const nbgl_icon_details_t C_Check_Circle_64px;  // CHECK_CIRCLE_ICON
extern const nbgl_icon_details_t C_Settings_40px;      // WHEEL_ICON
extern const nbgl_icon_details_t C_Info_40px;          // INFO_I_ICON
extern const nbgl_icon_details_t C_Close_40px;         // CLOSE_ICON
extern const nbgl_icon_details_t C_Back_40px;          // LEFT_ARROW_ICON
extern const nbgl_icon_details_t C_Mini_Push_40px;     // MINI_PUSH_ICON
extern const nbgl_icon_details_t C_switch_60_40;       // SWITCH_ICON
extern const nbgl_icon_details_t C_Check_40px;         // VALIDATE_ICON
extern const nbgl_icon_details_t
    C_Chevron_Back_40px;  // CHEVRON_BACK_ICON (nbgl_layout_navigation.c, TARGET_FLEX)
extern const nbgl_icon_details_t
    C_Chevron_Next_40px;  // CHEVRON_NEXT_ICON (nbgl_layout_navigation.c, TARGET_FLEX)
extern const nbgl_icon_details_t C_pin_24;  // DIGIT_ICON (nbgl_layout_keypad.c, SCREEN_SIZE_WALLET)

// Additional icons referenced by the existing app UI code.
extern const nbgl_icon_details_t C_Warning_40px;
extern const nbgl_icon_details_t C_Warning_64px;
extern const nbgl_icon_details_t C_Warning_32px;
extern const nbgl_icon_details_t C_Info_Circle_64px;
extern const nbgl_icon_details_t C_Important_Circle_64px;
