#include <stddef.h>

#include "nbgl_obj.h"

// App-specific icon definitions — not generated in the fuzz build.
const nbgl_icon_details_t C_cardano_64;
const nbgl_icon_details_t C_icon_ada_stax;
const nbgl_icon_details_t C_icon_ada_flex;
const nbgl_icon_details_t C_icon_ada_nanox;
const nbgl_icon_details_t C_icon_ada_apex;
const nbgl_icon_details_t C_icon_warning;

// SDK NBGL icon stubs for symbols referenced via nbgl_icons.h macros in
// nbgl_page.c and nbgl_layout.c.  Zero-initialised; display functions are
// mocked out so the data is never accessed at runtime.
const nbgl_icon_details_t C_Chevron_40px;
const nbgl_icon_details_t C_Check_Circle_64px;
const nbgl_icon_details_t C_Settings_40px;
const nbgl_icon_details_t C_Info_40px;
const nbgl_icon_details_t C_Close_40px;
const nbgl_icon_details_t C_Back_40px;
const nbgl_icon_details_t C_Mini_Push_40px;
const nbgl_icon_details_t C_switch_60_40;
const nbgl_icon_details_t C_Check_40px;

// Additional icons referenced by the app UI code.
const nbgl_icon_details_t C_Warning_40px;
const nbgl_icon_details_t C_Info_Circle_64px;
