/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

/**
 * Start NBGL streaming UI for native script hash derivation.
 * Called once on init APDU to show title screen.
 */
void ui_start_native_script_streaming(void);

/**
 * Display native script content during streaming.
 * Called for each script APDU to show script details.
 */
void ui_display_native_script_hash(void);
