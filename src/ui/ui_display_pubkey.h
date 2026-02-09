#pragma once

#include "securityPolicy.h"

/**
 * Display public key for export approval
 *
 * @param securityPolicy Security policy result
 * @param warnings Warning bits
 */
void ui_display_pubkey(security_policy_t securityPolicy, warning_bits_t warnings);
