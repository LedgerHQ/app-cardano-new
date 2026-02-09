#pragma once

#include "securityPolicy.h"

/**
 * Display operational certificate for signing approval
 *
 * @param securityPolicy Security policy result
 * @param warnings Warning bits
 */
void ui_display_opcert(security_policy_t securityPolicy, warning_bits_t warnings);
