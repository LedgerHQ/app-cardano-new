#pragma once

#include "securityPolicy.h"

/**
 * Display CIP-8 message signing confirmation screen.
 *
 * @param[in] securityPolicy  Security policy (expected to be POLICY_SHOW)
 */
void ui_display_sign_msg(security_policy_t securityPolicy);
