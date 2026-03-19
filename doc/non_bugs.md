# Review instructions

* Security and auditability is critically important for this app.
* Efficiency is not critically important; if doing something twice makes the code cleaner and more auditable, it is preferable to do it twice.
* Auditability is increased by following the same text patterns (macro calls, function params, style of loops, switch instead of if chain over enum values, memory init/cleanup etc.).
* Ledger devices have little memory, so standard ways of doing things are sometimes unsuitable.
* Unless told specifically, we do not want legacy wrappers or support for deprecated stuff.


# List of **not bugs**, do not report them.

Format: -> means explanation why not a bug.

* IPv6 Relay Address Corruption (Critical Security): Hashing logic incorrectly swaps bytes of big-endian IPv6 addresses on little-endian devices. While the UI displays the correct address, the signed hash is corrupted.
-> this is how Cardano blockchain does it, we have to do the same.

* Missing Canonical Ordering Checks (CDDL Violations): required_signers (Key 14) are not checked for canonical sorting, pool_owners within stake pool registration certificates are not checked for canonical sorting.
-> for historical reason, we do not check unique elements in sets.

* Unsupported Field Omission (Protocol Gap): Key 20 (proposal_procedures) is defined as "NOT SUPPORTED" in the CDDL but is silently ignored by the app's parsing logic.
-> no plans to support proposal_procedures for now, it is ok. The app behaves as if it did not know anything about proposal procedures and that is the intended behavior.

* `swap_handle_check_address` hardcodes `MAINNET_NETWORK_ID`.
-> intentional and inherited from the old app (`../app-cardano/src/swap/handle_check_address.c`); swap flow is mainnet-only.

* Init ordering nit: whether handlers set `G_context.req_type` before or after a local state check in INIT flow.
-> not a bug by itself. Both patterns are acceptable when handler invariants hold and failures route through reset/deny paths. Prefer consistency within each handler/state machine over enforcing one global ordering rule.

* "Redundant state check" right after setting state in handler flow (for example `derive_address` PARSED check) and CVote INIT check after `explicit_bzero(&G_context.cvote_info, ...)`.
-> not a bug by itself. In `derive_address`, the immediate check is an intentional defensive invariant/style pattern. In CVote, zeroing `cvote_info` does not zero `state.cvote_state` (different global-context fields), so `ensure_sign_cvote_state(VOTECAST_STATE_NONE)` is a real precondition check.

* `mark_unusual_key_derivation(...)` may look coupled to `bip44_isPathReasonable(...)` / SHOW behavior.
-> not a bug by itself. Preferred style is to keep the link explicit at call sites with `SHOW_IF(mark_unusual_key_derivation(...))`, optionally followed by unconditional `SHOW()` when the field/path must always be shown anyway. This makes warning-vs-visibility behavior local and auditable.

* Unreachable `default` in `switch` over enum/type value after prior strict validation.
-> intentional defensive programming pattern. Keeping `ASSERT(false)`/`LEDGER_ASSERT(false, ...)` in logically unreachable branches documents invariants and catches unexpected state corruption or future regressions during development; this should not be downgraded to a normal runtime fallback just to remove "dead code". Also protects against memory-modified-in-the-middle attacks.

* Host-provided total length causes early allocation/reservation (up to protocol/app limits), even before all bytes are received.
-> not a bug by itself. In streamed APDU flows, the app commits to the declared size and then strictly enforces that exact byte count in subsequent chunks. The device handles one request/session at a time (no parallel users/calls), so this is perfectly intentional.

* Missing `amount > 0` check for withdrawals.
-> not a bug. CDDL defines `withdrawals = {+ reward_account => coin}` and `coin = uint`, so zero is protocol-valid. This differs from places that require strictly positive quantities (for example output token amounts). Allowing zero withdrawals is harmless and avoids adding wallet-local restrictions beyond the ledger format.

* "Unbounded" loops over host-declared counts (withdrawals, mint groups, mint tokens) without extra small hardcaps.
-> not a bug by itself. These loops are bounded by protocol field widths (`uint16_t` counts) and by the already-validated transaction byte budget (`raw_tx_total_length`, capped by app limit). Parsing uses bounded buffer readers and fails immediately on underflow/malformed data; full consumption is enforced at the end. This is an intentional compatibility/auditability tradeoff (no arbitrary wallet-local count limits), not an infinite-loop risk.

* No extra wallet-local upper bound for length-prefixed nested payloads (for example stake pool registration certificate payload).
-> not a bug by itself. The nested payload length is validated against remaining bytes before parsing, then parsed via a bounded sub-buffer, required to be fully consumed, and finally the outer cursor advances by exactly that length. Combined with global transaction size caps, this is a safe and auditable framing strategy without arbitrary additional caps.

* Missing repeated UI-time bound assertion for fields that were already strictly bounded at parse time (for example pool metadata `urlSize` in rendering).
-> not a bug by itself. If the field is parsed with strict limits and then carried through immutable parse->policy->render flow, rechecking the same bound in each consumer is optional defense-in-depth, not a correctness or security requirement.

* No explicit small hardcaps for stake pool registration `numPoolOwners` / `numRelays`.
-> not a bug by itself. Counts are wire-bounded (`uint16_t`) and constrained by the enclosing payload length and full-consumption checks. Processing is finite and fails on malformed/short input. Additional wallet-local maxima would be policy restrictions, not a memory-safety fix.

* URL formatter enforces printable ASCII without spaces for displayed URLs.
-> intentional display-safety policy. Percent-encoded URLs (including `%20`) are ASCII and allowed; non-ASCII/confusable URLs are intentionally rejected as not safely displayable without ambiguity.

* Non-mainnet network IDs 2–15 are rendered with mainnet-looking `addr`/`stake` bech32 prefixes.
-> not a bug. These IDs don't exist on any real network, and `isNetworkUsual()` returns false for them, triggering an unusual-network warning to the user. Behavior matches the old app.

* `extractProtocolMagic` parses the tag-24 inner Byron payload on the outer buffer without a dedicated sub-buffer.
-> not a bug. The outer buffer bounds, whole-buffer exhaustion check, and CRC32 checksum verification together ensure correctness; a sub-buffer would add no security value.

* `aux_data_hash_builder.c` trace buffers (`AUX_DATA_TRACE_BUFFER_SIZE` / `CVOTE_PAYLOAD_TRACE_BUFFER_SIZE`) are only 4 KiB each and will assert if a high-delegation CIP-36 registration overflows them.
-> intentional. Buffers are debug-only (compiled in only under `-DTRACE_AUX_DATA_HASH_BUILDER`, never in production). The assert-on-overflow is deliberate: if a developer enables tracing and hits the limit, they get a loud failure rather than silent truncation of the trace, and can decide how to proceed. Production hashing is unaffected.
