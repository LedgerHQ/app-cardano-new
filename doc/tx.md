# Cardano Transaction Processing Overview

This document describes the details of transaction parsing, hashing, and the data structures used within the Ledger application.

## Transaction Body Specification

The transaction body structure follows the Cardano CDDL specification. The authoritative reference for the supported transaction format is [conway.cddl](conway.cddl).

### Supported Fields

The application supports the following fields in the `transaction_body` map:

- `0`: `inputs`
- `1`: `outputs`
- `2`: `fee`
- `3`: `ttl` (optional)
- `4`: `certificates` (optional)
- `5`: `withdrawals` (optional)
- `7`: `auxiliary_data_hash` (optional)
- `8`: `validity_interval_start` (optional)
- `9`: `mint` (optional)
- `11`: `script_data_hash` (optional)
- `13`: `collateral_inputs` (optional)
- `14`: `required_signers` (optional)
- `15`: `network_id` (optional)
- `16`: `collateral_output` (optional)
- `17`: `total_collateral` (optional)
- `18`: `reference_inputs` (optional)
- `19`: `voting_procedures` (optional)
- `21`: `treasury` (optional)
- `22`: `donation` (optional)

*Note: Proposal procedures (`20`) are intentionally NOT supported.*

## Transaction Hashing (`tx_hash_builder.c`)

The `tx_hash_builder` is a stateful component responsible for computing the Blake2b-256 hash of the transaction body. It ensures:

1.  **Canonical CBOR Encoding**: Data is hashed in the exact format required by the Cardano ledger.
2.  **State Machine Validation**: It enforces that fields are added in the correct order and that all expected data (like all tokens in an asset group) has been provided before moving to the next field.
3.  **Efficiency**: It hashes data incrementally to minimize memory usage, which is critical for the restricted environment of a Ledger device.

## Parsing Logic (`tx_parse.c`)

The parser decodes the custom APDU-based serialization format sent by the client into internal C structures.

- **Dynamic Allocation**: Uses a specialized allocator (`app_mem_alloc`) to manage memory during the parsing phase.
- **Linked Lists**: Complex structures like multi-asset outputs or multiple certificates are stored in linked lists (`flist.h`) to handle variable-length data without large static buffers.
- **Field Parsing**: Specialized modules handle complex fields:
  - `tx_parse_outputs.c`: Parses outputs including addresses, datums, and reference scripts.
  - `tx_parse_certificates.c`: Parses all certificate types (stake operations, pool operations, committee/DRep operations).

## Transaction Validation and Hashing (`tx_validate.c`)

The validation phase enforces security policies and computes the Blake2b-256 transaction hash in a single pass via the state machine in `tx_hash_builder.c`.

**Primary Function:** `tx_validate_and_compute_hash(tx_ui_plan_t* plan)`

This function:
1. Iterates through transaction fields in canonical CBOR order (keys 0-22).
2. For each field, calls the corresponding security policy function to validate elements.
   - **POLICY_DENY**: Transaction rejected immediately.
   - **POLICY_SHOW**: Element will be displayed to user (pair count incremented).
   - **POLICY_HIDE**: Element not shown to user.
3. Feeds validated data to the hash builder for incremental Blake2b-256 computation.
4. Counts the number of UI pairs needed for display in the provided `tx_ui_plan_t` structure.
5. Returns success or error code.

**Key Design:** Validation, hashing, and UI planning cannot be easily separated because canonical CBOR checking requires the full hash builder state machine, and UI element counts depend on security policy results.

## Security Policy Integration

Security policies are evaluated during the validation phase. Each field validator calls a corresponding `policyFor*()` function from `securityPolicy/securityPolicy.c`, which examines the element with full context and returns the policy decision.

Policies enforce:
- Single-account constraint (all witness paths use the same BIP44 account).
- Credential type restrictions (e.g., script hashes forbidden in ordinary signing mode).
- Certificate type restrictions (depends on signing mode).
- Address validations for change outputs and collateral returns.

## UI Preparation (`tx_prepare.c`)

Once the transaction is hashed and the UI plan is populated, `tx_prepare.c` formats the transaction into human-readable NBGL UI pairs:
- Formats ADA amounts and native token quantities using decimal places from token registry.
- Converts raw data (addresses, certificate details) into user-friendly strings.
- Identifies "change" outputs (device-owned addresses) to minimize unnecessary confirmations.
- Builds UI pairs in the same field order and count as planned during validation.
