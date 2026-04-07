# Raw Transaction Buffer

This document covers the raw transaction buffer format, size calculations, and the dynamic allocation optimization.

## Table of Contents

1. [Background](#background)
2. [Format Differences: CBOR vs Raw](#format-differences-cbor-vs-raw)
3. [Buffer Size Calculation](#buffer-size-calculation)
4. [Dynamic Allocation Optimization](#dynamic-allocation-optimization)

---

## Background

The Ledger Cardano application uses a **custom non-CBOR serialization format** for transaction data sent via APDUs (the "raw format"). This format differs from the canonical CBOR encoding used on-chain.

**Why a custom format?**
- Simplifies parsing on constrained devices
- Avoids CBOR library dependencies
- Enables efficient streaming validation
- Allows exact memory pre-allocation

**Key constraint:** Cardano limits transaction body size to **16 KB CBOR**. We must determine the maximum raw buffer size needed to accommodate any valid 16KB CBOR transaction.

---

## Format Differences: CBOR vs Raw

### CBOR Format
As defined in [`conway.cddl`](conway.cddl):

- **Variable-length integer encoding** (compact for small values)
  - Values < 24: 1 byte
  - Values < 2⁸: 2 bytes
  - Values < 2¹⁶: 3 bytes
  - Values < 2³²: 5 bytes
  - Values ≥ 2³²: 9 bytes
- **Map structure** with keys 0-22 (1 byte per key in range 0-23)
- **Array/map headers** with length prefixes
- **Nested structures** with CBOR tags (e.g., `#6.24` for script references)
- **Compact byte strings** with length prefix

### Raw Format
As implemented in [`tx_parse.c`](../src/transaction/tx_parse.c) and [`command_builder.py`](../tests/application_client/command_builder.py):

- **Fixed 8-byte encoding** for all uint64 fields (`u64 BE`)
- **Explicit 2-byte size prefixes** for:
  - Output data length (per output)
  - Number of tokens (per asset group)
  - Number of votes (per voter)
  - Inline datum size (if present)
  - Reference script size (if present)
  - Address length (for third-party addresses)
- **No map/array structure overhead**
- **Direct byte encoding** for hashes and credentials (no length prefix for fixed-size fields)

---

## Buffer Size Calculation

### Methodology

The calculation uses **actual CBOR encoding** (via `cbor2` Python library) to measure sizes, not estimates.

For each component type:
1. Measure actual CBOR size per instance
2. Measure raw format size per instance
3. Calculate how many instances fit in 16KB CBOR
4. Determine total overhead when maximizing that component type

**Worst case = component type with maximum total overhead**

### Component-by-Component Analysis

Using actual CBOR encoding measurements:

| Component | CBOR Size | Raw Size | Difference | Notes |
|-----------|-----------|----------|------------|-------|
| **Transaction input** | 38 bytes | 36 bytes | **-2 bytes** | Raw saves array overhead |
| **Output (small coin)** | 64 bytes | 75 bytes | **+11 bytes** | CBOR compact for small amounts |
| **Output (large coin)** | 71 bytes | 75 bytes | **+4 bytes** | CBOR less efficient for large amounts |
| **Output (1 token)** | 147 bytes | 146 bytes | **-1 byte** | Raw token encoding efficient |
| **Output (5 tokens)** | 319 bytes | 310 bytes | **-9 bytes** | More tokens = better CBOR efficiency |
| **Simple certificate** | 34 bytes | 30 bytes | **-4 bytes** | Raw saves array overhead |
| **32-byte hash** | 34 bytes | 32 bytes | **-2 bytes** | Raw saves length prefix |
| **Withdrawal** | 36 bytes | 37 bytes | **+1 byte** | Minimal overhead |

**Key observation:** As outputs contain more tokens, CBOR becomes MORE efficient than raw format.

### Worst-Case Scenario

The worst-case overhead occurs when filling the entire 16KB CBOR budget with **minimal outputs containing small coin values**.

#### Why Small Coin Values?

CBOR's variable-length encoding is maximally efficient for small values:
- Small coin (100 lovelace): 2 bytes in CBOR
- Same value in raw: 8 bytes (u64 BE - always fixed)

This maximizes the overhead.

#### Detailed Breakdown (Per Output)

**CBOR encoding for output with coin=100:**
```
{0: address_bytes, 1: 100}
```

- Map header (2 keys): `0xA2` = 1 byte
- Key 0: `0x00` = 1 byte
- Address (57-byte base address):
  - Major type 2 (byte string): 1 byte
  - Length 57: `0x39` = 1 byte
  - Data: 57 bytes
  - **Subtotal: 59 bytes**
- Key 1: `0x01` = 1 byte
- Coin value 100:
  - Major type 0 (uint): 1 byte
  - Value: `0x64` = 1 byte
  - **Subtotal: 2 bytes**
- **Total CBOR: 64 bytes**

**Raw encoding:**
- destination_type: 1 byte
- address_size: 2 bytes
- address: 57 bytes
- amount: **8 bytes** (u64 BE - always 8 regardless of value)
- format: 1 byte
- num_asset_groups: 2 bytes
- datum_flag: 1 byte
- ref_script_flag: 1 byte
- output_data_size_prefix: 2 bytes
- **Total raw: 75 bytes**

**Overhead: 75 - 64 = +11 bytes per output**

#### Scaling to 16KB

- Outputs fitting in 16KB CBOR: 16,384 / 64 = **256 outputs**
- Total CBOR: 256 × 64 = 16,384 bytes
- Total raw: 256 × 75 = 19,200 bytes
- **Total overhead: +2,816 bytes (+17.19%)**

### Calculation Results

When a transaction reaches the maximum 16 KB (16,384 bytes) CBOR size:

- **Worst-case scenario:** 256 outputs with small coin values
- **Total CBOR size:** 16,384 bytes
- **Total raw size:** 19,200 bytes
- **Maximum overhead:** +2,816 bytes (+17.19%)
- **With 256-byte safety margin:** **19,456 bytes**

### Configuration

**`MAX_TX_BUFFER_SIZE`** (defined in [`tx_constants.h`](../src/transaction/tx_constants.h)):

```c
#define MAX_TX_BUFFER_SIZE (21 * 1024)  // 21 KB
```

Set to **21 KB** (not 19.456 KB) to:
- Provide ~1.5 KB margin for edge cases
- Leave more memory for UI structures
- Future-proof against format changes

### Verification Script

The following Python script provides automated verification of the worst-case calculation using actual CBOR encoding (via `cbor2` library):

```python
#!/usr/bin/env python3
"""
Final precise calculation focusing on outputs with varying coin sizes.
"""

import cbor2
from io import BytesIO

MAX_CBOR_TX_SIZE = 16 * 1024

def measure_cbor_size(obj):
    buf = BytesIO()
    cbor2.dump(obj, buf)
    return len(buf.getvalue())

def analyze_outputs():
    print("="*80)
    print("FINAL PRECISE WORST-CASE ANALYSIS")
    print("="*80)
    print()
    print("Testing outputs with varying coin sizes to find maximum overhead.")
    print()

    address = b'\x00' * 57

    # Test different coin sizes
    test_cases = [
        ("Small coin (100)", 100),
        ("Medium coin (10^6)", 10**6),
        ("Large coin (10^12)", 10**12),
        ("Max uint32 (2^32-1)", 2**32 - 1),
        ("Large uint64 (2^50)", 2**50),
        ("Max uint64 (2^64-1)", 2**64 - 1),
    ]

    print(f"{'Coin Value':<25} {'CBOR':>8} {'Raw':>8} {'Diff':>6} {'Count':>6} {'Total Overhead':>15}")
    print("-"*80)

    max_overhead = 0
    worst_case = None

    for label, coin_value in test_cases:
        # CBOR: {0: address, 1: coin}
        output_cbor = {0: address, 1: coin_value}
        cbor_size = measure_cbor_size(output_cbor)

        # Raw: destination_type(1) + address_size(2) + address(57) + amount(8) +
        #      format(1) + num_asset_groups(2) + datum_flag(1) + ref_script_flag(1) +
        #      output_data_size_prefix(2)
        raw_size = 1 + 2 + 57 + 8 + 1 + 2 + 1 + 1 + 2

        diff = raw_size - cbor_size
        count = MAX_CBOR_TX_SIZE // cbor_size
        total_cbor = count * cbor_size
        total_raw = count * raw_size
        total_overhead = total_raw - total_cbor

        print(f"{label:<25} {cbor_size:8} {raw_size:8} {diff:+6} {count:6} {total_overhead:+15}")

        if total_overhead > max_overhead:
            max_overhead = total_overhead
            worst_case = {
                'label': label,
                'cbor_per': cbor_size,
                'raw_per': raw_size,
                'diff_per': diff,
                'count': count,
                'total_cbor': total_cbor,
                'total_raw': total_raw,
                'total_overhead': total_overhead
            }

    print("="*80)
    print()
    print("WORST CASE IDENTIFIED:")
    print(f"  Scenario: {worst_case['label']}")
    print(f"  CBOR per output: {worst_case['cbor_per']} bytes")
    print(f"  Raw per output:  {worst_case['raw_per']} bytes")
    print(f"  Overhead per output: {worst_case['diff_per']:+} bytes")
    print(f"  Number fitting in 16KB: {worst_case['count']}")
    print(f"  Total CBOR: {worst_case['total_cbor']:,} bytes")
    print(f"  Total raw:  {worst_case['total_raw']:,} bytes")
    print(f"  Total overhead: {worst_case['total_overhead']:+,} bytes ({100*worst_case['total_overhead']/worst_case['total_cbor']:+.2f}%)")
    print()

    # Add safety margin
    safety_margin = 256
    recommended = MAX_CBOR_TX_SIZE + worst_case['total_overhead'] + safety_margin

    print("RECOMMENDED TX_BUFFER_SIZE:")
    print(f"  16,384 (16KB CBOR)")
    print(f"  +{worst_case['total_overhead']:,} (worst-case overhead)")
    print(f"  +{safety_margin} (safety margin)")
    print(f"  = {recommended:,} bytes")
    print(f"  = {recommended / 1024:.2f} KB")
    print()

    # Current setting (MAX_TX_BUFFER_SIZE from tx_constants.h)
    current = 21 * 1024  # 21 KB
    print(f"Current MAX_TX_BUFFER_SIZE: {current:,} bytes ({current / 1024:.0f} KB)")
    print(f"Margin above required:  {current - recommended:+,} bytes")
    if current >= recommended:
        print("  ✓ Current setting is SAFE")
    else:
        print("  ✗ Current setting is TOO SMALL")
    print()

    # Also check what actually fits in remaining memory
    size_mem_buffer = 23 * 1024  # worst case (Nano X, the tightest device)
    heap_overhead = 200  # approximate overhead for heap structures
    available = size_mem_buffer - heap_overhead

    print(f"Memory constraints (Nano X, worst case):")
    print(f"  SIZE_MEM_BUFFER:     {size_mem_buffer:,} bytes")
    print(f"  Heap overhead:       ~{heap_overhead:,} bytes")
    print(f"  Available for TX:    {available:,} bytes")
    print(f"  Recommended TX size: {recommended:,} bytes")
    print(f"  Remaining margin:    {available - recommended:,} bytes")
    print()

    return worst_case

if __name__ == "__main__":
    analyze_outputs()
```

**Expected output:**
```
================================================================================
FINAL PRECISE WORST-CASE ANALYSIS
================================================================================

Testing outputs with varying coin sizes to find maximum overhead.

Coin Value                    CBOR      Raw   Diff  Count  Total Overhead
--------------------------------------------------------------------------------
Small coin (100)                64       75    +11    256           +2816
Medium coin (10^6)              67       75     +8    244           +1952
Large coin (10^12)              71       75     +4    230            +920
Max uint32 (2^32-1)             67       75     +8    244           +1952
Large uint64 (2^50)             71       75     +4    230            +920
Max uint64 (2^64-1)             71       75     +4    230            +920
================================================================================

WORST CASE IDENTIFIED:
  Scenario: Small coin (100)
  CBOR per output: 64 bytes
  Raw per output:  75 bytes
  Overhead per output: +11 bytes
  Number fitting in 16KB: 256
  Total CBOR: 16,384 bytes
  Total raw:  19,200 bytes
  Total overhead: +2,816 bytes (+17.19%)

RECOMMENDED TX_BUFFER_SIZE:
  16,384 (16KB CBOR)
  +2,816 (worst-case overhead)
  +256 (safety margin)
  = 19,456 bytes
  = 19.00 KB

Current MAX_TX_BUFFER_SIZE: 21,504 bytes (21 KB)
Margin above required:  +2,048 bytes
  ✓ Current setting is SAFE

Memory constraints (Nano X, worst case):
  SIZE_MEM_BUFFER:     23,552 bytes
  Heap overhead:       ~200 bytes
  Available for TX:    23,352 bytes
  Recommended TX size: 19,456 bytes
  Remaining margin:    3,896 bytes
```

---

## Dynamic Allocation Optimization

### Overview

The transaction signing protocol passes the **exact raw transaction buffer size** from the client in the INIT APDU. This enables the device to allocate only the memory needed for each specific transaction.

### Motivation

**Memory is precious** on hardware wallets. The raw transaction buffer is temporary, but UI structures must be allocated on top of it.

**Memory savings by transaction type:**

| Transaction Type | CBOR Size | Raw Size | Old (Fixed) | New (Dynamic) | Savings |
|------------------|-----------|----------|-------------|---------------|---------|
| Simple payment | 300 B | 350 B | 21 KB | 350 B | ~20.7 KB |
| Multi-output | 2 KB | 2.3 KB | 21 KB | 2,300 B | ~18.7 KB |
| Complex DeFi | 12 KB | 14 KB | 21 KB | 14,000 B | ~7 KB |
| Maximum | 16 KB | 19.2 KB | 21 KB | 19,200 B | ~1.8 KB |

**Average case saves ~17-19 KB**, leaving significantly more memory for UI structures.

### Protocol Change

#### INIT APDU Format (P1=0x10)

**New field added after `num_witnesses`:**

```
[existing fields...]
num_witnesses (2 bytes, BE)
raw_tx_total_length (2 bytes, BE)  ← NEW
```

#### Client Responsibilities

The Python client ([`command_builder.py`](../tests/application_client/command_builder.py)):
1. Serializes the transaction to raw format
2. Calculates the exact byte length
3. Passes this as `raw_tx_total_length` in INIT APDU
4. Sends transaction chunks matching this size exactly

#### Device Responsibilities

The device ([`sign_tx.c`](../src/handler/sign_tx.c)):
1. **INIT**: Reads `raw_tx_total_length`, validates ≤ `MAX_TX_BUFFER_SIZE` (21 KB)
2. **CHUNK**: Allocates exactly `raw_tx_total_length` bytes (not `MAX_TX_BUFFER_SIZE`)
3. **CHUNK**: Validates each chunk doesn't exceed advertised size
4. **CONFIRM**: Validates received length matches advertised length exactly

### Implementation

#### Device Side

**File**: [`src/globals.h`](../src/globals.h)
```c
typedef struct {
    uint8_t *raw_tx;
    size_t raw_tx_current_length;     /// Actual received length
    uint16_t raw_tx_total_length;     /// Advertised size from client
    // ...
} transaction_ctx_t;
```

**File**: [`src/handler/sign_tx.c`](../src/handler/sign_tx.c)
- Reads `raw_tx_total_length` in INIT handler
- Validates it's in range (1..`MAX_TX_BUFFER_SIZE`)
- Allocates exactly that amount
- Validates final length matches advertised length

#### Client Side

**File**: [`tests/application_client/command_builder.py`](../tests/application_client/command_builder.py)

Added to `TxInitParams`:
```python
@dataclass(frozen=True)
class TxInitParams:
    # ... existing fields ...
    raw_tx_buffer_size: int  # Size of raw transaction buffer
```

In `build_tx_init_params()`:
```python
# Calculate raw transaction buffer size
raw_tx_data = self._serialize_transaction_unpacked_raw(tx)
raw_tx_buffer_size = len(raw_tx_data)
```

### Validation Strategy

The device performs **three-layer validation**:

1. **INIT**: Advertised size must be 1..21,504 bytes (21 KB)
2. **CHUNK**: Running total must not exceed advertised size
3. **CONFIRM**: Final received length must **exactly match** advertised size

This catches:
- Client serialization bugs
- Chunk corruption
- Protocol implementation errors

### Error Codes

| Scenario | Error Code | When |
|----------|------------|------|
| `raw_tx_buffer_size == 0` | `SWO_WRONG_TX_INIT_APDU_DATA` | INIT |
| `raw_tx_buffer_size > MAX_TX_BUFFER_SIZE` (21 KB) | `SWO_INVALID_TX_LENGTH` | INIT |
| Chunk would exceed advertised size | `SWO_INVALID_TX_LENGTH` | CHUNK |
| Final length ≠ advertised length | `SWO_INVALID_TX_LENGTH` | CONFIRM |

### Memory Layout

Verification against device memory limits (Nano X is the tightest):

| Device | Total RAM | Heap Overhead | Available | MAX (21 KB) | Typical TX | UI Space |
|--------|-----------|---------------|-----------|-------------|------------|----------|
| Nano X | 23 KB | ~200 B | 22.8 KB | 21 KB | 2-3 KB | ~19-20 KB |
| Nano S+, Stax, Flex | 25 KB+ | ~200 B | 24.8 KB+ | 21 KB | 2-3 KB | ~21-22 KB |

The 21 KB maximum fits comfortably with room for UI structures.

### Testing

All existing tests updated to pass `raw_tx_total_length` in INIT APDU.

The Python test harness automatically calculates the correct size, verifying:
- Allocation uses advertised size
- Length validation works correctly
- Transactions parse successfully with exact-sized buffers

---

## References

- **Cardano CDDL specification**: [`doc/conway.cddl`](conway.cddl)
- **Raw format parser**: [`src/transaction/tx_parse.c`](../src/transaction/tx_parse.c)
- **Raw format serializer**: [`tests/application_client/command_builder.py`](../tests/application_client/command_builder.py)
- **Buffer size constant**: [`src/transaction/tx_constants.h`](../src/transaction/tx_constants.h)
- **Transaction overview**: [`doc/tx.md`](tx.md)
