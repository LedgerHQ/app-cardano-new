# Test Fixture Conversion (LedgerJS -> Ragger Static Fixtures)

> **Historical reference only.** This documents a one-time migration that has already been
> completed. The scripts below are not maintained and may not work without adaptation.

This document captures the one-time conversion flow used to migrate LedgerJS reject fixtures
into static ragger fixtures inside `tests/standalone/input_files/signTx.py`.

Goal: keep `signTx.py` as static data only (no loader logic), while preserving the full
set of reject fixtures previously exported from LedgerJS.

## 1) Export reject fixtures from LedgerJS

Two helper scripts are required for the export: a USB stub to keep LedgerJS happy
and the actual exporter that walks LedgerJS fixtures. Since they are no longer committed,
copy them from this document before running the command.

### 1.1 Create the mock USB loader

Save `tests/unit/mock_usb_loader.js` with the following contents:

```javascript
const Module = require('module')

const originalLoad = Module._load

Module._load = function (request, parent, isMain) {
  if (request === 'usb') {
    const usbStub = {
      Device: function () {},
      getDeviceList: () => [],
    }
    usbStub.Device.prototype = {}
    usbStub.Device.prototype.constructor = usbStub.Device
    usbStub.on = () => {}
    usbStub.removeListener = () => {}
    return usbStub
  }
  return originalLoad.apply(this, arguments)
}
```

This stub prevents LedgerJS from trying to talk to a real Ledger device during the export.

### 1.2 Create the exporter

Save `tests/unit/export_sign_tx_rejects.js` with this script (adapted from LedgerJS):

```javascript
#!/usr/bin/env node

"use strict"

require("ts-node/register")

const path = require("path")

const {
  transactionInitDenyTestCases,
  addressParamsDenyTestCases,
  certificateDenyTestCases,
  certificateStakingDenyTestCases,
  certificateStakePoolRetirementDenyTestCases,
  withdrawalDenyTestCases,
  witnessDenyTestCases,
  singleAccountDenyTestCases,
  collateralOutputDenyTestCases,
  testsInvalidTokenBundleOrdering,
  outputDenyTestCases,
  testsCVoteRegistrationDenies,
} = require(
  path.resolve(__dirname, "../../ledgerjs-cardano-shelley/test/integration/__fixtures__/signTxRejects.ts"),
)

const {
  poolRegistrationOwnerDenyTestCases,
  stakePoolRegistrationOwnerDenyTestCases,
  stakePoolRegistrationPoolIdDenyTestCases,
  invalidCertificates,
  invalidPoolMetadataTestCases,
  invalidRelayTestCases,
} = require(
  path.resolve(
    __dirname,
    "../../ledgerjs-cardano-shelley/test/integration/__fixtures__/signTxPoolRegistrationRejects.ts",
  ),
)

const {InvalidDataReason} = require(
  path.resolve(__dirname, "../../ledgerjs-cardano-shelley/src/errors/invalidDataReason"),
)

const invalidDataReasonLookup = new Map(
  Object.entries(InvalidDataReason).map(([key, value]) => [value, key]),
)

const normalizeRejectReason = (reason) => {
  if (!reason) {
    return reason
  }
  const entry = invalidDataReasonLookup.get(reason)
  return entry ? `InvalidDataReason.${entry}` : reason
}

const fixtures = {
  transactionInitDenyTestCases,
  addressParamsDenyTestCases,
  certificateDenyTestCases,
  certificateStakingDenyTestCases,
  certificateStakePoolRetirementDenyTestCases,
  withdrawalDenyTestCases,
  witnessDenyTestCases,
  singleAccountDenyTestCases,
  collateralOutputDenyTestCases,
  testsInvalidTokenBundleOrdering,
  poolRegistrationOwnerDenyTestCases,
  stakePoolRegistrationOwnerDenyTestCases,
  stakePoolRegistrationPoolIdDenyTestCases,
  outputDenyTestCases,
  invalidCertificates,
  testsCVoteRegistrationDenies,
  invalidPoolMetadataTestCases: (invalidPoolMetadataTestCases || []).filter((entry) => {
    if (entry.rejectReason !== InvalidDataReason.POOL_REGISTRATION_METADATA_INVALID_URL) {
      return true
    }
    const certificates = entry.tx && entry.tx.certificates
    if (!certificates || certificates.length === 0) {
      return true
    }
    return certificates.every((certificate) => {
      const metadata = certificate && certificate.params && certificate.params.metadata
      if (!metadata) {
        return true
      }
      return metadata.metadataUrl !== undefined
    })
  }),
  invalidRelayTestCases,
}

const normalizedFixtures = {}
for (const [setName, entries] of Object.entries(fixtures)) {
  if (!entries) {
    continue
  }

  normalizedFixtures[setName] = entries.map((entry) => ({
    ...entry,
    rejectReason: normalizeRejectReason(entry.rejectReason),
  }))
}

process.stdout.write(JSON.stringify(normalizedFixtures))
```

### 1.3 Run the exporter

With the scripts in place, run the exporter from the repo root:

```bash
source ~/.nvm/nvm.sh
nvm use 16.20.2 >/dev/null
REPO_ROOT=$(git rev-parse --show-toplevel)
cd $REPO_ROOT/../ledgerjs-cardano-shelley
NODE_OPTIONS=--require=$REPO_ROOT/tests/unit/mock_usb_loader.js \
NODE_PATH=./node_modules \
node $REPO_ROOT/tests/unit/export_sign_tx_rejects.js \
  > $REPO_ROOT/tests/standalone/input_files/signTxRejects.json
```

This produces a JSON payload with all reject test cases.

## 2) Generate a static Python section for `signTx.py`

Create a helper script that imports `signTx.py`, reads the reject lists that were built
from the JSON export, and prints a static section of Python fixtures.

Save the following as `/tmp/gen_rejects_section.py`:

```python
from __future__ import annotations
from pathlib import Path
import importlib.util
import sys
import dataclasses
from enum import Enum
from typing import Any

sign_tx_path = Path("/home/jan/praca/vacuumlabs/cardano/ledger-app-cardano/tests/standalone/input_files/signTx.py")

import subprocess
repo_root = subprocess.check_output(["git", "rev-parse", "--show-toplevel"]).decode().strip()
sign_tx_path = Path(repo_root) / "tests/standalone/input_files/signTx.py"

spec = importlib.util.spec_from_file_location("signTx_module", sign_tx_path)
mod = importlib.util.module_from_spec(spec)
sys.modules["signTx_module"] = mod
spec.loader.exec_module(mod)  # type: ignore

list_names = [
    "transactionInitDenyTestCases",
    "addressParamsDenyTestCases",
    "certificateDenyTestCases",
    "certificateStakingDenyTestCases",
    "certificateStakePoolRetirementDenyTestCases",
    "withdrawalDenyTestCases",
    "witnessDenyTestCases",
    "singleAccountDenyTestCases",
    "collateralOutputDenyTestCases",
    "testsInvalidTokenBundleOrdering",
    "poolRegistrationOwnerDenyTestCases",
    "stakePoolRegistrationPoolIdDenyTestCases",
    "stakePoolRegistrationOwnerDenyTestCases",
    "outputDenyTestCases",
    "testsCVoteRegistrationDenies",
    "invalidCertificates",
    "invalidPoolMetadataTestCases",
    "invalidRelayTestCases",
]


def to_code(value: Any) -> str:
    if isinstance(value, Enum):
        return f"{value.__class__.__name__}.{value.name}"
    if dataclasses.is_dataclass(value):
        cls_name = value.__class__.__name__
        fields = []
        for field in dataclasses.fields(value):
            field_value = getattr(value, field.name)
            fields.append(f"{field.name}={to_code(field_value)}")
        return f"{cls_name}({', '.join(fields)})"
    if isinstance(value, list):
        return f"[{', '.join(to_code(item) for item in value)}]"
    if isinstance(value, tuple):
        inner = ", ".join(to_code(item) for item in value)
        if len(value) == 1:
            inner += ","
        return f"({inner})"
    if isinstance(value, dict):
        items = ", ".join(f"{to_code(k)}: {to_code(v)}" for k, v in value.items())
        return f"{{{items}}}"
    return repr(value)


lines = []
lines.append("# =================")
lines.append("# Rejects signTx")
lines.append("# =================")

for name in list_names:
    items = getattr(mod, name)
    lines.append(f"{name}: List[SignTxTestCase] = [")
    for item in items:
        lines.append(f"    {to_code(item)},")
    lines.append("]")
    lines.append("")

output = "\n".join(lines).rstrip() + "\n"
Path("/tmp/signTx_rejects_section.py").write_text(output, encoding="utf-8")
print("wrote", len(lines), "lines")
```

Run it with the ragger venv and proper `PYTHONPATH`:

```bash
source tests/venv/bin/activate
PYTHONPATH=$(git rev-parse --show-toplevel)/tests \
python3 /tmp/gen_rejects_section.py
```

This writes `/tmp/signTx_rejects_section.py` containing static fixture lists.

## 3) Replace the reject section in `signTx.py`

Replace the reject section in `tests/standalone/input_files/signTx.py` starting at:

```
# =================
# Rejects signTx
# =================
```

with the contents of `/tmp/signTx_rejects_section.py`.

Example script:

```python
from pathlib import Path

import subprocess
repo_root = subprocess.check_output(["git", "rev-parse", "--show-toplevel"]).decode().strip()
sign_tx_path = Path(repo_root) / "tests/standalone/input_files/signTx.py"
section_path = Path("/tmp/signTx_rejects_section.py")

content = sign_tx_path.read_text(encoding="utf-8")
section = section_path.read_text(encoding="utf-8")

marker = "# =================\n# Rejects signTx\n# =================\n"
idx = content.find(marker)
if idx == -1:
    raise SystemExit("Rejects marker not found")

new_content = content[:idx] + section
sign_tx_path.write_text(new_content, encoding="utf-8")
```

## 4) Regenerate unit-test fixtures

```bash
source tests/venv/bin/activate
pushd tests/unit
python3 generators/generate_unit_tests_from_ragger.py deny_tests
popd
```

## 5) Validate

```bash
cd tests/unit
cmake -Bbuild -H. && cmake --build build -j4
CTEST_OUTPUT_ON_FAILURE=1 ctest --test-dir build -R test_sign_tx_deny_tests
```
