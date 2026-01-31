from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
UNIT_TESTS_DIR = REPO_ROOT / "unit-tests"
FIXTURES_DIR = UNIT_TESTS_DIR
EXPORT_SCRIPT = UNIT_TESTS_DIR / "export_sign_tx_rejects.js"
MOCK_LOADER = UNIT_TESTS_DIR / "mock_usb_loader.js"
LEDGERJS_CARDANO_SHELLEY_DIR = REPO_ROOT.parent / "ledgerjs-cardano-shelley"
