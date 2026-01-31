
import sys
import types
from pathlib import Path

UNIT_TESTS_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = UNIT_TESTS_DIR.parent
NODE_VERSION = "16.20.2"


def read_file_safe(file_path: Path) -> str:
    """Read file with proper error handling. Exits immediately on error."""
    if not file_path.exists():
        print(f"ERROR: Input file not found: {file_path}")
        sys.exit(1)

    try:
        return file_path.read_text(encoding='utf-8')
    except PermissionError as exc:
        print(f"ERROR: Permission denied reading {file_path}: {exc}")
        sys.exit(1)
    except UnicodeDecodeError as exc:
        print(f"ERROR: File encoding error in {file_path}: {exc}")
        sys.exit(1)
    except OSError as exc:
        print(f"ERROR: Failed to read file {file_path}: {exc}")
        sys.exit(1)
    except Exception as exc:
        print(f"ERROR: Unexpected error reading {file_path}: {exc}")
        sys.exit(1)


def write_file_safe(file_path: Path, content: str) -> None:
    """Write file with proper error handling. Exits immediately on error."""
    try:
        # Create parent directories if needed
        file_path.parent.mkdir(parents=True, exist_ok=True)
    except Exception as exc:
        print(f"ERROR: Failed to create directory {file_path.parent}: {exc}")
        sys.exit(1)

    try:
        file_path.write_text(content, encoding='utf-8')
    except PermissionError as exc:
        print(f"ERROR: Permission denied writing to {file_path}: {exc}")
        sys.exit(1)
    except OSError as exc:
        print(f"ERROR: Failed to write file {file_path}: {exc}")
        sys.exit(1)
    except Exception as exc:
        print(f"ERROR: Unexpected error writing {file_path}: {exc}")
        sys.exit(1)


def _add_tests_to_sys_path() -> None:
    sys.path.insert(0, str(REPO_ROOT / "tests"))
    sys.path.insert(0, str(REPO_ROOT / "tests" / "application_client"))
    sys.path.insert(0, str(REPO_ROOT / "tests" / "standalone"))

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
ALPHABET_INDEX = {char: index for index, char in enumerate(ALPHABET)}

def _ensure_base58_module() -> None:
    if "base58" in sys.modules:
        return

    def b58encode(data: bytes) -> bytes:
        if not data:
            return b""

        zero_prefix = 0
        for byte in data:
            if byte == 0:
                zero_prefix += 1
            else:
                break
        num = int.from_bytes(data, "big")
        encoded_bytes = bytearray()
        while num > 0:
            num, remainder = divmod(num, 58)
            encoded_bytes.append(ord(ALPHABET[remainder]))
        encoded_bytes.reverse()
        result = bytearray(b"1" * zero_prefix)
        if encoded_bytes:
            result.extend(encoded_bytes)
        elif zero_prefix == 0:
            result.extend(b"1")
        return bytes(result)

    def b58decode(value: bytes | str) -> bytes:
        if isinstance(value, bytes):
            value = value.decode("ascii")
        if value == "":
            return b""
        num = 0
        for char in value:
            num = num * 58 + ALPHABET_INDEX[char]
        decoded = num.to_bytes((num.bit_length() + 7) // 8, "big") if num > 0 else b""
        zero_prefix = len(value) - len(value.lstrip("1"))
        return b"\x00" * zero_prefix + decoded

    module = types.ModuleType("base58")
    module.b58encode = b58encode
    module.b58decode = b58decode
    sys.modules["base58"] = module

