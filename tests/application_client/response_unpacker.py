from typing import Tuple
from struct import unpack

# Unpack from response:
# response = app_name (var)
def unpack_get_app_name_response(response: bytes) -> str:
    return response.decode("ascii")

# Unpack from response:
# response = MAJOR (1)
#            MINOR (1)
#            PATCH (1)
def unpack_get_version_response(response: bytes) -> Tuple[int, int, int]:
    assert len(response) == 3
    major, minor, patch = unpack("BBB", response)
    return (major, minor, patch)

# Unpack from response:
# response = serial (7)
def unpack_get_serial_response(response: bytes) -> bytes:
    SERIAL_LENGTH = 7
    assert len(response) == SERIAL_LENGTH
    return response

# Unpack from response:
# response = pub_key (32)
#            chain_code (32)
def unpack_get_pubkey_response(response: bytes) -> Tuple[bytes, bytes]:
    PUBLIC_KEY_LENGTH = 32
    CHAIN_CODE_LENGTH = 32
    assert len(response) == PUBLIC_KEY_LENGTH + CHAIN_CODE_LENGTH
    public_key = response[:PUBLIC_KEY_LENGTH]
    chain_code = response[PUBLIC_KEY_LENGTH:]
    return public_key, chain_code

# Unpack from response:
# response = signature (64)
def unpack_sign_opcert_response(response: bytes) -> bytes:
    SIGNATURE_LENGTH = 64
    assert len(response) == SIGNATURE_LENGTH
    return response

# Unpack from response:
# response = signature (64)
def unpack_sign_tx_witness_response(response: bytes) -> bytes:
    SIGNATURE_LENGTH = 64
    assert len(response) == SIGNATURE_LENGTH
    return response

# Unpack from response:
# response = tx_hash (32)
def unpack_sign_tx_hash_response(response: bytes) -> bytes:
    TX_HASH_LENGTH = 32
    assert len(response) == TX_HASH_LENGTH
    return response

# Unpack from response:
# response = address (var)
def unpack_derive_address_response(response: bytes) -> bytes:
    return response

# Unpack from response:
# response = script_hash (28)
def unpack_derive_native_script_hash_response(response: bytes) -> bytes:
    SCRIPT_HASH_LENGTH = 28
    assert len(response) == SCRIPT_HASH_LENGTH
    return response

# Unpack from response:
# response = signature (64)
def unpack_sign_message_response(response: bytes) -> bytes:
    SIGNATURE_LENGTH = 64
    assert len(response) == SIGNATURE_LENGTH
    return response

# Unpack from response:
# response = votecast_hash (32) + signature (64)
def unpack_sign_cip36_confirm_response(response: bytes) -> tuple[bytes, bytes]:
    HASH_LENGTH = 32
    SIGNATURE_LENGTH = 64
    assert len(response) == HASH_LENGTH + SIGNATURE_LENGTH
    votecast_hash = response[:HASH_LENGTH]
    signature = response[HASH_LENGTH:]
    return votecast_hash, signature
