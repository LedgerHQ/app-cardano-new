import pytest

from ragger.error import ExceptionRAPDU
from ragger.backend.interface import BackendInterface

from application_client.command_builder import CLA, InsType, P1Type, P2Type
from application_client.status_words import StatusWord


# Ensure the app returns an error when a bad CLA is used
def test_bad_cla(backend: BackendInterface) -> None:
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(cla=CLA + 1, ins=InsType.INS_GET_VERSION)
    assert e.value.status == StatusWord.SWO_INVALID_CLA


# Ensure the app returns an error when a bad INS is used
def test_bad_ins(backend: BackendInterface) -> None:
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(cla=CLA, ins=0xff)
    assert e.value.status == StatusWord.SWO_INVALID_INS


# Ensure the app returns an error when a bad P1 or P2 is used
def test_wrong_p1p2(backend: BackendInterface) -> None:
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(cla=CLA, ins=InsType.INS_GET_VERSION, p1=P1Type.P1_UNUSED + 1, p2=P2Type.P2_LAST)
    assert e.value.status == StatusWord.SWO_INCORRECT_P1_P2
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(cla=CLA, ins=InsType.INS_GET_VERSION, p1=P1Type.P1_UNUSED, p2=P2Type.P2_MORE)
    assert e.value.status == StatusWord.SWO_INCORRECT_P1_P2
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(cla=CLA, ins=InsType.INS_GET_APP_NAME, p1=P1Type.P1_UNUSED + 1, p2=P2Type.P2_LAST)
    assert e.value.status == StatusWord.SWO_INCORRECT_P1_P2
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(cla=CLA, ins=InsType.INS_GET_APP_NAME, p1=P1Type.P1_UNUSED, p2=P2Type.P2_MORE)
    assert e.value.status == StatusWord.SWO_INCORRECT_P1_P2


# Ensure the app returns an error when a bad data length is used
def test_wrong_data_length(backend: BackendInterface) -> None:
    # APDUs must be at least 4 bytes: CLA, INS, P1, P2Type.
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange_raw(bytes.fromhex("E00300"))
    assert e.value.status == StatusWord.SWO_WRONG_DATA_LENGTH
    # APDUs advertises a too long length
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange_raw(bytes.fromhex("E003000005"))
    assert e.value.status == StatusWord.SWO_WRONG_DATA_LENGTH


# Ensure the app returns an error when instructions are sent in wrong sequence/state
def test_invalid_state(backend: BackendInterface) -> None:
    """Test state machine guards prevent instruction interleaving and invalid sequences."""

    # Test 1: Try to send transaction data chunk (P1_TX_DATA_CHUNK) without initializing (P1_TX_INIT) first
    # This violates the state machine: can only send chunks when req_type == REQUEST_SIGN_TRANSACTION
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(cla=CLA,
                         ins=InsType.INS_SIGN_TX,
                         p1=P1Type.P1_TX_DATA_CHUNK,  # Try to continue without init
                         p2=P2Type.P2_UNUSED,
                         data=b"abcde")
    assert e.value.status == StatusWord.SWO_BAD_STATE

    # Test 2: Try to send final chunk (P1_TX_CHUNK_LAST) without initializing first
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(cla=CLA,
                         ins=InsType.INS_SIGN_TX,
                         p1=P1Type.P1_TX_CHUNK_LAST,
                         p2=P2Type.P2_UNUSED,
                         data=b"")
    assert e.value.status == StatusWord.SWO_BAD_STATE

    # Test 3: Try to sign witness (P1_TX_SIGN_WITNESS) before transaction is approved
    with pytest.raises(ExceptionRAPDU) as e:
        backend.exchange(cla=CLA,
                         ins=InsType.INS_SIGN_TX,
                         p1=P1Type.P1_TX_WITNESSES,
                         p2=P2Type.P2_UNUSED,
                         data=b"")
    assert e.value.status == StatusWord.SWO_BAD_STATE
