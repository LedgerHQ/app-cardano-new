# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0

from typing import Callable, Generator, List, Optional
from contextlib import contextmanager

from ragger.backend.interface import BackendInterface, RAPDU
from ragger.error import ExceptionRAPDU


from standalone.input_files.signOpCert import OpCertTestCase
from application_client.command_builder import (
    CommandBuilder,
    SETTINGS_DISABLED,
    SETTINGS_ENABLED,
    gather_witness_paths,
    P1Type,
)
from standalone.input_files.derive_address import DeriveAddressTestCase
from standalone.input_files.native_script import NativeScript, NativeScriptHashDisplayFormat
from application_client.status_words import StatusWord
from standalone.input_files.signTx import Transaction, TxAuxiliaryDataCIP36, TxAuxiliaryDataType
from standalone.input_files.cvote import CVoteTestCase


class CommandSender:
    def __init__(self, backend: BackendInterface) -> None:
        self.backend = backend
        self._cmd_builder = CommandBuilder()

    def _exchange(self, payload: bytes) -> RAPDU:
        """Synchronous APDU exchange with response

        Args:
            payload (bytes): APDU data to send

        Returns:
            Response APDU
        """

        return self.backend.exchange_raw(payload)


    @contextmanager
    def _exchange_async(self, payload: bytes) -> Generator[bool, None, None]:
        """Asynchronous APDU exchange with response

        Args:
            payload (bytes): APDU data to send

        Returns:
            Generator
        """

        with self.backend.exchange_async_raw(payload) as has_data_available:
            yield has_data_available


    def get_async_response(self) -> Optional[RAPDU]:
        """Asynchronous APDU response

        Returns:
            Response APDU
        """

        return self.backend.last_async_response


    def get_version(self) -> RAPDU:
        return self._exchange(self._cmd_builder.get_version())

    def get_app_name(self) -> RAPDU:
        return self._exchange(self._cmd_builder.get_app_name())

    def get_serial(self) -> RAPDU:
        return self._exchange(self._cmd_builder.get_serial())

    @contextmanager
    def get_pubkey_async(self, path: str) -> Generator[None, None, None]:
        with self._exchange_async(self._cmd_builder.get_pubkey_path(path)):
            yield


    @contextmanager
    def sign_opcert_async(self, test_case: OpCertTestCase) -> Generator[None, None, None]:
        """APDU Sign Operational Certificate

        Args:
            test_case (OpCertTestCase): Test parameters

        Returns:
            Generator
        """

        with self._exchange_async(self._cmd_builder.sign_opcert(test_case)):
            yield


    @contextmanager
    def sign_tx_witness_async(self, path: str) -> Generator[bool, None, None]:
        """APDU Sign TX Witness

        Args:
            path (str): BIP44 derivation path

        Returns:
            Generator
        """

        with self._exchange_async(self._cmd_builder.sign_tx_witness(path)) as has_data_available:
            yield has_data_available

    def sign_tx(self,
                tx: Transaction,
                signing_mode: int,
                additional_witness_paths: Optional[List[str]] = None,
                options: int = 0,
                on_review: Optional[Callable[[], None]] = None,
                on_cvote_review: Optional[Callable[[], None]] = None,
                on_advance: Optional[Callable[[int], None]] = None) -> bytes:
        """Sign a transaction and return the transaction hash bytes.

        This builds the init APDU from the transaction body, sends the raw chunks,
        and waits for the final response after the user approves the transaction.
        """
        extra_paths = additional_witness_paths or []
        witness_paths = gather_witness_paths(tx, signing_mode, extra_paths)

        init_params = self._cmd_builder.build_tx_init_params(
            tx=tx,
            signing_mode=signing_mode,
            witness_paths=witness_paths,
            options=options,
        )
        response = self._exchange(self._cmd_builder.sign_tx_init(init_params))
        if response.status != StatusWord.SWO_SUCCESS:
            raise AssertionError(f"Init failed: {hex(response.status)}")

        self._send_tx_aux_data_if_present(tx, on_cvote_review, on_advance)

        with self.sign_tx_send_chunks_async(tx) as has_data_available:
            if on_review is not None and not has_data_available:
                on_review()

        response = self.get_async_response()
        if response is None:
            raise AssertionError("No response from final chunk")
        if response.status != StatusWord.SWO_SUCCESS:
            raise AssertionError(f"Transaction failed: {hex(response.status)}")

        return response.data

    def _send_tx_aux_data_if_present(self,
                                     tx: Transaction,
                                     on_review: Optional[Callable[[], None]] = None,
                                     on_advance: Optional[Callable[[int], None]] = None) -> None:
        if tx.auxiliaryData is None:
            return
        if tx.auxiliaryData.type != TxAuxiliaryDataType.CIP36_REGISTRATION:
            return

        aux_params = tx.auxiliaryData.params
        if not isinstance(aux_params, TxAuxiliaryDataCIP36):
            raise AssertionError("Unexpected auxiliary data params type")

        has_delegations = len(aux_params.delegations) > 0

        if has_delegations:
            if on_advance:
                with self._exchange_async(self._cmd_builder.sign_tx_aux_data_init(tx, aux_params)):
                    on_advance(2)
                response = self.get_async_response()
                if response is None:
                    raise AssertionError("No response from AUX_DATA init")
            else:
                response = self._exchange(self._cmd_builder.sign_tx_aux_data_init(tx, aux_params))
            if response.status != StatusWord.SWO_SUCCESS:
                raise AssertionError(f"AUX_DATA init failed: {hex(response.status)}")

            for delegation in aux_params.delegations[:-1]:
                if on_advance:
                    with self._exchange_async(self._cmd_builder.sign_tx_aux_data_delegation(delegation)):
                        on_advance(1)
                    response = self.get_async_response()
                    if response is None:
                        raise AssertionError("No response from AUX_DATA delegation")
                else:
                    response = self._exchange(self._cmd_builder.sign_tx_aux_data_delegation(delegation))
                if response.status != StatusWord.SWO_SUCCESS:
                    raise AssertionError(f"AUX_DATA registration failed: {hex(response.status)}")

            last_delegation = aux_params.delegations[-1]
            with self._exchange_async(self._cmd_builder.sign_tx_aux_data_delegation(last_delegation)):
                if on_review:
                    on_review()

            response = self.get_async_response()
            if response is None:
                raise AssertionError("No response from last delegation")
            if response.status != StatusWord.SWO_SUCCESS:
                raise AssertionError(f"AUX_DATA registration failed: {hex(response.status)}")
        else:
            with self._exchange_async(self._cmd_builder.sign_tx_aux_data_init(tx, aux_params)):
                if on_review:
                    on_review()

            response = self.get_async_response()
            if response is None:
                raise AssertionError("No response from AUX_DATA init")
            if response.status != StatusWord.SWO_SUCCESS:
                raise AssertionError(f"AUX_DATA init failed: {hex(response.status)}")

    @contextmanager
    def sign_tx_send_chunks_async(self, tx) -> Generator[bool, None, None]:
        """Serialize transaction into chunks and send them.

        Sends all intermediate chunks synchronously, then the final chunk asynchronously
        for UI navigation.

        Args:
            tx: Transaction object from signTx.py

        Returns:
            Generator (use with 'with' statement for navigation)
        """
        chunks = self._cmd_builder.serialize_transaction_chunks(tx)

        # Send all intermediate chunks synchronously
        for chunk in chunks[:-1]:
            response = self._exchange(chunk)
            if response.status != StatusWord.SWO_SUCCESS:
                raise AssertionError(f"Intermediate chunk failed: {hex(response.status)}")

        # Send final chunk asynchronously (for UI navigation)
        with self._exchange_async(chunks[-1]) as has_data_available:
            yield has_data_available

    def sign_tx_witness(self, path: str) -> RAPDU:
        """APDU Sign TX Witness (synchronous)

        Args:
            path (str): BIP44 derivation path for witness

        Returns:
            Response APDU with signature
        """
        return self._exchange(self._cmd_builder.sign_tx_witness(path))


    def set_debug_settings(self, expert_mode: bool, silent_export: bool) -> RAPDU:
        """Set app settings via debug APDU (only works with DEBUG builds).

        This is a debug-only command that allows tests to programmatically set
        app settings without UI navigation. It only works when the app is built
        with DEBUG=1 flag.

        Args:
            expert_mode: True to enable expert mode, False to disable
            silent_export: True to enable silent pubkey export, False to disable

        Returns:
            Response APDU with current settings as confirmation (2 bytes)

        Raises:
            AssertionError: If the command fails or returns unexpected status
        """
        response = self.try_set_debug_settings(expert_mode, silent_export)

        if response.status != StatusWord.SWO_SUCCESS:
            raise AssertionError(f"Debug set settings failed: {hex(response.status)}")

        # Verify response contains 2 bytes (current settings)
        if len(response.data) != 2:
            raise AssertionError(f"Expected 2 bytes in response, got {len(response.data)}")

        # Verify settings were applied correctly
        actual_expert = response.data[0]
        actual_silent = response.data[1]
        expected_expert = SETTINGS_ENABLED if expert_mode else SETTINGS_DISABLED
        expected_silent = SETTINGS_ENABLED if silent_export else SETTINGS_DISABLED

        if actual_expert != expected_expert or actual_silent != expected_silent:
            raise AssertionError(
                f"Settings mismatch: expected expert={expected_expert}, silent={expected_silent}, "
                f"got expert={actual_expert}, silent={actual_silent}"
            )

        return response

    def try_set_debug_settings(self, expert_mode: bool, silent_export: bool) -> RAPDU:
        """Send the debug settings APDU and return the raw response."""
        try:
            return self._exchange(self._cmd_builder.debug_set_settings(expert_mode, silent_export))
        except ExceptionRAPDU as err:
            return RAPDU(data=err.data, status=err.status)

    @contextmanager
    def derive_address_async(self, p1: P1Type, test_case: DeriveAddressTestCase) -> Generator[None, None, None]:
        """APDU Derive Address

        Args:
            p1 (P1Type): APDU Parameter 1
            test_case (DeriveAddressTestCase): Test parameters

        Returns:
            Generator
        """

        with self._exchange_async(self._cmd_builder.derive_address(p1, test_case)):
            yield

    def derive_address(self, p1: P1Type, test_case: DeriveAddressTestCase) -> RAPDU:
        """APDU Derive Address

        Args:
            p1 (P1Type): APDU Parameter 1
            test_case (DeriveAddressTestCase): Test parameters

        Returns:
            Response APDU
        """

        return self._exchange(self._cmd_builder.derive_address(p1, test_case))

    @contextmanager
    def derive_script_add_simple_async(self, script: NativeScript) -> Generator[None, None, None]:
        """APDU NATIVE SCRIPT HASH - SIMPLE SCRIPT step

        Args:
            script (NativeScript): Input Test param

        Returns:
            Generator
        """

        with self._exchange_async(self._cmd_builder.derive_script_add_simple(script)):
            yield

    @contextmanager
    def derive_script_init_async(self) -> Generator[None, None, None]:
        """APDU NATIVE SCRIPT HASH - INIT step"""
        with self._exchange_async(self._cmd_builder.derive_script_init()):
            yield


    @contextmanager
    def derive_script_add_complex_async(self, script: NativeScript) -> Generator[None, None, None]:
        """APDU NATIVE SCRIPT HASH - COMPLEX SCRIPT step

        Args:
            script (NativeScript): Input Test param

        Returns:
            Generator
        """

        with self._exchange_async(self._cmd_builder.derive_script_add_complex(script)):
            yield


    @contextmanager
    def derive_script_finish_async(self, display_format: NativeScriptHashDisplayFormat) -> Generator[None, None, None]:
        """APDU NATIVE SCRIPT HASH - FINISH step

        Args:
            display_format (NativeScriptHashDisplayFormat): Input Test param

        Returns:
            Generator
        """

        with self._exchange_async(self._cmd_builder.derive_script_finish(display_format)):
            yield

    @contextmanager
    def sign_cip36_init_async(self, testCase: CVoteTestCase) -> Generator[None, None, None]:
        """APDU CIP36 Vote - CHUNK step

        Args:
            testCase (CVoteTestCase): Test parameters

        Returns:
            Generator
        """

        with self._exchange_async(self._cmd_builder.sign_cvote_init(testCase)):
            yield


    def sign_cip36_chunk(self, testCase: CVoteTestCase) -> RAPDU:
        """APDU CIP36 Vote - INIT step

        Args:
            testCase (CVoteTestCase): Test parameters

        Returns:
            Response APDU
        """

        chunks = self._cmd_builder.sign_cvote_chunk(testCase)
        for chunk in chunks[:-1]:
            resp = self._exchange(chunk)
            assert resp.status == StatusWord.SWO_SUCCESS
        return self._exchange(chunks[-1])


    @contextmanager
    def sign_cip36_confirm_async(self, testCase: CVoteTestCase) -> Generator[None, None, None]:
        """APDU CIP36 Vote - CONFIRM step

        Args:
            testCase (CVoteTestCase): Test parameters

        Returns:
            Generator
        """

        with self._exchange_async(self._cmd_builder.sign_cvote_confirm(testCase)):
            yield

    @contextmanager
    def sign_msg_init_async(self, testCase) -> Generator[None, None, None]:
        """APDU Sign Message - INIT step

        Args:
            testCase: SignMsgTestCase with message data

        Returns:
            Generator
        """
        with self._exchange_async(self._cmd_builder.sign_msg_init(testCase)):
            yield

    def sign_msg(self,
                 testCase,
                 on_review: Optional[Callable[[], None]] = None) -> bytes:
        """Sign a message, returning the composite response

        Args:
            testCase: SignMsgTestCase data
            on_review: Optional callback invoked while waiting for user confirmation

        Returns:
            Raw response bytes (signature + pubkey + address field)
        """
        response = self._exchange(self._cmd_builder.sign_msg_init(testCase))
        if response.status != StatusWord.SWO_SUCCESS:
            raise AssertionError(f"Init failed: {hex(response.status)}")

        chunk_apdus = self._cmd_builder.sign_msg_chunks(testCase)
        for chunk_apdu in chunk_apdus:
            response = self._exchange(chunk_apdu)
            if response.status != StatusWord.SWO_SUCCESS:
                raise AssertionError(f"Chunk failed: {hex(response.status)}")

        with self.sign_msg_confirm_async():
            if on_review is not None:
                on_review()

        response = self.get_async_response()
        if response is None:
            raise AssertionError("No response from confirm")
        if response.status != StatusWord.SWO_SUCCESS:
            raise AssertionError(f"Confirm failed: {hex(response.status)}")
        return response.data

    @contextmanager
    def sign_msg_confirm_async(self) -> Generator[None, None, None]:
        """APDU Sign Message - CONFIRM step

        Returns:
            Generator
        """
        with self._exchange_async(self._cmd_builder.sign_msg_confirm()):
            yield
