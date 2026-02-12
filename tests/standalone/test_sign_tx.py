# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2025-2026 Vacuumlabs
# SPDX-License-Identifier: Apache-2.0

# Test file for Cardano transaction signing with simple chunked flow

import pytest
from hashlib import blake2b
from ledgered.devices import Device
from ragger.backend import BackendInterface
from ragger.navigator import Navigator, NavInsID
from ragger.navigator.navigation_scenario import NavigateWithScenario
from ragger.error import ExceptionRAPDU

from application_client.status_words import StatusWord
from application_client.command_builder import gather_witness_paths
from application_client.command_sender import CommandSender
from application_client.response_unpacker import unpack_sign_tx_witness_response
from standalone.utils import verify_signature, idTestFunc
from standalone.input_files.signTx import (  # type: ignore
    testsByron,
    testsMary,
    testsShelleyNoCertificates,
    testsShelleyWithCertificates,
    testsConwayWithCertificates,
    testsAllegra,
    testsAlonzoTrezorComparison,
    testsBabbageTrezorComparison,
    testsAlonzo,
    testsBabbage,
    testsConwayWithoutCertificates,
    testsConwayVotingProcedures,
    testsMultidelegation,
    testsCatalystRegistration,
    testsCVoteRegistrationCIP36,
    testsMultisig,
    poolRegistrationOwnerTestCases,
    poolRegistrationOperatorTestCases,
    transactionInitRejectTestCases,
    addressParamsRejectTestCases,
    certificateRejectTestCases,
    certificateStakingRejectTestCases,
    certificateStakePoolRetirementRejectTestCases,
    withdrawalRejectTestCases,
    witnessRejectTestCases,
    singleAccountRejectTestCases,
    collateralOutputRejectTestCases,
    testsInvalidTokenBundleOrdering,
    poolRegistrationOwnerRejectTestCases,
    stakePoolRegistrationPoolIdRejectTestCases,
    stakePoolRegistrationOwnerRejectTestCases,
    invalidCertificates,
    invalidPoolMetadataTestCases,
    invalidRelayTestCases,
    SignTxTestCase,
    TxAuxiliaryDataType,
    ThirdPartyAddressParams,
    TransactionSigningMode
)


def _run_sign_tx_test(device: Device,
                      backend: BackendInterface,
                      navigator: Navigator,
                      scenario_navigator: NavigateWithScenario,
                      testCase: SignTxTestCase,
                      expert_mode: bool) -> None:
    """Helper function to run a single sign_tx test iteration.

    Args:
        device: The Ledger device
        backend: The backend interface
        navigator: The navigator for UI interactions
        scenario_navigator: Scenario-based navigator
        testCase: The test case to run
        expert_mode: Whether expert mode is enabled for this run
    """
    mode_str = "expert" if expert_mode else "non_expert"
    print(f"\n{'='*60}")
    print(f"Running test in {mode_str} mode: {testCase.name}")
    print(f"{'='*60}")

    client = CommandSender(backend)
    tx = testCase.tx

    # Calculate expected transaction hash from the CBOR txBody
    expected_cbor = bytes.fromhex(testCase.txBody)
    expected_hash = blake2b(expected_cbor, digest_size=32).digest()
    print(f"Expected tx hash: {expected_hash.hex()}")

    def review_cvote() -> None:
        # CVote auxiliary data review (if present)
        if testCase.tx.auxiliaryData is not None:
            if testCase.tx.auxiliaryData.type == TxAuxiliaryDataType.CIP36_REGISTRATION:
                test_name = f"{testCase.name}-{mode_str}/cvote_review"
                if testCase.has_aux_warning:
                    scenario_navigator.review_approve_with_warning(test_name=test_name, custom_screen_text="Confirm")
                else:
                    scenario_navigator.review_approve(test_name=test_name, custom_screen_text="Confirm")

    def review_tx() -> None:
        # Main transaction review
        test_name = f"{testCase.name}-{mode_str}/review"
        if testCase.has_warning:
            scenario_navigator.review_approve_with_warning(test_name=test_name, custom_screen_text="Sign transaction")
        else:
            scenario_navigator.review_approve(test_name=test_name, custom_screen_text="Sign transaction")

    witness_paths = gather_witness_paths(tx, testCase.signingMode, testCase.additionalWitnessPaths or [])
    tx_hash = client.sign_tx(
        tx=tx,
        signing_mode=testCase.signingMode,
        additional_witness_paths=testCase.additionalWitnessPaths,
        options=testCase.options,
        on_review=review_tx,
        on_cvote_review=review_cvote
    )
    print(f"Witness paths: {witness_paths}")

    def _is_ordinary_witness_path(witness_path: str) -> bool:
        path_elements = witness_path.replace("'", "").split("/")
        if len(path_elements) < 2:
            return False
        try:
            purpose = int(path_elements[1])
        except ValueError:
            return False
        return purpose in (44, 1852)

    # Step 4: Get witness signatures
    # After user approval, request signatures for all witness paths
    for path_idx, path in enumerate(witness_paths):
        # Determine navigation moves based on path and transaction properties
        # (adapted from Shelley app's _signTx_setWitnesses logic)
        moves = []

        # Parse path to check for unusual paths (non-standard accounts or change addresses)
        path_elements = path.replace("'", "").split("/")
        if len(path_elements) > 1:
            try:
                purpose = int(path_elements[1])
                # Unusual purpose (not 1852 for Shelley) or unusual change address
                if purpose > 1852 or (len(path_elements) > 4 and int(path_elements[4]) > 2):
                    moves += [NavInsID.BOTH_CLICK] * 2
                elif isinstance(testCase.tx.outputs[0].destination.params, ThirdPartyAddressParams):
                    # Third-party addresses don't need extra moves
                    pass
                elif testCase.signingMode == TransactionSigningMode.PLUTUS_TRANSACTION:
                    moves += [NavInsID.BOTH_CLICK] * 2
                elif testCase.signingMode in (TransactionSigningMode.POOL_REGISTRATION_AS_OWNER,
                                              TransactionSigningMode.POOL_REGISTRATION_AS_OPERATOR):
                    moves += [NavInsID.BOTH_CLICK]
                elif testCase.tx.auxiliaryData is not None and testCase.tx.auxiliaryData.type != TxAuxiliaryDataType.CIP36_REGISTRATION:
                    # Other auxiliary data (not CIP36/Catalyst) may need extra moves
                    # CIP36 witnesses with reasonable paths use POLICY_HIDE in non-expert mode
                    moves += [NavInsID.BOTH_CLICK] * 3
            except (ValueError, IndexError):
                # If path parsing fails, use no extra moves
                pass

        # Pool registration witnesses (owner/operator) always need confirmation.
        pool_or_plutus_modes = (
            TransactionSigningMode.POOL_REGISTRATION_AS_OWNER,
            TransactionSigningMode.POOL_REGISTRATION_AS_OPERATOR,
            TransactionSigningMode.PLUTUS_TRANSACTION,
        )
        should_confirm_witness = (
            testCase.signingMode in pool_or_plutus_modes
            or len(moves) > 0
            or (expert_mode and _is_ordinary_witness_path(path))
        )
        if should_confirm_witness and device.is_nano and len(moves) == 0:
            moves = [NavInsID.BOTH_CLICK]

        # Each witness requires explicit confirmation on the device
        with client.sign_tx_witness_async(path):
            if should_confirm_witness:
                test_name = f"{testCase.name}-{mode_str}/witness_{path_idx}"
                scenario_navigator.address_review_approve(test_name=test_name)
            else:
                pass

        response = client.get_async_response()
        assert response is not None, f"No response for witness {path_idx}: {path}"
        assert response.status == StatusWord.SWO_SUCCESS, f"Witness failed for {path}: {hex(response.status)}"

        signature = unpack_sign_tx_witness_response(response.data)
        print(f"Witness signature for {path} ({len(signature)} bytes): {signature.hex()}")
        verify_signature(path, signature, tx_hash)


@pytest.mark.parametrize(
    "expert_mode",
    [False, True],
    ids=["non_expert", "expert"]
)
@pytest.mark.parametrize(
    "testCase",
    testsByron + testsMary + testsShelleyNoCertificates + testsShelleyWithCertificates +
    testsAllegra + testsAlonzoTrezorComparison + testsBabbageTrezorComparison +
    testsAlonzo + testsBabbage + testsConwayWithCertificates +
    testsConwayWithoutCertificates + testsConwayVotingProcedures +
    testsMultidelegation + testsCatalystRegistration + testsCVoteRegistrationCIP36 +
    testsMultisig + poolRegistrationOwnerTestCases + poolRegistrationOperatorTestCases,
    ids=idTestFunc
)
def test_sign_tx(device: Device,
                 backend: BackendInterface,
                 navigator: Navigator,
                 scenario_navigator: NavigateWithScenario,
                 testCase: SignTxTestCase,
                 expert_mode: bool) -> None:
    """Test transaction signing under a specific expert mode setting.

    NOTE: This test assumes a DEBUG build because it uses the debug settings APDU.
    For production builds, drop the debug APDU call and run only the standard UI flow.

    Each run performs:
    1. Set expert mode via debug APDU (only works with DEBUG builds)
    2. Send init APDU with transaction description
    3. Send transaction data in unpacked format
    4. User approves transaction
    5. Request witness signature
    """

    client = CommandSender(backend)
    client.set_debug_settings(expert_mode=expert_mode, silent_export=False)

    if testCase.name == "Sign_tx_with_all_certificates_except_pool_registration":
        pytest.skip("Skipped: out of memory")

    if testCase.name == "Sign_tx_with_CIP36_registration_with_many_delegations_streaming":
        pytest.skip("Skipped: failing navigation even on Stax")

    if device.is_nano and (testCase.has_warning or testCase.has_aux_warning):
        pytest.skip("Skipped: failing warning navigation for Nano")

    try:
        _run_sign_tx_test(device, backend, navigator, scenario_navigator, testCase, expert_mode=expert_mode)
    except Exception as e:
        mode_label = "EXPERT MODE" if expert_mode else "NON-EXPERT MODE"
        raise AssertionError(f"Test FAILED in {mode_label}: {testCase.name}") from e


# Collect all deny test cases
all_deny_test_cases = (
    transactionInitRejectTestCases +
    addressParamsRejectTestCases +
    certificateRejectTestCases +
    certificateStakingRejectTestCases +
    certificateStakePoolRetirementRejectTestCases +
    withdrawalRejectTestCases +
    witnessRejectTestCases +
    singleAccountRejectTestCases +
    collateralOutputRejectTestCases +
    testsInvalidTokenBundleOrdering +
    poolRegistrationOwnerRejectTestCases +
    stakePoolRegistrationPoolIdRejectTestCases +
    stakePoolRegistrationOwnerRejectTestCases +
    invalidCertificates +
    invalidPoolMetadataTestCases +
    invalidRelayTestCases
)


@pytest.mark.parametrize(
    "testCase",
    all_deny_test_cases,
    ids=idTestFunc
)
def test_sign_tx_deny(backend: BackendInterface,
                        scenario_navigator: NavigateWithScenario,
                        testCase: SignTxTestCase) -> None:
    """Test that invalid transaction parameters are correctly rejected"""

    if testCase.unsuitable_in_ragger_reason is not None:
        pytest.skip(f"Unsuitable in ragger: {testCase.unsuitable_in_ragger_reason}")

    client = CommandSender(backend)

    def _requires_warning_navigation() -> bool:
        if testCase.has_warning:
            return True

        if testCase.signingMode == TransactionSigningMode.PLUTUS_TRANSACTION:
            return True

        for certificate in testCase.tx.certificates:
            cert_params = getattr(certificate, "params", None)
            if cert_params is None:
                continue
            if hasattr(cert_params, "poolOwners") and len(cert_params.poolOwners) == 0:
                return True
            if hasattr(cert_params, "relays") and len(cert_params.relays) == 0:
                return True
        return False

    def review_tx() -> None:
        if testCase.deny_before_review:
            return

        if _requires_warning_navigation():
            scenario_navigator.review_approve_with_warning(
                test_name=f"{testCase.name}-deny/review",
                do_comparison=False,
            )
        else:
            scenario_navigator.review_approve(
                test_name=f"{testCase.name}-deny/review",
                do_comparison=False,
            )

    # Phase 1: try to observe expected failure during init/chunk/review.
    try:
        client.sign_tx(
            tx=testCase.tx,
            signing_mode=testCase.signingMode,
            additional_witness_paths=testCase.additionalWitnessPaths,
            options=testCase.options,
            on_review=review_tx,
        )
    except ExceptionRAPDU as err:
        assert err.status == testCase.expected_sw
        return

    # Phase 2: tx body passed; expected denial must happen in witness phase.
    witness_paths = gather_witness_paths(
        testCase.tx,
        testCase.signingMode,
        testCase.additionalWitnessPaths or [],
    )
    if len(witness_paths) == 0:
        raise AssertionError("Transaction unexpectedly succeeded but no witness paths were found")

    witness_paths_to_try = (
        [testCase.additionalWitnessPaths[-1]]
        if len(testCase.additionalWitnessPaths) > 0
        else list(reversed(witness_paths))
    )

    deny_observed = False
    for witness_path in witness_paths_to_try:
        try:
            client.sign_tx_witness(witness_path)
        except ExceptionRAPDU as err:
            if err.status == testCase.expected_sw:
                deny_observed = True
                break
            raise

        # Witness succeeded, continue searching for the deny-driving path.
        # Successful witnesses here are expected to be POLICY_HIDE paths.
        continue

    assert deny_observed, "Expected witness-level DENY was not observed"
