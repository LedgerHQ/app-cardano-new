/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#pragma once

#include "buffer.h"
#include "tx.h"
#include "tx_parse.h"

/**
 * Parse CERTIFICATE_STAKE_REGISTRATION or CERTIFICATE_STAKE_DEREGISTRATION (Shelley era)
 *
 * Format:
 * - certificate_type (1 byte): 0 or 1
 * - stake_credential (variable): type + data
 *
 * @param[in]  buf      Buffer with serialized certificate
 * @param[in]  cert_type Either CERTIFICATE_STAKE_REGISTRATION or CERTIFICATE_STAKE_DEREGISTRATION
 * @param[out] cert_data Parsed certificate data
 *
 * @return 0 on success, SWO_TX_PARSING_FAIL_CERTIFICATES on failure
 */
bool parse_certificate_stake_registration_deregistration(
    buffer_t *buf,
    certificate_type_t cert_type,
    certificate_data_t *cert_data);

/**
 * Parse CERTIFICATE_STAKE_DELEGATION
 *
 * Format:
 * - certificate_type (1 byte): 2
 * - stake_credential (variable): type + data
 * - pool_key_hash (28 bytes)
 *
 * @param[in]  buf      Buffer with serialized certificate
 * @param[out] cert_data Parsed certificate data
 *
 * @return 0 on success, SWO_TX_PARSING_FAIL_CERTIFICATES on failure
 */
bool parse_certificate_stake_delegation(buffer_t *buf,
                                                  certificate_data_t *cert_data);

/**
 * Parse CERTIFICATE_STAKE_REGISTRATION_CONWAY or CERTIFICATE_STAKE_DEREGISTRATION_CONWAY
 *
 * Format:
 * - certificate_type (1 byte): 7 or 8
 * - stake_credential (variable): type + data
 * - deposit (8 bytes): deposit amount in lovelace
 *
 * @param[in]  buf       Buffer with serialized certificate
 * @param[in]  cert_type Either CERTIFICATE_STAKE_REGISTRATION_CONWAY or CERTIFICATE_STAKE_DEREGISTRATION_CONWAY
 * @param[out] cert_data  Parsed certificate data
 *
 * @return 0 on success, SWO_TX_PARSING_FAIL_CERTIFICATES on failure
 */
bool parse_certificate_stake_registration_deregistration_conway(
    buffer_t *buf,
    certificate_type_t cert_type,
    certificate_data_t *cert_data);

/**
 * Parse CERTIFICATE_STAKE_POOL_RETIREMENT
 *
 * Format:
 * - certificate_type (1 byte): 4
 * - pool_key_path (variable): BIP44 derivation path
 * - retirement_epoch (8 bytes): epoch number
 *
 * @param[in]  buf      Buffer with serialized certificate
 * @param[out] cert_data Parsed certificate data
 *
 * @return 0 on success, SWO_TX_PARSING_FAIL_CERTIFICATES on failure
 */
bool parse_certificate_stake_pool_retirement(buffer_t *buf,
                                                       certificate_data_t *cert_data);

/**
 * Parse CERTIFICATE_VOTE_DELEGATION
 *
 * Format:
 * - certificate_type (1 byte): 9
 * - stake_credential (variable): type + data
 * - drep (variable): DRep specification (key hash, key path, script hash, abstain, or no confidence)
 *
 * @param[in]  buf      Buffer with serialized certificate
 * @param[out] cert_data Parsed certificate data
 *
 * @return 0 on success, SWO_TX_PARSING_FAIL_CERTIFICATES on failure
 */
bool parse_certificate_vote_delegation(buffer_t *buf,
                                                 certificate_data_t *cert_data);

/**
 * Parse CERTIFICATE_STAKE_POOL_AND_DREP_DELEGATION
 *
 * Format:
 * - certificate_type (1 byte): 10
 * - stake_credential (variable): type + data
 * - pool_key_hash (28 bytes)
 * - drep (variable): DRep specification
 */
bool parse_certificate_stake_pool_and_drep_delegation(buffer_t *buf,
                                                                 certificate_data_t *cert_data);

bool parse_certificate_account_registration_delegation_to_stake_pool(
    buffer_t *buf,
    certificate_data_t *cert_data);

bool parse_certificate_account_registration_delegation_to_drep(
    buffer_t *buf,
    certificate_data_t *cert_data);

bool parse_certificate_account_registration_delegation_to_stake_pool_and_drep(
    buffer_t *buf,
    certificate_data_t *cert_data);

/**
 * Parse CERTIFICATE_AUTHORIZE_COMMITTEE_HOT
 *
 * Format:
 * - certificate_type (1 byte): 14
 * - cold_credential (variable): committee cold key credential
 * - hot_credential (variable): committee hot key credential
 *
 * @param[in]  buf      Buffer with serialized certificate
 * @param[out] cert_data Parsed certificate data
 *
 * @return 0 on success, SWO_TX_PARSING_FAIL_CERTIFICATES on failure
 */
bool parse_certificate_authorize_committee_hot(buffer_t *buf,
                                                         certificate_data_t *cert_data);

/**
 * Parse CERTIFICATE_RESIGN_COMMITTEE_COLD
 *
 * Format:
 * - certificate_type (1 byte): 15
 * - cold_credential (variable): committee cold key credential
 * - anchor (variable): optional anchor (URL + hash)
 *
 * @param[in]  buf      Buffer with serialized certificate
 * @param[out] cert_data Parsed certificate data
 *
 * @return 0 on success, SWO_TX_PARSING_FAIL_CERTIFICATES on failure
 */
bool parse_certificate_resign_committee_cold(buffer_t *buf,
                                                       certificate_data_t *cert_data);

/**
 * Parse CERTIFICATE_DREP_REGISTRATION
 *
 * Format:
 * - certificate_type (1 byte): 16
 * - drep_credential (variable): DRep key credential
 * - deposit (8 bytes): deposit amount
 * - anchor (variable): anchor (URL + hash)
 *
 * @param[in]  buf      Buffer with serialized certificate
 * @param[out] cert_data Parsed certificate data
 *
 * @return 0 on success, SWO_TX_PARSING_FAIL_CERTIFICATES on failure
 */
bool parse_certificate_drep_registration(buffer_t *buf,
                                                   certificate_data_t *cert_data);

/**
 * Parse CERTIFICATE_DREP_DEREGISTRATION
 *
 * Format:
 * - certificate_type (1 byte): 17
 * - drep_credential (variable): DRep key credential
 * - deposit (8 bytes): deposit amount
 *
 * @param[in]  buf      Buffer with serialized certificate
 * @param[out] cert_data Parsed certificate data
 *
 * @return 0 on success, SWO_TX_PARSING_FAIL_CERTIFICATES on failure
 */
bool parse_certificate_drep_deregistration(buffer_t *buf,
                                                     certificate_data_t *cert_data);

/**
 * Parse CERTIFICATE_DREP_UPDATE
 *
 * Format:
 * - certificate_type (1 byte): 18
 * - drep_credential (variable): DRep key credential
 * - anchor (variable): anchor (URL + hash)
 *
 * @param[in]  buf      Buffer with serialized certificate
 * @param[out] cert_data Parsed certificate data
 *
 * @return 0 on success, SWO_TX_PARSING_FAIL_CERTIFICATES on failure
 */
bool parse_certificate_drep_update(buffer_t *buf,
                                             certificate_data_t *cert_data);

/**
 * Parse CERTIFICATE_STAKE_POOL_REGISTRATION
 *
 * Format:
 * - certificate_type (1 byte): 3
 * - pool_id (variable): operator key hash or path
 * - vrf_keyhash (32 bytes): VRF key hash
 * - pledge (8 bytes): pledge amount in lovelace
 * - cost (8 bytes): pool cost in lovelace
 * - margin (variable): unit interval (numerator + denominator)
 * - reward_account (29 bytes): reward account address
 * - has_metadata (1 byte): flag indicating presence of pool metadata
 * - pool_owners (variable): array of owner credentials
 * - relays (variable): array of relay specifications
 * - pool_metadata (variable): metadata URL and hash, only present if has_metadata is set
 *
 * @param[in]  buf      Buffer with serialized certificate
 * @param[out] cert_data Parsed certificate data
 *
 * @return 0 on success, SWO_TX_PARSING_FAIL_CERTIFICATES on failure
 */
bool parse_certificate_stake_pool_registration(buffer_t *buf,
                                                         certificate_data_t *cert_data);

bool parse_pool_relay(buffer_t *buf, pool_relay_t *relay);
bool parse_pool_metadata(buffer_t *buf, pool_metadata_t *out_metadata);

bool parse_certificate(buffer_t *buf, certificate_data_t *out_certificate_data);
