/*****************************************************************************
 *   Ledger App Cardano.
 *   (c) 2025 Vacuumlabs
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *****************************************************************************/

#include "buffer.h"
#include "mem.h"
#include "flist.h"

#include "os.h"

#include "cardano_swo.h"
#include "assert.h"
#include "buffer_write.h"
#include "utils.h"
#include "textUtils.h"
#include "ui_formatters.h"
#include "tx_parse_certificates.h"
#include "tx.h"
#include "cardano_parsers.h"

/// Parse a complete stake credential (type + data)
parser_status_e parse_stake_credential(buffer_t *buf, ext_credential_t *credential) {
    TRACE("Parsing stake credential");
    if (!buffer_read_credential(buf, credential)) {
        TRACE("Failed to parse stake credential");
        return CERTIFICATES_PARSING_ERROR;
    }
    TRACE("Successfully parsed stake credential");
    return PARSING_OK;
}

/// Parse CERTIFICATE_STAKE_REGISTRATION or CERTIFICATE_STAKE_DEREGISTRATION
parser_status_e parse_certificate_stake_registration_deregistration(
    buffer_t *buf,
    certificate_type_t cert_type,
    certificate_data_t *cert_data) {
    TRACE("Parsing STAKE_REGISTRATION/DEREGISTRATION certificate, type=%u", cert_type);
    LEDGER_ASSERT(cert_type == CERTIFICATE_STAKE_REGISTRATION ||
                  cert_type == CERTIFICATE_STAKE_DEREGISTRATION,
                  "Invalid certificate type for stake registration/deregistration");

    cert_data->type = cert_type;
    parser_status_e status = parse_stake_credential(buf, &cert_data->stakeCredential);
    if (status != PARSING_OK) {
        TRACE("Failed to parse stake credential");
        return status;
    }
    TRACE("Successfully parsed STAKE_REGISTRATION/DEREGISTRATION");
    return PARSING_OK;
}

/// Parse CERTIFICATE_STAKE_DELEGATION
parser_status_e parse_certificate_stake_delegation(buffer_t *buf,
                                                  certificate_data_t *cert_data) {
    TRACE("Parsing STAKE_DELEGATION certificate");
    cert_data->type = CERTIFICATE_STAKE_DELEGATION;

    parser_status_e status = parse_stake_credential(buf, &cert_data->stakeCredential);
    if (status != PARSING_OK) {
        TRACE("Failed to parse stake credential");
        return status;
    }

    // Store pointer to pool key hash in raw buffer instead of copying
    if (!buffer_read_bytes_ptr(buf, &cert_data->poolKeyHash, POOL_KEY_HASH_LENGTH)) {
        TRACE("Failed to read pool key hash");
        return CERTIFICATES_PARSING_ERROR;
    }
    ASSERT(cert_data->poolKeyHash != NULL);
    TRACE("Successfully parsed STAKE_DELEGATION");
    return PARSING_OK;
}

/// Parse CERTIFICATE_STAKE_REGISTRATION_CONWAY or CERTIFICATE_STAKE_DEREGISTRATION_CONWAY
parser_status_e parse_certificate_stake_registration_deregistration_conway(
    buffer_t *buf,
    certificate_type_t cert_type,
    certificate_data_t *cert_data) {
    TRACE("Parsing STAKE_REGISTRATION/DEREGISTRATION_CONWAY certificate, type=%u", cert_type);
    LEDGER_ASSERT(cert_type == CERTIFICATE_STAKE_REGISTRATION_CONWAY ||
                  cert_type == CERTIFICATE_STAKE_DEREGISTRATION_CONWAY,
                  "Invalid certificate type for Conway stake registration/deregistration");

    cert_data->type = cert_type;

    parser_status_e status = parse_stake_credential(buf, &cert_data->stakeCredential);
    if (status != PARSING_OK) {
        TRACE("Failed to parse stake credential");
        return status;
    }

    ASSERT_TYPE(cert_data->deposit, uint64_t);
    if (!buffer_read_u64(buf, &cert_data->deposit, BE)) {
        TRACE("Failed to parse deposit");
        return CERTIFICATES_PARSING_ERROR;
    }
    TRACE("Successfully parsed STAKE_REGISTRATION/DEREGISTRATION_CONWAY, deposit=");
    TRACE_UINT64(cert_data->deposit);
    return PARSING_OK;
}

/// Parse CERTIFICATE_STAKE_POOL_RETIREMENT
parser_status_e parse_certificate_stake_pool_retirement(buffer_t *buf,
                                                       certificate_data_t *cert_data) {
    TRACE("Parsing STAKE_POOL_RETIREMENT certificate, buf->offset=%u buf->size=%u", buf->offset, buf->size);
    cert_data->type = CERTIFICATE_STAKE_POOL_RETIREMENT;

    TRACE("About to parse pool credential at offset=%u", buf->offset);
    if (!buffer_read_credential(buf, &cert_data->poolCredential)) {
        TRACE("Failed to parse pool credential");
        return CERTIFICATES_PARSING_ERROR;
    }

    ASSERT_TYPE(cert_data->retirementEpoch, uint64_t);
    if (!buffer_read_u64(buf, &cert_data->retirementEpoch, BE)) {
        TRACE("Failed to parse retirement epoch");
        return CERTIFICATES_PARSING_ERROR;
    }
    TRACE("Successfully parsed pool retirement, epoch=");
    TRACE_UINT64(cert_data->retirementEpoch);
    return PARSING_OK;
}

/// Parse CERTIFICATE_VOTE_DELEGATION
parser_status_e parse_certificate_vote_delegation(buffer_t *buf,
                                                 certificate_data_t *cert_data) {
    TRACE("Parsing VOTE_DELEGATION certificate");
    cert_data->type = CERTIFICATE_VOTE_DELEGATION;

    parser_status_e status = parse_stake_credential(buf, &cert_data->stakeCredential);
    if (status != PARSING_OK) {
        TRACE("Failed to parse stake credential");
        return status;
    }

    if (!buffer_read_drep(buf, &cert_data->drep)) {
        TRACE("Failed to parse DRep");
        return CERTIFICATES_PARSING_ERROR;
    }
    TRACE("Successfully parsed VOTE_DELEGATION");
    return PARSING_OK;
}

/// Parse CERTIFICATE_STAKE_POOL_AND_DREP_DELEGATION
parser_status_e parse_certificate_stake_pool_and_drep_delegation(buffer_t *buf,
                                                                 certificate_data_t *cert_data) {
    LEDGER_ASSERT(cert_data != NULL, "NULL certificate data");
    TRACE("Parsing STAKE_POOL_AND_DREP_DELEGATION certificate");
    cert_data->type = CERTIFICATE_STAKE_POOL_AND_DREP_DELEGATION;

    parser_status_e status = parse_stake_credential(buf, &cert_data->stakeCredential);
    if (status != PARSING_OK) {
        TRACE("Failed to parse stake credential");
        return status;
    }

    if (!buffer_read_bytes_ptr(buf, &cert_data->combinedDelegPoolKeyHash, POOL_KEY_HASH_LENGTH)) {
        TRACE("Failed to read pool key hash");
        return CERTIFICATES_PARSING_ERROR;
    }
    ASSERT(cert_data->combinedDelegPoolKeyHash != NULL);

    if (!buffer_read_drep(buf, &cert_data->drep)) {
        TRACE("Failed to parse DRep");
        return CERTIFICATES_PARSING_ERROR;
    }
    TRACE("Successfully parsed STAKE_POOL_AND_DREP_DELEGATION");
    return PARSING_OK;
}

/// Parse CERTIFICATE_ACCOUNT_REGISTRATION_DELEGATION_TO_STAKE_POOL
parser_status_e parse_certificate_account_registration_delegation_to_stake_pool(
    buffer_t *buf,
    certificate_data_t *cert_data) {
    LEDGER_ASSERT(cert_data != NULL, "NULL certificate data");
    TRACE("Parsing ACCOUNT_REGISTRATION_DELEGATION_TO_STAKE_POOL certificate");
    cert_data->type = CERTIFICATE_ACCOUNT_REGISTRATION_DELEGATION_TO_STAKE_POOL;

    parser_status_e status = parse_stake_credential(buf, &cert_data->stakeCredential);
    if (status != PARSING_OK) {
        TRACE("Failed to parse stake credential");
        return status;
    }

    if (!buffer_read_bytes_ptr(buf, &cert_data->combinedDelegPoolKeyHash, POOL_KEY_HASH_LENGTH)) {
        TRACE("Failed to read pool key hash");
        return CERTIFICATES_PARSING_ERROR;
    }
    ASSERT(cert_data->combinedDelegPoolKeyHash != NULL);

    ASSERT_TYPE(cert_data->deposit, uint64_t);
    if (!buffer_read_u64(buf, &cert_data->deposit, BE)) {
        TRACE("Failed to parse deposit");
        return CERTIFICATES_PARSING_ERROR;
    }
    TRACE("Successfully parsed ACCOUNT_REGISTRATION_DELEGATION_TO_STAKE_POOL");
    return PARSING_OK;
}

/// Parse CERTIFICATE_ACCOUNT_REGISTRATION_DELEGATION_TO_DREP
parser_status_e parse_certificate_account_registration_delegation_to_drep(
    buffer_t *buf,
    certificate_data_t *cert_data) {
    LEDGER_ASSERT(cert_data != NULL, "NULL certificate data");
    TRACE("Parsing ACCOUNT_REGISTRATION_DELEGATION_TO_DREP certificate");
    cert_data->type = CERTIFICATE_ACCOUNT_REGISTRATION_DELEGATION_TO_DREP;

    parser_status_e status = parse_stake_credential(buf, &cert_data->stakeCredential);
    if (status != PARSING_OK) {
        TRACE("Failed to parse stake credential");
        return status;
    }

    if (!buffer_read_drep(buf, &cert_data->drep)) {
        TRACE("Failed to parse DRep");
        return CERTIFICATES_PARSING_ERROR;
    }

    ASSERT_TYPE(cert_data->deposit, uint64_t);
    if (!buffer_read_u64(buf, &cert_data->deposit, BE)) {
        TRACE("Failed to parse deposit");
        return CERTIFICATES_PARSING_ERROR;
    }
    TRACE("Successfully parsed ACCOUNT_REGISTRATION_DELEGATION_TO_DREP");
    return PARSING_OK;
}

/// Parse CERTIFICATE_ACCOUNT_REGISTRATION_DELEGATION_TO_STAKE_POOL_AND_DREP
parser_status_e parse_certificate_account_registration_delegation_to_stake_pool_and_drep(
    buffer_t *buf,
    certificate_data_t *cert_data) {
    LEDGER_ASSERT(cert_data != NULL, "NULL certificate data");
    TRACE("Parsing ACCOUNT_REGISTRATION_DELEGATION_TO_STAKE_POOL_AND_DREP certificate");
    cert_data->type = CERTIFICATE_ACCOUNT_REGISTRATION_DELEGATION_TO_STAKE_POOL_AND_DREP;

    parser_status_e status = parse_stake_credential(buf, &cert_data->stakeCredential);
    if (status != PARSING_OK) {
        TRACE("Failed to parse stake credential");
        return status;
    }

    if (!buffer_read_bytes_ptr(buf, &cert_data->combinedDelegPoolKeyHash, POOL_KEY_HASH_LENGTH)) {
        TRACE("Failed to read pool key hash");
        return CERTIFICATES_PARSING_ERROR;
    }
    ASSERT(cert_data->combinedDelegPoolKeyHash != NULL);

    if (!buffer_read_drep(buf, &cert_data->drep)) {
        TRACE("Failed to parse DRep");
        return CERTIFICATES_PARSING_ERROR;
    }

    ASSERT_TYPE(cert_data->deposit, uint64_t);
    if (!buffer_read_u64(buf, &cert_data->deposit, BE)) {
        TRACE("Failed to parse deposit");
        return CERTIFICATES_PARSING_ERROR;
    }
    TRACE("Successfully parsed ACCOUNT_REGISTRATION_DELEGATION_TO_STAKE_POOL_AND_DREP");
    return PARSING_OK;
}

/// Parse CERTIFICATE_AUTHORIZE_COMMITTEE_HOT
parser_status_e parse_certificate_authorize_committee_hot(buffer_t *buf,
                                                         certificate_data_t *cert_data) {
    TRACE("Parsing AUTHORIZE_COMMITTEE_HOT certificate");
    cert_data->type = CERTIFICATE_AUTHORIZE_COMMITTEE_HOT;

    parser_status_e status = parse_stake_credential(buf, &cert_data->coldCredential);
    if (status != PARSING_OK) {
        TRACE("Failed to parse cold credential");
        return status;
    }

    // Second credential is the hot credential
    TRACE("Parsing hot credential");
    if (!buffer_read_credential(buf, &cert_data->hotCredential)) {
        TRACE("Failed to parse hot credential");
        return CERTIFICATES_PARSING_ERROR;
    }
    TRACE("Successfully parsed AUTHORIZE_COMMITTEE_HOT");
    return PARSING_OK;
}

/// Parse CERTIFICATE_RESIGN_COMMITTEE_COLD
parser_status_e parse_certificate_resign_committee_cold(buffer_t *buf,
                                                       certificate_data_t *cert_data) {
    TRACE("Parsing RESIGN_COMMITTEE_COLD certificate");
    cert_data->type = CERTIFICATE_RESIGN_COMMITTEE_COLD;

    parser_status_e status = parse_stake_credential(buf, &cert_data->coldCredential);
    if (status != PARSING_OK) {
        TRACE("Failed to parse cold credential");
        return status;
    }

    if (!buffer_read_anchor(buf, &cert_data->anchor)) {
        TRACE("Failed to parse anchor");
        return CERTIFICATES_PARSING_ERROR;
    }
    TRACE("Successfully parsed RESIGN_COMMITTEE_COLD");
    return PARSING_OK;
}

/// Parse CERTIFICATE_DREP_REGISTRATION
parser_status_e parse_certificate_drep_registration(buffer_t *buf,
                                                   certificate_data_t *cert_data) {
    TRACE("Parsing DREP_REGISTRATION certificate");
    cert_data->type = CERTIFICATE_DREP_REGISTRATION;

    parser_status_e status = parse_stake_credential(buf, &cert_data->dRepCredential);
    if (status != PARSING_OK) {
        TRACE("Failed to parse DRep credential");
        return status;
    }

    ASSERT_TYPE(cert_data->deposit, uint64_t);
    if (!buffer_read_u64(buf, &cert_data->deposit, BE)) {
        TRACE("Failed to parse deposit");
        return CERTIFICATES_PARSING_ERROR;
    }
    TRACE("Deposit: ");
    TRACE_UINT64(cert_data->deposit);

    if (!buffer_read_anchor(buf, &cert_data->anchor)) {
        TRACE("Failed to parse anchor");
        return CERTIFICATES_PARSING_ERROR;
    }
    TRACE("Successfully parsed DREP_REGISTRATION");
    return PARSING_OK;
}

/// Parse CERTIFICATE_DREP_DEREGISTRATION
parser_status_e parse_certificate_drep_deregistration(buffer_t *buf,
                                                     certificate_data_t *cert_data) {
    TRACE("Parsing DREP_DEREGISTRATION certificate");
    cert_data->type = CERTIFICATE_DREP_DEREGISTRATION;

    parser_status_e status = parse_stake_credential(buf, &cert_data->dRepCredential);
    if (status != PARSING_OK) {
        TRACE("Failed to parse DRep credential");
        return status;
    }

    ASSERT_TYPE(cert_data->deposit, uint64_t);
    if (!buffer_read_u64(buf, &cert_data->deposit, BE)) {
        TRACE("Failed to parse deposit");
        return CERTIFICATES_PARSING_ERROR;
    }
    TRACE("Deposit: ");
    TRACE_UINT64(cert_data->deposit);

    TRACE("Successfully parsed DREP_DEREGISTRATION");
    return PARSING_OK;
}

/// Parse CERTIFICATE_DREP_UPDATE
parser_status_e parse_certificate_drep_update(buffer_t *buf,
                                             certificate_data_t *cert_data) {
    TRACE("Parsing DREP_UPDATE certificate");
    cert_data->type = CERTIFICATE_DREP_UPDATE;

    parser_status_e status = parse_stake_credential(buf, &cert_data->dRepCredential);
    if (status != PARSING_OK) {
        TRACE("Failed to parse DRep credential");
        return status;
    }

    if (!buffer_read_anchor(buf, &cert_data->anchor)) {
        TRACE("Failed to parse anchor");
        return CERTIFICATES_PARSING_ERROR;
    }
    TRACE("Successfully parsed DREP_UPDATE");
    return PARSING_OK;
}

/// Helper to parse pool ID (operator key - hash or path)
static parser_status_e _parse_pool_id(buffer_t *buf, pool_id_t *pool_id) {
    TRACE("Parsing pool ID");
    uint8_t pool_id_type_wire;
    if (!buffer_read_u8(buf, &pool_id_type_wire)) {
        TRACE("Failed to read pool ID type byte");
        return CERTIFICATES_PARSING_ERROR;
    }

    TRACE("Pool ID type wire=0x%02x", pool_id_type_wire);
    switch (pool_id_type_wire) {
        case EXT_CREDENTIAL_KEY_HASH:
            pool_id->keyReferenceType = KEY_REFERENCE_HASH;
            if (!buffer_read_bytes_ptr(buf, &pool_id->hash, POOL_KEY_HASH_LENGTH)) {
                TRACE("Failed to read pool key hash");
                return CERTIFICATES_PARSING_ERROR;
            }
            ASSERT(pool_id->hash != NULL);
            TRACE("Successfully parsed pool ID as KEY_HASH");
            break;
        case EXT_CREDENTIAL_KEY_PATH:
            pool_id->keyReferenceType = KEY_REFERENCE_PATH;
            if (!buffer_read_bip44_path(buf, &pool_id->path)) {
                TRACE("Failed to read pool key path");
                return CERTIFICATES_PARSING_ERROR;
            }
            TRACE("Successfully parsed pool ID as KEY_PATH");
            break;
        default:
            TRACE("Invalid pool ID type wire value: 0x%02x", pool_id_type_wire);
            return CERTIFICATES_PARSING_ERROR;
    }
    return PARSING_OK;
}

/// Helper to parse a single pool relay
static parser_status_e _parse_pool_relay(buffer_t *buf, pool_relay_t *relay) {
    TRACE("Parsing pool relay");
    uint8_t relay_type;
    if (!buffer_read_u8(buf, &relay_type)) {
        TRACE("Failed to read relay type");
        return CERTIFICATES_PARSING_ERROR;
    }

    TRACE("Relay type: %u", relay_type);
    switch (relay_type) {
        case RELAY_SINGLE_HOST_IP: {
            // Format: type (0) + port + ipv4 (optional) + ipv6 (optional)
            relay->format = RELAY_SINGLE_HOST_IP;

            // Port (2 bytes) - null or value
            bool port_included = false;
            if (!buffer_read_flag_included(buf, &port_included)) {
                TRACE("Invalid port present flag");
                return CERTIFICATES_PARSING_ERROR;
            }
            relay->port.isNull = !port_included;
            if (port_included) {
                ASSERT_TYPE(relay->port.number, uint16_t);
                if (!buffer_read_u16(buf, &relay->port.number, BE)) {
                    TRACE("Failed to read port number");
                    return CERTIFICATES_PARSING_ERROR;
                }
                TRACE("Relay port: %u", relay->port.number);
            }
            if (relay->port.isNull) {
                TRACE("Relay port missing");
                return CERTIFICATES_PARSING_ERROR;
            }

            // IPv4 (optional)
            bool ipv4_included = false;
            if (!buffer_read_flag_included(buf, &ipv4_included)) {
                TRACE("Invalid IPv4 present flag");
                return CERTIFICATES_PARSING_ERROR;
            }
            relay->ipv4.isNull = !ipv4_included;
            if (ipv4_included) {
                if (!buffer_read_bytes_ptr(buf, &relay->ipv4.ip, IPV4_LENGTH)) {
                    TRACE("Failed to read IPv4 address");
                    return CERTIFICATES_PARSING_ERROR;
                }
                ASSERT(relay->ipv4.ip != NULL);
                TRACE("Relay IPv4 present");
            }

            // IPv6 (optional)
            bool ipv6_included = false;
            if (!buffer_read_flag_included(buf, &ipv6_included)) {
                TRACE("Invalid IPv6 present flag");
                return CERTIFICATES_PARSING_ERROR;
            }
            relay->ipv6.isNull = !ipv6_included;
            if (ipv6_included) {
                if (!buffer_read_bytes_ptr(buf, &relay->ipv6.ip, IPV6_LENGTH)) {
                    TRACE("Failed to read IPv6 address");
                    return CERTIFICATES_PARSING_ERROR;
                }
                ASSERT(relay->ipv6.ip != NULL);
                TRACE("Relay IPv6 present");
            }
            if (relay->ipv4.isNull && relay->ipv6.isNull) {
                TRACE("Relay missing IPv4/IPv6 address");
                return CERTIFICATES_PARSING_ERROR;
            }
            break;
        }
        case RELAY_SINGLE_HOST_NAME: {
            // Format: type (1) + port + dns_name
            relay->format = RELAY_SINGLE_HOST_NAME;

            // Port (2 bytes) - null or value
            bool port_included = false;
            if (!buffer_read_flag_included(buf, &port_included)) {
                TRACE("Invalid port present flag");
                return CERTIFICATES_PARSING_ERROR;
            }
            relay->port.isNull = !port_included;
            if (port_included) {
                ASSERT_TYPE(relay->port.number, uint16_t);
                if (!buffer_read_u16(buf, &relay->port.number, BE)) {
                    TRACE("Failed to read port number");
                    return CERTIFICATES_PARSING_ERROR;
                }
                TRACE("Relay port: %u", relay->port.number);
            }
            if (relay->port.isNull) {
                TRACE("Relay port missing");
                return CERTIFICATES_PARSING_ERROR;
            }

            // DNS name (length + data)
            bool dns_included = false;
            if (!buffer_read_flag_included(buf, &dns_included)) {
                TRACE("Invalid DNS name present flag");
                return CERTIFICATES_PARSING_ERROR;
            }
            if (!dns_included) {
                TRACE("Relay DNS name missing");
                return CERTIFICATES_PARSING_ERROR;
            }
            uint8_t dns_len;
            if (!buffer_read_u8(buf, &dns_len)) {
                TRACE("Failed to read DNS name length");
                return CERTIFICATES_PARSING_ERROR;
            }
            relay->dnsNameSize = dns_len;

            if (dns_len > 0) {
                if (dns_len > MAX_DNS_NAME_LENGTH) {
                    TRACE("DNS name length exceeds maximum: %u > %u", dns_len, MAX_DNS_NAME_LENGTH);
                    return CERTIFICATES_PARSING_ERROR;
                }
                if (!buffer_read_bytes_ptr(buf, &relay->dnsName, dns_len)) {
                    TRACE("Failed to read DNS name");
                    return CERTIFICATES_PARSING_ERROR;
                }
                ASSERT(relay->dnsName != NULL);
            } else {
                relay->dnsName = NULL;
            }
            if (relay->dnsNameSize == 0) {
                TRACE("Relay DNS name missing");
                return CERTIFICATES_PARSING_ERROR;
            }
            if (!str_isUnambiguousAscii(relay->dnsName, relay->dnsNameSize)) {
                TRACE("Relay DNS name contains non-ASCII characters");
                return CERTIFICATES_PARSING_ERROR;
            }
            TRACE("Relay DNS name length: %u", dns_len);
            break;
        }
        case RELAY_MULTIPLE_HOST_NAME: {
            // Format: type (2) + dns_name (single SRV record)
            relay->format = RELAY_MULTIPLE_HOST_NAME;
            relay->port.isNull = true;
            relay->ipv4.isNull = true;
            relay->ipv6.isNull = true;

            // DNS name (length + data)
            bool dns_included = false;
            if (!buffer_read_flag_included(buf, &dns_included)) {
                TRACE("Invalid DNS name present flag");
                return CERTIFICATES_PARSING_ERROR;
            }
            if (!dns_included) {
                TRACE("Relay DNS name missing");
                return CERTIFICATES_PARSING_ERROR;
            }
            uint8_t dns_len;
            if (!buffer_read_u8(buf, &dns_len)) {
                TRACE("Failed to read DNS name length");
                return CERTIFICATES_PARSING_ERROR;
            }
            relay->dnsNameSize = dns_len;

            if (dns_len > 0) {
                if (dns_len > MAX_DNS_NAME_LENGTH) {
                    TRACE("DNS name length exceeds maximum: %u > %u", dns_len, MAX_DNS_NAME_LENGTH);
                    return CERTIFICATES_PARSING_ERROR;
                }
                if (!buffer_read_bytes_ptr(buf, &relay->dnsName, dns_len)) {
                    TRACE("Failed to read DNS name");
                    return CERTIFICATES_PARSING_ERROR;
                }
                ASSERT(relay->dnsName != NULL);
            } else {
                relay->dnsName = NULL;
            }
            if (relay->dnsNameSize == 0) {
                TRACE("Relay DNS name missing");
                return CERTIFICATES_PARSING_ERROR;
            }
            if (!str_isUnambiguousAscii(relay->dnsName, relay->dnsNameSize)) {
                TRACE("Relay DNS name contains non-ASCII characters");
                return CERTIFICATES_PARSING_ERROR;
            }
            TRACE("Relay multi-host DNS name length: %u", dns_len);
            break;
        }
        default:
            TRACE("Invalid relay type: %u", relay_type);
            return CERTIFICATES_PARSING_ERROR;
    }
    TRACE("Successfully parsed pool relay");
    return PARSING_OK;
}

/// Helper to parse pool metadata (URL + hash or null)
static parser_status_e _parse_pool_metadata(buffer_t *buf,
                                            pool_metadata_t *metadata,
                                            bool *isNull) {
    TRACE("Parsing pool metadata");
    anchor_t anchor = {0};
    if (!buffer_read_anchor(buf, &anchor)) {
        TRACE("Failed to parse pool metadata");
        return CERTIFICATES_PARSING_ERROR;
    }

    if (!anchor.isIncluded) {
        *isNull = true;
        TRACE("Pool metadata is null");
        return PARSING_OK;
    }

    *isNull = false;
    metadata->url = anchor.url;
    metadata->urlSize = anchor.urlLength;
    metadata->hash = anchor.hash;
    TRACE("Successfully parsed pool metadata");
    return PARSING_OK;
}

/// Parse CERTIFICATE_STAKE_POOL_REGISTRATION
parser_status_e parse_certificate_stake_pool_registration(buffer_t *buf,
                                                         certificate_data_t *cert_data) {
    TRACE("Parsing STAKE_POOL_REGISTRATION certificate");
    cert_data->type = CERTIFICATE_STAKE_POOL_REGISTRATION;

    // Parse pool ID (operator key - hash or path)
    parser_status_e status = _parse_pool_id(buf, &cert_data->poolId);
    if (status != PARSING_OK) {
        TRACE("Failed to parse pool ID");
        return status;
    }

    // Parse VRF key hash (32 bytes)
    if (!buffer_read_bytes_ptr(buf, &cert_data->vrfKeyHash, VRF_KEY_HASH_LENGTH)) {
        TRACE("Failed to read VRF key hash");
        return CERTIFICATES_PARSING_ERROR;
    }
    TRACE("Successfully parsed VRF key hash");

    // Parse financials
    ASSERT_TYPE(cert_data->poolRegistration.pledge, uint64_t);
    if (!buffer_read_u64(buf, &cert_data->poolRegistration.pledge, BE)) {
        TRACE("Failed to read pledge");
        return CERTIFICATES_PARSING_ERROR;
    }
    TRACE("Pledge: ");
    TRACE_UINT64(cert_data->poolRegistration.pledge);

    ASSERT_TYPE(cert_data->poolRegistration.cost, uint64_t);
    if (!buffer_read_u64(buf, &cert_data->poolRegistration.cost, BE)) {
        TRACE("Failed to read cost");
        return CERTIFICATES_PARSING_ERROR;
    }
    TRACE("Cost: ");
    TRACE_UINT64(cert_data->poolRegistration.cost);

    // Parse margin (unit_interval: numerator + denominator)
    ASSERT_TYPE(cert_data->poolRegistration.marginNumerator, uint64_t);
    if (!buffer_read_u64(buf, &cert_data->poolRegistration.marginNumerator, BE)) {
        TRACE("Failed to read margin numerator");
        return CERTIFICATES_PARSING_ERROR;
    }
    TRACE("Margin numerator: ");
    TRACE_UINT64(cert_data->poolRegistration.marginNumerator);

    ASSERT_TYPE(cert_data->poolRegistration.marginDenominator, uint64_t);
    if (!buffer_read_u64(buf, &cert_data->poolRegistration.marginDenominator, BE)) {
        TRACE("Failed to read margin denominator");
        return CERTIFICATES_PARSING_ERROR;
    }
    if (cert_data->poolRegistration.marginDenominator == 0) {
        TRACE("Invalid margin denominator: cannot be zero");
        return CERTIFICATES_PARSING_ERROR;
    }
    if (cert_data->poolRegistration.marginNumerator > cert_data->poolRegistration.marginDenominator) {
        TRACE("Invalid margin: numerator > denominator");
        TRACE_UINT64(cert_data->poolRegistration.marginNumerator);
        TRACE_UINT64(cert_data->poolRegistration.marginDenominator);
        return CERTIFICATES_PARSING_ERROR;
    }
    TRACE("Margin denominator: ");
    TRACE_UINT64(cert_data->poolRegistration.marginDenominator);

    // Parse reward account (hash or path)
    uint8_t reward_account_type;
    if (!buffer_read_u8(buf, &reward_account_type)) {
        TRACE("Failed to read reward account type");
        return CERTIFICATES_PARSING_ERROR;
    }

    TRACE("Reward account type wire: 0x%02x", reward_account_type);
    switch (reward_account_type) {
        case EXT_CREDENTIAL_KEY_HASH:
            cert_data->poolRegistration.rewardAccount.keyReferenceType = KEY_REFERENCE_HASH;
            if (!buffer_read_bytes_ptr(buf, &cert_data->poolRegistration.rewardAccount.hashBuffer,
                                       REWARD_ACCOUNT_LENGTH)) {
                TRACE("Failed to read reward account hash");
                return CERTIFICATES_PARSING_ERROR;
            }
            ASSERT(cert_data->poolRegistration.rewardAccount.hashBuffer != NULL);
            TRACE("Successfully parsed reward account as KEY_HASH");
            break;
        case EXT_CREDENTIAL_KEY_PATH:
            cert_data->poolRegistration.rewardAccount.keyReferenceType = KEY_REFERENCE_PATH;
            if (!buffer_read_bip44_path(buf, &cert_data->poolRegistration.rewardAccount.path)) {
                TRACE("Failed to read reward account path");
                return CERTIFICATES_PARSING_ERROR;
            }
            TRACE("Successfully parsed reward account as KEY_PATH");
            break;
        default:
            TRACE("Invalid reward account type: 0x%02x", reward_account_type);
            return CERTIFICATES_PARSING_ERROR;
    }

    // Parse pool owners array
    uint8_t num_owners;
    if (!buffer_read_u8(buf, &num_owners)) {
        TRACE("Failed to read number of pool owners");
        return CERTIFICATES_PARSING_ERROR;
    }
    cert_data->poolRegistration.numPoolOwners = num_owners;
    TRACE("Number of pool owners: %u", num_owners);

    // Parse each pool owner
    cert_data->poolRegistration.poolOwners = NULL;
    for (uint16_t i = 0; i < num_owners; i++) {
        TRACE("Parsing pool owner %u", i);
        tx_certificate_node_t *owner_item = (tx_certificate_node_t *) APP_MEM_ALLOC_ZEROED(sizeof(tx_certificate_node_t));
        if (owner_item == NULL) {
            TRACE("Failed to allocate memory for pool owner");
            return CERTIFICATES_PARSING_ERROR;
        }

        status = parse_stake_credential(buf, &owner_item->certificate.stakeCredential);
        if (status != PARSING_OK) {
            TRACE("Failed to parse pool owner credential");
            APP_MEM_FREE(owner_item);
            return status;
        }

        // Add to linked list
        owner_item->flist_node.next = NULL;
        flist_push_back(&cert_data->poolRegistration.poolOwners, &owner_item->flist_node);
    }

    // Parse relays array
    uint8_t num_relays;
    if (!buffer_read_u8(buf, &num_relays)) {
        TRACE("Failed to read number of relays");
        return CERTIFICATES_PARSING_ERROR;
    }
    cert_data->poolRegistration.numRelays = num_relays;
    TRACE("Number of relays: %u", num_relays);

    // Parse each relay
    cert_data->poolRegistration.relays = NULL;
    for (uint16_t i = 0; i < num_relays; i++) {
        TRACE("Parsing relay %u", i);
        tx_certificate_node_t *relay_item = (tx_certificate_node_t *) APP_MEM_ALLOC_ZEROED(sizeof(tx_certificate_node_t));
        if (relay_item == NULL) {
            TRACE("Failed to allocate memory for relay");
            return CERTIFICATES_PARSING_ERROR;
        }

        // We need to get the certificate_data properly typed for relay
        // The certificate_data union contains pool_relay_t space
        pool_relay_t *relay = (pool_relay_t *) &relay_item->certificate;

        status = _parse_pool_relay(buf, relay);
        if (status != PARSING_OK) {
            TRACE("Failed to parse relay");
            APP_MEM_FREE(relay_item);
            return status;
        }

        // Add to linked list
        relay_item->flist_node.next = NULL;
        flist_push_back(&cert_data->poolRegistration.relays, &relay_item->flist_node);
    }

    // Parse pool metadata
    status = _parse_pool_metadata(buf, &cert_data->poolRegistration.poolMetadata,
                                 &cert_data->poolRegistration.poolMetadataIsNull);
    if (status != PARSING_OK) {
        TRACE("Failed to parse pool metadata");
        return status;
    }

    TRACE("Successfully parsed STAKE_POOL_REGISTRATION");
    return PARSING_OK;
}
