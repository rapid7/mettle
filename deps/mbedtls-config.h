/*
 *  Minimal configuration for TLS 1.1 (RFC 4346)
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */
/*
 * Minimal configuration for TLS 1.1 (RFC 4346), implementing only the
 * required ciphersuite: MBEDTLS_TLS_RSA_WITH_3DES_EDE_CBC_SHA
 *
 * See README.txt for usage instructions.
 */

#ifndef MBEDTLS_CONFIG_H
#define MBEDTLS_CONFIG_H

/* System support */
#define MBEDTLS_HAVE_ASM
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_PLATFORM_SNPRINTF_ALT
#define MBEDTLS_HAVE_TIME

// Uncomment to test the embedded Marsenne Twister PRNG algorithm 
// #define MBEDTLS_NO_PLATFORM_ENTROPY 

/* mbed TLS feature support */
#define MBEDTLS_CIPHER_MODE_CBC
#define MBEDTLS_PKCS1_V15
#define MBEDTLS_KEY_EXCHANGE_RSA_ENABLED
#define MBEDTLS_SSL_PROTO_TLS1_0
#define MBEDTLS_SSL_PROTO_TLS1_1
#define MBEDTLS_SSL_PROTO_TLS1_2

/* mbed TLS modules */
#define MBEDTLS_AES_C
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_CIPHER_C
#define MBEDTLS_CTR_DRBG_C
#define MBEDTLS_DES_C
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_MD_C
#define MBEDTLS_MD5_C
#define MBEDTLS_NET_C
#define MBEDTLS_OID_C
#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C
#define MBEDTLS_PK_WRITE_C
#define MBEDTLS_RSA_C
#define MBEDTLS_SHA1_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_SSL_CLI_C
#define MBEDTLS_SSL_SRV_C
#define MBEDTLS_SSL_TLS_C
#define MBEDTLS_ERROR_STRERROR_DUMMY
#define MBEDTLS_X509_CRT_PARSE_C
#define MBEDTLS_X509_CRL_PARSE_C
#define MBEDTLS_X509_USE_C
#define MBEDTLS_VERSION_C
#define MBEDTLS_VERSION_FEATURES

/* Enable extensions in TLS handshake */
#define MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED
#define MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
#define MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED
#define MBEDTLS_ECDH_C
#define MBEDTLS_SSL_PROTO_TLS1_3
#define MBEDTLS_SSL_CONTEXT_SERIALIZATION
#define MBEDTLS_SSL_SERVER_NAME_INDICATION
#define MBEDTLS_ECDSA_C
#define MBEDTLS_ECP_C
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#define MBEDTLS_ECP_DP_SECP384R1_ENABLED
#define MBEDTLS_ECP_DP_CURVE25519_ENABLED
#define MBEDTLS_X509_RSASSA_PSS_SUPPORT
#define MBEDTLS_PKCS1_V21
#define MBEDTLS_SSL_EXTENDED_MASTER_SECRET
#define MBEDTLS_SSL_ENCRYPT_THEN_MAC
#define MBEDTLS_SSL_ALPN
#define MBEDTLS_SSL_SESSION_TICKETS
#define MBEDTLS_SSL_CIPHERSUITES \
      MBEDTLS_TLS_RSA_WITH_AES_128_CBC_SHA, \
      MBEDTLS_TLS_RSA_WITH_AES_256_CBC_SHA, \
      MBEDTLS_TLS_RSA_WITH_AES_128_GCM_SHA256, \
      MBEDTLS_TLS_RSA_WITH_AES_256_GCM_SHA384, \
      MBEDTLS_TLS_RSA_WITH_3DES_EDE_CBC_SHA, \
      MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, \
      MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, \
      MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, \
      MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, \
      MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, \
      MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, \
      MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, \
      MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, \
      MBEDTLS_TLS_DHE_RSA_WITH_AES_128_CBC_SHA, \
      MBEDTLS_TLS_DHE_RSA_WITH_AES_256_CBC_SHA, \
      MBEDTLS_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256, \
      MBEDTLS_TLS_DHE_RSA_WITH_AES_256_GCM_SHA384, \
      MBEDTLS_TLS_PSK_WITH_AES_128_CBC_SHA, \
      MBEDTLS_TLS_PSK_WITH_AES_256_CBC_SHA, \
      MBEDTLS_TLS_PSK_WITH_AES_128_GCM_SHA256, \
      MBEDTLS_TLS_PSK_WITH_AES_256_GCM_SHA384, \
      MBEDTLS_TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA, \
      MBEDTLS_TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA, \
      MBEDTLS_TLS_RSA_WITH_AES_128_CBC_SHA, \
      MBEDTLS_TLS_RSA_WITH_AES_256_CBC_SHA, \
      MBEDTLS_TLS_RSA_WITH_AES_128_GCM_SHA256, \
      MBEDTLS_TLS_RSA_WITH_AES_256_GCM_SHA384, \
      MBEDTLS_TLS_RSA_WITH_3DES_EDE_CBC_SHA

/* For test certificates */
#define MBEDTLS_BASE64_C
#define MBEDTLS_CERTS_C
#define MBEDTLS_PEM_PARSE_C

/* For testing with compat.sh */
#define MBEDTLS_FS_IO

#include "mbedtls/check_config.h"

#endif /* MBEDTLS_CONFIG_H */
