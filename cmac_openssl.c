/*
  chronyd/chronyc - Programs for keeping computer clocks accurate.

 **********************************************************************
 * Copyright (C) Miroslav Lichvar  2019
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 **********************************************************************

  =======================================================================

  Support for AES128 and AES256 CMAC using the OpenSSL library.
  Uses EVP_MAC (OpenSSL 3.x) or CMAC_CTX (OpenSSL 1.1.x).

  */

#include "config.h"

#include "sysincl.h"

#include <openssl/evp.h>
#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/params.h>
#include <openssl/core_names.h>
#else
#include <openssl/cmac.h>
#endif

#include "cmac.h"
#include "hash.h"
#include "memory.h"

#define AES128_KEY_SIZE    16
#define AES256_KEY_SIZE    32
#define CMAC128_DIGEST_SIZE 16

struct CMC_Instance_Record {
  CMC_Algorithm algorithm;
  int key_length;
  unsigned char key[AES256_KEY_SIZE];
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  char cipher_name[16];
  EVP_MAC *mac;
  EVP_MAC_CTX *ctx;
#else
  const EVP_CIPHER *cipher;
  CMAC_CTX *ctx;
#endif
};

/* ================================================== */

int
CMC_GetKeyLength(CMC_Algorithm algorithm)
{
  switch (algorithm) {
    case CMC_AES128: return AES128_KEY_SIZE;
    case CMC_AES256: return AES256_KEY_SIZE;
    default:         return 0;
  }
}

/* ================================================== */

CMC_Instance
CMC_CreateInstance(CMC_Algorithm algorithm, const unsigned char *key, int length)
{
  CMC_Instance inst;

  if (length <= 0 || length != CMC_GetKeyLength(algorithm))
    return NULL;

  inst = MallocNew(struct CMC_Instance_Record);
  inst->algorithm = algorithm;
  inst->key_length = length;
  memcpy(inst->key, key, length);

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  if (algorithm == CMC_AES128)
    strncpy(inst->cipher_name, "AES-128-CBC", sizeof(inst->cipher_name));
  else
    strncpy(inst->cipher_name, "AES-256-CBC", sizeof(inst->cipher_name));

  inst->mac = EVP_MAC_fetch(NULL, "CMAC", NULL);
  if (!inst->mac) {
    Free(inst);
    return NULL;
  }

  inst->ctx = EVP_MAC_CTX_new(inst->mac);
  if (!inst->ctx) {
    EVP_MAC_free(inst->mac);
    Free(inst);
    return NULL;
  }
#else
  inst->cipher = (algorithm == CMC_AES128) ? EVP_aes_128_cbc() : EVP_aes_256_cbc();

  inst->ctx = CMAC_CTX_new();
  if (!inst->ctx) {
    Free(inst);
    return NULL;
  }
#endif

  return inst;
}

/* ================================================== */

int
CMC_Hash(CMC_Instance inst, const void *in, int in_len, unsigned char *out, int out_len)
{
  unsigned char buf[CMAC128_DIGEST_SIZE];
  size_t buf_len;

  if (in_len < 0 || out_len < 0)
    return 0;

  if (out_len > CMAC128_DIGEST_SIZE)
    out_len = CMAC128_DIGEST_SIZE;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  {
    OSSL_PARAM params[2];

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER,
                                                  inst->cipher_name, 0);
    params[1] = OSSL_PARAM_construct_end();

    if (!EVP_MAC_init(inst->ctx, inst->key, inst->key_length, params) ||
        !EVP_MAC_update(inst->ctx, in, in_len))
      return 0;

    buf_len = sizeof(buf);
    if (!EVP_MAC_final(inst->ctx, buf, &buf_len, sizeof(buf)))
      return 0;
  }
#else
  {
    if (!CMAC_Init(inst->ctx, inst->key, inst->key_length, inst->cipher, NULL) ||
        !CMAC_Update(inst->ctx, in, in_len))
      return 0;

    buf_len = sizeof(buf);
    if (!CMAC_Final(inst->ctx, buf, &buf_len))
      return 0;
  }
#endif

  if ((int)buf_len < out_len)
    out_len = (int)buf_len;

  memcpy(out, buf, out_len);
  return out_len;
}

/* ================================================== */

void
CMC_DestroyInstance(CMC_Instance inst)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  EVP_MAC_CTX_free(inst->ctx);
  EVP_MAC_free(inst->mac);
#else
  CMAC_CTX_free(inst->ctx);
#endif
  Free(inst);
}
