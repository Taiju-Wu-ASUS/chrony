/*
  chronyd/chronyc - Programs for keeping computer clocks accurate.

 **********************************************************************
 * Copyright (C) Miroslav Lichvar  2019, 2022
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

  SIV ciphers using the OpenSSL library (requires OpenSSL 3.2+).

  Ciphertext layout (matching the nettle/gnutls convention):
    ciphertext = tag (16 bytes) || encrypted plaintext

  AES-SIV-CMAC-256: The nonce is treated as the first associated data
  component (S2V input), consistent with RFC 5297.

  AES-128-GCM-SIV: The nonce is the 12-byte IV; assoc is the AAD.

  */

#include "config.h"

#include "sysincl.h"

#include <openssl/evp.h>

#include "logging.h"
#include "memory.h"
#include "siv.h"

#define SIV_TAG_LENGTH 16

struct SIV_Instance_Record {
  SIV_Algorithm algorithm;
  EVP_CIPHER *cipher;
  int key_length;
  int tag_length;
  int min_nonce_length;
  int max_nonce_length;
  int key_set;
  unsigned char key[SIV_MAX_KEY_LENGTH];
};

/* ================================================== */

SIV_Instance
SIV_CreateInstance(SIV_Algorithm algorithm)
{
  SIV_Instance instance;
  EVP_CIPHER *cipher;
  const char *cipher_name;

  switch (algorithm) {
    case AEAD_AES_SIV_CMAC_256:
      cipher_name = "AES-128-SIV";
      break;
#ifdef HAVE_OPENSSL_SIV_GCM
    case AEAD_AES_128_GCM_SIV:
      cipher_name = "AES-128-GCM-SIV";
      break;
#endif
    default:
      return NULL;
  }

  cipher = EVP_CIPHER_fetch(NULL, cipher_name, NULL);
  if (!cipher)
    return NULL;

  instance = MallocNew(struct SIV_Instance_Record);
  instance->algorithm = algorithm;
  instance->cipher = cipher;
  instance->tag_length = SIV_TAG_LENGTH;
  instance->key_set = 0;

  switch (algorithm) {
    case AEAD_AES_SIV_CMAC_256:
      /* RFC 5297 SIV-CMAC: key = K1 || K2 (two AES-128 keys) */
      instance->key_length = 32;
      /* Nonce is treated as additional associated data; any length >= 1 */
      instance->min_nonce_length = 1;
      instance->max_nonce_length = INT_MAX;
      break;
#ifdef HAVE_OPENSSL_SIV_GCM
    case AEAD_AES_128_GCM_SIV:
      instance->key_length = 16;
      instance->min_nonce_length = 12;
      instance->max_nonce_length = 12;
      break;
#endif
    default:
      assert(0);
  }

  return instance;
}

/* ================================================== */

void
SIV_DestroyInstance(SIV_Instance instance)
{
  EVP_CIPHER_free(instance->cipher);
  Free(instance);
}

/* ================================================== */

int
SIV_GetKeyLength(SIV_Algorithm algorithm)
{
  switch (algorithm) {
    case AEAD_AES_SIV_CMAC_256: return 32;
#ifdef HAVE_OPENSSL_SIV_GCM
    case AEAD_AES_128_GCM_SIV: {
      /* Runtime probe: the cipher may not be available even if compiled in */
      static int available = -1;

      if (available < 0) {
        EVP_CIPHER *c = EVP_CIPHER_fetch(NULL, "AES-128-GCM-SIV", NULL);
        available = (c != NULL) ? 1 : 0;
        EVP_CIPHER_free(c);
      }
      return available ? 16 : 0;
    }
#endif
    default: return 0;
  }
}

/* ================================================== */

int
SIV_SetKey(SIV_Instance instance, const unsigned char *key, int length)
{
  if (length <= 0 || length != instance->key_length)
    return 0;

  memcpy(instance->key, key, length);
  instance->key_set = 1;

  return 1;
}

/* ================================================== */

int
SIV_GetMinNonceLength(SIV_Instance instance)
{
  return instance->min_nonce_length;
}

/* ================================================== */

int
SIV_GetMaxNonceLength(SIV_Instance instance)
{
  return instance->max_nonce_length;
}

/* ================================================== */

int
SIV_GetTagLength(SIV_Instance instance)
{
  return instance->tag_length;
}

/* ================================================== */

int
SIV_Encrypt(SIV_Instance instance,
            const unsigned char *nonce, int nonce_length,
            const void *assoc, int assoc_length,
            const void *plaintext, int plaintext_length,
            unsigned char *ciphertext, int ciphertext_length)
{
  EVP_CIPHER_CTX *ctx;
  int len, outl, ok;
  /* ciphertext[0..tag_length-1] = tag; [tag_length..] = encrypted data */
  const unsigned char *iv;

  if (!instance->key_set)
    return 0;

  if (nonce_length < instance->min_nonce_length ||
      nonce_length > instance->max_nonce_length || assoc_length < 0 ||
      plaintext_length < 0 ||
      ciphertext_length != plaintext_length + instance->tag_length)
    return 0;

  assert(assoc && plaintext);

  ctx = EVP_CIPHER_CTX_new();
  if (!ctx)
    return 0;

  /*
   * AES-SIV-CMAC: IV is NULL (the SIV is computed internally from the data).
   * AES-GCM-SIV:  IV is the 12-byte nonce.
   */
  iv = (instance->algorithm == AEAD_AES_SIV_CMAC_256) ? NULL : nonce;

  ok = EVP_EncryptInit_ex(ctx, instance->cipher, NULL, instance->key, iv);

  if (ok && instance->algorithm == AEAD_AES_SIV_CMAC_256) {
    /* Feed nonce as the first S2V associated data component */
    ok = EVP_EncryptUpdate(ctx, NULL, &len, nonce, nonce_length);
  }

  /* Only feed assoc as an S2V component when non-empty, matching Nettle/GnuTLS
     behaviour: an empty assoc is not counted as a separate S2V input. */
  if (ok && assoc_length > 0)
    ok = EVP_EncryptUpdate(ctx, NULL, &len, assoc, assoc_length);

  if (ok)
    ok = EVP_EncryptUpdate(ctx, ciphertext + instance->tag_length, &len,
                           plaintext, plaintext_length);

  outl = 0;
  if (ok)
    ok = EVP_EncryptFinal_ex(ctx, ciphertext + instance->tag_length + len, &outl);

  /* Retrieve the tag (SIV or GCM-SIV tag) and place it at the front */
  if (ok)
    ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG,
                              instance->tag_length, ciphertext);

  EVP_CIPHER_CTX_free(ctx);

  return ok ? 1 : 0;
}

/* ================================================== */

int
SIV_Decrypt(SIV_Instance instance,
            const unsigned char *nonce, int nonce_length,
            const void *assoc, int assoc_length,
            const unsigned char *ciphertext, int ciphertext_length,
            void *plaintext, int plaintext_length)
{
  EVP_CIPHER_CTX *ctx;
  int len, outl, ok;
  const unsigned char *iv;

  if (!instance->key_set)
    return 0;

  if (nonce_length < instance->min_nonce_length ||
      nonce_length > instance->max_nonce_length || assoc_length < 0 ||
      plaintext_length < 0 ||
      ciphertext_length != plaintext_length + instance->tag_length)
    return 0;

  assert(assoc && plaintext);

  ctx = EVP_CIPHER_CTX_new();
  if (!ctx)
    return 0;

  iv = (instance->algorithm == AEAD_AES_SIV_CMAC_256) ? NULL : nonce;

  ok = EVP_DecryptInit_ex(ctx, instance->cipher, NULL, instance->key, iv);

  /*
   * Set the expected tag (first tag_length bytes of ciphertext) before
   * processing any data so the implementation can use it as the CTR IV
   * for SIV-CMAC decryption.
   */
  if (ok)
    ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG,
                              instance->tag_length,
                              (void *)ciphertext);

  if (ok && instance->algorithm == AEAD_AES_SIV_CMAC_256)
    ok = EVP_DecryptUpdate(ctx, NULL, &len, nonce, nonce_length);

  if (ok && assoc_length > 0)
    ok = EVP_DecryptUpdate(ctx, NULL, &len, assoc, assoc_length);

  if (ok)
    ok = EVP_DecryptUpdate(ctx, plaintext, &len,
                           ciphertext + instance->tag_length, plaintext_length);

  outl = 0;
  if (ok)
    ok = EVP_DecryptFinal_ex(ctx, (unsigned char *)plaintext + len, &outl);

  EVP_CIPHER_CTX_free(ctx);

  return ok ? 1 : 0;
}
