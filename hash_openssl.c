/*
  chronyd/chronyc - Programs for keeping computer clocks accurate.

 **********************************************************************
 * Copyright (C) Miroslav Lichvar  2012
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

  Routines implementing crypto hashing using the OpenSSL library.

  */

#include "config.h"

#include "sysincl.h"

#include <openssl/evp.h>
#include <openssl/opensslv.h>

#include "hash.h"
#include "memory.h"

struct hash {
  HSH_Algorithm algorithm;
  const EVP_MD *md;
  EVP_MD_CTX *context;
};

static struct hash hashes[] = {
  { HSH_MD5,      NULL, NULL },
  { HSH_SHA1,     NULL, NULL },
  { HSH_SHA256,   NULL, NULL },
  { HSH_SHA384,   NULL, NULL },
  { HSH_SHA512,   NULL, NULL },
  { HSH_SHA3_224, NULL, NULL },
  { HSH_SHA3_256, NULL, NULL },
  { HSH_SHA3_384, NULL, NULL },
  { HSH_SHA3_512, NULL, NULL },
  { 0,            NULL, NULL }
};

static const EVP_MD *
get_evp_md(HSH_Algorithm algorithm)
{
  switch (algorithm) {
    case HSH_MD5:    return EVP_md5();
    case HSH_SHA1:   return EVP_sha1();
    case HSH_SHA256: return EVP_sha256();
    case HSH_SHA384: return EVP_sha384();
    case HSH_SHA512: return EVP_sha512();
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
    case HSH_SHA3_224: return EVP_sha3_224();
    case HSH_SHA3_256: return EVP_sha3_256();
    case HSH_SHA3_384: return EVP_sha3_384();
    case HSH_SHA3_512: return EVP_sha3_512();
#endif
    default: return NULL;
  }
}

int
HSH_GetHashId(HSH_Algorithm algorithm)
{
  int id;

  if (algorithm == HSH_MD5_NONCRYPTO)
    algorithm = HSH_MD5;

  for (id = 0; hashes[id].algorithm != 0; id++) {
    if (hashes[id].algorithm == algorithm)
      break;
  }

  if (hashes[id].algorithm == 0)
    return -1;

  if (hashes[id].context)
    return id;

  hashes[id].md = get_evp_md(algorithm);
  if (!hashes[id].md)
    return -1;

  hashes[id].context = EVP_MD_CTX_new();
  if (!hashes[id].context) {
    hashes[id].md = NULL;
    return -1;
  }

  return id;
}

int
HSH_Hash(int id, const void *in1, int in1_len, const void *in2, int in2_len,
         unsigned char *out, int out_len)
{
  unsigned char buf[MAX_HASH_LENGTH];
  unsigned int digest_len;
  int evp_size;

  if (in1_len < 0 || in2_len < 0 || out_len < 0)
    return 0;

  evp_size = EVP_MD_size(hashes[id].md);
  if (evp_size <= 0 || evp_size > (int)sizeof(buf))
    return 0;

  if (out_len > evp_size)
    out_len = evp_size;

  if (!EVP_DigestInit_ex(hashes[id].context, hashes[id].md, NULL) ||
      !EVP_DigestUpdate(hashes[id].context, in1, in1_len) ||
      (in2 && !EVP_DigestUpdate(hashes[id].context, in2, in2_len)))
    return 0;

  digest_len = sizeof(buf);
  if (!EVP_DigestFinal_ex(hashes[id].context, buf, &digest_len))
    return 0;

  memcpy(out, buf, out_len);
  return out_len;
}

void
HSH_Finalise(void)
{
  int i;

  for (i = 0; hashes[i].algorithm != 0; i++) {
    if (hashes[i].context) {
      EVP_MD_CTX_free(hashes[i].context);
      hashes[i].context = NULL;
      hashes[i].md = NULL;
    }
  }
}
