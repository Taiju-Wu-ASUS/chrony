/*
  chronyd/chronyc - Programs for keeping computer clocks accurate.

 **********************************************************************
 * Copyright (C) Miroslav Lichvar  2020-2021
 * Copyright (C) Anthony Brandon  2025
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

  Routines implementing TLS session handling using the OpenSSL library.

  Design notes:
  - TLS_Credentials wraps an SSL_CTX (cast to void *).
  - TLS 1.3 is required; older versions are rejected at SSL_CTX creation.
  - Session tickets are disabled (NTS is stateless).
  - ALPN for client is set per-SSL via SSL_set_alpn_protos().
  - ALPN for server is selected via a CTX-level callback that retrieves
    the expected name from per-SSL ex_data.
  - Certificate verification time uses chrony's clock via
    X509_VERIFY_PARAM_set_time(), set before each handshake attempt.
  */

#include "config.h"

#include "sysincl.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/tls1.h>

#include "conf.h"
#include "logging.h"
#include "memory.h"
#include "tls.h"
#include "util.h"

struct TLS_Instance_Record {
  SSL *ssl;
  int server;
  char *server_name;
  char *label;
  char *alpn_name;
};

/* ================================================== */

static time_t (*g_get_time)(time_t *t) = NULL;

/* Per-SSL ex_data index used by the server ALPN callback to retrieve
   the TLS_Instance pointer (and thus the expected ALPN name). */
static int ssl_ex_data_inst_idx = -1;

/* ================================================== */

/* Log and drain the OpenSSL error queue. */
static void
log_ssl_errors(const char *context, const char *peer_label, int server)
{
  char buf[256];
  unsigned long e;

  while ((e = ERR_get_error()) != 0) {
    ERR_error_string_n(e, buf, sizeof(buf));
    LOG(server ? LOGS_DEBUG : LOGS_ERR, "%s %s : %s", context, peer_label, buf);
  }
}

/* ================================================== */

/* Server-side ALPN selection callback.  Picks the protocol that matches
   the TLS_Instance's expected alpn_name. */
static int
alpn_select_cb(SSL *ssl, const unsigned char **out, unsigned char *outlen,
               const unsigned char *in, unsigned int inlen, void *arg)
{
  TLS_Instance inst = SSL_get_ex_data(ssl, ssl_ex_data_inst_idx);
  const unsigned char *p = in;
  unsigned int len;

  if (!inst)
    return SSL_TLSEXT_ERR_NOACK;

  len = (unsigned int)strlen(inst->alpn_name);

  while (p < in + inlen) {
    unsigned int proto_len = *p++;
    if (proto_len == len && memcmp(p, inst->alpn_name, len) == 0) {
      *out = p;
      *outlen = (unsigned char)proto_len;
      return SSL_TLSEXT_ERR_OK;
    }
    p += proto_len;
  }

  return SSL_TLSEXT_ERR_NOACK;
}

/* ================================================== */

/* Verify that the negotiated ALPN matches inst->alpn_name. */
static int
check_alpn(TLS_Instance inst)
{
  const unsigned char *proto;
  unsigned int proto_len;
  size_t expected_len = strlen(inst->alpn_name);

  SSL_get0_alpn_selected(inst->ssl, &proto, &proto_len);

  return proto && proto_len == (unsigned int)expected_len &&
         memcmp(proto, inst->alpn_name, expected_len) == 0;
}

/* ================================================== */

/* Translate SSL_get_error() into TLS_Status for I/O operations.
   Drains the error queue on fatal errors. */
static TLS_Status
ssl_error_status(TLS_Instance inst, int ret, const char *op)
{
  int err = SSL_get_error(inst->ssl, ret);

  switch (err) {
    case SSL_ERROR_WANT_READ:
      return TLS_AGAIN_INPUT;
    case SSL_ERROR_WANT_WRITE:
      return TLS_AGAIN_OUTPUT;
    case SSL_ERROR_ZERO_RETURN:
      return TLS_CLOSED;
    case SSL_ERROR_SYSCALL:
      if (ERR_peek_error() == 0)
        return TLS_CLOSED;
      /* fall through */
    default:
      log_ssl_errors(op, inst->label, inst->server);
      return TLS_FAILED;
  }
}

/* ================================================== */

int
TLS_Initialise(time_t (*get_time)(time_t *t))
{
  g_get_time = get_time;

  ssl_ex_data_inst_idx = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
  if (ssl_ex_data_inst_idx < 0) {
    LOG(LOGS_ERR, "Could not allocate SSL ex_data index");
    return 0;
  }

  return 1;
}

/* ================================================== */

void
TLS_Finalise(void)
{
  /* OpenSSL 3.x cleans up automatically at process exit. */
}

/* ================================================== */

TLS_Credentials
TLS_CreateCredentials(const char **certs, const char **keys, int n_certs_keys,
                      const char **trusted_certs, uint32_t *trusted_certs_ids,
                      int n_trusted_certs, uint32_t trusted_cert_set)
{
  SSL_CTX *ctx;
  int i;

  ctx = SSL_CTX_new(TLS_method());
  if (!ctx) {
    LOG(LOGS_ERR, "Could not create SSL context");
    return NULL;
  }

  /* NTS specification requires TLS 1.3 or later. */
  if (!SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION)) {
    LOG(LOGS_ERR, "Could not set minimum TLS version to 1.3");
    goto error;
  }

  /* Disable session tickets — NTS-KE sessions are not resumed. */
  SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);

  if (certs && keys) {
    /* Server credentials: certificate chain + private key. */
    BRIEF_ASSERT(!trusted_certs && !trusted_certs_ids);

    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    for (i = 0; i < n_certs_keys; i++) {
      if (!UTI_CheckFilePermissions(keys[i], 0771))
        ;

      if (!SSL_CTX_use_certificate_chain_file(ctx, certs[i])) {
        LOG(LOGS_ERR, "Could not load certificate from %s", certs[i]);
        goto error;
      }
      if (!SSL_CTX_use_PrivateKey_file(ctx, keys[i], SSL_FILETYPE_PEM)) {
        LOG(LOGS_ERR, "Could not load private key from %s", keys[i]);
        goto error;
      }
      if (!SSL_CTX_check_private_key(ctx)) {
        LOG(LOGS_ERR, "Certificate and key do not match: %s / %s", certs[i], keys[i]);
        goto error;
      }
    }
  } else {
    /* Client credentials: trusted certificate store. */
    BRIEF_ASSERT(!certs && !keys && n_certs_keys <= 0);

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    if (trusted_cert_set == 0 && !CNF_GetNoSystemCert()) {
      if (!SSL_CTX_set_default_verify_paths(ctx)) {
        LOG(LOGS_ERR, "Could not load system trusted certificates");
        goto error;
      }
    }

    if (trusted_certs && trusted_certs_ids) {
      X509_STORE *store = SSL_CTX_get_cert_store(ctx);

      for (i = 0; i < n_trusted_certs; i++) {
        struct stat sb;
        int r;

        if (trusted_certs_ids[i] != trusted_cert_set)
          continue;

        if (stat(trusted_certs[i], &sb) == 0 && S_ISDIR(sb.st_mode))
          r = X509_STORE_load_path(store, trusted_certs[i]);
        else
          r = X509_STORE_load_file(store, trusted_certs[i]);

        if (!r) {
          LOG(LOGS_ERR, "Could not load trusted certificate from %s", trusted_certs[i]);
          goto error;
        }

        DEBUG_LOG("Added trusted certificates from %s", trusted_certs[i]);
      }
    }
  }

  return (TLS_Credentials)ctx;

error:
  log_ssl_errors("Could not set credentials :", "", 0);
  SSL_CTX_free(ctx);
  return NULL;
}

/* ================================================== */

void
TLS_DestroyCredentials(TLS_Credentials credentials)
{
  SSL_CTX_free((SSL_CTX *)credentials);
}

/* ================================================== */

TLS_Instance
TLS_CreateInstance(int server_mode, int sock_fd, const char *server_name,
                   const char *label, const char *alpn_name,
                   TLS_Credentials credentials, int disable_time_checks)
{
  SSL_CTX *ctx = (SSL_CTX *)credentials;
  TLS_Instance inst;

  inst = MallocNew(struct TLS_Instance_Record);
  inst->ssl = NULL;
  inst->server = server_mode;
  inst->server_name = NULL;
  inst->label = Strdup(label);
  inst->alpn_name = Strdup(alpn_name);

  inst->ssl = SSL_new(ctx);
  if (!inst->ssl) {
    LOG(LOGS_ERR, "Could not create TLS session");
    goto error;
  }

  /* Store instance pointer for use in server ALPN callback. */
  SSL_set_ex_data(inst->ssl, ssl_ex_data_inst_idx, inst);

  if (!SSL_set_fd(inst->ssl, sock_fd)) {
    LOG(LOGS_ERR, "Could not set TLS session socket");
    goto error;
  }

  if (!server_mode) {
    int name_len;
    size_t alpn_len;
    unsigned char alpn_buf[256];

    assert(server_name);
    inst->server_name = Strdup(server_name);

    /* Remove trailing dot as OpenSSL expects a bare hostname. */
    name_len = strlen(inst->server_name);
    if (name_len > 1 && inst->server_name[name_len - 1] == '.')
      inst->server_name[name_len - 1] = '\0';

    if (!UTI_IsStringIP(inst->server_name)) {
      /* SNI: advertise hostname to the server. */
      if (!SSL_set_tlsext_host_name(inst->ssl, inst->server_name)) {
        LOG(LOGS_ERR, "Could not set TLS SNI hostname");
        goto error;
      }

      /* Hostname matching for certificate verification. */
      if (!SSL_set1_host(inst->ssl, inst->server_name)) {
        LOG(LOGS_ERR, "Could not set TLS verification hostname");
        goto error;
      }
    }

    /* ALPN in wire format: [1-byte length][protocol name]. */
    alpn_len = strlen(alpn_name);
    if (alpn_len > 255) {
      LOG(LOGS_ERR, "ALPN name too long");
      goto error;
    }
    alpn_buf[0] = (unsigned char)alpn_len;
    memcpy(alpn_buf + 1, alpn_name, alpn_len);

    /* Note: SSL_set_alpn_protos returns 0 on success (inverted convention). */
    if (SSL_set_alpn_protos(inst->ssl, alpn_buf, (unsigned int)(alpn_len + 1))) {
      LOG(LOGS_ERR, "Could not set ALPN protocols");
      goto error;
    }

    SSL_set_connect_state(inst->ssl);
  } else {
    /* Register server-side ALPN selection callback on the shared CTX.
       The callback reads the expected protocol name from SSL ex_data. */
    SSL_CTX_set_alpn_select_cb(ctx, alpn_select_cb, NULL);
    SSL_set_accept_state(inst->ssl);
  }

  if (disable_time_checks) {
    X509_VERIFY_PARAM *vpm = SSL_get0_param(inst->ssl);
    X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_NO_CHECK_TIME);
    DEBUG_LOG("Disabled certificate time checks");
  }

  return inst;

error:
  log_ssl_errors("Could not set TLS session :", label, server_mode);
  TLS_DestroyInstance(inst);
  return NULL;
}

/* ================================================== */

void
TLS_DestroyInstance(TLS_Instance inst)
{
  if (inst->ssl)
    SSL_free(inst->ssl);
  if (inst->server_name)
    Free(inst->server_name);
  Free(inst->label);
  Free(inst->alpn_name);
  Free(inst);
}

/* ================================================== */

TLS_Status
TLS_DoHandshake(TLS_Instance inst)
{
  int r;

  /* Use chrony's clock for certificate time verification.  Set before
     each call so the time reflects when verification actually runs. */
  if (g_get_time && !inst->server) {
    X509_VERIFY_PARAM *vpm = SSL_get0_param(inst->ssl);
    X509_VERIFY_PARAM_set_time(vpm, g_get_time(NULL));
  }

  r = SSL_do_handshake(inst->ssl);

  if (r == 1) {
    if (DEBUG) {
      const SSL_CIPHER *cipher = SSL_get_current_cipher(inst->ssl);
      DEBUG_LOG("Handshake with %s completed (%s, %s)",
                inst->label,
                SSL_get_version(inst->ssl),
                cipher ? SSL_CIPHER_get_name(cipher) : "unknown cipher");
    }

    if (!check_alpn(inst)) {
      LOG(inst->server ? LOGS_DEBUG : LOGS_ERR,
          "NTS-KE not supported by %s", inst->label);
      return TLS_FAILED;
    }

    return TLS_SUCCESS;
  }

  {
    int err = SSL_get_error(inst->ssl, r);
    long verify_result;

    switch (err) {
      case SSL_ERROR_WANT_READ:
        return TLS_AGAIN_INPUT;
      case SSL_ERROR_WANT_WRITE:
        return TLS_AGAIN_OUTPUT;
      case SSL_ERROR_ZERO_RETURN:
        return TLS_CLOSED;
      case SSL_ERROR_SYSCALL:
        if (ERR_peek_error() == 0)
          return TLS_CLOSED;
        /* fall through */
      default:
        verify_result = SSL_get_verify_result(inst->ssl);
        if (verify_result != X509_V_OK) {
          LOG(inst->server ? LOGS_DEBUG : LOGS_ERR,
              "TLS handshake with %s failed : %s",
              inst->label, X509_verify_cert_error_string(verify_result));
          ERR_clear_error();
        } else {
          log_ssl_errors("TLS handshake with", inst->label, inst->server);
        }

        if (err == SSL_ERROR_SYSCALL)
          return TLS_CLOSED;

        return TLS_FAILED;
    }
  }
}

/* ================================================== */

TLS_Status
TLS_Send(TLS_Instance inst, const void *data, int length, int *sent)
{
  int r;

  if (length < 0)
    return TLS_FAILED;

  r = SSL_write(inst->ssl, data, length);

  if (r > 0) {
    *sent = r;
    return TLS_SUCCESS;
  }

  {
    int err = SSL_get_error(inst->ssl, r);
    switch (err) {
      case SSL_ERROR_WANT_READ:
        return TLS_AGAIN_INPUT;
      case SSL_ERROR_WANT_WRITE:
        return TLS_AGAIN_OUTPUT;
      case SSL_ERROR_ZERO_RETURN:
        return TLS_CLOSED;
      default:
        log_ssl_errors("Could not send NTS-KE message to", inst->label, inst->server);
        return TLS_FAILED;
    }
  }
}

/* ================================================== */

TLS_Status
TLS_Receive(TLS_Instance inst, void *data, int length, int *received)
{
  int r;

  if (length < 0)
    return TLS_FAILED;

  r = SSL_read(inst->ssl, data, length);

  if (r > 0) {
    *received = r;
    return TLS_SUCCESS;
  }

  {
    int err = SSL_get_error(inst->ssl, r);
    switch (err) {
      case SSL_ERROR_WANT_READ:
        return TLS_AGAIN_INPUT;
      case SSL_ERROR_WANT_WRITE:
        return TLS_AGAIN_OUTPUT;
      case SSL_ERROR_ZERO_RETURN:
        return TLS_CLOSED;
      case SSL_ERROR_SYSCALL:
        if (ERR_peek_error() == 0)
          return TLS_CLOSED;
        /* fall through */
      default:
        log_ssl_errors("Could not receive NTS-KE message from", inst->label, inst->server);
        return TLS_FAILED;
    }
  }
}

/* ================================================== */

int
TLS_CheckPending(TLS_Instance inst)
{
  return SSL_pending(inst->ssl) > 0;
}

/* ================================================== */

TLS_Status
TLS_Shutdown(TLS_Instance inst)
{
  int r = SSL_shutdown(inst->ssl);

  /* r == 1: both sides sent close_notify — done.
     r == 0: our close_notify sent, waiting for peer's — try again later.
     r < 0: non-blocking would-block or error. */
  if (r == 1)
    return TLS_SUCCESS;

  if (r == 0)
    return TLS_AGAIN_INPUT;

  {
    int err = SSL_get_error(inst->ssl, r);
    switch (err) {
      case SSL_ERROR_WANT_READ:
        return TLS_AGAIN_INPUT;
      case SSL_ERROR_WANT_WRITE:
        return TLS_AGAIN_OUTPUT;
      default:
        DEBUG_LOG("Shutdown with %s failed", inst->label);
        ERR_clear_error();
        return TLS_FAILED;
    }
  }
}

/* ================================================== */

int
TLS_ExportKey(TLS_Instance inst, int label_length, const char *label,
              int context_length, const void *context, int key_length, unsigned char *key)
{
  if (label_length < 0 || context_length < 0 || key_length < 0)
    return 0;

  return SSL_export_keying_material(inst->ssl, key, (size_t)key_length,
                                    label, (size_t)label_length,
                                    (const unsigned char *)context,
                                    (size_t)context_length,
                                    context_length > 0 ? 1 : 0) == 1;
}
