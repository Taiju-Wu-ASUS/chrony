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
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <openssl/tls1.h>
#include <sys/socket.h>

#include "conf.h"
#include "logging.h"
#include "memory.h"
#include "tls.h"
#include "util.h"

struct TLS_Instance_Record {
  SSL *ssl;
  int server;
  int disable_time_checks;
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

/* Data for SNI-based certificate selection when the server has multiple
   cert/key pairs.  The main SSL_CTX holds cert[0]; additional CTXs are
   stored here and selected via the servername callback. */
typedef struct {
  int n_ctxs;
  SSL_CTX **ctxs;
} SnoCertData;

static int sno_cert_data_idx = -1;

static void
sno_cert_data_free(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
                   int idx, long argl, void *argp)
{
  SnoCertData *scd = (SnoCertData *)ptr;
  int i;

  if (!scd)
    return;
  for (i = 0; i < scd->n_ctxs; i++)
    SSL_CTX_free(scd->ctxs[i]);
  Free(scd->ctxs);
  Free(scd);
}

static int
sno_cert_select_cb(SSL *ssl, int *al, void *arg)
{
  SnoCertData *scd = (SnoCertData *)arg;
  const char *name;
  X509 *cert;
  int i;

  name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
  if (!name)
    return SSL_TLSEXT_ERR_OK;

  for (i = 0; i < scd->n_ctxs; i++) {
    cert = SSL_CTX_get0_certificate(scd->ctxs[i]);
    if (cert && X509_check_host(cert, name, 0, 0, NULL) == 1) {
      SSL_set_SSL_CTX(ssl, scd->ctxs[i]);
      return SSL_TLSEXT_ERR_OK;
    }
  }

  return SSL_TLSEXT_ERR_OK;
}

/* ================================================== */

/* Verify callback used when disable_time_checks is set.
   Ignores notBefore/notAfter errors so an expired cert is accepted. */
static int
verify_no_time_check(int ok, X509_STORE_CTX *ctx)
{
  if (!ok) {
    int err = X509_STORE_CTX_get_error(ctx);
    if (err == X509_V_ERR_CERT_HAS_EXPIRED ||
        err == X509_V_ERR_CERT_NOT_YET_VALID) {
      X509_STORE_CTX_set_error(ctx, X509_V_OK);
      return 1;
    }
  }
  return ok;
}

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

int
TLS_Initialise(time_t (*get_time)(time_t *t))
{
  g_get_time = get_time;

  ssl_ex_data_inst_idx = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
  if (ssl_ex_data_inst_idx < 0) {
    LOG(LOGS_ERR, "Could not allocate SSL ex_data index");
    return 0;
  }

  sno_cert_data_idx = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, sno_cert_data_free);
  if (sno_cert_data_idx < 0) {
    LOG(LOGS_ERR, "Could not allocate SSL_CTX ex_data index");
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
    SnoCertData *scd = NULL;

    /* Server credentials: certificate chain + private key. */
    BRIEF_ASSERT(!trusted_certs && !trusted_certs_ids);

    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    if (n_certs_keys > 1) {
      scd = MallocNew(SnoCertData);
      scd->n_ctxs = 0;
      scd->ctxs = Malloc(n_certs_keys * sizeof(*scd->ctxs));
      /* Store immediately so SSL_CTX_free() in the error path frees it */
      SSL_CTX_set_ex_data(ctx, sno_cert_data_idx, scd);
    }

    for (i = 0; i < n_certs_keys; i++) {
      SSL_CTX *cert_ctx;

      if (!UTI_CheckFilePermissions(keys[i], 0771))
        ;

      if (!scd || i == 0) {
        cert_ctx = ctx;
      } else {
        /* Each additional cert gets its own CTX for SNI-based selection */
        cert_ctx = SSL_CTX_new(TLS_method());
        if (!cert_ctx) {
          LOG(LOGS_ERR, "Could not create SSL context for cert %s", certs[i]);
          goto error;
        }
        /* Store before any operation that can fail so it gets freed on error */
        scd->ctxs[scd->n_ctxs++] = cert_ctx;
        if (!SSL_CTX_set_min_proto_version(cert_ctx, TLS1_3_VERSION))
          goto error;
        SSL_CTX_set_options(cert_ctx, SSL_OP_NO_TICKET);
        SSL_CTX_set_verify(cert_ctx, SSL_VERIFY_NONE, NULL);
      }

      if (!SSL_CTX_use_certificate_chain_file(cert_ctx, certs[i])) {
        LOG(LOGS_ERR, "Could not load certificate from %s", certs[i]);
        goto error;
      }
      if (!SSL_CTX_use_PrivateKey_file(cert_ctx, keys[i], SSL_FILETYPE_PEM)) {
        LOG(LOGS_ERR, "Could not load private key from %s", keys[i]);
        goto error;
      }
      if (!SSL_CTX_check_private_key(cert_ctx)) {
        LOG(LOGS_ERR, "Certificate and key do not match: %s / %s", certs[i], keys[i]);
        goto error;
      }
    }

    if (scd) {
      /* Set ALPN callback on additional CTXs (main CTX gets it in TLS_CreateInstance) */
      for (i = 0; i < scd->n_ctxs; i++)
        SSL_CTX_set_alpn_select_cb(scd->ctxs[i], alpn_select_cb, NULL);
      SSL_CTX_set_tlsext_servername_callback(ctx, sno_cert_select_cb);
      SSL_CTX_set_tlsext_servername_arg(ctx, scd);
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
          /* An empty file (e.g. /dev/null) has no certs — not an error */
          if (sb.st_size == 0) {
            ERR_clear_error();
          } else {
            LOG(LOGS_ERR, "Could not load trusted certificate from %s", trusted_certs[i]);
            goto error;
          }
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

/* Custom socket BIO using recv/send instead of read/write.
   On Linux, OpenSSL's default socket BIO uses read()/write(), but in
   clknetsim those syscalls are not intercepted for virtual socket fds.
   recv()/send() ARE intercepted, so we route through them here. */

typedef struct {
  int fd;
  int eof;   /* set when recv() returns 0 (peer closed the connection) */
} CbioData;

static int cbio_write(BIO *b, const char *buf, int len)
{
  CbioData *d = BIO_get_data(b);
  int r;

  /* If we already received an EOF on the read side (e.g. the peer closed
     the TCP connection), refuse to write.  Without this guard, OpenSSL's
     attempt to send a TLS alert after an unexpected disconnect would call
     send() on a socket that clknetsim has already marked as disconnected,
     triggering an assertion in clknetsim's sendmsg. */
  if (d->eof) {
    errno = EPIPE;
    return -1;
  }

  r = send(d->fd, buf, len, MSG_NOSIGNAL);
  BIO_clear_retry_flags(b);
  if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
    BIO_set_retry_write(b);
  return r;
}

static int cbio_read(BIO *b, char *buf, int len)
{
  CbioData *d = BIO_get_data(b);
  int r;

  r = recv(d->fd, buf, len, 0);
  BIO_clear_retry_flags(b);
  if (r == 0) {
    d->eof = 1;
    BIO_set_flags(b, BIO_FLAGS_IN_EOF);
  } else if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
    BIO_set_retry_read(b);
  return r;
}

static long cbio_ctrl(BIO *b, int cmd, long num, void *ptr)
{
  switch (cmd) {
    case BIO_CTRL_FLUSH:
      return 1;
    case BIO_CTRL_EOF:
      return (BIO_get_flags(b) & BIO_FLAGS_IN_EOF) ? 1 : 0;
    case BIO_CTRL_PENDING:
    case BIO_CTRL_WPENDING:
      return 0;
    case BIO_CTRL_GET_CLOSE:
      return BIO_get_shutdown(b);
    case BIO_CTRL_SET_CLOSE:
      BIO_set_shutdown(b, (int)num);
      return 1;
    default:
      return 0;
  }
}

static int cbio_create(BIO *b)
{
  BIO_set_init(b, 0);
  BIO_set_data(b, NULL);
  return 1;
}

static int cbio_destroy(BIO *b)
{
  Free(BIO_get_data(b));
  BIO_set_data(b, NULL);
  return 1;
}

static BIO *make_socket_bio(int sock_fd)
{
  static BIO_METHOD *meth = NULL;
  CbioData *d;
  BIO *bio;

  if (!meth) {
    meth = BIO_meth_new(BIO_get_new_index() | BIO_TYPE_SOURCE_SINK,
                        "recv/send socket");
    if (!meth)
      return NULL;
    BIO_meth_set_write(meth, cbio_write);
    BIO_meth_set_read(meth, cbio_read);
    BIO_meth_set_ctrl(meth, cbio_ctrl);
    BIO_meth_set_create(meth, cbio_create);
    BIO_meth_set_destroy(meth, cbio_destroy);
  }

  d = Malloc(sizeof(*d));
  d->fd = sock_fd;
  d->eof = 0;

  bio = BIO_new(meth);
  if (!bio) {
    Free(d);
    return NULL;
  }
  BIO_set_data(bio, d);
  BIO_set_init(bio, 1);
  return bio;
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
  inst->disable_time_checks = disable_time_checks;
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

  {
    BIO *bio = make_socket_bio(sock_fd);
    if (!bio) {
      LOG(LOGS_ERR, "Could not create socket BIO");
      goto error;
    }
    SSL_set_bio(inst->ssl, bio, bio);
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

  if (disable_time_checks && !server_mode) {
    SSL_set_verify(inst->ssl, SSL_VERIFY_PEER, verify_no_time_check);
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
     each call so the time reflects when verification actually runs.
     Skip when disable_time_checks is set — the verify callback handles that. */
  if (g_get_time && !inst->server && !inst->disable_time_checks) {
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
      DEBUG_LOG("NTS-KE not supported by %s", inst->label);
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
        /* OpenSSL 3.x reports a remote TCP close mid-handshake as
           SSL_ERROR_SSL/SSL_R_UNEXPECTED_EOF_WHILE_READING rather than
           SSL_ERROR_SYSCALL.  Treat it the same as TLS_CLOSED so the
           NTS-KE session keeps the shorter CONNECT retry interval. */
        if (err == SSL_ERROR_SSL &&
            ERR_GET_REASON(ERR_peek_error()) == SSL_R_UNEXPECTED_EOF_WHILE_READING) {
          ERR_clear_error();
          return TLS_CLOSED;
        }

        verify_result = SSL_get_verify_result(inst->ssl);
        if (verify_result != X509_V_OK) {
          const char *errstr = verify_result == X509_V_ERR_CERT_HAS_EXPIRED ?
                               "expired certificate" :
                               X509_verify_cert_error_string(verify_result);
          LOG(inst->server ? LOGS_DEBUG : LOGS_ERR,
              "TLS handshake with %s failed : %s", inst->label, errstr);
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
