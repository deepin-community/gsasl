/* server.c --- SASL CRAM-MD5 server side functions.
 * Copyright (C) 2009-2021 Simon Josefsson
 *
 * This file is part of GNU SASL Library.
 *
 * GNU SASL Library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * GNU SASL Library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with GNU SASL Library; if not, write to the Free
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/* Get specification. */
#include "scram.h"

/* Get malloc, free, strtoul. */
#include <stdlib.h>

/* Get ULONG_MAX. */
#include <limits.h>

/* Get memcpy, strdup, strlen. */
#include <string.h>

/* Get MAX. */
#include "minmax.h"

#include "tokens.h"
#include "parser.h"
#include "printer.h"
#include "gc.h"
#include "memxor.h"
#include "tools.h"
#include "mechtools.h"

#define DEFAULT_SALT_BYTES 12
#define SNONCE_ENTROPY_BYTES 18

struct scram_server_state
{
  bool plus;
  Gsasl_hash hash;
  int step;
  char *cbind;
  char *gs2header;		/* copy of client first gs2-header */
  char *cfmb_str;		/* copy of client first message bare */
  char *sf_str;			/* copy of server first message */
  char *snonce;
  char *clientproof;
  char storedkey[GSASL_HASH_MAX_SIZE];
  char serverkey[GSASL_HASH_MAX_SIZE];
  char *authmessage;
  char *cbtlsunique;
  size_t cbtlsuniquelen;
  struct scram_client_first cf;
  struct scram_server_first sf;
  struct scram_client_final cl;
  struct scram_server_final sl;
};

static int
scram_start (Gsasl_session * sctx _GL_UNUSED, void **mech_data,
	     bool plus, Gsasl_hash hash)
{
  struct scram_server_state *state;
  char buf[MAX (SNONCE_ENTROPY_BYTES, DEFAULT_SALT_BYTES)];
  int rc;

  state = (struct scram_server_state *) calloc (sizeof (*state), 1);
  if (state == NULL)
    return GSASL_MALLOC_ERROR;

  state->plus = plus;
  state->hash = hash;

  rc = gsasl_nonce (buf, SNONCE_ENTROPY_BYTES);
  if (rc != GSASL_OK)
    goto end;

  rc = gsasl_base64_to (buf, SNONCE_ENTROPY_BYTES, &state->snonce, NULL);
  if (rc != GSASL_OK)
    goto end;

  rc = gsasl_nonce (buf, DEFAULT_SALT_BYTES);
  if (rc != GSASL_OK)
    goto end;

  rc = gsasl_base64_to (buf, DEFAULT_SALT_BYTES, &state->sf.salt, NULL);
  if (rc != GSASL_OK)
    goto end;

  *mech_data = state;

  return GSASL_OK;

end:
  free (state->sf.salt);
  free (state->snonce);
  free (state);
  return rc;
}

#ifdef USE_SCRAM_SHA1
int
_gsasl_scram_sha1_server_start (Gsasl_session * sctx, void **mech_data)
{
  return scram_start (sctx, mech_data, false, GSASL_HASH_SHA1);
}

int
_gsasl_scram_sha1_plus_server_start (Gsasl_session * sctx, void **mech_data)
{
  return scram_start (sctx, mech_data, true, GSASL_HASH_SHA1);
}
#endif

#ifdef USE_SCRAM_SHA256
int
_gsasl_scram_sha256_server_start (Gsasl_session * sctx, void **mech_data)
{
  return scram_start (sctx, mech_data, false, GSASL_HASH_SHA256);
}

int
_gsasl_scram_sha256_plus_server_start (Gsasl_session * sctx, void **mech_data)
{
  return scram_start (sctx, mech_data, true, GSASL_HASH_SHA256);
}
#endif

static int
extract_serverkey (struct scram_server_state *state,
		   const char *b64, char *buf)
{
  char *bin;
  size_t binlen;
  int rc;

  rc = gsasl_base64_from (b64, strlen (b64), &bin, &binlen);
  if (rc != GSASL_OK)
    return rc;

  if (binlen != gsasl_hash_length (state->hash))
    {
      free (bin);
      return GSASL_AUTHENTICATION_ERROR;
    }

  memcpy (buf, bin, binlen);

  free (bin);

  return GSASL_OK;
}

int
_gsasl_scram_server_step (Gsasl_session * sctx,
			  void *mech_data,
			  const char *input,
			  size_t input_len, char **output, size_t *output_len)
{
  struct scram_server_state *state = mech_data;
  int res = GSASL_MECHANISM_CALLED_TOO_MANY_TIMES;
  int rc;

  *output = NULL;
  *output_len = 0;

  switch (state->step)
    {
    case 0:
      {
	if (input_len == 0)
	  return GSASL_NEEDS_MORE;

	{
	  const char *p;

	  p = gsasl_property_get (sctx, GSASL_CB_TLS_UNIQUE);
	  if (state->plus && !p)
	    return GSASL_NO_CB_TLS_UNIQUE;
	  if (p)
	    {
	      rc = gsasl_base64_from (p, strlen (p), &state->cbtlsunique,
				      &state->cbtlsuniquelen);
	      if (rc != GSASL_OK)
		return rc;
	    }
	}

	if (scram_parse_client_first (input, input_len, &state->cf) < 0)
	  return GSASL_MECHANISM_PARSE_ERROR;

	/* In PLUS server mode, we require use of channel bindings. */
	if (state->plus && state->cf.cbflag != 'p')
	  return GSASL_AUTHENTICATION_ERROR;

	/* In non-PLUS mode, but where have channel bindings data (and
	   thus advertised PLUS) we reject a client 'y' cbflag. */
	if (!state->plus
	    && state->cbtlsuniquelen > 0 && state->cf.cbflag == 'y')
	  return GSASL_AUTHENTICATION_ERROR;

	/* Check that username doesn't fail SASLprep. */
	{
	  char *tmp;
	  rc = gsasl_saslprep (state->cf.username, GSASL_ALLOW_UNASSIGNED,
			       &tmp, NULL);
	  if (rc != GSASL_OK || *tmp == '\0')
	    return GSASL_AUTHENTICATION_ERROR;
	  gsasl_free (tmp);
	}

	{
	  const char *p;

	  /* Save "gs2-header" and "message-bare" for next step. */
	  p = memchr (input, ',', input_len);
	  if (!p)
	    return GSASL_AUTHENTICATION_ERROR;
	  p++;
	  p = memchr (p, ',', input_len - (p - input));
	  if (!p)
	    return GSASL_AUTHENTICATION_ERROR;
	  p++;

	  state->gs2header = malloc (p - input + 1);
	  if (!state->gs2header)
	    return GSASL_MALLOC_ERROR;
	  memcpy (state->gs2header, input, p - input);
	  state->gs2header[p - input] = '\0';

	  state->cfmb_str = malloc (input_len - (p - input) + 1);
	  if (!state->cfmb_str)
	    return GSASL_MALLOC_ERROR;
	  memcpy (state->cfmb_str, p, input_len - (p - input));
	  state->cfmb_str[input_len - (p - input)] = '\0';
	}

	/* Create new nonce. */
	{
	  size_t cnlen = strlen (state->cf.client_nonce);
	  size_t snlen = strlen (state->snonce);

	  state->sf.nonce = malloc (cnlen + snlen + 1);
	  if (!state->sf.nonce)
	    return GSASL_MALLOC_ERROR;

	  memcpy (state->sf.nonce, state->cf.client_nonce, cnlen);
	  memcpy (state->sf.nonce + cnlen, state->snonce, snlen);
	  state->sf.nonce[cnlen + snlen] = '\0';
	}

	gsasl_property_set (sctx, GSASL_AUTHID, state->cf.username);
	gsasl_property_set (sctx, GSASL_AUTHZID, state->cf.authzid);

	{
	  const char *p = gsasl_property_get (sctx, GSASL_SCRAM_ITER);

	  if (p)
	    state->sf.iter = strtoul (p, NULL, 10);
	  if (!p || state->sf.iter == 0 || state->sf.iter == ULONG_MAX)
	    state->sf.iter = 4096;

	  /* Save salt/iter as properties, so that client callback can
	     access them. */
	  {
	    char *str = NULL;
	    int n;
	    n = asprintf (&str, "%zu", state->sf.iter);
	    if (n < 0 || str == NULL)
	      return GSASL_MALLOC_ERROR;
	    gsasl_property_set (sctx, GSASL_SCRAM_ITER, str);
	    free (str);
	  }
	}

	{
	  const char *p = gsasl_property_get (sctx, GSASL_SCRAM_SALT);
	  if (p)
	    {
	      free (state->sf.salt);
	      state->sf.salt = strdup (p);
	    }
	  else
	    gsasl_property_set (sctx, GSASL_SCRAM_SALT, state->sf.salt);
	}

	rc = scram_print_server_first (&state->sf, &state->sf_str);
	if (rc != 0)
	  return GSASL_MALLOC_ERROR;

	*output = strdup (state->sf_str);
	if (!*output)
	  return GSASL_MALLOC_ERROR;
	*output_len = strlen (*output);

	state->step++;
	return GSASL_NEEDS_MORE;
	break;
      }

    case 1:
      {
	if (scram_parse_client_final (input, input_len, &state->cl) < 0)
	  return GSASL_MECHANISM_PARSE_ERROR;

	if (strcmp (state->cl.nonce, state->sf.nonce) != 0)
	  return GSASL_AUTHENTICATION_ERROR;

	/* Base64 decode the c= field and check that it matches
	   client-first.  Also check channel binding data. */
	{
	  size_t len;

	  rc = gsasl_base64_from (state->cl.cbind, strlen (state->cl.cbind),
				  &state->cbind, &len);
	  if (rc != 0)
	    return rc;

	  if (state->cf.cbflag == 'p')
	    {
	      if (len < strlen (state->gs2header))
		return GSASL_AUTHENTICATION_ERROR;

	      if (memcmp (state->cbind, state->gs2header,
			  strlen (state->gs2header)) != 0)
		return GSASL_AUTHENTICATION_ERROR;

	      if (len - strlen (state->gs2header) != state->cbtlsuniquelen)
		return GSASL_AUTHENTICATION_ERROR;

	      if (memcmp (state->cbind + strlen (state->gs2header),
			  state->cbtlsunique, state->cbtlsuniquelen) != 0)
		return GSASL_AUTHENTICATION_ERROR;
	    }
	  else
	    {
	      if (len != strlen (state->gs2header))
		return GSASL_AUTHENTICATION_ERROR;

	      if (memcmp (state->cbind, state->gs2header, len) != 0)
		return GSASL_AUTHENTICATION_ERROR;
	    }
	}

	/* Base64 decode client proof and check that length matches
	   hash size. */
	{
	  size_t len;

	  rc = gsasl_base64_from (state->cl.proof, strlen (state->cl.proof),
				  &state->clientproof, &len);
	  if (rc != 0)
	    return rc;
	  if (gsasl_hash_length (state->hash) != len)
	    return GSASL_MECHANISM_PARSE_ERROR;
	}
	{
	  const char *p, *q;

	  /* Get StoredKey and ServerKey */
	  if ((p = gsasl_property_get (sctx, GSASL_SCRAM_SERVERKEY))
	      && (q = gsasl_property_get (sctx, GSASL_SCRAM_STOREDKEY)))
	    {
	      rc = extract_serverkey (state, p, state->serverkey);
	      if (rc != GSASL_OK)
		return rc;
	      rc = extract_serverkey (state, q, state->storedkey);
	      if (rc != GSASL_OK)
		return rc;
	    }
	  else if ((p = gsasl_property_get (sctx, GSASL_PASSWORD)))
	    {
	      char *salt;
	      size_t saltlen;
	      char saltedpassword[GSASL_HASH_MAX_SIZE];
	      char clientkey[GSASL_HASH_MAX_SIZE];
	      char *b64str;

	      rc = gsasl_base64_from (state->sf.salt, strlen (state->sf.salt),
				      &salt, &saltlen);
	      if (rc != GSASL_OK)
		return rc;

	      rc = gsasl_scram_secrets_from_password (state->hash,
						      p,
						      state->sf.iter,
						      salt, saltlen,
						      saltedpassword,
						      clientkey,
						      state->serverkey,
						      state->storedkey);
	      if (rc != GSASL_OK)
		return rc;

	      set_saltedpassword (sctx, state->hash, saltedpassword);

	      rc = gsasl_base64_to (state->serverkey,
				    gsasl_hash_length (state->hash),
				    &b64str, NULL);
	      if (rc != 0)
		return rc;
	      gsasl_property_set (sctx, GSASL_SCRAM_SERVERKEY, b64str);
	      free (b64str);


	      rc = gsasl_base64_to (state->storedkey,
				    gsasl_hash_length (state->hash),
				    &b64str, NULL);
	      if (rc != 0)
		return rc;
	      gsasl_property_set (sctx, GSASL_SCRAM_STOREDKEY, b64str);
	      free (b64str);

	      gsasl_free (salt);
	    }
	  else
	    return GSASL_NO_PASSWORD;

	  /* Compute AuthMessage */
	  {
	    size_t len;
	    int n;

	    /* Get client-final-message-without-proof. */
	    p = memmem (input, input_len, ",p=", 3);
	    if (!p)
	      return GSASL_MECHANISM_PARSE_ERROR;
	    len = p - input;

	    n = asprintf (&state->authmessage, "%s,%.*s,%.*s",
			  state->cfmb_str,
			  (int) strlen (state->sf_str), state->sf_str,
			  (int) len, input);
	    if (n <= 0 || !state->authmessage)
	      return GSASL_MALLOC_ERROR;
	  }

	  /* Check client proof. */
	  {
	    char clientsignature[GSASL_HASH_MAX_SIZE];
	    char maybe_storedkey[GSASL_HASH_MAX_SIZE];

	    /* ClientSignature := HMAC(StoredKey, AuthMessage) */
	    rc = _gsasl_hmac (state->hash,
			      state->storedkey,
			      gsasl_hash_length (state->hash),
			      state->authmessage, strlen (state->authmessage),
			      clientsignature);
	    if (rc != 0)
	      return rc;

	    /* ClientKey := ClientProof XOR ClientSignature */
	    memxor (clientsignature, state->clientproof,
		    gsasl_hash_length (state->hash));

	    rc = _gsasl_hash (state->hash, clientsignature,
			      gsasl_hash_length (state->hash),
			      maybe_storedkey);
	    if (rc != 0)
	      return rc;

	    rc = memcmp (state->storedkey, maybe_storedkey,
			 gsasl_hash_length (state->hash));
	    if (rc != 0)
	      return GSASL_AUTHENTICATION_ERROR;
	  }

	  /* Generate server verifier. */
	  {
	    char serversignature[GSASL_HASH_MAX_SIZE];

	    /* ServerSignature := HMAC(ServerKey, AuthMessage) */
	    rc = _gsasl_hmac (state->hash, state->serverkey,
			      gsasl_hash_length (state->hash),
			      state->authmessage,
			      strlen (state->authmessage), serversignature);
	    if (rc != 0)
	      return rc;

	    rc = gsasl_base64_to (serversignature,
				  gsasl_hash_length (state->hash),
				  &state->sl.verifier, NULL);
	    if (rc != 0)
	      return rc;
	  }
	}

	rc = scram_print_server_final (&state->sl, output);
	if (rc != 0)
	  return GSASL_MALLOC_ERROR;
	*output_len = strlen (*output);

	state->step++;
	return GSASL_OK;
	break;
      }

    default:
      break;
    }

  return res;
}

void
_gsasl_scram_server_finish (Gsasl_session * sctx _GL_UNUSED, void *mech_data)
{
  struct scram_server_state *state = mech_data;

  if (!state)
    return;

  free (state->cbind);
  free (state->gs2header);
  free (state->cfmb_str);
  free (state->sf_str);
  free (state->snonce);
  free (state->clientproof);
  free (state->authmessage);
  free (state->cbtlsunique);
  scram_free_client_first (&state->cf);
  scram_free_server_first (&state->sf);
  scram_free_client_final (&state->cl);
  scram_free_server_final (&state->sl);

  free (state);
}
