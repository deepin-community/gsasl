/* client.c --- SASL SCRAM client side functions.
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

/* Get malloc, free. */
#include <stdlib.h>

/* Get memcpy, strlen, strchr. */
#include <string.h>

/* Get bool. */
#include <stdbool.h>

#include "tokens.h"
#include "parser.h"
#include "printer.h"
#include "gc.h"
#include "memxor.h"
#include "tools.h"
#include "mechtools.h"

#define CNONCE_ENTROPY_BYTES 18

struct scram_client_state
{
  bool plus;
  Gsasl_hash hash;
  int step;
  char *cfmb;			/* client first message bare */
  char *serversignature;
  char *authmessage;
  char *cbtlsunique;
  size_t cbtlsuniquelen;
  struct scram_client_first cf;
  struct scram_server_first sf;
  struct scram_client_final cl;
  struct scram_server_final sl;
};

static int
scram_start (Gsasl_session * sctx _GL_UNUSED,
	     void **mech_data, bool plus, Gsasl_hash hash)
{
  struct scram_client_state *state;
  char buf[CNONCE_ENTROPY_BYTES];
  int rc;

  state = (struct scram_client_state *) calloc (sizeof (*state), 1);
  if (state == NULL)
    return GSASL_MALLOC_ERROR;

  state->plus = plus;
  state->hash = hash;

  rc = gsasl_nonce (buf, CNONCE_ENTROPY_BYTES);
  if (rc != GSASL_OK)
    {
      free (state);
      return rc;
    }

  rc = gsasl_base64_to (buf, CNONCE_ENTROPY_BYTES,
			&state->cf.client_nonce, NULL);
  if (rc != GSASL_OK)
    {
      free (state);
      return rc;
    }

  *mech_data = state;

  return GSASL_OK;
}

#ifdef USE_SCRAM_SHA1
int
_gsasl_scram_sha1_client_start (Gsasl_session * sctx, void **mech_data)
{
  return scram_start (sctx, mech_data, false, GSASL_HASH_SHA1);
}

int
_gsasl_scram_sha1_plus_client_start (Gsasl_session * sctx, void **mech_data)
{
  return scram_start (sctx, mech_data, true, GSASL_HASH_SHA1);
}
#endif

#ifdef USE_SCRAM_SHA256
int
_gsasl_scram_sha256_client_start (Gsasl_session * sctx, void **mech_data)
{
  return scram_start (sctx, mech_data, false, GSASL_HASH_SHA256);
}

int
_gsasl_scram_sha256_plus_client_start (Gsasl_session * sctx, void **mech_data)
{
  return scram_start (sctx, mech_data, true, GSASL_HASH_SHA256);
}
#endif

int
_gsasl_scram_client_step (Gsasl_session * sctx,
			  void *mech_data,
			  const char *input, size_t input_len,
			  char **output, size_t *output_len)
{
  struct scram_client_state *state = mech_data;
  int res = GSASL_MECHANISM_CALLED_TOO_MANY_TIMES;
  int rc;

  *output = NULL;
  *output_len = 0;

  switch (state->step)
    {
    case 0:
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

	if (state->plus)
	  {
	    state->cf.cbflag = 'p';
	    state->cf.cbname = strdup ("tls-unique");
	  }
	else
	  {
	    if (state->cbtlsuniquelen > 0)
	      state->cf.cbflag = 'y';
	    else
	      state->cf.cbflag = 'n';
	  }

	p = gsasl_property_get (sctx, GSASL_AUTHID);
	if (!p)
	  return GSASL_NO_AUTHID;

	rc = gsasl_saslprep (p, GSASL_ALLOW_UNASSIGNED,
			     &state->cf.username, NULL);
	if (rc != GSASL_OK)
	  return rc;

	p = gsasl_property_get (sctx, GSASL_AUTHZID);
	if (p)
	  state->cf.authzid = strdup (p);

	rc = scram_print_client_first (&state->cf, output);
	if (rc == -2)
	  return GSASL_MALLOC_ERROR;
	else if (rc != 0)
	  return GSASL_AUTHENTICATION_ERROR;

	*output_len = strlen (*output);

	/* Point p to client-first-message-bare. */
	p = strchr (*output, ',');
	if (!p)
	  return GSASL_AUTHENTICATION_ERROR;
	p++;
	p = strchr (p, ',');
	if (!p)
	  return GSASL_AUTHENTICATION_ERROR;
	p++;

	/* Save "client-first-message-bare" for the next step. */
	state->cfmb = strdup (p);
	if (!state->cfmb)
	  return GSASL_MALLOC_ERROR;

	/* Prepare B64("cbind-input") for the next step. */
	if (state->cf.cbflag == 'p')
	  {
	    size_t len = (p - *output) + state->cbtlsuniquelen;
	    char *cbind_input = malloc (len);
	    if (cbind_input == NULL)
	      return GSASL_MALLOC_ERROR;
	    memcpy (cbind_input, *output, p - *output);
	    memcpy (cbind_input + (p - *output), state->cbtlsunique,
		    state->cbtlsuniquelen);
	    rc = gsasl_base64_to (cbind_input, len, &state->cl.cbind, NULL);
	    free (cbind_input);
	  }
	else
	  rc = gsasl_base64_to (*output, p - *output, &state->cl.cbind, NULL);
	if (rc != 0)
	  return rc;

	/* We are done. */
	state->step++;
	return GSASL_NEEDS_MORE;
	break;
      }

    case 1:
      {
	if (scram_parse_server_first (input, input_len, &state->sf) < 0)
	  return GSASL_MECHANISM_PARSE_ERROR;

	if (strlen (state->sf.nonce) < strlen (state->cf.client_nonce) ||
	    memcmp (state->cf.client_nonce, state->sf.nonce,
		    strlen (state->cf.client_nonce)) != 0)
	  return GSASL_AUTHENTICATION_ERROR;

	state->cl.nonce = strdup (state->sf.nonce);
	if (!state->cl.nonce)
	  return GSASL_MALLOC_ERROR;

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

	gsasl_property_set (sctx, GSASL_SCRAM_SALT, state->sf.salt);

	/* Generate ClientProof. */
	{
	  char saltedpassword[GSASL_HASH_MAX_SIZE];
	  char clientkey[GSASL_HASH_MAX_SIZE];
	  char serverkey[GSASL_HASH_MAX_SIZE];
	  char storedkey[GSASL_HASH_MAX_SIZE];
	  const char *p;

	  /* Get SaltedPassword. */

	  if ((p = gsasl_property_get (sctx, GSASL_SCRAM_SALTED_PASSWORD))
	      && (strlen (p) == 2 * gsasl_hash_length (state->hash))
	      && _gsasl_hex_p (p))
	    {
	      _gsasl_hex_decode (p, saltedpassword);

	      rc = gsasl_scram_secrets_from_salted_password (state->hash,
							     saltedpassword,
							     clientkey,
							     serverkey,
							     storedkey);
	      if (rc != 0)
		return rc;
	    }
	  else if ((p = gsasl_property_get (sctx, GSASL_PASSWORD)) != NULL)
	    {
	      char *salt;
	      size_t saltlen;

	      rc = gsasl_base64_from (state->sf.salt, strlen (state->sf.salt),
				      &salt, &saltlen);
	      if (rc != 0)
		return rc;

	      rc = gsasl_scram_secrets_from_password (state->hash,
						      p,
						      state->sf.iter,
						      salt, saltlen,
						      saltedpassword,
						      clientkey,
						      serverkey, storedkey);
	      if (rc != 0)
		return rc;

	      set_saltedpassword (sctx, state->hash, saltedpassword);

	      gsasl_free (salt);
	    }
	  else
	    return GSASL_NO_PASSWORD;

	  /* Get client-final-message-without-proof. */
	  {
	    char *cfmwp;
	    int n;

	    state->cl.proof = strdup ("p");
	    rc = scram_print_client_final (&state->cl, &cfmwp);
	    if (rc != 0)
	      return GSASL_MALLOC_ERROR;
	    free (state->cl.proof);

	    /* Compute AuthMessage */
	    n = asprintf (&state->authmessage, "%s,%.*s,%.*s",
			  state->cfmb,
			  (int) input_len, input,
			  (int) (strlen (cfmwp) - 4), cfmwp);
	    free (cfmwp);
	    if (n <= 0 || !state->authmessage)
	      return GSASL_MALLOC_ERROR;
	  }

	  {
	    char clientsignature[GSASL_HASH_MAX_SIZE];
	    char clientproof[GSASL_HASH_MAX_SIZE];

	    /* ClientSignature := HMAC(StoredKey, AuthMessage) */
	    rc = _gsasl_hmac (state->hash,
			      storedkey,
			      gsasl_hash_length (state->hash),
			      state->authmessage,
			      strlen (state->authmessage), clientsignature);
	    if (rc != 0)
	      return rc;

	    /* ClientProof := ClientKey XOR ClientSignature */
	    memcpy (clientproof, clientkey, gsasl_hash_length (state->hash));
	    memxor (clientproof, clientsignature,
		    gsasl_hash_length (state->hash));

	    rc =
	      gsasl_base64_to (clientproof, gsasl_hash_length (state->hash),
			       &state->cl.proof, NULL);
	    if (rc != 0)
	      return rc;
	  }

	  /* Generate ServerSignature, for comparison in next step. */
	  {
	    char serversignature[GSASL_HASH_MAX_SIZE];

	    /* ServerSignature := HMAC(ServerKey, AuthMessage) */
	    rc = _gsasl_hmac (state->hash,
			      serverkey, gsasl_hash_length (state->hash),
			      state->authmessage,
			      strlen (state->authmessage), serversignature);
	    if (rc != 0)
	      return rc;

	    rc = gsasl_base64_to (serversignature,
				  gsasl_hash_length (state->hash),
				  &state->serversignature, NULL);
	    if (rc != 0)
	      return rc;
	  }
	}

	rc = scram_print_client_final (&state->cl, output);
	if (rc != 0)
	  return GSASL_MALLOC_ERROR;

	*output_len = strlen (*output);

	state->step++;
	return GSASL_NEEDS_MORE;
	break;
      }

    case 2:
      {
	if (scram_parse_server_final (input, input_len, &state->sl) < 0)
	  return GSASL_MECHANISM_PARSE_ERROR;

	if (strcmp (state->sl.verifier, state->serversignature) != 0)
	  return GSASL_AUTHENTICATION_ERROR;

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
_gsasl_scram_client_finish (Gsasl_session * sctx _GL_UNUSED, void *mech_data)
{
  struct scram_client_state *state = mech_data;

  if (!state)
    return;

  free (state->cfmb);
  free (state->serversignature);
  free (state->authmessage);
  free (state->cbtlsunique);
  scram_free_client_first (&state->cf);
  scram_free_server_first (&state->sf);
  scram_free_client_final (&state->cl);
  scram_free_server_final (&state->sl);

  free (state);
}
