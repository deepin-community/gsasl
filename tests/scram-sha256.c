/* scram-sha256.c --- Test the SCRAM-SHA256 mechanism.
 * Copyright (C) 2009-2021 Simon Josefsson
 *
 * This file is part of GNU SASL.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "utils.h"

#define USERNAME "user"
#define PASSWORD "pencil"

static int
callback (Gsasl * ctx, Gsasl_session * sctx, Gsasl_property prop)
{
  int rc = GSASL_NO_CALLBACK;

  /* Get user info from user. */

  switch (prop)
    {
    case GSASL_PASSWORD:
      gsasl_property_set (sctx, prop, PASSWORD);
      rc = GSASL_OK;
      break;

    case GSASL_AUTHID:
      gsasl_property_set (sctx, prop, USERNAME);
      rc = GSASL_OK;
      break;

      /* SCRAM/SALT: Attempt to reproduce RFC 7677 test vector.
         Requires that SCRAMDEBUG=1 when compiling so that
         client/server nonce ends up the same as in the document.  */

    case GSASL_SCRAM_ITER:
      if (strcmp (gsasl_property_fast (sctx, GSASL_AUTHID), USERNAME) != 0)
	fail ("Username mismatch: %s",
	      gsasl_property_fast (sctx, GSASL_AUTHID));
      gsasl_property_set (sctx, prop, "4096");
      rc = GSASL_OK;
      break;

    case GSASL_SCRAM_SALT:
      gsasl_property_set (sctx, prop, "W22ZaJ0SNY7soEsUEjb6gQ==");
      rc = GSASL_OK;
      break;

    case GSASL_CB_TLS_UNIQUE:
    case GSASL_AUTHZID:
    case GSASL_SCRAM_SALTED_PASSWORD:
    case GSASL_SCRAM_SERVERKEY:
    case GSASL_SCRAM_STOREDKEY:
      break;

    default:
      fail ("Unknown callback property %u\n", prop);
      break;
    }

  return rc;
}

void
doit (void)
{
  Gsasl *ctx = NULL;
  Gsasl_session *server = NULL, *client = NULL;
  char *s1, *s2;
  size_t s1len, s2len;
  int res;

  res = gsasl_init (&ctx);
  if (res != GSASL_OK)
    {
      fail ("gsasl_init() failed (%d):\n%s\n", res, gsasl_strerror (res));
      return;
    }

  if (!gsasl_client_support_p (ctx, "SCRAM-SHA-256")
      || !gsasl_server_support_p (ctx, "SCRAM-SHA-256"))
    {
      gsasl_done (ctx);
      fail ("No support for SCRAM-SHA-256.\n");
      exit (77);
    }

  gsasl_callback_set (ctx, callback);

  res = gsasl_server_start (ctx, "SCRAM-SHA-256", &server);
  if (res != GSASL_OK)
    {
      fail ("gsasl_server_start() failed (%d):\n%s\n",
	    res, gsasl_strerror (res));
      return;
    }
  res = gsasl_client_start (ctx, "SCRAM-SHA-256", &client);
  if (res != GSASL_OK)
    {
      fail ("gsasl_client_start() failed (%d):\n%s\n",
	    res, gsasl_strerror (res));
      return;
    }

  s1 = NULL;
  s1len = 0;

  /* Client first... */

  res = gsasl_step (client, s1, s1len, &s1, &s1len);
  if (res != GSASL_NEEDS_MORE)
    {
      fail ("gsasl_step(1) failed (%d):\n%s\n", res, gsasl_strerror (res));
      return;
    }

  if (debug)
    printf ("C: %.*s [%c]\n", (int) s1len, s1, res == GSASL_OK ? 'O' : 'N');

  /* Server first... */

  res = gsasl_step (server, s1, s1len, &s2, &s2len);
  gsasl_free (s1);
  if (res != GSASL_NEEDS_MORE)
    {
      fail ("gsasl_step(2) failed (%d):\n%s\n", res, gsasl_strerror (res));
      return;
    }

  if (debug)
    printf ("S: %.*s [%c]\n", (int) s2len, s2, res == GSASL_OK ? 'O' : 'N');

  /* Client final... */

  res = gsasl_step (client, s2, s2len, &s1, &s1len);
  gsasl_free (s2);
  if (res != GSASL_NEEDS_MORE)
    {
      fail ("gsasl_step(3) failed (%d):\n%s\n", res, gsasl_strerror (res));
      return;
    }

  if (debug)
    printf ("C: %.*s [%c]\n", (int) s1len, s1, res == GSASL_OK ? 'O' : 'N');

  /* Server final... */

  res = gsasl_step (server, s1, s1len, &s2, &s2len);
  gsasl_free (s1);
  if (res != GSASL_OK)
    {
      fail ("gsasl_step(4) failed (%d):\n%s\n", res, gsasl_strerror (res));
      return;
    }

  if (debug)
    printf ("S: %.*s [%c]\n", (int) s2len, s2, res == GSASL_OK ? 'O' : 'N');

  /* Let client parse server final... */

  res = gsasl_step (client, s2, s2len, &s1, &s1len);
  gsasl_free (s2);
  if (res != GSASL_OK)
    {
      fail ("gsasl_step(5) failed (%d):\n%s\n", res, gsasl_strerror (res));
      return;
    }

  if (s1len != 0)
    fail ("dummy final client step produced output?!\n");

  {
    const char *p = gsasl_property_fast (server, GSASL_AUTHID);
    if (p && strcmp (p, USERNAME) != 0)
      fail ("Bad authid? %s != %s\n", p, USERNAME);
  }

  {
    const char *sp =
      gsasl_property_fast (client, GSASL_SCRAM_SALTED_PASSWORD);
    if (!sp
	|| strcmp (sp,
		   "c4a49510323ab4f952cac1fa99441939"
		   "e78ea74d6be81ddf7096e87513dc615d") != 0)
      fail ("client didn't set salted password: %s\n",
	    gsasl_property_fast (client, GSASL_SCRAM_SALTED_PASSWORD));
  }

  {
    const char *sp =
      gsasl_property_fast (server, GSASL_SCRAM_SALTED_PASSWORD);
    if (!sp
	|| strcmp (sp,
		   "c4a49510323ab4f952cac1fa99441939"
		   "e78ea74d6be81ddf7096e87513dc615d") != 0)
      fail ("server didn't set salted password: %s\n",
	    gsasl_property_fast (client, GSASL_SCRAM_SALTED_PASSWORD));
  }

  if (debug)
    printf ("\n");

  gsasl_finish (client);
  gsasl_finish (server);

  gsasl_done (ctx);
}
