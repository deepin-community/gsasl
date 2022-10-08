/* scram-nopasswd.c --- Test the SCRAM-SHA256 mechanism.
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

/* This self-test is about making sure SCRAM works without a supplied
   password both in client and server mode. */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "utils.h"

/*
  $ src/gsasl --mkpasswd --password pencil --mechanism SCRAM-SHA-256 --iteration-count 4096 --salt 8tkvpwuPHUIvxZdV
  SCRAM-SHA-256:4096:8tkvpwuPHUIvxZdV:kx5HW/tXBntkDU9vYAphILpp9GkCBpYXdb7G6n5B/y4=:CwOgbBjlXTbH2gXK5XKich7UnzHrMh5vre1ipvSW0jE=:9e1uUmKhrFexDKE2zfHs3aCuRANzfnf5EQG6MFXvmKM=
  $
 */

#define USERNAME "user"
#define ITER "4096"
#define SALT "8tkvpwuPHUIvxZdV"
#define SALTED_PASSWORD "931e475bfb57067b640d4f6f600a6120" \
  "ba69f4690206961775bec6ea7e41ff2e"
#define SERVERKEY "CwOgbBjlXTbH2gXK5XKich7UnzHrMh5vre1ipvSW0jE="
#define STOREDKEY "9e1uUmKhrFexDKE2zfHs3aCuRANzfnf5EQG6MFXvmKM="

static int
callback (Gsasl * ctx, Gsasl_session * sctx, Gsasl_property prop)
{
  int rc = GSASL_NO_CALLBACK;

  /* Get user info from user. */

  switch (prop)
    {
    case GSASL_SCRAM_SALTED_PASSWORD:
      gsasl_property_set (sctx, prop, SALTED_PASSWORD);
      rc = GSASL_OK;
      break;

    case GSASL_SCRAM_SERVERKEY:
      gsasl_property_set (sctx, prop, SERVERKEY);
      rc = GSASL_OK;
      break;

    case GSASL_SCRAM_STOREDKEY:
      gsasl_property_set (sctx, prop, STOREDKEY);
      rc = GSASL_OK;
      break;

    case GSASL_SCRAM_ITER:
      gsasl_property_set (sctx, prop, ITER);
      rc = GSASL_OK;
      break;

    case GSASL_SCRAM_SALT:
      gsasl_property_set (sctx, prop, SALT);
      rc = GSASL_OK;
      break;

    case GSASL_AUTHID:
      gsasl_property_set (sctx, prop, USERNAME);
      rc = GSASL_OK;
      break;

    case GSASL_PASSWORD:
    case GSASL_CB_TLS_UNIQUE:
    case GSASL_AUTHZID:
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
    if (debug)
      printf ("GSASL_AUTHID: %s\n", p);
  }

  {
    const char *ci = gsasl_property_fast (client, GSASL_SCRAM_ITER);
    const char *si = gsasl_property_fast (server, GSASL_SCRAM_ITER);
    if (debug)
      {
	printf ("GSASL_SCRAM_ITER (client): %s\n", ci);
	printf ("GSASL_SCRAM_ITER (server): %s\n", si);
      }
    if (!ci || !si || strcmp (ci, si) != 0)
      fail ("scram iter mismatch\n");
  }

  {
    const char *cs = gsasl_property_fast (client, GSASL_SCRAM_SALT);
    const char *ss = gsasl_property_fast (server, GSASL_SCRAM_SALT);
    if (debug)
      {
	printf ("GSASL_SCRAM_ITER (client): %s\n", cs);
	printf ("GSASL_SCRAM_ITER (server): %s\n", ss);
      }
    if (!cs || !ss || strcmp (cs, ss) != 0)
      fail ("scram salt mismatch\n");
  }

  {
    const char *csp =
      gsasl_property_fast (client, GSASL_SCRAM_SALTED_PASSWORD);
    const char *ssp =
      gsasl_property_fast (server, GSASL_SCRAM_SALTED_PASSWORD);

    if (debug)
      {
	printf ("GSASL_SCRAM_SALTED_PASSWORD (client): %s\n", csp);
	printf ("GSASL_SCRAM_SALTED_PASSWORD (server): %s\n", ssp);
      }
    if (!csp || strcmp (csp, SALTED_PASSWORD) != 0)
      fail ("client scram salted password mismatch\n");
    if (ssp)
      fail ("server salted password set?\n");
  }

  {
    const char *sek = gsasl_property_fast (server, GSASL_SCRAM_SERVERKEY);
    const char *stk = gsasl_property_fast (server, GSASL_SCRAM_STOREDKEY);

    if (debug)
      {
	printf ("GSASL_SCRAM_SERVERKEY: %s\n", sek);
	printf ("GSASL_SCRAM_STOREDKEY: %s\n", stk);
      }

    if (!sek)
      fail ("missing ServerKey\n");
    if (!stk)
      fail ("missing StoredKey\n");
    if (strcmp (sek, SERVERKEY) != 0)
      fail ("invalid ServerKey\n");
    if (strcmp (stk, STOREDKEY) != 0)
      fail ("invalid StoredKey\n");
  }

  if (debug)
    printf ("\n");

  gsasl_finish (client);
  gsasl_finish (server);

  gsasl_done (ctx);
}
