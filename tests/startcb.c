/* startcb.c --- Verify that mechanism start() do not invoke callbacks.
 * Copyright (C) 2020-2021 Simon Josefsson
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
#include <stdbool.h>
#include <gsasl.h>

#include "utils.h"

/*
  The problem with calling callbacks in the start() function is that
  the callback will have no per-session context at that point, only a
  global context, so the only way to give per-session unique callback
  responses is to use a separate global handle per session.  This was
  discovered in the Exim implementation of gsasl with SCRAM that used
  to request the GSASL_CB_TLS_UNIQUE property in the start() function.
  After noticing this design issue, and writing this self test, it was
  discovered that it also happened for the GSSAPI/GS2 server (not
  client) mechanism for the GSASL_SERVICE and GSASL_HOSTNAME
  properties.

  https://lists.gnu.org/archive/html/help-gsasl/2020-01/msg00035.html
*/

static bool incb;

static int
cb (Gsasl * ctx, Gsasl_session * sctx, Gsasl_property prop)
{
  const char *mn = gsasl_mechanism_name (sctx);

  printf ("Callback %s for property %u\n", mn, prop);

  incb = true;

  return GSASL_NO_CALLBACK;
}

void
doit (void)
{
  Gsasl *ctx = NULL;
  char *out = NULL;
  int res;

  res = gsasl_init (&ctx);
  if (res != GSASL_OK)
    {
      fail ("gsasl_init() failed (%d):\n%s\n", res, gsasl_strerror (res));
      return;
    }

  gsasl_callback_set (ctx, cb);

  /* This self-test relies on that gsasl_client_mechlist() and
     gsasl_client_mechlist() invoke gsasl_client_start() and
     gsasl_server_start() respectively, for each and every mechanism.

     If that internal design is modified, this self-tests needs to
     updated to call gsasl_*_start() in a strtok() loop of the
     mechanisms. */

  incb = false;
  res = gsasl_client_mechlist (ctx, &out);
  if (res != GSASL_OK)
    fail ("gsasl_client_mechlist() failed (%d):\n%s\n",
	  res, gsasl_strerror (res));
  success ("client_mechlist: %s\n", out);
  if (incb)
    fail ("callback was invoked through mechlist/start\n");
  gsasl_free (out);
  out = NULL;

  incb = false;
  res = gsasl_server_mechlist (ctx, &out);
  if (res != GSASL_OK)
    fail ("gsasl_server_mechlist() failed (%d):\n%s\n",
	  res, gsasl_strerror (res));
  success ("server_mechlist: %s\n", out);
  if (incb)
    fail ("callback was invoked through mechlist/start\n");
  gsasl_free (out);
  out = NULL;

  gsasl_done (ctx);

  /* Sanity check interfaces. */
  gsasl_finish (NULL);
  gsasl_done (NULL);
}
