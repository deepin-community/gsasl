/* tools.c --- Shared client/server SCRAM code
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

#include "config.h"

#include "tools.h"
#include "mechtools.h"

/* Hex encode HASHBUF which is HASH digest output and set salted
   password property to the hex encoded value. */
void
set_saltedpassword (Gsasl_session * sctx,
		    Gsasl_hash hash, const char *hashbuf)
{
  char hexstr[GSASL_HASH_MAX_SIZE * 2 + 1];

  _gsasl_hex_encode (hashbuf, gsasl_hash_length (hash), hexstr);
  gsasl_property_set (sctx, GSASL_SCRAM_SALTED_PASSWORD, hexstr);
}
