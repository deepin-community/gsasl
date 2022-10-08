/* mechtools.h --- Helper functions available for use by any mechanism.
 * Copyright (C) 2010-2021 Simon Josefsson
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

#ifndef MECHTOOLS_H
#define MECHTOOLS_H

/* Get size_t. */
#include <stddef.h>

/* Get bool. */
#include <stdbool.h>

#include <gsasl.h>

extern int _gsasl_parse_gs2_header (const char *data, size_t len,
				    char **authzid, size_t *headerlen);

extern int _gsasl_gs2_generate_header (bool nonstd, char cbflag,
				       const char *cbname,
				       const char *authzid, size_t extralen,
				       const char *extra, char **gs2h,
				       size_t *gs2hlen);

extern void _gsasl_hex_encode (const char *in, size_t inlen, char *out);
extern void _gsasl_hex_decode (const char *hexstr, char *bin);
extern bool _gsasl_hex_p (const char *hexstr);

extern int _gsasl_hash (Gsasl_hash hash,
			const char *in, size_t inlen, char *out);
extern int _gsasl_hmac (Gsasl_hash hash,
			const char *key, size_t keylen,
			const char *in, size_t inlen, char *outhash);

extern int _gsasl_pbkdf2 (Gsasl_hash hash,
			  const char *password,
			  size_t passwordlen,
			  const char *salt,
			  size_t saltlen,
			  unsigned int c, char *dk, size_t dklen);

#endif
