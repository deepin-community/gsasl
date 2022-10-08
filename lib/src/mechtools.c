/* mechtools.c --- Helper functions available for use by any mechanism.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/* Get specification. */
#include "mechtools.h"

/* Get strcmp. */
#include <string.h>

/* Get malloc, free. */
#include <stdlib.h>

/* Get asprintf. */
#include <stdio.h>

/* Get error codes. */
#include <gsasl.h>

/* Gnulib gc.h */
#include <gc.h>

/* Create in AUTHZID a newly allocated copy of STR where =2C is
   replaced with , and =3D is replaced with =.  Return GSASL_OK on
   success, GSASL_MALLOC_ERROR on memory errors, GSASL_PARSE_ERRORS if
   string contains any unencoded ',' or incorrectly encoded
   sequence.  */
static int
unescape_authzid (const char *str, size_t len, char **authzid)
{
  char *p;

  if (memchr (str, ',', len) != NULL)
    return GSASL_MECHANISM_PARSE_ERROR;

  p = *authzid = malloc (len + 1);
  if (!p)
    return GSASL_MALLOC_ERROR;

  while (len > 0 && *str)
    {
      if (len >= 3 && str[0] == '=' && str[1] == '2' && str[2] == 'C')
	{
	  *p++ = ',';
	  str += 3;
	  len -= 3;
	}
      else if (len >= 3 && str[0] == '=' && str[1] == '3' && str[2] == 'D')
	{
	  *p++ = '=';
	  str += 3;
	  len -= 3;
	}
      else if (str[0] == '=')
	{
	  free (*authzid);
	  *authzid = NULL;
	  return GSASL_MECHANISM_PARSE_ERROR;
	}
      else
	{
	  *p++ = *str;
	  str++;
	  len--;
	}
    }
  *p = '\0';

  return GSASL_OK;
}

/* Parse the GS2 header containing flags and authorization identity.
   Put authorization identity (or NULL) in AUTHZID and length of
   header in HEADERLEN.  Return GSASL_OK on success or an error
   code.*/
int
_gsasl_parse_gs2_header (const char *data, size_t len,
			 char **authzid, size_t *headerlen)
{
  char *authzid_endptr;

  if (len < 3)
    return GSASL_MECHANISM_PARSE_ERROR;

  if (strncmp (data, "n,,", 3) == 0)
    {
      *headerlen = 3;
      *authzid = NULL;
    }
  else if (strncmp (data, "n,a=", 4) == 0 &&
	   (authzid_endptr = memchr (data + 4, ',', len - 4)))
    {
      int res;

      if (authzid_endptr == NULL)
	return GSASL_MECHANISM_PARSE_ERROR;

      res = unescape_authzid (data + 4, authzid_endptr - (data + 4), authzid);
      if (res != GSASL_OK)
	return res;

      *headerlen = authzid_endptr - data + 1;
    }
  else
    return GSASL_MECHANISM_PARSE_ERROR;

  return GSASL_OK;
}

/* Return newly allocated copy of STR with all occurrences of ','
   replaced with =2C and '=' with '=3D', or return NULL on memory
   allocation errors.  */
static char *
escape_authzid (const char *str)
{
  char *out = malloc (strlen (str) * 3 + 1);
  char *p = out;

  if (!out)
    return NULL;

  while (*str)
    {
      if (*str == ',')
	{
	  memcpy (p, "=2C", 3);
	  p += 3;
	}
      else if (*str == '=')
	{
	  memcpy (p, "=3D", 3);
	  p += 3;
	}
      else
	{
	  *p = *str;
	  p++;
	}
      str++;
    }
  *p = '\0';

  return out;
}

/* Generate a newly allocated GS2 header, escaping authzid
   appropriately, and appending EXTRA. */
int
_gsasl_gs2_generate_header (bool nonstd, char cbflag,
			    const char *cbname, const char *authzid,
			    size_t extralen, const char *extra,
			    char **gs2h, size_t *gs2hlen)
{
  int elen = extralen;
  char *gs2cbflag;
  int len;

  if (cbflag == 'p')
    len = asprintf (&gs2cbflag, "p=%s", cbname);
  else if (cbflag == 'n')
    len = asprintf (&gs2cbflag, "n");
  else if (cbflag == 'y')
    len = asprintf (&gs2cbflag, "y");
  else
    /* internal caller error */
    return GSASL_MECHANISM_PARSE_ERROR;

  if (len <= 0 || gs2cbflag == NULL)
    return GSASL_MALLOC_ERROR;

  if (authzid)
    {
      char *escaped_authzid = escape_authzid (authzid);

      if (!escaped_authzid)
	{
	  free (gs2cbflag);
	  return GSASL_MALLOC_ERROR;
	}

      len = asprintf (gs2h, "%s%s,a=%s,%.*s", nonstd ? "F," : "",
		      gs2cbflag, escaped_authzid, elen, extra);

      free (escaped_authzid);
    }
  else
    len = asprintf (gs2h, "%s%s,,%.*s", nonstd ? "F," : "", gs2cbflag,
		    elen, extra);

  free (gs2cbflag);

  if (len <= 0 || gs2h == NULL)
    return GSASL_MALLOC_ERROR;

  *gs2hlen = len;

  return GSASL_OK;
}

/* Hex encode binary octet array IN of INLEN length, putting the hex
   encoded string in OUT which must have room for the data and
   terminating zero, i.e., 2*INLEN+1. */
void
_gsasl_hex_encode (const char *in, size_t inlen, char *out)
{
  size_t i;
  const char *p = in;

  for (i = 0; i < 2 * inlen;)
    {
      unsigned char c = *p++;
      out[i++] = "0123456789abcdef"[c >> 4];
      out[i++] = "0123456789abcdef"[c & 0x0f];
    }

  out[i] = '\0';
}

static char
hexdigit_to_char (char hexdigit)
{
  if (hexdigit >= '0' && hexdigit <= '9')
    return hexdigit - '0';
  if (hexdigit >= 'a' && hexdigit <= 'f')
    return hexdigit - 'a' + 10;
  return 0;
}

static char
hex_to_char (char u, char l)
{
  return (char) (((unsigned char) hexdigit_to_char (u)) * 16
		 + hexdigit_to_char (l));
}

/* Hex decode string HEXSTR containing only hex "0-9A-F" characters
   into binary buffer BIN which must have room for data, i.e., strlen
   (hexstr)/2. */
void
_gsasl_hex_decode (const char *hexstr, char *bin)
{
  while (*hexstr)
    {
      *bin = hex_to_char (hexstr[0], hexstr[1]);
      hexstr += 2;
      bin++;
    }
}

/* Return whether string contains hex "0-9a-f" symbols only. */
bool
_gsasl_hex_p (const char *hexstr)
{
  static const char hexalpha[] = "0123456789abcdef";

  for (; *hexstr; hexstr++)
    if (strchr (hexalpha, *hexstr) == NULL)
      return false;

  return true;
}

/*
 * _gsasl_hash:
 * @hash: a %Gsasl_hash hash algorithm identifier, e.g. #GSASL_HASH_SHA256.
 * @in: input character array of data to hash.
 * @inlen: length of input character array of data to hash.
 * @outhash: buffer to hold hash of data.
 *
 * Compute hash of data using the @hash algorithm.  The @outhash
 * buffer must have room to hold the size of @hash's output; a safe
 * value that have room for all possible outputs is
 * %GSASL_HASH_MAX_SIZE.
 *
 * Return value: Returns %GSASL_OK iff successful.
 *
 * Since: 1.10
 **/
int
_gsasl_hash (Gsasl_hash hash, const char *in, size_t inlen, char *outhash)
{
  int rc;

  if (hash == GSASL_HASH_SHA1)
    rc = gc_sha1 (in, inlen, outhash);
  else if (hash == GSASL_HASH_SHA256)
    rc = gc_sha256 (in, inlen, outhash);
  else
    rc = GSASL_CRYPTO_ERROR;

  return rc;
}

/*
 * _gsasl_hmac:
 * @hash: a %Gsasl_hash hash algorithm identifier, e.g. #GSASL_HASH_SHA256.
 * @key: input character array with key to use.
 * @keylen: length of input character array with key to use.
 * @in: input character array of data to hash.
 * @inlen: length of input character array of data to hash.
 * @outhash: buffer to hold keyed hash of data.
 *
 * Compute keyed checksum of data using HMAC for the @hash algorithm.
 * The @outhash buffer must have room to hold the size of @hash's
 * output; a safe value that have room for all possible outputs is
 * %GSASL_HASH_MAX_SIZE.
 *
 * Return value: Returns %GSASL_OK iff successful.
 *
 * Since: 1.10
 **/
int
_gsasl_hmac (Gsasl_hash hash,
	     const char *key, size_t keylen,
	     const char *in, size_t inlen, char *outhash)
{
  int rc;

  if (hash == GSASL_HASH_SHA1)
    rc = gc_hmac_sha1 (key, keylen, in, inlen, outhash);
  else if (hash == GSASL_HASH_SHA256)
    rc = gc_hmac_sha256 (key, keylen, in, inlen, outhash);
  else
    rc = GSASL_CRYPTO_ERROR;

  return rc;
}

/*
 * gsasl_pbkdf2:
 * @hash: a %Gsasl_hash hash algorithm identifier.
 * @password: input character array with password to use.
 * @passwordlen: length of @password.
 * @salt: input character array with salt, typically a short string.
 * @saltlen: length of @salt.
 * @c: iteration count, typically larger than 4096.
 * @dk: output buffer, must be able to hold @dklen.
 * @dklen: length of output buffer, or 0 to indicate @hash output size.
 *
 * Hash and salt password according to PBKDF2 algorithm with the @hash
 * function used in HMAC.  This function can be used to prepare SCRAM
 * SaltedPassword values for the %GSASL_SCRAM_SALTED_PASSWORD
 * property.  Note that password should normally be prepared using
 * gsasl_saslprep(GSASL_ALLOW_UNASSIGNED) before calling this
 * function.
 *
 * Return value: Returns %GSASL_OK if successful, or error code.
 *
 * Since: 1.10
 **/
int
_gsasl_pbkdf2 (Gsasl_hash hash,
	       const char *password, size_t passwordlen,
	       const char *salt, size_t saltlen,
	       unsigned int c, char *dk, size_t dklen)
{
  int rc;
  Gc_hash gch;

  switch (hash)
    {
    case GSASL_HASH_SHA1:
      if (dklen == 0)
	dklen = GSASL_HASH_SHA1_SIZE;
      gch = GC_SHA1;
      break;

    case GSASL_HASH_SHA256:
      if (dklen == 0)
	dklen = GSASL_HASH_SHA256_SIZE;
      gch = GC_SHA256;
      break;

    default:
      return GSASL_CRYPTO_ERROR;
    }

  rc = gc_pbkdf2_hmac (gch, password, passwordlen,
		       salt, saltlen, c, dk, dklen);
  if (rc != GC_OK)
    return GSASL_CRYPTO_ERROR;

  return GSASL_OK;
}
