/* crypto.c --- Simple crypto wrappers for applications.
 * Copyright (C) 2002-2021 Simon Josefsson
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
 * License License along with GNU SASL Library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 *
 */

#include "internal.h"
#include "mechtools.h"

#include "gc.h"

/**
 * gsasl_nonce:
 * @data: output array to be filled with unpredictable random data.
 * @datalen: size of output array.
 *
 * Store unpredictable data of given size in the provided buffer.
 *
 * Return value: Returns %GSASL_OK iff successful.
 **/
int
gsasl_nonce (char *data, size_t datalen)
{
  return gc_nonce (data, datalen);
}

/**
 * gsasl_random:
 * @data: output array to be filled with strong random data.
 * @datalen: size of output array.
 *
 * Store cryptographically strong random data of given size in the
 * provided buffer.
 *
 * Return value: Returns %GSASL_OK iff successful.
 **/
int
gsasl_random (char *data, size_t datalen)
{
  return gc_random (data, datalen);
}

/**
 * gsasl_hash_length:
 * @hash: a %Gsasl_hash element, e.g., #GSASL_HASH_SHA256.
 *
 * Return the digest output size for hash function @hash.  For
 * example, gsasl_hash_length(GSASL_HASH_SHA256) returns
 * GSASL_HASH_SHA256_SIZE which is 32.
 *
 * Returns: size of supplied %Gsasl_hash element.
 *
 * Since: 1.10
 **/
size_t
gsasl_hash_length (Gsasl_hash hash)
{
  switch (hash)
    {
    case GSASL_HASH_SHA1:
      return GSASL_HASH_SHA1_SIZE;
    case GSASL_HASH_SHA256:
      return GSASL_HASH_SHA256_SIZE;
    }

  return 0;
}

/**
 * gsasl_scram_secrets_from_salted_password:
 * @hash: a %Gsasl_hash element, e.g., #GSASL_HASH_SHA256.
 * @salted_password: input array with salted password.
 * @client_key: pre-allocated output array with derived client key.
 * @server_key: pre-allocated output array with derived server key.
 * @stored_key: pre-allocated output array with derived stored key.
 *
 * Helper function to derive SCRAM ClientKey/ServerKey/StoredKey.  The
 * @client_key, @server_key, and @stored_key buffers must have room to
 * hold digest for given @hash, use #GSASL_HASH_MAX_SIZE which is
 * sufficient for all hashes.
 *
 * Return value: Returns %GSASL_OK if successful, or error code.
 *
 * Since: 1.10
 **/
int
gsasl_scram_secrets_from_salted_password (Gsasl_hash hash,
					  const char *salted_password,
					  char *client_key,
					  char *server_key, char *stored_key)
{
  int res;
  size_t hashlen = gsasl_hash_length (hash);

  /* ClientKey */
#define CLIENT_KEY "Client Key"
  res = _gsasl_hmac (hash, salted_password, hashlen,
		     CLIENT_KEY, strlen (CLIENT_KEY), client_key);
  if (res != GSASL_OK)
    return res;

  /* StoredKey */
  res = _gsasl_hash (hash, client_key, hashlen, stored_key);
  if (res != GSASL_OK)
    return res;

  /* ServerKey */
#define SERVER_KEY "Server Key"
  res = _gsasl_hmac (hash, salted_password, hashlen,
		     SERVER_KEY, strlen (SERVER_KEY), server_key);
  if (res != GSASL_OK)
    return res;

  return GSASL_OK;
}

/**
 * gsasl_scram_secrets_from_password:
 * @hash: a %Gsasl_hash element, e.g., #GSASL_HASH_SHA256.
 * @password: input parameter with password.
 * @iteration_count: number of PBKDF2 rounds to apply.
 * @salt: input character array of @saltlen length with salt for PBKDF2.
 * @saltlen: length of @salt.
 * @salted_password: pre-allocated output array with derived salted password.
 * @client_key: pre-allocated output array with derived client key.
 * @server_key: pre-allocated output array with derived server key.
 * @stored_key: pre-allocated output array with derived stored key.
 *
 * Helper function to generate SCRAM secrets from a password.  The
 * @salted_password, @client_key, @server_key, and @stored_key buffers
 * must have room to hold digest for given @hash, use
 * #GSASL_HASH_MAX_SIZE which is sufficient for all hashes.
 *
 * Return value: Returns %GSASL_OK if successful, or error code.
 *
 * Since: 1.10
 **/
int
gsasl_scram_secrets_from_password (Gsasl_hash hash,
				   const char *password,
				   unsigned int iteration_count,
				   const char *salt,
				   size_t saltlen,
				   char *salted_password,
				   char *client_key,
				   char *server_key, char *stored_key)
{
  int res;
  char *preppass;

  res = gsasl_saslprep (password, GSASL_ALLOW_UNASSIGNED, &preppass, NULL);
  if (res != GSASL_OK)
    return res;

  res = _gsasl_pbkdf2 (hash, preppass, strlen (preppass),
		       salt, saltlen, iteration_count, salted_password, 0);
  free (preppass);
  if (res != GSASL_OK)
    return res;

  return gsasl_scram_secrets_from_salted_password (hash, salted_password,
						   client_key, server_key,
						   stored_key);
}
