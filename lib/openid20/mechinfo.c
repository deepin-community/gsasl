/* mechinfo.c --- Definition of OPENID20 mechanism.
 * Copyright (C) 2011-2021 Simon Josefsson
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
#include "openid20.h"

Gsasl_mechanism gsasl_openid20_mechanism = {
  GSASL_OPENID20_NAME,
  {
   NULL,
   NULL,
#ifdef USE_CLIENT
   _gsasl_openid20_client_start,
   _gsasl_openid20_client_step,
   _gsasl_openid20_client_finish,
#else
   NULL,
   NULL,
   NULL,
#endif
   NULL,
   NULL}
  ,
  {
   NULL,
   NULL,
#ifdef USE_SERVER
   _gsasl_openid20_server_start,
   _gsasl_openid20_server_step,
   _gsasl_openid20_server_finish,
#else
   NULL,
   NULL,
   NULL,
#endif
   NULL,
   NULL}
};
