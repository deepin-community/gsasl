/* gsasl.c --- Command line interface to libgsasl.
 * Copyright (C) 2002-2021 Simon Josefsson
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

#include "internal.h"
#include "callbacks.h"
#include "imap.h"
#include "smtp.h"

#include "sockets.h"

#ifdef HAVE_LIBGNUTLS
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
gnutls_session_t session;
bool using_tls = false;
#endif

char *b64cbtlsunique = NULL;

struct gengetopt_args_info args_info;
int sockfd = 0;

#ifdef HAVE_LIBGNUTLS
static bool
_handle_tlserror (int error)
{
  int rc;

  switch (error)
    {
    case GNUTLS_E_REHANDSHAKE:
      for (;;)
	{
	  rc = gnutls_handshake (session);
	  switch (rc)
	    {
	    case GNUTLS_E_INTERRUPTED:
	    case GNUTLS_E_AGAIN:
	      continue;

	    case GNUTLS_E_GOT_APPLICATION_DATA:
	      /* TODO: signal this somehow? */
	      continue;

	    case GNUTLS_E_WARNING_ALERT_RECEIVED:
	      fprintf (stderr, "ALERT: %s\n",
		       gnutls_alert_get_name (gnutls_alert_get (session)));
	      continue;

	    default:
	      fprintf (stderr, "TLS rehandshake failed: %s\n",
		       gnutls_strerror (rc));
	      /* make every error fatal */
	      return false;
	    }

	  return true;
	}

    case GNUTLS_E_INTERRUPTED:
    case GNUTLS_E_AGAIN:
      /* not fatal */
      return true;

    default:
      fprintf (stderr, "TLS error: %s\n", gnutls_strerror (error));
      return false;
    }
}
#endif

static ssize_t
_recv (void *dst, size_t cnt)
{
#ifdef HAVE_LIBGNUTLS
  if (using_tls)
    {
      ssize_t l = 0;
      do
	{
	  l = gnutls_record_recv (session, dst, cnt);

	  if (l < 0 && !_handle_tlserror (l))
	    break;
	}
      while (l < 0);

      return l;
    }
#endif

  return recv (sockfd, dst, cnt, 0);
}

static ssize_t
_send (void const *src, size_t cnt)
{
#ifdef HAVE_LIBGNUTLS
  if (using_tls)
    {
      ssize_t l;
      do
	{
	  if (cnt > 0)
	    l = gnutls_record_send (session, src, cnt);
	  else
	    l = 0;

	  if (l < 0 && !_handle_tlserror (l))
	    break;
	}
      while (l < 0);

      return l;
    }
#endif

  return write (sockfd, src, cnt);
}

int
writeln (const char *str)
{
  printf ("%s\n", str);

  if (sockfd)
    {
      ssize_t len = strlen (str);

      len = _send (str, len);
      if (len != (ssize_t) strlen (str))
	return 0;

#define CRLF "\r\n"

      len = _send (CRLF, strlen (CRLF));
      if (len != strlen (CRLF))
	return 0;
    }

  return 1;
}

int
readln (char **out)
{
  if (sockfd)
    {
      size_t allocated = 0, used = 0;
      char *input = NULL;

      /* FIXME: Read larger chunks.  Problem: buffering too large reads? */

      do
	{
	  ssize_t nread;

	  if (used == allocated)
	    input = x2realloc (input, &allocated);

	  nread = _recv (&input[used], 1);
	  if (nread <= 0)
	    return 0;

	  used += nread;
	}
      while (input[used - 1] != '\n');

      if (used == allocated)
	input = x2realloc (input, &allocated);

      input[used] = '\0';

      *out = input;

      printf ("%s", *out);
    }
  else
    {
      *out = readline ("");
      if (*out == NULL)
	return 0;
    }

  return 1;
}

static int
greeting (void)
{
  if (args_info.imap_flag)
    return imap_greeting ();
  if (args_info.smtp_flag)
    return smtp_greeting ();

  return 1;
}

#ifdef HAVE_LIBGNUTLS
static int
has_starttls (void)
{
  if (args_info.imap_flag)
    return imap_has_starttls ();
  if (args_info.smtp_flag)
    return smtp_has_starttls ();

  return 0;
}

static int
starttls (void)
{
  if (args_info.imap_flag)
    return imap_starttls ();
  if (args_info.smtp_flag)
    return smtp_starttls ();

  return 1;
}
#endif

static int
select_mechanism (char **mechlist)
{
  char *in;

  if (args_info.imap_flag)
    return imap_select_mechanism (mechlist);
  if (args_info.smtp_flag)
    return smtp_select_mechanism (mechlist);

  if (args_info.mechanism_arg)
    *mechlist = args_info.mechanism_arg;
  else if (args_info.server_flag)
    {
      if (!args_info.quiet_given)
	fprintf (stderr, _("Input list of SASL mechanisms:\n"));
      if (!readln (&in))
	return 0;
      *mechlist = in;
    }
  else				/* if (args_info.client_flag) */
    {
      if (!args_info.quiet_given)
	fprintf (stderr,
		 _("Input list of SASL mechanisms supported by server:\n"));
      if (!readln (&in))
	return 0;

      *mechlist = in;
    }

  return 1;
}

static int
authenticate (const char *mech)
{
  if (args_info.imap_flag)
    return imap_authenticate (mech);
  if (args_info.smtp_flag)
    return smtp_authenticate (mech);

  if (!args_info.quiet_given)
    fprintf (stderr, _("Using mechanism:\n"));
  puts (mech);

  return 1;
}

static int
step_send (const char *data)
{
  if (args_info.imap_flag)
    return imap_step_send (data);
  if (args_info.smtp_flag)
    return smtp_step_send (data);

  if (!args_info.quiet_given)
    {
      if (args_info.server_flag)
	fprintf (stderr, _("Output from server:\n"));
      else
	fprintf (stderr, _("Output from client:\n"));
    }
  fprintf (stdout, "%s\n", data);

  return 1;
}

/* Return 1 on token, 2 on protocol success, 3 on protocol fail, 0 on
   errors. */
static int
step_recv (char **data)
{
  if (args_info.imap_flag)
    return imap_step_recv (data);
  if (args_info.smtp_flag)
    return smtp_step_recv (data);

  if (!readln (data))
    return 0;

  return 1;
}

static int
logout (void)
{
  if (args_info.imap_flag)
    return imap_logout ();
  if (args_info.smtp_flag)
    return smtp_logout ();

  return 1;
}

const char version_etc_copyright[] =
  /* Do *not* mark this string for translation.  %s is a copyright
     symbol suitable for this locale, and %d is the copyright
     year.  */
  "Copyright %s %d Simon Josefsson.";

static void
usage (int status)
  GSASL_ATTR_NO_RETRUN;

     static void usage (int status)
{
  if (status != EXIT_SUCCESS)
    fprintf (stderr, _("Try `%s --help' for more information.\n"),
	     program_name);
  else
    {
      cmdline_parser_print_help ();
      emit_bug_reporting_address ();
    }
  exit (status);
}

#define DEFAULT_SALT_SIZE 12

static void
mkpasswd (void)
{
  char salt_buf[DEFAULT_SALT_SIZE];
  char *salt;
  size_t saltlen;
  char *b64salt;
  char saltedpassword[GSASL_HASH_MAX_SIZE];
  char *hexsaltedpassword;
  size_t hexsaltedpasswordlen;
  int hash = 0;
  size_t hashlen = 0;
  char clientkey[GSASL_HASH_MAX_SIZE];
  char serverkey[GSASL_HASH_MAX_SIZE];
  char storedkey[GSASL_HASH_MAX_SIZE];
  char *b64serverkey, *b64storedkey;
  size_t b64serverkeylen, b64storedkeylen;
  int res;

  if (args_info.mechanism_arg == NULL)
    error (EXIT_FAILURE, 0, _("required --mechanism missing"));

  if (strcmp (args_info.mechanism_arg, "SCRAM-SHA-1") == 0)
    {
      hash = GSASL_HASH_SHA1;
      hashlen = GSASL_HASH_SHA1_SIZE;
    }
  else if (strcmp (args_info.mechanism_arg, "SCRAM-SHA-256") == 0)
    {
      hash = GSASL_HASH_SHA256;
      hashlen = GSASL_HASH_SHA256_SIZE;
    }
  else
    error (EXIT_FAILURE, 0, _("unsupported --mechanism for --mkpasswd: %s"),
	   args_info.mechanism_arg);

  if (args_info.iteration_count_arg <= 0)
    error (EXIT_FAILURE, 0, _("iteration count must be positive: %d"),
	   args_info.iteration_count_arg);

  if (args_info.salt_given)
    {
      b64salt = args_info.salt_arg;

      res = gsasl_base64_from (b64salt, strlen (b64salt), &salt, &saltlen);
      if (res != GSASL_OK)
	error (EXIT_FAILURE, 0, "%s: %s", gsasl_strerror (res), b64salt);
    }
  else
    {
      salt = salt_buf;
      saltlen = sizeof (salt_buf);

      res = gsasl_nonce (salt, saltlen);
      if (res != GSASL_OK)
	error (EXIT_FAILURE, 0, "%s", gsasl_strerror (res));

      res = gsasl_base64_to (salt, saltlen, &b64salt, NULL);
      if (res != GSASL_OK)
	error (EXIT_FAILURE, 0, "%s", gsasl_strerror (res));
    }

  if (args_info.password_arg == NULL)
    args_info.password_arg = readutf8pass (_("Enter password: "));

  res = gsasl_scram_secrets_from_password (hash, args_info.password_arg,
					   args_info.iteration_count_arg,
					   salt, saltlen,
					   saltedpassword,
					   clientkey, serverkey, storedkey);
  if (res != GSASL_OK)
    error (EXIT_FAILURE, 0, "%s", gsasl_strerror (res));

  res = gsasl_hex_to (saltedpassword, hashlen,
		      &hexsaltedpassword, &hexsaltedpasswordlen);
  if (res != GSASL_OK)
    error (EXIT_FAILURE, 0, "%s", gsasl_strerror (res));

  res = gsasl_base64_to (storedkey, hashlen, &b64storedkey, &b64storedkeylen);
  if (res != GSASL_OK)
    error (EXIT_FAILURE, 0, "%s", gsasl_strerror (res));

  res = gsasl_base64_to (serverkey, hashlen, &b64serverkey, &b64serverkeylen);
  if (res != GSASL_OK)
    error (EXIT_FAILURE, 0, "%s", gsasl_strerror (res));

  printf ("{%s}%d,%s,%s,%s", args_info.mechanism_arg,
	  args_info.iteration_count_arg, b64salt, b64storedkey, b64serverkey);
  if (args_info.verbose_given)
    printf (",%s", hexsaltedpassword);
  printf ("\n");

  if (salt != salt_buf)
    free (salt);
  if (b64salt != args_info.salt_arg)
    free (b64salt);
  free (b64serverkey);
  free (b64storedkey);
  free (hexsaltedpassword);
}


int
main (int argc, char *argv[])
{
  Gsasl *ctx = NULL;
  int res;
  char *in;
  char *connect_hostname = NULL;
  char *connect_service = NULL;
#ifdef HAVE_LIBGNUTLS
  gnutls_anon_client_credentials_t anoncred;
  gnutls_certificate_credentials_t x509cred;
#endif

  set_program_name (argv[0]);
  setlocale (LC_ALL, "");
  bindtextdomain (PACKAGE, LOCALEDIR);
  textdomain (PACKAGE);

  /* This is necessary for modern MinGW compilers that provide working
     getaddrinfo function, which results in gnulib not detecting that
     it is broken.  The proper fix is for gnulib to wrap the
     getaddrinfo call and initialize Windows sockets in the
     wrapper.  */
  (void) gl_sockets_startup (SOCKETS_1_1);

  if (cmdline_parser (argc, argv, &args_info) != 0)
    return EXIT_FAILURE;

  if (args_info.version_given)
    {
      const char *p = PACKAGE_NAME;
      if (strcmp (gsasl_check_version (NULL), PACKAGE_VERSION) != 0)
	p = PACKAGE_STRING;
      version_etc (stdout, "gsasl", p, gsasl_check_version (NULL),
		   "Simon Josefsson", (char *) NULL);
      return EXIT_SUCCESS;
    }

  if (args_info.help_given)
    usage (EXIT_SUCCESS);

  if (!(args_info.client_flag || args_info.client_given) &&
      !args_info.server_given &&
      !args_info.client_mechanisms_flag && !args_info.server_mechanisms_flag
      && !args_info.mkpasswd_given)
    {
      error (0, 0, _("missing argument"));
      usage (EXIT_FAILURE);
    }

  if ((args_info.x509_cert_file_arg && !args_info.x509_key_file_arg) ||
      (!args_info.x509_cert_file_arg && args_info.x509_key_file_arg))
    error (EXIT_FAILURE, 0,
	   _("need both --x509-cert-file and --x509-key-file"));

  if (args_info.starttls_flag && args_info.no_starttls_flag)
    error (EXIT_FAILURE, 0,
	   _("cannot use both --starttls and --no-starttls"));

  if (args_info.smtp_flag && args_info.imap_flag)
    error (EXIT_FAILURE, 0, _("cannot use both --smtp and --imap"));

  if (!args_info.connect_given && args_info.inputs_num == 0 &&
      !args_info.client_given && !args_info.server_given &&
      !args_info.client_mechanisms_flag && !args_info.server_mechanisms_flag
      && !args_info.mkpasswd_given)
    {
      cmdline_parser_print_help ();
      emit_bug_reporting_address ();
      return EXIT_SUCCESS;
    }

  if (args_info.connect_given)
    {
      if (strrchr (args_info.connect_arg, ':'))
	{
	  connect_hostname = xstrdup (args_info.connect_arg);
	  *strrchr (connect_hostname, ':') = '\0';
	  connect_service =
	    xstrdup (strrchr (args_info.connect_arg, ':') + 1);
	}
      else
	{
	  connect_hostname = xstrdup (args_info.connect_arg);
	  if (args_info.smtp_flag)
	    connect_service = xstrdup ("smtp");
	  else
	    connect_service = xstrdup ("imap");
	}
    }
  else if (args_info.inputs_num > 0)
    {
      connect_hostname = args_info.inputs[0];
      if (args_info.inputs_num > 1)
	connect_service = args_info.inputs[1];
      else if (args_info.smtp_flag)
	connect_service = xstrdup ("smtp");
      else
	connect_service = xstrdup ("imap");
    }

  if (connect_service && !args_info.smtp_flag && !args_info.imap_flag)
    {
      if (strcmp (connect_service, "25") == 0 ||
	  strcmp (connect_service, "smtp") == 0 ||
	  strcmp (connect_service, "587") == 0 ||
	  strcmp (connect_service, "submission") == 0)
	args_info.smtp_flag = 1;
      else if (strcmp (connect_service, "143") == 0 ||
	       strcmp (connect_service, "imap") == 0)
	args_info.imap_flag = 1;
      else
	error (EXIT_FAILURE, 0,
	       _("cannot guess SASL profile (try --smtp or --imap)"));
    }

  if (args_info.imap_flag && !args_info.service_given)
    args_info.service_arg = xstrdup ("imap");

  if (args_info.smtp_flag && !args_info.service_given)
    args_info.service_arg = xstrdup ("smtp");

  if (args_info.imap_flag || args_info.smtp_flag)
    args_info.no_client_first_flag = 1;

  if (connect_hostname && !args_info.hostname_arg)
    args_info.hostname_arg = xstrdup (connect_hostname);

  if (!isatty (STDOUT_FILENO))
    setvbuf (stdout, NULL, _IOLBF, BUFSIZ);

  res = gsasl_init (&ctx);
  if (res != GSASL_OK)
    error (EXIT_FAILURE, 0, _("initialization failure: %s"),
	   gsasl_strerror (res));

  gsasl_callback_set (ctx, callback);

  if (args_info.client_mechanisms_flag || args_info.server_mechanisms_flag)
    {
      char *mechs;

      if (args_info.client_mechanisms_flag)
	res = gsasl_client_mechlist (ctx, &mechs);
      else
	res = gsasl_server_mechlist (ctx, &mechs);

      if (res != GSASL_OK)
	error (EXIT_FAILURE, 0, _("error listing mechanisms: %s"),
	       gsasl_strerror (res));

      if (!args_info.quiet_given)
	{
	  if (args_info.client_mechanisms_flag)
	    fprintf (stderr,
		     _("This client supports the following mechanisms:\n"));
	  else
	    fprintf (stderr,
		     _("This server supports the following mechanisms:\n"));
	}

      fprintf (stdout, "%s\n", mechs);

      free (mechs);

      goto done;
    }

  if (args_info.mkpasswd_given)
    {
      mkpasswd ();
      goto done;
    }

  if (args_info.connect_given || args_info.inputs_num > 0)
    {
      struct addrinfo hints;
      struct addrinfo *ai0, *ai;

      memset (&hints, 0, sizeof (hints));
      hints.ai_flags = AI_CANONNAME;
      hints.ai_socktype = SOCK_STREAM;
      res = getaddrinfo (connect_hostname, connect_service, &hints, &ai0);
      if (res != 0)
	error (EXIT_FAILURE, 0, "%s: %s", connect_hostname,
	       gai_strerror (res));

      for (ai = ai0; ai; ai = ai->ai_next)
	{
	  fprintf (stderr, "Trying %s...\n", quote (ai->ai_canonname ?
						    ai->ai_canonname :
						    connect_hostname));

	  sockfd = socket (ai->ai_family, ai->ai_socktype, ai->ai_protocol);
	  if (sockfd < 0)
	    {
	      error (0, errno, "socket");
	      continue;
	    }

	  if (connect (sockfd, ai->ai_addr, ai->ai_addrlen) < 0)
	    {
	      int save_errno = errno;
	      close (sockfd);
	      sockfd = -1;
	      error (0, save_errno, "connect");
	      continue;
	    }
	  break;
	}

      if (sockfd < 0)
	error (EXIT_FAILURE, errno, "socket");

      freeaddrinfo (ai);
    }

  if (!greeting ())
    return 1;

#ifdef HAVE_LIBGNUTLS
  if (sockfd && !args_info.no_starttls_flag &&
      (args_info.starttls_flag || has_starttls ()))
    {
      res = gnutls_global_init ();
      if (res < 0)
	error (EXIT_FAILURE, 0, _("GnuTLS global initialization failed: %s"),
	       gnutls_strerror (res));

      res = gnutls_init (&session, GNUTLS_CLIENT);
      if (res < 0)
	error (EXIT_FAILURE, 0, _("GnuTLS initialization failed: %s"),
	       gnutls_strerror (res));

      res = gnutls_set_default_priority (session);
      if (res < 0)
	error (EXIT_FAILURE, 0, _("setting GnuTLS defaults failed: %s"),
	       gnutls_strerror (res));

      res =
	gnutls_server_name_set (session, GNUTLS_NAME_DNS, connect_hostname,
				strlen (connect_hostname));
      if (res < 0)
	error (EXIT_FAILURE, 0, _("setting GnuTLS server name failed: %s"),
	       gnutls_strerror (res));

      res = gnutls_anon_allocate_client_credentials (&anoncred);
      if (res < 0)
	error (EXIT_FAILURE, 0,
	       _("allocating anonymous GnuTLS credential: %s"),
	       gnutls_strerror (res));

      res = gnutls_credentials_set (session, GNUTLS_CRD_ANON, anoncred);
      if (res < 0)
	error (EXIT_FAILURE, 0, _("setting anonymous GnuTLS credential: %s"),
	       gnutls_strerror (res));

      res = gnutls_certificate_allocate_credentials (&x509cred);
      if (res < 0)
	error (EXIT_FAILURE, 0, _("allocating X.509 GnuTLS credential: %s"),
	       gnutls_strerror (res));

      if (args_info.x509_cert_file_arg && args_info.x509_key_file_arg)
	res = gnutls_certificate_set_x509_key_file
	  (x509cred, args_info.x509_cert_file_arg,
	   args_info.x509_key_file_arg, GNUTLS_X509_FMT_PEM);
      if (res != GNUTLS_E_SUCCESS)
	error (EXIT_FAILURE, 0, _("loading X.509 GnuTLS credential: %s"),
	       gnutls_strerror (res));

      if (args_info.x509_ca_file_arg && *args_info.x509_ca_file_arg)
	{
	  res = gnutls_certificate_set_x509_trust_file
	    (x509cred, args_info.x509_ca_file_arg, GNUTLS_X509_FMT_PEM);
	  if (res < 0)
	    error (EXIT_FAILURE, 0, _("no X.509 CAs found: %s"),
		   gnutls_strerror (res));
	  if (res == 0)
	    error (EXIT_FAILURE, 0, _("no X.509 CAs found"));
	}
      else if (!args_info.x509_ca_file_arg)
	{
	  res = gnutls_certificate_set_x509_system_trust (x509cred);
	  if (res < 0)
	    error (EXIT_FAILURE, 0, _("setting GnuTLS system trust: %s"),
		   gnutls_strerror (res));
	}

      res = gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE,
				    x509cred);
      if (res < 0)
	error (EXIT_FAILURE, 0, _("setting X.509 GnuTLS credential: %s"),
	       gnutls_strerror (res));

      if (args_info.x509_ca_file_arg == NULL || *args_info.x509_ca_file_arg)
	gnutls_session_set_verify_cert (session, connect_hostname, 0);

      if (args_info.priority_arg)
	{
	  const char *err_pos;

	  res = gnutls_priority_set_direct (session, args_info.priority_arg,
					    &err_pos);
	  if (res < 0)
	    error (EXIT_FAILURE, 0,
		   _("setting GnuTLS cipher priority (%s): %s\n"),
		   gnutls_strerror (res), err_pos);
	}

      gnutls_transport_set_ptr (session, (gnutls_transport_ptr_t)
				(unsigned long) sockfd);

      if (!starttls ())
	return 1;

      do
	{
	  res = gnutls_handshake (session);
	}
      while (res < 0 && gnutls_error_is_fatal (res) == 0);

      if (!args_info.quiet_given)
	{
	  int type;
	  unsigned status;
	  gnutls_datum_t out;

	  type = gnutls_certificate_type_get (session);
	  status = gnutls_session_get_verify_cert_status (session);
	  gnutls_certificate_verification_status_print (status, type, &out,
							0);
	  fprintf (stderr, _("TLS X.509 Verification: %s\n"), out.data);
	  gnutls_free (out.data);
	}

      if (res < 0)
	error (EXIT_FAILURE, 0, _("GnuTLS handshake failed: %s"),
	       gnutls_strerror (res));

      if (args_info.verbose_given)
	{
	  char *desc = gnutls_session_get_desc (session);
	  const gnutls_datum_t *cert_list;
	  unsigned int cert_list_size = 0, i;
	  gnutls_x509_crt_t cert;
	  gnutls_datum_t out;

	  fprintf (stderr, _("TLS session info: %s\n"), desc);
	  gnutls_free (desc);
	  fflush (stderr);

	  cert_list = gnutls_certificate_get_peers (session, &cert_list_size);

	  for (i = 0; i < cert_list_size; i++)
	    {
	      res = gnutls_x509_crt_init (&cert);
	      if (res < 0)
		continue;

	      res = gnutls_x509_crt_import (cert, &cert_list[i],
					    GNUTLS_X509_FMT_DER);
	      if (res < 0)
		continue;

	      res = gnutls_x509_crt_print (cert, GNUTLS_CRT_PRINT_ONELINE,
					   &out);
	      if (res == 0)
		{
		  fprintf (stderr, _("TLS X.509 Certificate %u: %s\n"), i,
			   out.data);
		  gnutls_free (out.data);
		}

	      gnutls_x509_crt_deinit (cert);
	    }
	}

      if (args_info.x509_ca_file_arg && *args_info.x509_ca_file_arg)
	{
	  unsigned int status;

	  res = gnutls_certificate_verify_peers2 (session, &status);
	  if (res < 0)
	    error (EXIT_FAILURE, 0, _("verifying peer certificate: %s"),
		   gnutls_strerror (res));

	  if (status & GNUTLS_CERT_INVALID)
	    error (EXIT_FAILURE, 0, _("server certificate is not trusted"));

	  if (status & GNUTLS_CERT_SIGNER_NOT_FOUND)
	    error (EXIT_FAILURE, 0,
		   _("server certificate hasn't got a known issuer"));

	  if (status & GNUTLS_CERT_REVOKED)
	    error (EXIT_FAILURE, 0, _("server certificate has been revoked"));

	  if (status != 0)
	    error (EXIT_FAILURE, 0,
		   _("could not verify server certificate (rc=%u)"), status);
	}

#if HAVE_GNUTLS_SESSION_CHANNEL_BINDING
      if (!args_info.no_cb_flag)
	{
	  gnutls_datum_t cb;

	  res = gnutls_session_channel_binding (session,
						GNUTLS_CB_TLS_UNIQUE, &cb);
	  if (res != GNUTLS_E_SUCCESS)
	    error (EXIT_FAILURE, 0, _("getting channel binding failed: %s"),
		   gnutls_strerror (res));

	  res = gsasl_base64_to ((char *) cb.data, cb.size,
				 &b64cbtlsunique, NULL);
	  if (res != GSASL_OK)
	    error (EXIT_FAILURE, 0, "%s", gsasl_strerror (res));
	}
#endif

      using_tls = true;
    }
#endif

  if (args_info.client_flag || args_info.client_given
      || args_info.server_given)
    {
      char *out;
      char *b64output;
      size_t output_len;
      size_t b64output_len;
      const char *mech;
      Gsasl_session *xctx = NULL;

      if (!select_mechanism (&in))
	return 1;

      mech = gsasl_client_suggest_mechanism (ctx, in);
      if (mech == NULL)
	{
	  fprintf (stderr, _("Cannot find mechanism...\n"));
	  goto done;
	}

      if (args_info.mechanism_arg)
	mech = args_info.mechanism_arg;

      if (!authenticate (mech))
	return 1;

      /* Authenticate using mechanism */

      if (args_info.server_flag)
	res = gsasl_server_start (ctx, mech, &xctx);
      else
	res = gsasl_client_start (ctx, mech, &xctx);
      if (res != GSASL_OK)
	error (EXIT_FAILURE, 0, _("mechanism unavailable: %s"),
	       gsasl_strerror (res));

      in = NULL;
      out = NULL;

      if (!args_info.server_flag && args_info.no_client_first_flag)
	{
	  res = GSASL_NEEDS_MORE;
	  goto no_client_first;
	}

      do
	{
	  int res2;

	  res = gsasl_step64 (xctx, in, &out);
	  if (res != GSASL_NEEDS_MORE && res != GSASL_OK)
	    break;

	  if (!step_send (out))
	    return 1;

	no_client_first:
	  if (!args_info.quiet_given &&
	      !args_info.imap_flag && !args_info.smtp_flag)
	    {
	      if (args_info.server_flag)
		fprintf (stderr, _("Enter base64 authentication data "
				   "from client (press RET if none):\n"));
	      else
		fprintf (stderr, _("Enter base64 authentication data "
				   "from server (press RET if none):\n"));
	    }

	  /* Return 1 on token, 2 on protocol success, 3 on protocol fail, 0 on
	     errors. */
	  res2 = step_recv (&in);
	  if (!res2)
	    return 1;
	  if (res2 == 3)
	    error (EXIT_FAILURE, 0, _("server error"));
	  if (res2 == 2)
	    break;
	}
      while (args_info.imap_flag || args_info.smtp_flag
	     || res == GSASL_NEEDS_MORE);

      if (res != GSASL_OK)
	error (EXIT_FAILURE, 0, _("mechanism error: %s"),
	       gsasl_strerror (res));

      if (!args_info.quiet_given)
	{
	  if (args_info.server_flag)
	    fprintf (stderr, _("Server authentication "
			       "finished (client trusted)...\n"));
	  else
	    fprintf (stderr, _("Client authentication "
			       "finished (server trusted)...\n"));
	  fflush (stderr);
	}

      /* Transfer application payload */
      if (args_info.application_data_flag)
	{
	  struct pollfd pfd[2];
	  char *sockbuf = NULL;
	  /* we read chunks of 1000 bytes at a time */
	  size_t sockpos = 0, sockalloc = 0, sockalloc1 = 1000;

	  /* Setup pollfd structs... */
	  pfd[0].fd = STDIN_FILENO;
	  pfd[0].events = POLLIN;
	  if (sockfd)
	    {
	      pfd[1].fd = sockfd;
	      pfd[1].events = POLLIN;
	    }

	  if (!args_info.quiet_given)
	    {
	      fprintf (stderr,
		       _("Enter application data (EOF to finish):\n"));
	      fflush (stderr);
	    }

	  while (1)
	    {
	      int rc;

	      pfd[0].revents = 0;
	      pfd[1].revents = 0;

	      rc = poll (pfd, sockfd ? 2 : 1, -1);
	      if (rc < 0 && errno == EINTR)
		continue;

	      /* Always check for errors */
	      if (rc < 0)
		error (EXIT_FAILURE, errno, "poll");

	      /* We got data to read from stdin.. */
	      if ((pfd[0].revents & (POLLIN | POLLERR)) == POLLIN)
		{
		  char *line = NULL;
		  size_t n;
		  ssize_t len;

		  len = getline (&line, &n, stdin);
		  if (len <= 0)
		    break;

		  if (args_info.imap_flag || args_info.smtp_flag)
		    {
		      if (len < 2 || strcmp (&line[len - 2], "\r\n") != 0)
			{
			  line = xrealloc (line, len + 2);
			  line[len - 1] = '\r';
			  line[len] = '\n';
			  line[len + 1] = '\0';
			  len++;
			}
		    }
		  else
		    {
		      len--;
		      line[len] = '\0';
		    }

		  res = gsasl_encode (xctx, line, len, &out, &output_len);
		  if (res != GSASL_OK)
		    break;

		  if (sockfd)
		    {
		      len = _send (out, output_len);
		      if (len != (ssize_t) output_len)
			error (EXIT_FAILURE, errno, "write");
		    }
		  else if (!(strlen (line) == output_len &&
			     memcmp (line, out, output_len) == 0))
		    {
		      res = gsasl_base64_to (out, output_len,
					     &b64output, &b64output_len);
		      if (res != GSASL_OK)
			break;

		      if (!args_info.quiet_given)
			fprintf (stderr, _("Base64 encoded application "
					   "data to send:\n"));
		      fprintf (stdout, "%s\n", b64output);

		      free (b64output);
		    }

		  free (line);
		  free (out);
		}
	      /* If there was an error, quit.  */
	      else if (pfd[0].revents & (POLLERR | POLLHUP))
		{
		  error (0, 0, "poll stdin");
		  break;
		}

	      /* We got data to read from the socket.. */
	      if (sockfd && (pfd[1].revents & (POLLIN | POLLERR)) == POLLIN)
		{
		  ssize_t len;

		  if (sockalloc == sockpos)
		    sockbuf = x2realloc (sockbuf, &sockalloc1);
		  sockalloc = sockalloc1;

		  len = _recv (&sockbuf[sockpos], sockalloc - sockpos);
		  if (len <= 0)
		    break;

		  sockpos += len;

		  res = gsasl_decode (xctx, sockbuf, sockpos,
				      &out, &output_len);
		  if (res == GSASL_NEEDS_MORE)
		    {
#define MAX_INPUT_SIZE	0x100000
		      if (sockpos > MAX_INPUT_SIZE)
			error (EXIT_FAILURE, 0,
			       _("SASL record too large: %zu\n"), sockpos);
		      continue;
		    }
		  if (res != GSASL_OK)
		    break;

		  free (sockbuf);
		  sockbuf = NULL;
		  sockpos = 0;
		  sockalloc = 0;
		  sockalloc1 = 1000;

		  printf ("%.*s", (int) output_len, out);
		  free (out);
		}
	      /* If there was an error, quit.  */
	      else if (pfd[1].revents & (POLLERR | POLLHUP))
		{
		  error (0, 0, "poll socket");
		  break;
		}
	    }

	  if (res != GSASL_OK)
	    error (EXIT_FAILURE, 0, _("encoding error: %s"),
		   gsasl_strerror (res));
	}

      if (!args_info.quiet_given)
	fprintf (stderr, _("Session finished...\n"));

      if (!logout ())
	return 1;

      gsasl_finish (xctx);
    }

  if (sockfd)
    {
#ifdef HAVE_LIBGNUTLS
      if (using_tls)
	{
	  res = gnutls_bye (session, GNUTLS_SHUT_RDWR);
	  if (res < 0)
	    error (EXIT_FAILURE, 0,
		   _("terminating GnuTLS session failed: %s"),
		   gnutls_strerror (res));

	}
#endif
      shutdown (sockfd, SHUT_RDWR);
      close (sockfd);
    }

done:
  gsasl_done (ctx);

#ifdef HAVE_LIBGNUTLS
  if (using_tls)
    {
      gnutls_deinit (session);
      gnutls_anon_free_client_credentials (anoncred);
      gnutls_certificate_free_credentials (x509cred);
      gnutls_global_deinit ();
    }
#endif

  return EXIT_SUCCESS;
}
