## Process this file with automake to produce Makefile.in
# Copyright (C) 2002-2021 Simon Josefsson
#
# This file is part of GNU SASL.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

AM_CFLAGS = $(WERROR_CFLAGS) $(WARN_CFLAGS)
AM_CPPFLAGS = -I$(top_srcdir)/gl -I$(top_builddir)/gl \
	-I$(top_srcdir)/lib/src -I$(top_builddir)/lib/src
AM_CPPFLAGS += -DLOCALEDIR=\"$(datadir)/locale\"

bin_PROGRAMS = gsasl

gsasl_SOURCES = gsasl.c \
	imap.c imap.h smtp.c smtp.h \
	callbacks.h callbacks.c internal.h
gsasl_LDADD = ../lib/src/libgsasl.la ../gl/libgl.la \
	$(LTLIBREADLINE) $(LTLIBGNUTLS) $(LIBSOCKET) $(LTLIBINTL) \
	libgsasl_cmd.la

noinst_LTLIBRARIES = libgsasl_cmd.la
BUILT_SOURCES = gsasl_cmd.c gsasl_cmd.h
libgsasl_cmd_la_SOURCES = $(BUILT_SOURCES) gsasl.ggo
libgsasl_cmd_la_LIBADD = ../gl/libgl.la
libgsasl_cmd_la_CFLAGS =

$(BUILT_SOURCES): gsasl.ggo Makefile.am
	gengetopt --unamed-opts="HOST [PORT]" \
		--no-handle-version --no-handle-help \
		--input $< --file-name gsasl_cmd
