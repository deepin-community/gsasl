# Copyright (C) 2011-2021 Simon Josefsson
#
# This file is part of GNU SASL Library.
#
# GNU SASL Library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public License
# as published by the Free Software Foundation; either version 2.1 of
# the License, or (at your option) any later version.
#
# GNU SASL Library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with GNU SASL Library; if not, write to the Free
# Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# MA 02110-1301, USA.

AM_CFLAGS = $(WERROR_CFLAGS) $(WSTACK_CFLAGS) $(WARN_CFLAGS)
AM_CFLAGS += $(CFLAG_VISIBILITY)
AM_CPPFLAGS = -I$(srcdir)/../src -I../src -I$(srcdir)/../gl -I../gl

noinst_LTLIBRARIES = libgsasl-openid20.la
libgsasl_openid20_la_SOURCES = openid20.h mechinfo.c

if CLIENT
libgsasl_openid20_la_SOURCES += client.c
endif

if SERVER
libgsasl_openid20_la_SOURCES += server.c
endif
