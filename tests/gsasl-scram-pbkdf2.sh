#!/bin/sh

# Copyright (C) 2020-2021 Simon Josefsson
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

set -e
set -x

ROOT=`dirname $0`
GSASL="${GSASL:-$ROOT/../src/gsasl${EXEEXT}}"

if ! test -x "${GSASL}"; then
    exit 77
fi

if ! test -z "${VALGRIND}"; then
    VALGRIND="${LIBTOOL:-../libtool} --mode=execute ${VALGRIND} --leak-check=full --error-exitcode=1"
fi

# Sanity checks
${VALGRIND} "${GSASL}" --mkpasswd --password password --mechanism SCRAM-SHA-1
${VALGRIND} "${GSASL}" --mkpasswd --password password --mechanism SCRAM-SHA-256

# RFC 6070

#     Input:
#       P = "password" (8 octets)
#       S = "salt" (4 octets)
#       c = 1
#       dkLen = 20
#
#     Output:
#       DK = 0c 60 c8 0f 96 1f 0e 71
#            f3 a9 b5 24 af 60 12 06
#            2f e0 37 a6             (20 octets)

OUT=$(${VALGRIND} "${GSASL}" --mkpasswd --password password --mechanism SCRAM-SHA-1 --iteration-count 1 --salt c2FsdA== --verbose)
EXP="{SCRAM-SHA-1}1,c2FsdA==,vVnp0FhQZmQRSMvw9oq1LFMCh8E=,gEBmhcREcU59nXxkDhCePwlgRbY=,0c60c80f961f0e71f3a9b524af6012062fe037a6"
if test "$OUT" != "$EXP"; then
    echo expected $EXP got $OUT
    exit 1
fi

#     Input:
#       P = "password" (8 octets)
#       S = "salt" (4 octets)
#       c = 2
#       dkLen = 20
#
#     Output:
#       DK = ea 6c 01 4d c7 2d 6f 8c
#            cd 1e d9 2a ce 1d 41 f0
#            d8 de 89 57             (20 octets)

OUT=$(${VALGRIND} "${GSASL}" --mkpasswd --password password --mechanism SCRAM-SHA-1 --iteration-count 2 --salt c2FsdA== --verbose)
EXP="{SCRAM-SHA-1}2,c2FsdA==,J4+ucUpxxJUZf/2dj0CKWg+lhvs=,5Alx1KUCWBgKd9mxAgTkpDBis54=,ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"
if test "$OUT" != "$EXP"; then
    echo expected $EXP got $OUT
    exit 1
fi

#     Input:
#       P = "password" (8 octets)
#       S = "salt" (4 octets)
#       c = 4096
#       dkLen = 20
#
#     Output:
#       DK = 4b 00 79 01 b7 65 48 9a
#            be ad 49 d9 26 f7 21 d0
#            65 a4 29 c1             (20 octets)

OUT=$(${VALGRIND} "${GSASL}" --mkpasswd --password password --mechanism SCRAM-SHA-1 --iteration-count 4096 --salt c2FsdA== --verbose)
EXP="{SCRAM-SHA-1}4096,c2FsdA==,0qUypmwka5AUb9oe/OrTaR5uwR8=,BZ90E2UltiQTre5pA3UZCJJGU3w=,4b007901b765489abead49d926f721d065a429c1"
if test "$OUT" != "$EXP"; then
    echo expected $EXP got $OUT
    exit 1
fi

# RFC 7677

OUT=$(${VALGRIND} "${GSASL}" --mkpasswd --password pencil --mechanism SCRAM-SHA-256 --iteration-count 4096 --salt W22ZaJ0SNY7soEsUEjb6gQ== --verbose)
EXP="{SCRAM-SHA-256}4096,W22ZaJ0SNY7soEsUEjb6gQ==,WG5d8oPm3OtcPnkdi4Uo7BkeZkBFzpcXkuLmtbsT4qY=,wfPLwcE6nTWhTAmQ7tl2KeoiWGPlZqQxSrmfPwDl2dU=,c4a49510323ab4f952cac1fa99441939e78ea74d6be81ddf7096e87513dc615d"
if test "$OUT" != "$EXP"; then
    echo expected $EXP got $OUT
    exit 1
fi

exit 0
