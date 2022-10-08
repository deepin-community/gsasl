# Copyright (C) 2006-2021 Simon Josefsson
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

WFLAGS ?= --enable-gcc-warnings
ADDFLAGS ?=
CFGFLAGS ?= --enable-gtk-doc --enable-gtk-doc-pdf $(ADDFLAGS) $(WFLAGS)

_build-aux = lib/build-aux

INDENT_SOURCES = `find . -name '*.[chly]' | grep -v -e /gl -e build-aux -e /win32/ -e /examples/`

ifeq ($(.DEFAULT_GOAL),abort-due-to-no-makefile)
.DEFAULT_GOAL := bootstrap
endif

local-checks-to-skip = sc_prohibit_strcmp sc_error_message_uppercase	\
	sc_prohibit_have_config_h sc_require_config_h			\
	sc_require_config_h_first sc_immutable_NEWS sc_po_check		\
	sc_prohibit_gnu_make_extensions
VC_LIST_ALWAYS_EXCLUDE_REGEX = \
	^((lib/)?GNUmakefile|gtk-doc.make|m4/pkg.m4|doc/gendocs_template|doc/fdl-1.3.texi|doc/specification|doc/doxygen/Doxyfile|(lib/)?po/.*.po.in|(lib/)?maint.mk|((lib/)?(gl|gltests|build-aux))/.*)

# Explicit syntax-check exceptions.
exclude_file_name_regexp--sc_prohibit_empty_lines_at_EOF = ^(lib/)?ABOUT-NLS|doc/.*\.(dia|png)|tests/gssapi.tkt$$
exclude_file_name_regexp--sc_GPL_version = ^doc/lgpl-2.1.texi|lib/.*$$
exclude_file_name_regexp--sc_copyright_check = ^doc/gsasl.texi$$
exclude_file_name_regexp--sc_m4_quote_check = ^m4/.*|lib/m4/.*$$
exclude_file_name_regexp-- = ^m4/.*|lib/m4/.*$$
exclude_file_name_regexp--sc_unmarked_diagnostics = ^examples/.*|src/gsasl.c$$
exclude_file_name_regexp--sc_makefile_TAB_only_indentation = ^(lib/)?po/Makefile.in.in$$
exclude_file_name_regexp--sc_makefile_path_separator_check = ^(lib/)?po/Makefile.in.in$$
exclude_file_name_regexp--sc_bindtextdomain = ^doc/print-errors.c|examples/.*|lib/digest-md5/test-parser.c|lib/tests/test-error.c|tests/.*$$
exclude_file_name_regexp--sc_program_name = $(exclude_file_name_regexp--sc_bindtextdomain)
exclude_file_name_regexp--sc_prohibit_magic_number_exit = ^(lib/)?m4/.*|doc/gsasl.texi|examples/(openid20|saml20)/.*.php|tests.*$$
exclude_file_name_regexp--sc_trailing_blank = ^(lib/)?ABOUT-NLS|doc/.*\.(eps|png)|(lib/)?po/.*$$
exclude_file_name_regexp--sc_space_tab = ^(lib/)?m4/lib-prefix.m4$$
exclude_file_name_regexp--sc_useless_cpp_parens = ^(lib/)?m4/.*$$
exclude_file_name_regexp--sc_prohibit_test_minus_ao = ^lib/m4/libgcrypt.m4$$

update-copyright-env = UPDATE_COPYRIGHT_HOLDER="Simon Josefsson" UPDATE_COPYRIGHT_USE_INTERVALS=2 UPDATE_COPYRIGHT_FORCE=1

autoreconf:
	for f in po/*.po.in lib/po/*.po.in; do \
		cp $$f `echo $$f | sed 's/.in//'`; \
	done
	touch ChangeLog lib/ChangeLog
	if ! test -f ./configure; then \
		libtoolize --copy --install; \
		cd lib && libtoolize --copy --install && cd ..; \
		patch -d m4 < gl/override/0001-Fix-export-symbols-and-export-symbols-regex-support-.patch; \
		patch -d lib/m4 < gl/override/0001-Fix-export-symbols-and-export-symbols-regex-support-.patch; \
		AUTOPOINT=true LIBTOOLIZE=true autoreconf --install --verbose; \
	fi

update-po:
	$(MAKE) -C lib refresh-po PACKAGE=libgsasl
	$(MAKE) refresh-po PACKAGE=gsasl
	for f in `ls lib/po/*.po po/*.po | grep -v quot.po`; do \
		cp $$f $$f.in; \
	done
	git add po/*.po.in lib/po/*.po.in
	git commit -m "Sync with TP." \
		po/LINGUAS po/*.po.in lib/po/LINGUAS lib/po/*.po.in

bootstrap: autoreconf
	./configure $(CFGFLAGS)

glimport:
	gtkdocize --copy
	autopoint --force
	cd lib && autopoint --force
	gnulib-tool --add-import
	cd lib && gnulib-tool --add-import

review-diff:
	git diff `git describe --abbrev=0`.. \
	| grep -v -e ^index -e '^diff --git' \
	| filterdiff -p 1 -x 'gl/*' -x 'm4/*' -x 'gltests/*' -x 'lib/build-aux/*' -x 'lib/gl*' -x 'lib/m4/*' -x 'lib/gltests/*' -x 'po/*' -x 'lib/po/*' -x 'maint.mk' -x 'lib/maint.mk' -x '.gitignore' -x '.x-sc*' -x ChangeLog -x GNUmakefile -x ABOUT-NLS -x lib/ABOUT-NLS \
	| less

# Release

htmldir = ../www-$(PACKAGE)

i18n:
	-$(MAKE) update-po

gendoc-copy:
	cd doc && env MAKEINFO="makeinfo -I ../examples" \
		      TEXI2DVI="texi2dvi -I ../examples" \
		$(SHELL) ../$(_build-aux)/gendocs.sh \
			--html "--css-include=texinfo.css" \
			-o ../$(htmldir)/manual/ $(PACKAGE) "$(PACKAGE_NAME)"

gendoc-upload:
	cd $(htmldir) && \
		cvs add manual || true && \
		cvs add manual/html_node || true && \
		cvs add -kb manual/*.gz manual/*.pdf || true && \
		cvs add manual/*.txt manual/*.html \
			manual/html_node/*.html || true && \
		cvs commit -m "Update." manual/

gtkdoc-copy:
	mkdir -p $(htmldir)/reference/
	cp -v doc/reference/$(PACKAGE).pdf \
		doc/reference/html/*.html \
		doc/reference/html/*.png \
		doc/reference/html/*.devhelp2 \
		doc/reference/html/*.css \
		$(htmldir)/reference/

gtkdoc-upload:
	cd $(htmldir) && \
		cvs add reference || true && \
		cvs add -kb reference/*.png reference/*.pdf || true && \
		cvs add reference/*.html reference/*.css \
			reference/*.devhelp2 || true && \
		cvs commit -m "Update." reference/

doxygen-copy:
	cd doc/doxygen && \
		doxygen && \
		cd ../.. && \
		cp -v doc/doxygen/html/* $(htmldir)/doxygen/ && \
		cd doc/doxygen/latex && \
		make refman.pdf && \
		cd ../../../ && \
		cp doc/doxygen/latex/refman.pdf $(htmldir)/doxygen/$(PACKAGE).pdf

doxygen-upload:
	cd $(htmldir) && \
		cvs commit -m "Update." doxygen/

ChangeLog:
	git2cl > ChangeLog
	cat .clcopying >> ChangeLog

tag = $(PACKAGE)-`echo $(VERSION) | sed 's/\./-/g'`

tarball:
	$(MAKE) -C lib tarball
	! git tag -l $(tag) | grep $(PACKAGE) > /dev/null
	rm -f ChangeLog
	$(MAKE) ChangeLog distcheck

binaries:
	-mkdir windows/dist
	cp $(distdir).tar.gz windows/dist
	cd windows && $(MAKE) -f gsasl4win.mk gsasl4win VERSION=$(VERSION)

source:
	git tag -s -m $(VERSION) $(tag)

release-check: syntax-check i18n tarball gendoc-copy gtkdoc-copy doxygen-copy

release-upload-www: gendoc-upload gtkdoc-upload doxygen-upload

site = ftp.gnu.org

release-upload-ftp:
	$(_build-aux)/gnupload --to $(site):$(PACKAGE) $(distdir).tar.gz
	cd lib && ../$(_build-aux)/gnupload --to $(site):$(PACKAGE) lib$(distdir).tar.gz
	cp -v $(distdir).tar.gz* lib/lib$(distdir).tar.gz* ../releases/$(PACKAGE)/
	git push
	git push --tags

release: release-check release-upload-www source release-upload-ftp
