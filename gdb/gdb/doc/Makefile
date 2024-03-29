##Copyright (C) 1991, 1992, 1993, 1994, 1995, 1996, 1999, 2000, 2002, 2003,
##2007, 2008, 2009, 2010 Free Software Foundation, Inc.

# Makefile for GDB documentation.
# This file is part of GDB.

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

srcdir = .


prefix = /mnt/hgfs/prj/kern_dbg_info/gdb/gdb_bin

infodir = ${datarootdir}/info
datarootdir = ${prefix}/share
docdir = ${datarootdir}/doc/${PACKAGE}
pdfdir = ${docdir}
htmldir = ${docdir}

SHELL = /bin/bash

LN_S = ln -s

INSTALL = /usr/bin/install -c
INSTALL_PROGRAM = /usr/bin/install -c
INSTALL_DATA = /usr/bin/install -c -m 644

mkinstalldirs = $(SHELL) $(srcdir)/../../mkinstalldirs

# main GDB source directory
gdbdir = $(srcdir)/..

# where to find texinfo; GDB dist should include a recent one
TEXIDIR=${gdbdir}/../texinfo

# where to find makeinfo, preferably one designed for texinfo-2
MAKEINFO=makeinfo

MAKEHTML = $(MAKEINFO) --html 
MAKEHTMLFLAGS =

# where to find texi2roff, ditto
TEXI2ROFF=texi2roff

# where to find texi2dvi, ditto
TEXI2DVI=texi2dvi

# Package version and bug-reporting URL.
PKGVERSION = (GDB) 
BUGURL_TEXI = @uref{http://www.gnu.org/software/gdb/bugs/}

# Where is the source dir for the READLINE library doc?  
# Traditionally readline is in .. or .
READLINE_DIR = ${gdbdir}/../readline/doc

# The GDB/MI docs come from a sibling directory ../mi
GDBMI_DIR = ${gdbdir}/mi

SET_TEXINPUTS = \
   TEXINPUTS=${TEXIDIR}:.:$(srcdir):$(READLINE_DIR):$(GDBMI_DIR):$$TEXINPUTS

# Files which should be generated via 'info' and installed by 'install-info'
INFO_DEPS = gdb.info gdbint.info stabs.info annotate.info

# Files which should be generated via 'pdf' and installed by 'install-pdf'
PDFFILES = gdb.pdf gdbint.pdf stabs.pdf refcard.pdf annotate.pdf
# Files which should be generated via 'html' and installed by 'install-html'
HTMLFILES =  gdb/index.html gdbint/index.html stabs/index.html annotate/index.html
HTMLFILES_INSTALL = gdb gdbint stabs annotate

# There may be alternate predefined collections of switches to configure
# the GDB manual.  Normally this is not done in synch with the software
# config system, since this choice tends to be independent; most people
# want a doc config of `all' for a generic manual, regardless of sw config.
DOC_CONFIG = all

# This list of sed edits will edit the GDB reference card
# for what fonts and what papersize to use.
# By default (NO edits applied), the refcard uses:
#    - Computer Modern (CM) fonts
#    - US letter paper (8.5x11in)
# List some of the following files for alternative fonts and paper:
#  a4rc.sed     use A4 paper (297 x 210 mm)
#  psrc.sed     use PostScript fonts (Karl Berry short TeX names)
# lpsrc.sed     use PostScript fonts (full PostScript names in TeX)
# e.g. for A4, Postscript:  REFEDITS = a4rc.sed psrc.sed
#      for A4, CM fonts:    REFEDITS = a4rc.sed
#      for US, PS fonts:    REFEDITS = psrc.sed
#      for default:
REFEDITS =

# Don Knuth's TeX formatter
TEX = tex
PDFTEX = pdftex

# Program to generate Postscript files from DVI files.
DVIPS = dvips

# Main GDB manual
GDB_DOC_SOURCE_INCLUDES = \
	$(srcdir)/fdl.texi \
	$(srcdir)/gpl.texi \
	$(srcdir)/agentexpr.texi \
	$(READLINE_DIR)/rluser.texi \
	$(READLINE_DIR)/inc-hist.texinfo
GDB_DOC_BUILD_INCLUDES = \
	gdb-cfg.texi \
	GDBvn.texi
GDB_DOC_FILES = \
	$(srcdir)/gdb.texinfo \
	$(GDB_DOC_SOURCE_INCLUDES) \
	$(GDB_DOC_BUILD_INCLUDES)

# Internals Manual
GDBINT_DOC_SOURCE_INCLUDES = \
	$(srcdir)/fdl.texi \
	$(srcdir)/observer.texi
GDBINT_DOC_BUILD_INCLUDES = \
	gdb-cfg.texi \
	GDBvn.texi
GDBINT_DOC_FILES = \
	$(srcdir)/gdbint.texinfo \
	$(GDBINT_DOC_SOURCE_INCLUDES) \
	$(GDBINT_DOC_BUILD_INCLUDES)

# Stabs manual: All files
STABS_DOC_SOURCE_INCLUDES = \
	$(srcdir)/fdl.texi
STABS_DOC_BUILD_INCLUDES =
STABS_DOC_FILES = \
	$(srcdir)/stabs.texinfo \
	$(STABS_DOC_SOURCE_INCLUDES) \
	$(STABS_DOC_BUILD_INCLUDES)

# Annotate migration document
ANNOTATE_DOC_SOURCE_INCLUDES = \
	$(srcdir)/fdl.texi
ANNOTATE_DOC_BUILD_INCLUDES = \
	gdb-cfg.texi \
	GDBvn.texi
ANNOTATE_DOC_FILES = \
	$(srcdir)/annotate.texinfo \
	$(ANNOTATE_DOC_SOURCE_INCLUDES) \
	$(ANNOTATE_DOC_BUILD_INCLUDES)

#### Host, target, and site specific Makefile fragments come in here.
###

all:

info: $(INFO_DEPS)
dvi: gdb.dvi gdbint.dvi stabs.dvi refcard.dvi annotate.dvi
ps: gdb.ps gdbint.ps stabs.ps refcard.ps annotate.ps
html: $(HTMLFILES)
pdf: $(PDFFILES)
all-doc: info dvi ps # pdf
diststuff: info

install-info: $(INFO_DEPS)
	$(SHELL) $(srcdir)/../../mkinstalldirs $(DESTDIR)$(infodir)
	@list='$(INFO_DEPS)'; \
	for file in $$list; do \
	  if test -f $$file; then d=.; else d=$(srcdir); fi; \
	  for ifile in `cd $$d && echo $$file $$file-[0-9] $$file-[0-9][0-9]`; do \
	    if test -f $$d/$$ifile; then \
	      echo " $(INSTALL_DATA) $$d/$$ifile $(DESTDIR)$(infodir)/$$ifile"; \
	      $(INSTALL_DATA) $$d/$$ifile $(DESTDIR)$(infodir)/$$ifile; \
	    else : ; fi; \
	  done; \
	done
	$(POST_INSTALL)
	@if $(SHELL) -c 'install-info --version | sed 1q | fgrep -s -v -i debian' >/dev/null 2>&1; then \
	  list='$(INFO_DEPS)'; \
	  for file in $$list; do \
	    echo " install-info --info-dir=$(DESTDIR)$(infodir) $(DESTDIR)$(infodir)/$$file";\
	    install-info --info-dir=$(DESTDIR)$(infodir) $(DESTDIR)$(infodir)/$$file || :;\
	  done; \
	else : ; fi

uninstall-info:
	$(PRE_UNINSTALL)
	@if $(SHELL) -c 'install-info --version | sed 1q | fgrep -s -v -i debian' >/dev/null 2>&1; then \
	  ii=yes; \
	else ii=; fi; \
	list='$(INFO_DEPS)'; \
	for file in $$list; do \
	  test -z "$$ii" \
	    || install-info --info-dir=$(DESTDIR)$(infodir) --remove $$file; \
	done
	$(NORMAL_UNINSTALL)
	list='$(INFO_DEPS)'; \
	for file in $$list; do \
	  (cd $(DESTDIR)$(infodir) && rm -f $$file $$file-[0-9] $$file-[0-9][0-9]); \
	done

html__strip_dir = `echo $$p | sed -e 's|^.*/||'`;

install-html: $(HTMLFILES)
	@$(NORMAL_INSTALL)
	test -z "$(htmldir)" || $(mkinstalldirs) "$(DESTDIR)$(htmldir)"
	@list='$(HTMLFILES_INSTALL)'; for p in $$list; do \
	  if test -f "$$p" || test -d "$$p"; then d=""; else d="$(srcdir)/"; fi; \
	  f=$(html__strip_dir) \
	  if test -d "$$d$$p"; then \
	    echo " $(mkinstalldirs) '$(DESTDIR)$(htmldir)/$$f'"; \
	    $(mkinstalldirs) "$(DESTDIR)$(htmldir)/$$f" || exit 1; \
	    echo " $(INSTALL_DATA) '$$d$$p'/* '$(DESTDIR)$(htmldir)/$$f'"; \
	    $(INSTALL_DATA) "$$d$$p"/* "$(DESTDIR)$(htmldir)/$$f"; \
	  else \
	    echo " $(INSTALL_DATA) '$$d$$p' '$(DESTDIR)$(htmldir)/$$f'"; \
	    $(INSTALL_DATA) "$$d$$p" "$(DESTDIR)$(htmldir)/$$f"; \
	  fi; \
	done

pdf__strip_dir = `echo $$p | sed -e 's|^.*/||'`;

install-pdf: $(PDFFILES)
	@$(NORMAL_INSTALL)
	test -z "$(pdfdir)" || $(mkinstalldirs) "$(DESTDIR)$(pdfdir)"
	@list='$(PDFFILES)'; for p in $$list; do \
	  if test -f "$$p"; then d=; else d="$(srcdir)/"; fi; \
	  f=$(pdf__strip_dir) \
	  echo " $(INSTALL_DATA) '$$d$$p' '$(DESTDIR)$(pdfdir)/$$f'"; \
	  $(INSTALL_DATA) "$$d$$p" "$(DESTDIR)$(pdfdir)/$$f"; \
	done

STAGESTUFF = *.info* gdb-all.texi GDBvn.texi *.ps *.dvi *.pdf

# Copy the object files from a particular stage into a subdirectory.
stage1: force
	-mkdir stage1
	-mv $(STAGESTUFF) stage1

stage2: force
	-mkdir stage2
	-mv $(STAGESTUFF) stage2

stage3: force
	-mkdir stage3
	-mv $(STAGESTUFF) stage3

against=stage2

comparison: force
	for i in $(STAGESTUFF) ; do cmp $$i $(against)/$$i ; done

de-stage1: force
	-(cd stage1 ; mv -f * ..)
	-rmdir stage1

de-stage2: force
	-(cd stage2 ; mv -f * ..)
	-rmdir stage2

de-stage3: force
	-(cd stage3 ; mv -f * ..)
	-rmdir stage3

# GDB QUICK REFERENCE (dvi output)
refcard.dvi : refcard.tex $(REFEDITS)
	echo > tmp.sed
	for f in x $(REFEDITS) ; do \
		test x$$f = xx && continue ; \
		cat $(srcdir)/$$f >>tmp.sed ; \
	done
	sed -f tmp.sed $(srcdir)/refcard.tex >sedref.tex
	$(SET_TEXINPUTS) $(TEX) sedref.tex
	mv sedref.dvi refcard.dvi
	rm -f sedref.log sedref.tex tmp.sed

refcard.ps : refcard.dvi
	$(DVIPS) -t landscape -o $@ $?

refcard.pdf : refcard.tex $(REFEDITS)
	echo > tmp.sed
	for f in x $(REFEDITS) ; do \
		test x$$f = xx && continue ; \
		cat $(srcdir)/$$f >>tmp.sed ; \
	done
	sed -f tmp.sed $(srcdir)/refcard.tex >sedref.tex
	$(SET_TEXINPUTS) $(PDFTEX) sedref.tex
	mv sedref.pdf refcard.pdf
	rm -f sedref.log sedref.tex tmp.sed

# File to record current GDB version number (copied from main dir version.in)
GDBvn.texi : ${gdbdir}/version.in
	echo "@set GDBVN `sed q $(srcdir)/../version.in`" > ./GDBvn.new
	if [ -n "$(PKGVERSION)" ]; then \
	  echo "@set VERSION_PACKAGE $(PKGVERSION)" >> ./GDBvn.new; \
	fi
	echo "@set BUGURL $(BUGURL_TEXI)" >> ./GDBvn.new
	if [ "$(BUGURL_TEXI)" = "@uref{http://www.gnu.org/software/gdb/bugs/}" ]; then \
	  echo "@set BUGURL_DEFAULT" >> ./GDBvn.new; \
	fi
	mv GDBvn.new GDBvn.texi

# Updated atomically
.PRECIOUS: GDBvn.texi

# Choose configuration for GDB manual (normally `all'; normally not tied into
# `configure' script because most users prefer generic version of manual,
# not one for their binary config---which may not be specifically
# defined anyways).
gdb-cfg.texi: ${srcdir}/${DOC_CONFIG}-cfg.texi
	(test "$(LN_S)" = "ln -s" && \
	  ln -s ${srcdir}/${DOC_CONFIG}-cfg.texi gdb-cfg.texi) || \
	ln ${srcdir}/${DOC_CONFIG}-cfg.texi gdb-cfg.texi || \
	cp ${srcdir}/${DOC_CONFIG}-cfg.texi gdb-cfg.texi

# GDB MANUAL: texinfo source, using @set/@clear/@value/@ifset/@ifclear
# If your texinfo or makeinfo don't support these, get a new texinfo release
#
# The nonsense with GDBvn.texi gets this to run with both Sun and GNU make.
#   Note that we can *generate* GDBvn.texi, but since we distribute one in the
#   source directory for the benefit of people who *don't* use this makefile,
#   VPATH will often tell make not to bother building it, because the one
#   in the srcdir is up to date.  (if not, then make should build one here).

# Clean these up before each run.  Avoids a catch 22 with not being
# able to re-generate these files (to fix a corruption) because these
# files contain a corruption.
GDB_TEX_TMPS = gdb.aux gdb.cp* gdb.fn* gdb.ky* gdb.log gdb.pg* gdb.toc \
	gdb.tp* gdb.vr*

# GDB MANUAL: TeX dvi file
gdb.dvi: ${GDB_DOC_FILES}
	if [ ! -f ./GDBvn.texi ]; then \
		(test "$(LN_S)" = "ln -s" && ln -s $(srcdir)/GDBvn.texi .) || \
		ln $(srcdir)/GDBvn.texi . || \
		cp $(srcdir)/GDBvn.texi . ; else true; fi
	rm -f $(GDB_TEX_TMPS)
	$(TEXI2DVI) -I ${READLINE_DIR} -I ${GDBMI_DIR} -I $(srcdir) \
		$(srcdir)/gdb.texinfo

gdb.ps: gdb.dvi
	$(DVIPS) -o $@ $?

gdb.pdf: ${GDB_DOC_FILES}
	if [ ! -f ./GDBvn.texi ]; then \
		(test "$(LN_S)" = "ln -s" && ln -s $(srcdir)/GDBvn.texi .) || \
		ln $(srcdir)/GDBvn.texi . || \
		cp $(srcdir)/GDBvn.texi . ; else true; fi
	rm -f $(GDB_TEX_TMPS)
	$(TEXI2DVI) --pdf -I ${READLINE_DIR} -I ${GDBMI_DIR} -I $(srcdir) \
		$(srcdir)/gdb.texinfo

# GDB MANUAL: info file
gdb.info: ${GDB_DOC_FILES}
	$(MAKEINFO) -I ${READLINE_DIR} -I ${GDBMI_DIR} -I $(srcdir) \
		-o gdb.info $(srcdir)/gdb.texinfo

# GDB MANUAL: roff translations
# Try to use a recent texi2roff.  v2 was put on prep in jan91.
# If you want an index, see texi2roff doc for postprocessing 
# and add -i to texi2roff invocations below.
# Workarounds for texi2roff-2 (probably fixed in later texi2roff's, delete
#    corresponding -e lines when later texi2roff's are current)
# + @ifinfo's deleted explicitly due to texi2roff-2 bug w nested constructs.
# + @c's deleted explicitly because texi2roff sees texinfo commands in them
# + @   (that's at-BLANK) not recognized by texi2roff, turned into blank
# + @alphaenumerate is ridiculously new, turned into @enumerate

# texi2roff doesn't have a notion of include dirs, so we have to fake 
# it out for gdb manual's include files---but only if not configured
# in main sourcedir.
links2roff: $(GDB_DOC_SOURCE_INCLUDES)
	if [ ! -f gdb.texinfo ]; then \
		(test "$(LN_S)" = "ln -s" && ln -s $(GDB_DOC_SOURCE_INCLUDES) .) || \
		ln $(GDB_DOC_SOURCE_INCLUDES)    . || \
		cp $(GDB_DOC_SOURCE_INCLUDES)    . ; \
	fi
	touch links2roff

# gdb manual suitable for [gtn]roff -me
gdb.me: $(GDB_DOC_FILES) links2roff
	sed -e '/\\input texinfo/d' \
		-e '/@c TEXI2ROFF-KILL/,/@c END TEXI2ROFF-KILL/d' \
		-e '/^@ifinfo/,/^@end ifinfo/d' \
		-e '/^@c /d' \
		-e 's/{.*,,/{/' \
		-e 's/@ / /g' \
		-e 's/^@alphaenumerate/@enumerate/g' \
		-e 's/^@end alphaenumerate/@end enumerate/g' \
		$(srcdir)/gdb.texinfo | \
	$(TEXI2ROFF) -me | \
	sed -e 's/---/\\(em/g' \
	>gdb.me 

# gdb manual suitable for [gtn]roff -ms
gdb.ms: $(GDB_DOC_FILES) links2roff
	sed -e '/\\input texinfo/d' \
		-e '/@c TEXI2ROFF-KILL/,/@c END TEXI2ROFF-KILL/d' \
		-e '/^@ifinfo/,/^@end ifinfo/d' \
		-e '/^@c /d' \
		-e 's/{.*,,/{/' \
		-e 's/@ / /g' \
		-e 's/^@alphaenumerate/@enumerate/g' \
		-e 's/^@end alphaenumerate/@end enumerate/g' \
		$(srcdir)/gdb.texinfo | \
	$(TEXI2ROFF) -ms | \
	sed -e 's/---/\\(em/g' \
	>gdb.ms 

# gdb manual suitable for [tn]roff -mm
# '@noindent's removed due to texi2roff-2 mm bug; if yours is newer, 
#   try leaving them in
gdb.mm: $(GDB_DOC_FILES) links2roff
	sed -e '/\\input texinfo/d' \
		-e '/@c TEXI2ROFF-KILL/,/@c END TEXI2ROFF-KILL/d' \
		-e '/^@ifinfo/,/^@end ifinfo/d' \
		-e '/^@c /d' \
		-e 's/{.*,,/{/' \
		-e '/@noindent/d' \
		-e 's/@ / /g' \
		-e 's/^@alphaenumerate/@enumerate/g' \
		-e 's/^@end alphaenumerate/@end enumerate/g' \
		$(srcdir)/gdb.texinfo | \
	$(TEXI2ROFF) -mm | \
	sed -e 's/---/\\(em/g' \
	>gdb.mm 

# GDB MANUAL: HTML file

gdb/index.html: ${GDB_DOC_FILES}
	$(MAKEHTML) $(MAKEHTMLFLAGS) -I ${READLINE_DIR} -I ${GDBMI_DIR} -I $(srcdir) $(srcdir)/gdb.texinfo

# Clean these up before each run.  Avoids a catch 22 with not being
# able to re-generate these files (to fix a corruption) because these
# files contain a corruption.
GDBINT_TEX_TMPS = gdbint.aux gdbint.cp* gdbint.fn* gdbint.ky* \
	gdbint.log gdbint.pg* gdbint.toc gdbint.tp* gdbint.vr*

# GDB INTERNALS MANUAL: TeX dvi file
gdbint.dvi: $(GDBINT_DOC_FILES)
	rm -f $(GDBINT_TEX_TMPS)
	$(TEXI2DVI) -I $(srcdir) $(srcdir)/gdbint.texinfo

gdbint.ps : gdbint.dvi
	$(DVIPS) -o $@ $?

gdbint.pdf: $(GDBINT_DOC_FILES)
	rm -f $(GDBINT_TEX_TMPS)
	$(TEXI2DVI) --pdf -I $(srcdir) $(srcdir)/gdbint.texinfo

# GDB INTERNALS MANUAL: info file

gdbint.info: $(GDBINT_DOC_FILES)
	$(MAKEINFO) -I $(srcdir) -o gdbint.info $(srcdir)/gdbint.texinfo

# GDB INTERNALS MANUAL: HTML file

gdbint/index.html: $(GDBINT_DOC_FILES)
	$(MAKEHTML) $(MAKEHTMLFLAGS) -I $(srcdir) $(srcdir)/gdbint.texinfo

stabs.info: $(STABS_DOC_FILES)
	$(MAKEINFO) -I $(srcdir) -o stabs.info $(srcdir)/stabs.texinfo

# STABS DOCUMENTATION: HTML file

stabs/index.html: $(STABS_DOC_FILES)
	$(MAKEHTML) $(MAKEHTMLFLAGS) -I $(srcdir) $(srcdir)/stabs.texinfo

# Clean these up before each run.  Avoids a catch 22 with not being
# able to re-generate these files (to fix a corruption) because these
# files contain a corruption.
STABS_TEX_TMPS = stabs.aux stabs.cp* stabs.fn* stabs.ky* \
	stabs.log stabs.pg* stabs.toc stabs.tp* stabs.vr*

# STABS DOCUMENTATION: TeX dvi file
stabs.dvi : $(STABS_DOC_FILES)
	rm -f $(STABS_TEX_TMPS)
	$(TEXI2DVI) -I $(srcdir) $(srcdir)/stabs.texinfo

stabs.ps: stabs.dvi
	$(DVIPS) -o $@ $?

stabs.pdf: $(STABS_DOC_FILES)
	rm -f $(STABS_TEX_TMPS)
	$(TEXI2DVI) --pdf -I $(srcdir) $(srcdir)/stabs.texinfo

# Clean these up before each run.  Avoids a catch 22 with not being
# able to re-generate these files (to fix a corruption) because these
# files contain a corruption.
ANNOTATE_TEX_TMPS = annotate.aux annotate.cp* annotate.fn* annotate.ky* \
	annotate.log annotate.pg* annotate.toc annotate.tp* annotate.vr*

# ANNOTATE DOCUMENTATION: TeX dvi file
annotate.dvi : $(ANNOTATE_DOC_FILES)
	rm -f $(ANNOTATE_TEX_TMPS)
	$(TEXI2DVI) -I $(srcdir) $(srcdir)/annotate.texinfo

annotate.ps: annotate.dvi
	$(DVIPS) -o $@ $?

annotate.pdf: $(ANNOTATE_DOC_FILES)
	rm -f $(ANNOTATE_TEX_TMPS)
	$(TEXI2DVI) --pdf -I $(srcdir) $(srcdir)/annotate.texinfo

annotate.info: $(ANNOTATE_DOC_FILES)
	$(MAKEINFO)  -I $(srcdir) -o annotate.info $(srcdir)/annotate.texinfo

annotate/index.html: $(ANNOTATE_DOC_FILES)
	$(MAKEHTML) $(MAKEHTMLFLAGS) -I $(srcdir) $(srcdir)/annotate.texinfo

force:

Makefile: Makefile.in $(host_makefile_frag) config.status
	$(SHELL) ./config.status


# The "least clean" level of cleaning.  Get rid of files which are
# automatically generated files that are just intermediate files,

mostlyclean:
	rm -f gdb.mm gdb.ms gdb.me links2roff
	rm -f $(GDB_TEX_TMPS)
	rm -f $(GDBINT_TEX_TMPS)
	rm -f $(STABS_TEX_TMPS)
	rm -f $(ANNOTATE_TEX_TMPS)
	rm -f sedref.dvi sedref.tex tmp.sed

clean: mostlyclean
	rm -f gdb-cfg.texi

distclean: clean
	rm -f Makefile config.status config.log

# GDBvn.texi, the dvi files, the info files, and the postscript files, 
# are all part of the distribution, so it should not be removed by
# "clean" or "distclean".  Use maintainer-clean to remove them.

maintainer-clean realclean: distclean
	rm -f GDBvn.texi *.info* *.dvi *.ps *.html *.pdf

install: install-info

uninstall: uninstall-info
