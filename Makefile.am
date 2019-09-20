ACLOCAL_AMFLAGS = -I m4 -I ${VARNISHAPI_DATAROOTDIR}/aclocal

SUBDIRS = src

DISTCHECK_CONFIGURE_FLAGS = \
	VMOD_DIR='$${libdir}/varnish/vmods'

coverage:
	$(MAKE) $(AM_MAKEFLAGS) -C src coverage

EXTRA_DIST = README.rst LICENSE COPYING CONTRIBUTING.rst INSTALL.rst

doc_DATA = README.rst LICENSE COPYING CONTRIBUTING.rst INSTALL.rst

README.rst: src/vmod_file.vcc
	$(MAKE) $(AM_MAKEFLAGS) -C src vmod_file.man.rst
	cp src/vmod_file.man.rst README.rst

%.1 %.2 %.3 %.4 %.5 %.6 %.7 %.8 %.9:
if HAVE_RST2MAN
	${RST2MAN} $< $@
else
	@echo "========================================"
	@echo "You need rst2man installed to make dist"
	@echo "========================================"
	@false
endif
