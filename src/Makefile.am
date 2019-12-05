AUTOMAKE_OPTIONS = subdir-objects

AM_CFLAGS = $(VARNISHAPI_CFLAGS) -Wall -Werror -Wextra -std=c99
AM_LDFLAGS = $(VARNISHAPI_LIBS) -ldl -lrt

vmod_LTLIBRARIES = libvmod_file.la

libvmod_file_la_SOURCES = \
	vmod_file.c \
	zero_obj.h

nodist_libvmod_file_la_SOURCES = \
	vcc_if.c \
	vcc_if.h

vmod_file.lo: $(nodist_libvmod_file_la_SOURCES) zero_obj.h

dist_man_MANS = vmod_file.3

vcc_if.h vmod_file.rst vmod_file.man.rst: vcc_if.c

vcc_if.c: vmod_file.vcc
	$(AM_V_VMODTOOL) $(PYTHON) $(VMODTOOL) -o vcc_if $(srcdir)/vmod_file.vcc

vmod_file.3: vmod_file.man.rst
	$(AM_V_GEN) $(RST2MAN) vmod_file.man.rst vmod_file.3

AM_TESTS_ENVIRONMENT = \
	PATH="$(VMOD_TEST_PATH)" \
	LD_LIBRARY_PATH="$(VARNISH_LIBRARY_PATH)"
TEST_EXTENSIONS = .vtc
VTC_LOG_COMPILER = varnishtest -v
AM_VTC_LOG_FLAGS = -Dvmod_file="$(VMOD_FILE)"
TESTS = @VMOD_TESTS@

# To test an individual VTC test named test.vtc:
# $ cd src/
# $ make check TESTS=tests/test.vtc

gcov: clean
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) CC=gcc \
		CFLAGS="${AM_CFLAGS} --coverage -fno-inline -g -O0" check

# Set QUIET=-q for non-verbose builds, otherwise set to empty.
QUIET_0 = -q
QUIET_ = $(QUIET_@AM_DEFAULT_V@)
QUIET = $(QUIET_@AM_V@)

coverage/lcov.info: gcov
if HAVE_LCOV
	$(AM_V_at)@mkdir $(builddir)/coverage
	$(AM_V_GEN) $(LCOV) $(QUIET) -c -d . -o  $(builddir)/coverage/lcov.info
else
	@echo "================================================="
	@echo "You need lcov installed to generate coverage data"
	@echo "================================================="
	@false
endif

coverage: coverage/lcov.info
if HAVE_GENHTML
	$(AM_V_GEN) $(GENHTML) $(QUIET) $(builddir)/coverage/lcov.info \
		-o  $(builddir)/coverage
else
	@echo "======================================================="
	@echo "You need genhtml installed to generate coverage reports"
	@echo "======================================================="
	@false
endif

EXTRA_DIST = \
	vmod_file.vcc \
	$(VMOD_TESTS)

CLEANFILES = \
	$(builddir)/vcc_if.c \
	$(builddir)/vcc_if.h \
	$(builddir)/vmod_file.rst \
	$(builddir)/vmod_file.man.rst \
	$(builddir)/vmod_file.3 \
	$(builddir)/*.gcda \
	$(builddir)/*.gcno

clean-local:
	@rm -rf $(builddir)/coverage
