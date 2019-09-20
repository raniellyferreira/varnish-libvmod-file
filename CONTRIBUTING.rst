CONTRIBUTING
============

To contribute code or documentation, submit a pull request at the
`source repository website
<https://code.uplex.de/uplex-varnish/libvmod-file>`_.

If you have a problem or discover a bug, you can post an `issue
<https://code.uplex.de/uplex-varnish/libvmod-file/issues>`_ at
the website. You can also write to <varnish-support@uplex.de>.

For developers
--------------

The VMOD source code is in C, and compilation has been tested with gcc
and clang. The code MUST always compile successfully with both of
them.

The build specifies C99 conformance for C sources (``-std=c99``). All
compiler warnings are turned on, and all warnings are considered
errors (``-Werror -Wall -Wextra``).  The code MUST always build
without warnings or errors under these constraints.

By default, ``CFLAGS`` is set to ``-g -O2``, so that symbols are
included in the shared library, and optimization is at level
``O2``. To change or disable these options, set ``CFLAGS`` explicitly
before calling ``configure`` (it may be set to the empty string).

For development/debugging cycles, the ``configure`` option
``--enable-debugging`` is recommended (off by default). This will turn
off optimizations and function inlining, so that a debugger will step
through the code as expected.

Experience has shown that adding ``-ggdb3`` to ``CFLAGS`` is
beneficial if you need to examine the VMOD with the gdb debugger. The
shared object for a VMOD is loaded from a directory relative to the
Varnish home directory (by default ``/usr/local/var/$INSTANCE`` for
development builds). A debugger needs to locate the shared object from
that relative path to load its symbols, so the Varnish home directory
should be the current working directory when the debugger is run. For
example::

  # To run gdb and examine a coredump
  $ cd /usr/local/var/myinstance
  $ gdb /usr/local/sbin/varnishd /path/to/coredump

By default, the VMOD is built with the stack protector enabled
(compile option ``-fstack-protector``), but it can be disabled with
the ``configure`` option ``--disable-stack-protector``.
