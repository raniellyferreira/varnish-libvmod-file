..
.. NB:  This file is machine generated, DO NOT EDIT!
..
.. Edit vmod.vcc and run make instead
..

.. role:: ref(emphasis)

=========
VMOD file
=========

-----------------------------------------------------------------
Varnish Module for reading files that may be updated at intervals
-----------------------------------------------------------------

:Manual section: 3


SYNOPSIS
========

::

  import file;

  # VMOD version
  STRING file.version()

DESCRIPTION
===========

VMOD file is a Varnish module for reading the contents of a file and
caching its contents, returning the contents for use in the Varnish
Configuration Language (VCL), and checking if the file has changed
after specified time intervals elapse. If the file has changed, then
the new contents are read and cached, and are then available in VCL.

XXX ...

.. _file.reader():

new xreader = file.reader(STRING name, STRING path, DURATION ttl, BOOL log_checks)
----------------------------------------------------------------------------------

::

   new xreader = file.reader(
      STRING name,
      STRING path="/usr/local/etc/varnish:/usr/local/share/varnish/vcl:/usr/etc/varnish:/usr/share/varnish/vcl",
      DURATION ttl=120,
      BOOL log_checks=0
   )

XXX ...

.. _xreader.get():

STRING xreader.get()
--------------------

Retrieves the contents of file specified in the constructor. If the
``ttl`` has elapsed, then ``.get()`` checks if the file has changed;
if so, the new contents of the file are read, cached and returned. If
the ``ttl`` has not elapsed, or if the file is unchanged, then the
cached contents are returned.

XXX ...

.. _xreader.synth():

VOID xreader.synth()
--------------------

Generate a synthetic client response body from the file contents. This
method may only be called in ``vcl_synth``.

XXX ...

.. _xreader.error():

BOOL xreader.error()
--------------------

Returns true if and only if an error condition was determined the last
time the file was checked.

XXX ...

.. _xreader.errmsg():

STRING xreader.errmsg()
-----------------------

Returns the error message for any error condition determined the last
time the file was checked, or a message indicating that there was no
error.

XXX ...

.. _xreader.size():

BYTES xreader.size()
--------------------

Returns the size of the file when it was most recently checked.

XXX ...

.. _file.version():

STRING version()
----------------

Return the version string for this VMOD.

Example::

  std.log("Using VMOD file version: " + file.version());

ERRORS
======

XXX ...

REQUIREMENTS
============

The VMOD requires the Varnish master branch. See the source repository for
versions that are compatible with released Varnish versions.

XXX ...

INSTALLATION
============

See `INSTALL.rst <INSTALL.rst>`_ in the source repository.

LIMITATIONS
===========

XXX ...

SEE ALSO
========

* varnishd(1)
* vcl(7)

COPYRIGHT
=========

::

  Copyright (c) 2019 UPLEX Nils Goroll Systemoptimierung
  All rights reserved
 
  Author: Geoffrey Simmons <geoffrey.simmons@uplex.de>
 
  See LICENSE
 
