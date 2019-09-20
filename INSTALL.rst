INSTALLATION
============

Building from source
~~~~~~~~~~~~~~~~~~~~

The VMOD is built against a Varnish installation, and the autotools
use ``pkg-config(1)`` to locate the necessary header files and other
resources. This sequence will install the VMOD::

  > ./autogen.sh	# for builds from the git repo
  > ./configure
  > make
  > make check		# to run unit tests in src/tests/*.vtc
  > make distcheck	# run check and prepare a distribution tarball
  > sudo make install

See `CONTRIBUTING.rst <CONTRIBUTING.rst>`_ for notes about building
from source.

If you have installed Varnish in non-standard directories, call
``autogen.sh`` and ``configure`` with the ``PKG_CONFIG_PATH``
environment variable set to include the paths where the ``.pc`` file
can be located for ``varnishapi``. For example, when varnishd
configure was called with ``--prefix=$PREFIX``, use::

  > PKG_CONFIG_PATH=${PREFIX}/lib/pkgconfig
  > export PKG_CONFIG_PATH

By default, the vmod ``configure`` script installs the vmod in
the same directory as Varnish, determined via ``pkg-config(1)``. The
vmod installation directory can be overridden by passing the
``VMOD_DIR`` variable to ``configure``.

Other files such as the man-page are installed in the locations
determined by ``configure``, which inherits its default ``--prefix``
setting from Varnish.
