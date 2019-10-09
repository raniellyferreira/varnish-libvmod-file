# -D MUST pass in _version and _release, and SHOULD pass in dist.

Summary: Varnish VMOD for reading files that may be updated at intervals
Name: vmod-file
Version: %{_version}
Release: %{_release}%{?dist}
License: BSD
Group: System Environment/Daemons
URL: https://code.uplex.de/uplex-varnish/libvmod-file
Source0: %{name}-%{version}.tar.gz

# varnish from varnish63 at packagecloud
# This is the Requires for VMOD ABI compatibility with VRT >= 10.0.
Requires: varnishd(vrt)%{?_isa} >= 10

BuildRequires: varnish-devel >= 6.3.0
BuildRequires: pkgconfig
BuildRequires: make
BuildRequires: gcc
BuildRequires: python-docutils >= 0.6

# git builds
#BuildRequires: automake
#BuildRequires: autoconf
#BuildRequires: autoconf-archive
#BuildRequires: libtool
#BuildRequires: python-docutils >= 0.6

Provides: vmod-file, vmod-file-debuginfo

%description
VMOD file is a Varnish Module for reading the contents of a file and
caching its contents, returning the contents for use in the Varnish
Configuration Language (VCL), and checking if the file has changed after
specified time intervals elapse.

%prep
%setup -q -n %{name}-%{version}

%build

# if this were a git build
# ./autogen.sh

%configure

make -j

%check

make -j check

%install

make install DESTDIR=%{buildroot}

# Only use the version-specific docdir created by %doc below
rm -rf %{buildroot}%{_docdir}

# None of these for fedora/epel
find %{buildroot}/%{_libdir}/ -name '*.la' -exec rm -f {} ';'
find %{buildroot}/%{_libdir}/ -name '*.a' -exec rm -f {} ';'

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%{_libdir}/varnish*/vmods/
%{_mandir}/man3/*.3*
%doc README.rst COPYING LICENSE

%post
/sbin/ldconfig

%changelog
* Wed Oct 9 2019 Geoff Simmons <geoff@uplex.de> - %{_version}-%{_release}
- Bugfix: file mtime nanoseconds may be 0

* Tue Oct 8 2019 Geoff Simmons <geoff@uplex.de> - 0.2.0-1
- Require VRT 10.0, compatible with Varnish 6.3
