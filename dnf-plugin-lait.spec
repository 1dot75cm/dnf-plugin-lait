%{?!dnf_lowest_compatible: %global dnf_lowest_compatible 1.1.9}
%{?!dnf_not_compatible: %global dnf_not_compatible 3.0}

%if 0%{?rhel} && 0%{?rhel} <= 7
%bcond_with python3
%else
%bcond_without python3
%endif

Name:           dnf-plugin-lait
Version:        0.1.0
Release:        1%{?dist}
Summary:        Lait Plugin for DNF
License:        GPLv3
URL:            https://github.com/1dot75cm/dnf-plugin-lait
Source0:        %{url}/archive/%{name}-%{version}/%{name}-%{version}.tar.gz
BuildArch:      noarch
BuildRequires:  cmake
BuildRequires:  gettext
Requires:       git
Requires:       mock
Requires:       rpm-build
Requires:       createrepo_c
%if %{with python3}
Requires:       python3-%{name} = %{version}-%{release}
%else
Requires:       python2-%{name} = %{version}-%{release}
%endif
Recommends:     mock-rpmfusion-free
Recommends:     mock-rpmfusion-nonfree
Provides:       dnf-command(lait)

%description
Lait Plugin for DNF. This package enhances DNF with lait command. It is used
to build and install rpm package from the spec repository.

%package -n python2-%{name}
Summary:        Lait Plugin for DNF
%{?python_provide:%python_provide python2-%{name}}
BuildRequires:  python2-devel
BuildRequires:  python2-dnf >= %{dnf_lowest_compatible}
BuildRequires:  python2-dnf < %{dnf_not_compatible}
Requires:       python2-dnf >= %{dnf_lowest_compatible}
Requires:       python2-dnf < %{dnf_not_compatible}
Requires:       python2-dnf-plugins-core
# let the both python plugin versions be updated simultaneously
Conflicts:      python3-%{name} < %{version}-%{release}
Conflicts:      python-%{name} < %{version}-%{release}

%description -n python2-%{name}
Lait Plugin for DNF, Python 2 interface. This package enhances DNF with lait
command. It is used to build and install rpm package from the spec repository.

%if %{with python3}
%package -n python3-%{name}
Summary:    Lait Plugin for DNF
%{?python_provide:%python_provide python3-%{name}}
BuildRequires:  python3-devel
BuildRequires:  python3-dnf >= %{dnf_lowest_compatible}
BuildRequires:  python3-dnf < %{dnf_not_compatible}
Requires:       python3-dnf >= %{dnf_lowest_compatible}
Requires:       python3-dnf < %{dnf_not_compatible}
Requires:       python3-dnf-plugins-core
# let the both python plugin versions be updated simultaneously
Conflicts:      python2-%{name} < %{version}-%{release}
Conflicts:      python-%{name} < %{version}-%{release}

%description -n python3-%{name}
Lait Plugin for DNF, Python 3 interface. This package enhances DNF with lait
command. It is used to build and install rpm package from the spec repository.
%endif

%prep
%autosetup
mkdir build-py2
%if %{with python3}
mkdir build-py3
%endif

%build
pushd build-py2
  %{cmake} ..
  %{make_build}
popd
%if %{with python3}
pushd build-py3
  %{cmake} .. -DPYTHON_DESIRED:str=3
  %{make_build}
popd
%endif

%install
pushd build-py2
  %{make_install}
popd
%if %{with python3}
pushd build-py3
  %{make_install}
popd
%endif
%find_lang %{name}

%files
%license LICENSE
%doc README.md

%files -n python2-%{name} -f %{name}.lang
%license LICENSE
%doc README.md
%config %{_sysconfdir}/mock/*
%{python2_sitelib}/dnf-plugins/*

%if %{with python3}
%files -n python3-%{name} -f %{name}.lang
%license LICENSE
%doc README.md
%config %{_sysconfdir}/mock/*
%{python3_sitelib}/dnf-plugins/*
%endif

%changelog
* Wed Jun 15 2016 mosquito <sensor.wen@gmail.com> - 0.1.0-1
- Initial package
