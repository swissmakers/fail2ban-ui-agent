Name:           fail2ban-ui-agent
Version:        0.1.0
Release:        1%{?dist}
Summary:        Fail2ban UI Agent
License:        GPL-3.0-only
URL:            https://github.com/swissmakers/fail2ban-ui
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  golang >= 1.25
Requires:       fail2ban

%description
Standalone agent for Fail2ban-UI. Provides authenticated REST API
for jail/filter management, ban/unban actions, and service control.

%prep
%autosetup

%build
go build -trimpath -ldflags="-s -w" -o %{_builddir}/fail2ban-ui-agent ./cmd/agent

%install
install -D -m 0755 %{_builddir}/fail2ban-ui-agent %{buildroot}%{_bindir}/fail2ban-ui-agent
install -D -m 0644 packaging/systemd/fail2ban-ui-agent.service %{buildroot}%{_unitdir}/fail2ban-ui-agent.service

%post
%systemd_post fail2ban-ui-agent.service

%preun
%systemd_preun fail2ban-ui-agent.service

%postun
%systemd_postun_with_restart fail2ban-ui-agent.service

%files
%license LICENSE
%doc README.md
%{_bindir}/fail2ban-ui-agent
%{_unitdir}/fail2ban-ui-agent.service

%changelog
* Sun Apr 05 2026 Swissmakers <support@swissmakers.ch> - 0.1.0-1
- Initial RPM skeleton
