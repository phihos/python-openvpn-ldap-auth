# Python OpenVPN LDAP Auth

[![PyPI license](https://img.shields.io/pypi/l/openvpn-ldap-auth.svg)](https://pypi.python.org/pypi/openvpn-ldap-auth/)
[![PyPI status](https://img.shields.io/pypi/status/openvpn-ldap-auth.svg)](https://pypi.python.org/pypi/openvpn-ldap-auth/)
[![PyPI version shields.io](https://img.shields.io/pypi/v/openvpn-ldap-auth.svg)](https://pypi.python.org/pypi/openvpn-ldap-auth/)
[![PyPI pyversions](https://img.shields.io/pypi/pyversions/openvpn-ldap-auth.svg)](https://pypi.python.org/pypi/openvpn-ldap-auth/)
![main build status](https://github.com/phihos/python-openvpn-ldap-auth/actions/workflows/ci.yml/badge.svg?branch=main)

An auth verify script for [OpenVPN](https://community.openvpn.net) to authenticate via LDAP. Each VPN login is
forwarded to this script and the script in turn attempts a simple bind against the specified LDAP server. When the bind
is successful the script returns exit code 0 telling OpenVPN that the credentials are valid.

Although there already is the [openvpn-auth-ldap](https://github.com/threerings/openvpn-auth-ldap) plugin I felt the
need to write this auth script. First the source code is more accessible due to it being written in Python. Second it
offers more possibilities regarding
OpenVPN's [`static-challenge`](https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4/) parameter (see
below).

The downsides of using a script instead of a C-plugin
are [less performance and slightly reduced security](https://openvpn.net/community-resources/using-alternative-authentication-methods/).
If you are fine with that go ahead.

## Quickstart

Install the package (Python 3.11+, python-ldap needs the OpenLDAP and SASL headers to build):

```shell
apt install libldap-dev libsasl2-dev   # Debian/Ubuntu
pipx install openvpn-ldap-auth         # or: uv tool install openvpn-ldap-auth
```

Then create `/etc/openvpn/ldap.yaml`:

```yaml
ldap:
  url: 'ldaps://first.ldap.tld:636/ ldaps://second.ldap.tld:636/'
  bind_dn: 'uid=readonly,dc=example,dc=org'
  password: 'somesecurepassword'
  timeout: 5 # (optional) wait this many seconds for connection and response
authorization:
  base_dn: 'ou=people,dc=example,dc=org'
  search_filter: '(uid={})' # optional, {} will be replaced with the (escaped) username and is required
  static_challenge: 'ignore' # optional, other values are prepend, append 
```

The file contains the bind password, so make it readable for the OpenVPN user only.
Unknown keys are rejected, so typos fail loudly instead of being silently ignored.

Find out where `openvpn-ldap-auth` lives:

```shell
which openvpn-ldap-auth
```

Add the following line to your OpenVPN server configuration:

```
script-security 2
auth-user-pass-verify /path/to/openvpn-ldap-auth via-file
```

Now you can start your OpenVPN server and try to connect with a client.

## Installation

### Single Executable

For those who wish to [sacrifice a little more performance](https://pyinstaller.readthedocs.io/en/stable/operating-mode.html#how-the-one-file-program-works) for not having to install or compile a Python interpreter or you just want to quickly try the script out this option might be interesting.
Each [release](https://github.com/phihos/python-openvpn-ldap-auth/releases) also has executables attached to it: *openvpn-ldap-auth-&lt;version&gt;-ubuntu-&lt;ubuntu-version&gt;-&lt;amd64|arm64&gt;*. They are created via [PyInstaller](https://www.pyinstaller.org/) on the respective Ubuntu version and architecture. They also work on other distros that use the same or a later glibc version.

**Important: /tmp must not be read only.**

### From Source

Download or clone this repository, cd into it and run

```shell
uv build
pipx install dist/openvpn_ldap_auth-*.whl
```

## Configuration

### Static Challenge

If you want users to provide a normal password combined with a one-time-password OpenVPN's
[`static-challenge`](https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4/) parameter is what you
are looking for.

In the client configuration you need to add a line like

```
static-challenge "Enter OTP" 1 # use 0 if the OTP should not be echoed
```

When connecting you will now be prompted for your password and your OTP. By setting `authorization.static_challenge` you
can now influence how the OTP is used:

- *ignore (default)*: Just use the password for binding.
- *prepend*: Prepend the OTP to your password and use that for binding.
- *append*: Append the OTP to your password and use that for binding.

The last two options are useful if your LDAP server offers internal 2FA validation 
like [oath-ldap](https://oath-ldap.stroeder.com/).

### Using `via-env`

In the server configuration the following alternative setting is also supported but discouraged:

```
auth-user-pass-verify /path/to/openvpn-ldap-auth via-env
```

OpenVPN's manpage about that topic:

*If method is set to "via-env", OpenVPN will call script with the environmental variables username and password set to 
the username/password strings provided by the client. Be aware that this method is insecure on some platforms which 
make the environment of a process publicly visible to other unprivileged processes.*

If you still want to use `via-env` make sure to set `script-security` to `3`.

## Development

Install [uv](https://docs.astral.sh/uv/), then:

```shell
uv run pytest            # fast unit tests
uv run ruff format       # format
uv run ruff check        # lint
uv run mypy              # type-check
```

The system tests start a real OpenVPN server and client plus OpenLDAP in
[Docker](https://docs.docker.com/engine/install/) (with the compose plugin), test the
script installed from the built wheel and as a PyInstaller binary, and benchmark both against the
[openvpn-auth-ldap](https://github.com/threerings/openvpn-auth-ldap) C plugin:

```shell
tests/system/run.sh                  # Python 3.14, OpenVPN 2.6
tests/system/run.sh 3.11 2.7 -k env  # any Python/OpenVPN combination, extra args go to pytest
```

Benchmark results land in `benchmark/`.

## Releasing

Bump `version` in `pyproject.toml`, merge, then push a matching tag (`git tag v0.2.0 && git push --tags`).
The release workflow creates the GitHub release, publishes to PyPI via
[Trusted Publishing](https://docs.pypi.org/trusted-publishers/) and attaches the binaries.
